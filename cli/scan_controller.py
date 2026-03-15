"""
Scan Controller
===============
Orchestrates the phased scan lifecycle:
    Phase 1: Recon      (subfinder, httpx, nuclei)
    Phase 2: Fuzzing    (smart_fuzzer for discovered endpoints)
    Phase 3: Sniper     (nuclei sniper for fresh CVEs)
    Phase 4: Reporting  (auto-generated after completion)

Communicates with backend services exclusively via Redis queues.
Tracks progress, collects findings, and supports pause/resume.

Edge cases handled:
    #3  – Network partition / Redis unreachable → retry with backoff + buffer
    #4  – Target unreachable → log, continue, mark as failed
    #5  – AI provider fails → fallback to deterministic scans
    #6  – RAG timeout → proceed without context
    #8  – Resume: skip completed tasks via dedup
    #15 – Stuck tasks during pause → timeout monitor will requeue
"""

import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

logger = logging.getLogger("cli.scan_controller")

try:
    import redis as redis_lib

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    logger.error("redis library not installed. ScanController cannot function.")


class ScanController:
    """
    Master scan lifecycle manager.

    Pushes tasks to Redis queues, polls for completion, collects findings,
    and progresses through configured phases.
    """

    # Phase ordering
    ALL_PHASES = ["recon", "fuzzing", "sniper", "reporting"]

    def __init__(
        self,
        scan_id: str,
        targets: List[str],
        profile_name: str,
        profile_config: dict,
        config: dict,
        state_manager=None,
        resume_state: Optional[dict] = None,
    ):
        self.scan_id = scan_id
        self.targets = targets
        self.profile_name = profile_name
        self.profile_config = profile_config
        self._config = config
        self._state_manager = state_manager

        # Scan state
        self.phases_completed: List[str] = []
        self.current_phase: Optional[str] = None
        self.findings: List[dict] = []
        self.errors: List[dict] = []
        self.started_at: str = datetime.now(timezone.utc).isoformat()
        self.paused_at: Optional[str] = None

        # Task tracking
        self._pending_tasks: List[dict] = []  # tasks not yet pushed to Redis
        self._queued_task_ids: Set[str] = set()  # task IDs pushed to queue
        self._processing_task_ids: Set[str] = set()  # task IDs being processed
        self._completed_task_ids: Set[str] = set()  # task IDs finished
        self._failed_task_ids: Set[str] = set()

        # Stats
        self._stats = {
            "tasks_pushed": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "findings_count": 0,
            "requests_sent": 0,
            "ai_calls": 0,
            "rag_snippets": 0,
        }

        # Discovered data (from recon phase)
        self._discovered_endpoints: List[str] = []
        self._discovered_subdomains: List[str] = []

        # Shutdown / pause control
        self._shutdown_requested = threading.Event()
        self._lock = threading.Lock()

        # Redis
        self._redis: Optional[redis_lib.Redis] = None
        self._redis_cfg = config.get("redis", {})

        # Phase progress for dashboard
        self._phase_progress: Dict[str, dict] = {}

        # Load resume state if available
        if resume_state:
            self._restore_state(resume_state)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def is_paused(self) -> bool:
        return self._shutdown_requested.is_set() and self.current_phase is not None

    @property
    def is_completed(self) -> bool:
        enabled_phases = self.profile_config.get("phases", ["recon"])
        return all(p in self.phases_completed for p in enabled_phases)

    @property
    def status(self) -> str:
        if self.is_completed:
            return "COMPLETED"
        if self.is_paused:
            return "PAUSED"
        if self._shutdown_requested.is_set():
            return "SHUTTING_DOWN"
        if self.current_phase:
            return "RUNNING"
        return "IDLE"

    @property
    def elapsed_seconds(self) -> float:
        start = datetime.fromisoformat(self.started_at)
        now = datetime.now(timezone.utc)
        return (now - start).total_seconds()

    # ------------------------------------------------------------------
    # Redis connection
    # ------------------------------------------------------------------
    def _get_redis(self) -> Optional[redis_lib.Redis]:
        """Get or create Redis client with connection validation."""
        if self._redis is not None:
            try:
                self._redis.ping()
                return self._redis
            except Exception:
                self._redis = None

        if not HAS_REDIS:
            logger.error("redis library not available.")
            return None

        try:
            client = redis_lib.Redis(
                host=self._redis_cfg.get("host", "127.0.0.1"),
                port=self._redis_cfg.get("port", 6379),
                db=self._redis_cfg.get("db", 0),
                socket_timeout=self._redis_cfg.get("socket_timeout", 5),
                retry_on_timeout=self._redis_cfg.get("retry_on_timeout", True),
                decode_responses=True,
            )
            client.ping()
            self._redis = client
            return client
        except Exception as exc:
            logger.error("Cannot connect to Redis: %s (Edge case #3)", exc)
            return None

    # ------------------------------------------------------------------
    # Task ID generation
    # ------------------------------------------------------------------
    def _make_task_id(self, task_type: str, target: str, extra: str = "") -> str:
        """Generate a deterministic task ID for deduplication."""
        raw = f"{self.scan_id}:{task_type}:{target}:{extra}"
        return f"task_{uuid.uuid5(uuid.NAMESPACE_URL, raw).hex[:16]}"

    # ------------------------------------------------------------------
    # Push task to Redis (with retry)
    # ------------------------------------------------------------------
    @retry(
        retry=retry_if_exception_type(Exception),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=1, max=30),
        reraise=True,
    )
    def _push_task(self, queue: str, task: dict) -> bool:
        """
        Push a task to a Redis queue.
        Edge case #3: Retry with exponential backoff.
        """
        client = self._get_redis()
        if client is None:
            raise ConnectionError("Redis unavailable")

        task_json = json.dumps(task, default=str)
        client.rpush(queue, task_json)

        task_id = task.get("task_id", "unknown")
        # Also set a status key
        client.set(f"task:status:{task_id}", "QUEUED")

        with self._lock:
            self._queued_task_ids.add(task_id)
            self._stats["tasks_pushed"] += 1

        logger.debug("Pushed task %s to %s", task_id, queue)
        return True

    def _push_task_safe(self, queue: str, task: dict) -> bool:
        """Push task with graceful failure handling."""
        try:
            return self._push_task(queue, task)
        except Exception as exc:
            logger.error(
                "Failed to push task after retries: %s. Buffering. (Edge case #3)", exc
            )
            with self._lock:
                self._pending_tasks.append({"queue": queue, "task": task})
                self._add_error(f"Task push failed: {exc}")
            return False

    # ------------------------------------------------------------------
    # Poll task statuses
    # ------------------------------------------------------------------
    def _poll_task_statuses(self) -> Dict[str, str]:
        """
        Poll Redis for status of all queued/processing tasks.
        Returns dict of task_id → status.
        """
        client = self._get_redis()
        if client is None:
            return {}

        statuses = {}
        task_ids = list(self._queued_task_ids | self._processing_task_ids)

        if not task_ids:
            return {}

        # Use pipeline for efficiency
        pipe = client.pipeline(transaction=False)
        for tid in task_ids:
            pipe.get(f"task:status:{tid}")

        try:
            results = pipe.execute()
            for tid, result in zip(task_ids, results):
                statuses[tid] = result or "UNKNOWN"
        except Exception as exc:
            logger.warning("Status poll failed: %s", exc)

        return statuses

    def _consume_results(self) -> List[dict]:
        """
        Consume results from the results queue.
        Returns list of result dicts.
        """
        client = self._get_redis()
        if client is None:
            return []

        results = []
        results_key = f"results:{self.scan_id}"

        try:
            # Non-blocking LPOP in a batch
            while True:
                raw = client.lpop(results_key)
                if raw is None:
                    break
                try:
                    result = json.loads(raw)
                    results.append(result)
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON in results queue: %s", raw[:100])
        except Exception as exc:
            logger.warning("Results consumption failed: %s", exc)

        return results

    def _process_result(self, result: dict) -> None:
        """Process a single task result."""
        task_id = result.get("task_id", "unknown")
        status = result.get("status", "UNKNOWN").upper()
        data = result.get("data", {})

        with self._lock:
            self._queued_task_ids.discard(task_id)
            self._processing_task_ids.discard(task_id)

            if status == "COMPLETED":
                self._completed_task_ids.add(task_id)
                self._stats["tasks_completed"] += 1

                # Extract findings
                findings = data.get("findings", [])
                if findings:
                    for finding in findings:
                        finding["scan_id"] = self.scan_id
                        finding["discovered_at"] = datetime.now(timezone.utc).isoformat()
                    self.findings.extend(findings)
                    self._stats["findings_count"] += len(findings)
                    logger.info(
                        "Task %s completed with %d finding(s).", task_id, len(findings)
                    )

                # Extract discovered endpoints/subdomains
                endpoints = data.get("endpoints", [])
                subdomains = data.get("subdomains", [])
                self._discovered_endpoints.extend(endpoints)
                self._discovered_subdomains.extend(subdomains)

                # Track stats from result
                self._stats["requests_sent"] += data.get("requests_sent", 0)
                self._stats["ai_calls"] += data.get("ai_calls", 0)
                self._stats["rag_snippets"] += data.get("rag_snippets", 0)

            elif status == "FAILED":
                self._failed_task_ids.add(task_id)
                self._stats["tasks_failed"] += 1
                error_msg = data.get("error", result.get("error", "Unknown error"))
                self._add_error(f"Task {task_id} failed: {error_msg}")
                logger.warning("Task %s failed: %s", task_id, error_msg)
            else:
                # PROCESSING or other intermediate status
                self._processing_task_ids.add(task_id)

    # ------------------------------------------------------------------
    # Wait for phase completion
    # ------------------------------------------------------------------
    def _wait_for_phase(self, phase_name: str, timeout: int = 3600) -> bool:
        """
        Wait until all tasks for the current phase are done.
        Returns True if all completed, False if shutdown requested or timeout.
        """
        start_time = time.time()
        poll_interval = 2  # seconds
        auto_save_interval = self._state_manager.auto_save_interval if self._state_manager else 30
        last_auto_save = time.time()

        while not self._shutdown_requested.is_set():
            # Check timeout
            elapsed = time.time() - start_time
            if elapsed > timeout:
                logger.warning("Phase '%s' timed out after %ds.", phase_name, timeout)
                self._add_error(f"Phase {phase_name} timed out")
                return False

            # Consume and process results
            results = self._consume_results()
            for result in results:
                self._process_result(result)

            # Update statuses from Redis
            statuses = self._poll_task_statuses()
            with self._lock:
                for tid, s in statuses.items():
                    s_upper = s.upper()
                    if s_upper == "COMPLETED" and tid not in self._completed_task_ids:
                        # Result may come through results queue; this is backup
                        pass
                    elif s_upper == "PROCESSING":
                        self._queued_task_ids.discard(tid)
                        self._processing_task_ids.add(tid)
                    elif s_upper == "FAILED" and tid not in self._failed_task_ids:
                        self._failed_task_ids.add(tid)
                        self._stats["tasks_failed"] += 1

            # Check if all tasks are done
            with self._lock:
                pending_count = len(self._queued_task_ids) + len(self._processing_task_ids)

            if pending_count == 0 and not self._pending_tasks:
                logger.info("Phase '%s' completed.", phase_name)
                return True

            # Update phase progress for dashboard
            with self._lock:
                total = (
                    len(self._queued_task_ids)
                    + len(self._processing_task_ids)
                    + len(self._completed_task_ids)
                    + len(self._failed_task_ids)
                )
                done = len(self._completed_task_ids) + len(self._failed_task_ids)
                self._phase_progress[phase_name] = {
                    "total": total,
                    "done": done,
                    "pending": pending_count,
                }

            # Auto-save state periodically
            if time.time() - last_auto_save > auto_save_interval:
                if self._state_manager:
                    self._state_manager.save_state(self.get_state())
                    last_auto_save = time.time()

            time.sleep(poll_interval)

        # Shutdown requested
        logger.info("Shutdown requested during phase '%s'.", phase_name)
        return False

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------
    def _run_recon_phase(self) -> bool:
        """Phase 1: Reconnaissance."""
        self.current_phase = "recon"
        logger.info("=== Phase 1: Recon ===")

        recon_tasks = self.profile_config.get("recon_tasks", ["nuclei"])

        for target in self.targets:
            for task_type in recon_tasks:
                task_id = self._make_task_id(f"RECON_{task_type.upper()}", target)

                # Skip if already completed (edge case #8 – resume dedup)
                if task_id in self._completed_task_ids:
                    logger.info("Skipping already-completed task %s (Edge case #8)", task_id)
                    continue

                task = {
                    "task_id": task_id,
                    "scan_id": self.scan_id,
                    "type": f"RECON_{task_type.upper()}",
                    "target": target,
                    "params": {
                        "tool": task_type,
                        "profile": self.profile_name,
                    },
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

                self._push_task_safe("queue:recon", task)

        # Wait for recon completion
        timeout = self.profile_config.get("timeout", 3600)
        return self._wait_for_phase("recon", timeout=timeout)

    def _run_fuzzing_phase(self) -> bool:
        """Phase 2: Smart Fuzzing."""
        fuzzing_cfg = self.profile_config.get("fuzzing", {})
        if not fuzzing_cfg.get("enabled", False):
            logger.info("Fuzzing disabled in profile. Skipping.")
            return True

        self.current_phase = "fuzzing"
        logger.info("=== Phase 2: Fuzzing ===")

        vuln_types = fuzzing_cfg.get("vuln_types", ["xss", "sqli"])
        max_iterations = fuzzing_cfg.get("max_iterations", 3)

        # Use endpoints discovered in recon
        endpoints = self._discovered_endpoints or self.targets

        if not endpoints:
            logger.warning("No endpoints discovered for fuzzing. Using targets directly.")
            endpoints = self.targets

        for endpoint in endpoints:
            for vuln_type in vuln_types:
                task_id = self._make_task_id(f"FUZZ_{vuln_type.upper()}", endpoint)

                if task_id in self._completed_task_ids:
                    logger.info("Skipping completed fuzz task %s (Edge case #8)", task_id)
                    continue

                task = {
                    "task_id": task_id,
                    "scan_id": self.scan_id,
                    "type": f"FUZZ_{vuln_type.upper()}",
                    "target": endpoint,
                    "params": {
                        "vuln_type": vuln_type,
                        "max_iterations": max_iterations,
                        "profile": self.profile_name,
                    },
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }

                self._push_task_safe("queue:smart_fuzzer", task)

        timeout = self.profile_config.get("timeout", 3600)
        return self._wait_for_phase("fuzzing", timeout=timeout)

    def _run_sniper_phase(self) -> bool:
        """Phase 3: Sniper (CVE-based scanning)."""
        sniper_cfg = self.profile_config.get("sniper", {})
        if not sniper_cfg.get("enabled", False):
            logger.info("Sniper disabled in profile. Skipping.")
            return True

        self.current_phase = "sniper"
        logger.info("=== Phase 3: Sniper ===")

        feeds = sniper_cfg.get("feeds", ["github"])

        for target in self.targets:
            task_id = self._make_task_id("SNIPER", target)

            if task_id in self._completed_task_ids:
                logger.info("Skipping completed sniper task %s (Edge case #8)", task_id)
                continue

            task = {
                "task_id": task_id,
                "scan_id": self.scan_id,
                "type": "SNIPER",
                "target": target,
                "params": {
                    "feeds": feeds,
                    "profile": self.profile_name,
                },
                "created_at": datetime.now(timezone.utc).isoformat(),
            }

            self._push_task_safe("queue:sniper", task)

        timeout = self.profile_config.get("timeout", 3600)
        return self._wait_for_phase("sniper", timeout=timeout)

    # ------------------------------------------------------------------
    # Main run method
    # ------------------------------------------------------------------
    def run(self) -> None:
        """Execute the full scan lifecycle."""
        enabled_phases = self.profile_config.get("phases", ["recon"])
        logger.info(
            "Starting scan %s: targets=%d, phases=%s",
            self.scan_id,
            len(self.targets),
            enabled_phases,
        )

        # Store scan metadata in Redis
        self._store_scan_metadata()

        phase_runners = {
            "recon": self._run_recon_phase,
            "fuzzing": self._run_fuzzing_phase,
            "sniper": self._run_sniper_phase,
        }

        for phase in enabled_phases:
            if self._shutdown_requested.is_set():
                logger.info("Shutdown requested. Stopping before phase '%s'.", phase)
                break

            if phase in self.phases_completed:
                logger.info("Phase '%s' already completed (resume). Skipping.", phase)
                continue

            runner = phase_runners.get(phase)
            if runner is None:
                logger.warning("Unknown phase '%s'. Skipping.", phase)
                continue

            success = runner()
            if success:
                self.phases_completed.append(phase)
                logger.info("Phase '%s' completed successfully.", phase)
            elif self._shutdown_requested.is_set():
                break
            else:
                logger.error("Phase '%s' failed. Stopping scan.", phase)
                self._add_error(f"Phase {phase} failed")
                break

        # Final result consumption (drain any remaining results)
        results = self._consume_results()
        for result in results:
            self._process_result(result)

        if not self._shutdown_requested.is_set():
            self.current_phase = None
            logger.info(
                "Scan %s completed. Findings: %d, Failed tasks: %d",
                self.scan_id,
                len(self.findings),
                self._stats["tasks_failed"],
            )

    # ------------------------------------------------------------------
    # State management
    # ------------------------------------------------------------------
    def get_state(self) -> dict:
        """Export full scan state for persistence."""
        with self._lock:
            return {
                "scan_id": self.scan_id,
                "targets": self.targets,
                "profile": self.profile_name,
                "profile_config": self.profile_config,
                "phases_completed": list(self.phases_completed),
                "current_phase": self.current_phase,
                "findings": list(self.findings),
                "errors": list(self.errors),
                "pending_tasks": list(self._pending_tasks),
                "queued_tasks": list(self._queued_task_ids),
                "processing_tasks": list(self._processing_task_ids),
                "completed_tasks": list(self._completed_task_ids),
                "failed_tasks": list(self._failed_task_ids),
                "discovered_endpoints": list(self._discovered_endpoints),
                "discovered_subdomains": list(self._discovered_subdomains),
                "stats": dict(self._stats),
                "started_at": self.started_at,
                "paused_at": self.paused_at,
            }

    def _restore_state(self, state: dict) -> None:
        """Restore scan state from a previously saved state."""
        self.phases_completed = state.get("phases_completed", [])
        self.findings = state.get("findings", [])
        self.errors = state.get("errors", [])
        self.started_at = state.get("started_at", self.started_at)
        self._pending_tasks = state.get("pending_tasks", [])
        self._completed_task_ids = set(state.get("completed_tasks", []))
        self._failed_task_ids = set(state.get("failed_tasks", []))
        self._queued_task_ids = set(state.get("queued_tasks", []))
        self._processing_task_ids = set(state.get("processing_tasks", []))
        self._discovered_endpoints = state.get("discovered_endpoints", [])
        self._discovered_subdomains = state.get("discovered_subdomains", [])
        self._stats = state.get("stats", self._stats)
        logger.info(
            "State restored: %d phases completed, %d findings, %d pending tasks",
            len(self.phases_completed),
            len(self.findings),
            len(self._pending_tasks),
        )

    def _store_scan_metadata(self) -> None:
        """Store scan metadata in Redis for dashboard/other modules."""
        client = self._get_redis()
        if client is None:
            return
        try:
            meta = {
                "scan_id": self.scan_id,
                "targets": json.dumps(self.targets),
                "profile": self.profile_name,
                "started_at": self.started_at,
                "status": "RUNNING",
            }
            client.hset(f"scan:{self.scan_id}", mapping=meta)
            # Set TTL of 24 hours on scan metadata
            client.expire(f"scan:{self.scan_id}", 86400)
        except Exception as exc:
            logger.warning("Cannot store scan metadata: %s", exc)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def request_shutdown(self) -> None:
        """Request graceful shutdown."""
        logger.info("Shutdown requested for scan %s.", self.scan_id)
        self._shutdown_requested.set()
        self.paused_at = datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Dashboard data
    # ------------------------------------------------------------------
    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def get_phase_progress(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._phase_progress)

    def get_recent_findings(self, n: int = 50) -> List[dict]:
        with self._lock:
            return list(self.findings[-n:])

    def get_recent_errors(self, n: int = 20) -> List[dict]:
        with self._lock:
            return list(self.errors[-n:])

    def get_queue_lengths(self) -> Dict[str, int]:
        """Get current queue lengths from Redis."""
        client = self._get_redis()
        if client is None:
            return {}

        queues = {
            "queue:recon": 0,
            "queue:smart_fuzzer": 0,
            "queue:sniper": 0,
            f"results:{self.scan_id}": 0,
        }

        try:
            pipe = client.pipeline(transaction=False)
            for q in queues:
                pipe.llen(q)
            results = pipe.execute()
            for q, length in zip(queues, results):
                queues[q] = length or 0
        except Exception as exc:
            logger.debug("Queue length poll failed: %s", exc)

        return queues

    # ------------------------------------------------------------------
    # Error tracking
    # ------------------------------------------------------------------
    def _add_error(self, message: str) -> None:
        self.errors.append({
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        # Keep last 100 errors
        if len(self.errors) > 100:
            self.errors = self.errors[-100:]
