"""
Process Manager
===============
Manages backend service lifecycle (auto mode).
Ensures Redis, orchestrator, workers, and other services are running.

Edge cases handled:
    #1  – Redis not running → attempt to start; clear error if fails
    #2  – Service crashes during scan → detect via heartbeat; restart
    #16 – Hung child processes after Ctrl+C → SIGKILL after timeout
    #18 – No permissions to start services → suggest manual mode
"""

import logging
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("cli.process_manager")

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    logger.warning("psutil not installed. Process management capabilities reduced.")

try:
    import redis as redis_lib

    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    logger.warning("redis library not installed.")


class ProcessManager:
    """Start, monitor, and stop backend services."""

    def __init__(self, config: dict):
        self._config = config
        proc_cfg = config.get("processes", {})
        self._heartbeat_timeout = proc_cfg.get("heartbeat_timeout", 30)
        self._kill_timeout = proc_cfg.get("kill_timeout", 10)
        self._pid_dir = Path(
            os.path.expanduser(proc_cfg.get("pid_directory", "~/.centaur/pids"))
        )
        self._pid_dir.mkdir(parents=True, exist_ok=True)

        self._services_config: Dict[str, dict] = proc_cfg.get("services", {})
        self._managed_processes: Dict[str, subprocess.Popen] = {}
        self._redis_client: Optional[redis_lib.Redis] = None

        redis_cfg = config.get("redis", {})
        self._redis_host = redis_cfg.get("host", "127.0.0.1")
        self._redis_port = redis_cfg.get("port", 6379)
        self._redis_db = redis_cfg.get("db", 0)

    # ------------------------------------------------------------------
    # Redis
    # ------------------------------------------------------------------
    def _get_redis(self) -> Optional[redis_lib.Redis]:
        """Get or create a Redis client."""
        if self._redis_client is not None:
            try:
                self._redis_client.ping()
                return self._redis_client
            except Exception:
                self._redis_client = None

        if not HAS_REDIS:
            return None

        redis_cfg = self._config.get("redis", {})
        try:
            client = redis_lib.Redis(
                host=self._redis_host,
                port=self._redis_port,
                db=self._redis_db,
                socket_timeout=redis_cfg.get("socket_timeout", 5),
                retry_on_timeout=redis_cfg.get("retry_on_timeout", True),
                decode_responses=True,
            )
            client.ping()
            self._redis_client = client
            return client
        except Exception:
            return None

    def ensure_redis(self) -> bool:
        """
        Ensure Redis is running.
        Edge case #1: If not running, attempt to start it.
        """
        client = self._get_redis()
        if client is not None:
            logger.info("Redis is already running at %s:%d", self._redis_host, self._redis_port)
            return True

        logger.warning("Redis not responding. Attempting to start... (Edge case #1)")

        # Try starting Redis via common methods
        start_commands = [
            ["redis-server", "--daemonize", "yes", "--port", str(self._redis_port)],
            ["docker", "run", "-d", "--name", "centaur-redis", "-p", f"{self._redis_port}:6379", "redis:alpine"],
        ]

        for cmd in start_commands:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                if result.returncode == 0:
                    # Wait for Redis to be ready
                    for _ in range(10):
                        time.sleep(1)
                        client = self._get_redis()
                        if client is not None:
                            logger.info("Redis started successfully via: %s", " ".join(cmd))
                            return True
            except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
                logger.debug("Command %s failed: %s", cmd[0], exc)
                continue

        logger.error(
            "CRITICAL: Cannot start Redis. Install Redis and start it manually, "
            "or use Docker. (Edge case #1)"
        )
        return False

    # ------------------------------------------------------------------
    # Service management
    # ------------------------------------------------------------------
    def ensure_service(self, service_name: str) -> bool:
        """
        Ensure a named service is running.
        1. Check Redis first (edge case #1)
        2. Check heartbeat in Redis
        3. Check PID file
        4. If not running, start it

        Edge case #18: No permissions → return False with clear message.
        """
        # Always ensure Redis first
        if service_name != "redis" and not self.ensure_redis():
            logger.error("Cannot ensure service '%s' without Redis.", service_name)
            return False

        svc_cfg = self._services_config.get(service_name)
        if svc_cfg is None:
            logger.error("Unknown service '%s'. Check config.yaml.", service_name)
            return False

        # Check if already running via heartbeat
        if self._check_heartbeat(service_name, svc_cfg):
            logger.info("Service '%s' is running (heartbeat OK).", service_name)
            return True

        # Check if we have a managed process for it
        if service_name in self._managed_processes:
            proc = self._managed_processes[service_name]
            if proc.poll() is None:  # still running
                logger.info("Service '%s' process is alive (PID %d).", service_name, proc.pid)
                return True
            else:
                logger.warning(
                    "Service '%s' process exited (code %s). Restarting... (Edge case #2)",
                    service_name,
                    proc.returncode,
                )

        # Check PID file
        pid = self._read_pid_file(service_name)
        if pid and self._is_process_alive(pid):
            logger.info(
                "Service '%s' found via PID file (PID %d).", service_name, pid
            )
            return True

        # Start the service
        return self._start_service(service_name, svc_cfg)

    def _check_heartbeat(self, service_name: str, svc_cfg: dict) -> bool:
        """Check service heartbeat in Redis."""
        client = self._get_redis()
        if client is None:
            return False

        heartbeat_key = svc_cfg.get("heartbeat_key", f"heartbeat:{service_name}")
        try:
            last_beat = client.get(heartbeat_key)
            if last_beat is None:
                return False
            # Check if heartbeat is recent
            from datetime import datetime, timezone

            beat_time = datetime.fromisoformat(last_beat)
            elapsed = (datetime.now(timezone.utc) - beat_time).total_seconds()
            return elapsed < self._heartbeat_timeout
        except Exception as exc:
            logger.debug("Heartbeat check failed for %s: %s", service_name, exc)
            return False

    def _start_service(self, service_name: str, svc_cfg: dict) -> bool:
        """
        Start a service as a background subprocess.
        Edge case #18: Handle permission errors.
        """
        command = svc_cfg.get("command", "")
        if not command:
            logger.error("No command configured for service '%s'.", service_name)
            return False

        cmd_parts = command.split()
        logger.info("Starting service '%s': %s", service_name, command)

        try:
            # Create log file for the service
            log_dir = Path(os.path.expanduser("~/.centaur/logs"))
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / f"{service_name}.log"

            with open(log_file, "a") as lf:
                proc = subprocess.Popen(
                    cmd_parts,
                    stdout=lf,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,  # detach from parent
                    preexec_fn=os.setsid if sys.platform != "win32" else None,
                )

            self._managed_processes[service_name] = proc
            self._write_pid_file(service_name, proc.pid)

            # Wait a moment for the service to initialize
            time.sleep(3)

            # Verify it's still running
            if proc.poll() is not None:
                logger.error(
                    "Service '%s' exited immediately (code %s). Check %s for details.",
                    service_name,
                    proc.returncode,
                    log_file,
                )
                return False

            logger.info(
                "Service '%s' started (PID %d). Logs: %s",
                service_name,
                proc.pid,
                log_file,
            )
            return True

        except PermissionError as exc:
            logger.error(
                "Permission denied starting '%s': %s. (Edge case #18) "
                "Run with appropriate permissions or use --manual.",
                service_name,
                exc,
            )
            return False
        except FileNotFoundError as exc:
            logger.error(
                "Command not found for '%s': %s. Check config.yaml.", service_name, exc
            )
            return False
        except OSError as exc:
            logger.error("OS error starting '%s': %s", service_name, exc)
            return False

    # ------------------------------------------------------------------
    # PID files
    # ------------------------------------------------------------------
    def _write_pid_file(self, service_name: str, pid: int) -> None:
        pid_file = self._pid_dir / f"{service_name}.pid"
        try:
            pid_file.write_text(str(pid))
        except OSError as exc:
            logger.warning("Cannot write PID file %s: %s", pid_file, exc)

    def _read_pid_file(self, service_name: str) -> Optional[int]:
        pid_file = self._pid_dir / f"{service_name}.pid"
        if not pid_file.exists():
            return None
        try:
            return int(pid_file.read_text().strip())
        except (ValueError, OSError):
            return None

    def _remove_pid_file(self, service_name: str) -> None:
        pid_file = self._pid_dir / f"{service_name}.pid"
        pid_file.unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Process utilities
    # ------------------------------------------------------------------
    @staticmethod
    def _is_process_alive(pid: int) -> bool:
        if not HAS_PSUTIL:
            try:
                os.kill(pid, 0)
                return True
            except (ProcessLookupError, PermissionError):
                return False

        try:
            proc = psutil.Process(pid)
            return proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

    # ------------------------------------------------------------------
    # Health check (called periodically during scan)
    # ------------------------------------------------------------------
    def health_check(self) -> Dict[str, bool]:
        """
        Check all managed services' health.
        Edge case #2: Detect crashes; return status dict.
        """
        status = {}
        for svc_name in self._managed_processes:
            proc = self._managed_processes[svc_name]
            alive = proc.poll() is None
            status[svc_name] = alive
            if not alive:
                logger.warning(
                    "Service '%s' has crashed (exit code %s). (Edge case #2)",
                    svc_name,
                    proc.returncode,
                )
        return status

    def restart_crashed(self) -> List[str]:
        """Attempt to restart any crashed managed services."""
        restarted = []
        for svc_name, proc in list(self._managed_processes.items()):
            if proc.poll() is not None:  # process has exited
                svc_cfg = self._services_config.get(svc_name, {})
                logger.info("Attempting to restart crashed service '%s'...", svc_name)
                if self._start_service(svc_name, svc_cfg):
                    restarted.append(svc_name)
                else:
                    logger.error("Failed to restart '%s'.", svc_name)
        return restarted

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------
    def stop_all(self) -> None:
        """
        Gracefully stop all managed services.
        Edge case #16: SIGKILL after timeout for hung processes.
        """
        if not self._managed_processes:
            logger.debug("No managed processes to stop.")
            return

        logger.info("Stopping %d managed service(s)...", len(self._managed_processes))

        # Phase 1: Send SIGTERM to all
        for svc_name, proc in self._managed_processes.items():
            if proc.poll() is None:
                logger.info("Sending SIGTERM to '%s' (PID %d)", svc_name, proc.pid)
                try:
                    if sys.platform != "win32":
                        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                    else:
                        proc.terminate()
                except (ProcessLookupError, PermissionError, OSError) as exc:
                    logger.debug("SIGTERM to '%s' failed: %s", svc_name, exc)

        # Phase 2: Wait for graceful exit
        deadline = time.time() + self._kill_timeout
        for svc_name, proc in self._managed_processes.items():
            remaining = max(0, deadline - time.time())
            try:
                proc.wait(timeout=remaining)
                logger.info("Service '%s' exited gracefully.", svc_name)
            except subprocess.TimeoutExpired:
                # Phase 3: Force kill (edge case #16)
                logger.warning(
                    "Service '%s' did not stop within %ds. Sending SIGKILL. (Edge case #16)",
                    svc_name,
                    self._kill_timeout,
                )
                try:
                    if sys.platform != "win32":
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    else:
                        proc.kill()
                    proc.wait(timeout=5)
                except Exception as exc:
                    logger.error("Cannot kill '%s': %s", svc_name, exc)

            self._remove_pid_file(svc_name)

        self._managed_processes.clear()
        logger.info("All managed services stopped.")

    def stop_service(self, service_name: str) -> bool:
        """Stop a single managed service."""
        proc = self._managed_processes.get(service_name)
        if proc is None or proc.poll() is not None:
            self._remove_pid_file(service_name)
            return True

        try:
            proc.terminate()
            proc.wait(timeout=self._kill_timeout)
        except subprocess.TimeoutExpired:
            logger.warning("Force-killing '%s'. (Edge case #16)", service_name)
            proc.kill()
            proc.wait(timeout=5)

        self._remove_pid_file(service_name)
        del self._managed_processes[service_name]
        return True
