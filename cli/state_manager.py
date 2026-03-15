"""
State Manager
=============
Persists and restores scan state for pause/resume functionality.

State file format (JSON):
{
    "scan_id": "SCAN_XXXX",
    "targets": ["https://..."],
    "profile": "full",
    "phases_completed": ["recon"],
    "current_phase": "fuzzing",
    "findings": [...],
    "pending_tasks": [...],
    "queued_tasks": ["task_id_1"],
    "processing_tasks": ["task_id_2"],
    "stats": {...},
    "started_at": "ISO8601",
    "paused_at": "ISO8601"
}

Edge cases handled:
    #8  – Resume after crash: skip already-completed tasks via dedup
    #11 – Disk full: fallback directory + alert
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("cli.state_manager")


class StateManager:
    """Save and load scan state to/from disk."""

    def __init__(self, config: dict):
        state_cfg = config.get("state", {})
        self._primary_dir = Path(
            os.path.expanduser(state_cfg.get("directory", "~/.centaur/scans"))
        )
        self._fallback_dir = Path(
            os.path.expanduser(state_cfg.get("fallback_directory", "/tmp/centaur_scans"))
        )
        self._auto_save_interval = state_cfg.get("auto_save_interval", 30)
        self._ensure_directories()

    # ------------------------------------------------------------------
    # Directory management
    # ------------------------------------------------------------------
    def _ensure_directories(self) -> None:
        """Create state directories if they don't exist."""
        for d in [self._primary_dir, self._fallback_dir]:
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                logger.warning("Cannot create directory %s: %s", d, exc)

    def _get_writable_dir(self) -> Path:
        """
        Return a writable directory for state files.
        Edge case #11: disk full or no permissions → try fallback.
        """
        # Test write to primary
        test_file = self._primary_dir / ".write_test"
        try:
            test_file.write_text("test")
            test_file.unlink()
            return self._primary_dir
        except OSError:
            logger.warning(
                "Primary state dir %s not writable. Using fallback %s. (Edge case #11)",
                self._primary_dir,
                self._fallback_dir,
            )

        # Test write to fallback
        try:
            self._fallback_dir.mkdir(parents=True, exist_ok=True)
            test_file = self._fallback_dir / ".write_test"
            test_file.write_text("test")
            test_file.unlink()
            return self._fallback_dir
        except OSError as exc:
            logger.error(
                "CRITICAL: Neither primary nor fallback state directories are writable! "
                "State WILL NOT be saved. (Edge case #11) Error: %s",
                exc,
            )
            # Return primary anyway; save_state will catch the error
            return self._primary_dir

    # ------------------------------------------------------------------
    # Save / Load
    # ------------------------------------------------------------------
    def save_state(self, state: dict) -> Optional[str]:
        """
        Save scan state to JSON file.
        Returns the path where state was saved, or None on failure.
        """
        scan_id = state.get("scan_id", "UNKNOWN")
        state["paused_at"] = datetime.now(timezone.utc).isoformat()

        target_dir = self._get_writable_dir()
        filepath = target_dir / f"{scan_id}.json"

        # Write atomically: write to temp then rename
        tmp_filepath = filepath.with_suffix(".json.tmp")
        try:
            serialized = json.dumps(state, indent=2, default=str)
            tmp_filepath.write_text(serialized)
            # Atomic rename (on same filesystem)
            shutil.move(str(tmp_filepath), str(filepath))
            logger.info("Scan state saved to %s (%d bytes)", filepath, len(serialized))
            return str(filepath)
        except OSError as exc:
            logger.error(
                "Failed to save state to %s: %s (Edge case #11)", filepath, exc
            )
            # Try the other directory
            alt_dir = (
                self._fallback_dir
                if target_dir == self._primary_dir
                else self._primary_dir
            )
            alt_path = alt_dir / f"{scan_id}.json"
            try:
                alt_path.write_text(json.dumps(state, indent=2, default=str))
                logger.info("State saved to alternative location: %s", alt_path)
                return str(alt_path)
            except OSError as exc2:
                logger.error(
                    "CRITICAL: Cannot save state anywhere! %s (Edge case #11)", exc2
                )
                return None

    def load_state(self, scan_id: str) -> Optional[dict]:
        """
        Load scan state from JSON file.
        Searches both primary and fallback directories.
        Returns None if not found.
        """
        for search_dir in [self._primary_dir, self._fallback_dir]:
            filepath = search_dir / f"{scan_id}.json"
            if filepath.exists():
                try:
                    data = json.loads(filepath.read_text())
                    logger.info("Loaded scan state from %s", filepath)
                    return data
                except (json.JSONDecodeError, OSError) as exc:
                    logger.error("Corrupt state file %s: %s", filepath, exc)
                    continue

        logger.warning("No state file found for scan %s", scan_id)
        return None

    def list_saved_scans(self) -> list:
        """List all saved scan IDs with basic metadata."""
        scans = []
        for search_dir in [self._primary_dir, self._fallback_dir]:
            if not search_dir.exists():
                continue
            for filepath in search_dir.glob("SCAN_*.json"):
                try:
                    data = json.loads(filepath.read_text())
                    scans.append({
                        "scan_id": data.get("scan_id", filepath.stem),
                        "targets": data.get("targets", []),
                        "profile": data.get("profile", "unknown"),
                        "paused_at": data.get("paused_at", "unknown"),
                        "phases_completed": data.get("phases_completed", []),
                        "findings_count": len(data.get("findings", [])),
                        "path": str(filepath),
                    })
                except (json.JSONDecodeError, OSError):
                    continue
        return scans

    def delete_state(self, scan_id: str) -> bool:
        """Remove a saved state file (after successful completion)."""
        for search_dir in [self._primary_dir, self._fallback_dir]:
            filepath = search_dir / f"{scan_id}.json"
            if filepath.exists():
                try:
                    filepath.unlink()
                    logger.info("Deleted state file %s", filepath)
                    return True
                except OSError as exc:
                    logger.error("Cannot delete %s: %s", filepath, exc)
        return False

    @property
    def auto_save_interval(self) -> int:
        return self._auto_save_interval
