"""
shared/schemas.py
=================
Canonical data-transfer objects used across ALL Centaur-Jarvis modules.

Every schema enforces strict validation at construction time so that
invalid data never silently propagates across module boundaries.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class TaskType(str, enum.Enum):
    """Exhaustive set of recognised recon task types."""
    RECON_SUBDOMAIN = "RECON_SUBDOMAIN"
    RECON_HTTPX = "RECON_HTTPX"
    RECON_NUCLEI = "RECON_NUCLEI"
    RECON_PORTSCAN = "RECON_PORTSCAN"


class TaskStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    CANCELLED = "CANCELLED"


class ErrorType(str, enum.Enum):
    NONE = "NONE"
    TOOL_MISSING = "TOOL_MISSING"
    TOOL_ERROR = "TOOL_ERROR"
    TIMEOUT = "TIMEOUT"
    INVALID_TARGET = "INVALID_TARGET"
    PARSE_ERROR = "PARSE_ERROR"
    RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
    REDIS_ERROR = "REDIS_ERROR"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# Task — inbound work unit
# ---------------------------------------------------------------------------

@dataclass
class Task:
    """
    Represents a single recon work unit consumed from ``queue:recon``.

    Required fields (validated in ``from_dict``):
      - task_id
      - type   (must map to ``TaskType``)
      - target
    """
    task_id: str
    type: TaskType
    target: str
    params: Dict[str, Any] = field(default_factory=dict)
    priority: int = 0
    max_retries: int = 3
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # -- Validation ----------------------------------------------------------

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id must be a non-empty string")
        if not self.target:
            raise ValueError("target must be a non-empty string")
        if isinstance(self.type, str):
            try:
                self.type = TaskType(self.type)
            except ValueError as exc:
                raise ValueError(
                    f"Unknown task type '{self.type}'. "
                    f"Valid: {[t.value for t in TaskType]}"
                ) from exc

    # -- Serialisation -------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["type"] = self.type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        """
        Construct a ``Task`` from a raw dictionary (e.g. parsed JSON).

        Raises ``ValueError`` / ``KeyError`` on missing/invalid fields —
        callers are expected to catch and surface the error.
        """
        required = ("task_id", "type", "target")
        missing = [k for k in required if k not in data]
        if missing:
            raise KeyError(f"Task payload missing required fields: {missing}")
        return cls(
            task_id=str(data["task_id"]),
            type=data["type"],
            target=str(data["target"]),
            params=data.get("params", {}),
            priority=int(data.get("priority", 0)),
            max_retries=int(data.get("max_retries", 3)),
            retry_count=int(data.get("retry_count", 0)),
            created_at=float(data.get("created_at", time.time())),
            metadata=data.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# TaskResult — outbound result unit
# ---------------------------------------------------------------------------

@dataclass
class TaskResult:
    """
    Result payload pushed to ``results:incoming`` after a recon task
    completes (successfully or otherwise).
    """
    task_id: str
    status: TaskStatus
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    error_type: ErrorType = ErrorType.NONE
    worker_id: str = ""
    execution_time: float = 0.0
    completed_at: float = field(default_factory=time.time)
    tool_version: str = ""
    raw_output_lines: int = 0
    parse_warnings: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["error_type"] = self.error_type.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskResult":
        return cls(
            task_id=data["task_id"],
            status=TaskStatus(data["status"]),
            data=data.get("data", {}),
            error=data.get("error"),
            error_type=ErrorType(data.get("error_type", "NONE")),
            worker_id=data.get("worker_id", ""),
            execution_time=float(data.get("execution_time", 0)),
            completed_at=float(data.get("completed_at", time.time())),
            tool_version=data.get("tool_version", ""),
            raw_output_lines=int(data.get("raw_output_lines", 0)),
            parse_warnings=data.get("parse_warnings", []),
        )
