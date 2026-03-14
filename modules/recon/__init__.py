"""
Centaur-Jarvis Recon Workers Module
====================================
Deterministic reconnaissance task execution on cloud/VPS workers.

Consumes tasks from Redis queues, executes external security tools
(Subfinder, Httpx, Nuclei, Naabu), parses structured output,
and pushes results back to the orchestrator.

Architecture Contract:
  - 360-degree edge-case handling"""
Centaur-Jarvis Recon Workers Module
====================================
Deterministic reconnaissance task execution on cloud/VPS workers.

Consumes tasks from Redis queues, executes external security tools
(Subfinder, Httpx, Nuclei, Naabu), parses structured output,
and pushes results back to the orchestrator.

Architecture Contract:
  - 360-degree edge-case handling
  - No silent failures
  - Plug-and-play modularity
  - Comprehensive telemetry
"""

__version__ = "1.0.0"
__module_name__ = "recon_workers"

from modules.recon.worker import ReconWorker
from modules.recon.tasks import (
    subfinder_task,
    httpx_task,
    nuclei_task,
    naabu_task,
)
from modules.recon.parsers import (
    SubfinderParser,
    HttpxParser,
    NucleiParser,
    NaabuParser,
    get_parser,
)

__all__ = [
    "ReconWorker",
    "subfinder_task",
    "httpx_task",
    "nuclei_task",
    "naabu_task",
    "SubfinderParser",
    "HttpxParser",
    "NucleiParser",
    "NaabuParser",
    "get_parser",
]
  - No silent failures
  - Plug-and-play modularity
  - Comprehensive telemetry
"""

__version__ = "1.0.0"
__module_name__ = "recon_workers"

from modules.recon.worker import ReconWorker
from modules.recon.tasks import (
    subfinder_task,
    httpx_task,
    nuclei_task,
    naabu_task,
)
from modules.recon.parsers import (
    SubfinderParser,
    HttpxParser,
    NucleiParser,
    NaabuParser,
    get_parser,
)

__all__ = [
    "ReconWorker",
    "subfinder_task",
    "httpx_task",
    "nuclei_task",
    "naabu_task",
    "SubfinderParser",
    "HttpxParser",
    "NucleiParser",
    "NaabuParser",
    "get_parser",
]
