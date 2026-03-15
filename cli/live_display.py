"""
Live Display
============
Real-time terminal dashboard using the ``rich`` library.

Dashboard layout:
┌─────────────────────────────────────────────────────┐
│  CENTAUR-JARVIS  │ Scan: SCAN_XXX │ Target │ Status │  ← Header
├─────────────────────────────────────────────────────┤
│ Phase Progress                                      │  ← Phases panel
│  [✓] recon   [►] fuzzing [37%]   [ ] sniper        │
├───────────────────────┬─────────────────────────────┤
│ Latest Findings       │ Stats                       │
│ CRITICAL xss /login   │ Tasks:  12/15               │
│ HIGH     sqli /api    │ Findings: 7                 │
│ ...                   │ AI calls: 3                 │
├───────────────────────┴─────────────────────────────┤
│ Queues: recon=0  fuzzer=3  sniper=0  results=1      │
├─────────────────────────────────────────────────────┤
│ Errors (last 5)                                     │
│ [12:03] Task xyz failed: timeout                    │
└─────────────────────────────────────────────────────┘

Edge cases handled:
    #7  – Ctrl+C during live display → graceful stop, terminal restored
    #9  – Large findings set → limited to max_visible_findings
    #17 – Terminal resize → rich handles automatically
"""

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger("cli.live_display")

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TaskID
    from rich.table import Table
    from rich.text import Text

    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    logger.warning("rich library not installed. Live dashboard disabled.")


class LiveDashboard:
    """Real-time scan dashboard powered by rich."""

    SEVERITY_COLORS = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }

    def __init__(
        self,
        scan_id: str,
        targets: list,
        profile_name: str,
        config: dict,
        controller=None,
    ):
        self.scan_id = scan_id
        self.targets = targets
        self.profile_name = profile_name
        self._config = config
        self._controller = controller

        display_cfg = config.get("display", {})
        self._refresh_interval = display_cfg.get("refresh_interval", 2)
        self._max_findings = display_cfg.get("max_visible_findings", 50)
        self._show_queues = display_cfg.get("show_queues", True)
        self._show_errors = display_cfg.get("show_errors", True)
        self._max_errors = display_cfg.get("max_visible_errors", 20)

        self._console = Console() if HAS_RICH else None
        self._stop_event = threading.Event()
        self._live: Optional[Live] = None

    # ------------------------------------------------------------------
    # Main entry: run dashboard alongside scan controller
    # ------------------------------------------------------------------
    def run_with_scan(self, controller) -> None:
        """
        Run the scan controller in a background thread while displaying
        the live dashboard in the main thread.

        Edge case #7: Ctrl+C is handled by the signal handler in main.py,
        which calls controller.request_shutdown(), causing both threads
        to stop gracefully.
        """
        if not HAS_RICH:
            logger.warning("rich not available. Running scan without dashboard.")
            controller.run()
            return

        self._controller = controller

        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._scan_runner,
            args=(controller,),
            daemon=True,
            name="scan-controller",
        )
        scan_thread.start()

        # Run dashboard in main thread (for terminal control)
        try:
            self._run_dashboard()
        except KeyboardInterrupt:
            logger.debug("KeyboardInterrupt in dashboard (already handled by signal handler).")
        finally:
            # Wait for scan thread to finish
            self._stop_event.set()
            scan_thread.join(timeout=10)

    def _scan_runner(self, controller) -> None:
        """Background thread that runs the scan controller."""
        try:
            controller.run()
        except Exception as exc:
            logger.error("Scan controller crashed: %s", exc, exc_info=True)
        finally:
            self._stop_event.set()

    # ------------------------------------------------------------------
    # Dashboard rendering loop
    # ------------------------------------------------------------------
    def _run_dashboard(self) -> None:
        """Main dashboard loop using rich.Live."""
        with Live(
            self._render(),
            console=self._console,
            refresh_per_second=1,
            screen=False,
            transient=False,
        ) as live:
            self._live = live
            while not self._stop_event.is_set():
                try:
                    live.update(self._render())
                except Exception as exc:
                    logger.debug("Dashboard render error: %s", exc)
                time.sleep(self._refresh_interval)

            # Final render
            try:
                live.update(self._render())
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Layout construction
    # ------------------------------------------------------------------
    def _render(self) -> Layout:
        """Build the complete dashboard layout."""
        layout = Layout()

        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="phases", size=5),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=3) if self._show_queues else Layout(name="spacer", size=1),
        )

        if self._show_errors:
            layout["body"].split_row(
                Layout(name="findings", ratio=3),
                Layout(name="sidebar", ratio=1),
            )
            layout["sidebar"].split_column(
                Layout(name="stats", ratio=1),
                Layout(name="errors", ratio=1),
            )
        else:
            layout["body"].split_row(
                Layout(name="findings", ratio=3),
                Layout(name="stats", ratio=1),
            )

        # Fill panels
        layout["header"].update(self._make_header())
        layout["phases"].update(self._make_phases_panel())
        layout["findings"].update(self._make_findings_panel())

        if self._show_errors:
            layout["stats"].update(self._make_stats_panel())
            layout["errors"].update(self._make_errors_panel())
        else:
            layout["stats"].update(self._make_stats_panel())

        if self._show_queues:
            layout["footer"].update(self._make_queues_panel())

        return layout

    # ------------------------------------------------------------------
    # Panel builders
    # ------------------------------------------------------------------
    def _make_header(self) -> Panel:
        """Header panel with scan ID, target, elapsed time, status."""
        if self._controller is None:
            status_text = "INITIALIZING"
            elapsed = 0
        else:
            status_text = self._controller.status
            elapsed = self._controller.elapsed_seconds

        target_display = self.targets[0] if self.targets else "N/A"
        if len(self.targets) > 1:
            target_display += f" (+{len(self.targets) - 1} more)"

        elapsed_str = _format_duration(elapsed)

        status_color = {
            "RUNNING": "green",
            "PAUSED": "yellow",
            "COMPLETED": "bold green",
            "SHUTTING_DOWN": "bold yellow",
            "FAILED": "bold red",
        }.get(status_text, "white")

        header = Text()
        header.append("🛡️  CENTAUR-JARVIS", style="bold cyan")
        header.append("  │  ", style="dim")
        header.append(f"Scan: {self.scan_id}", style="bold white")
        header.append("  │  ", style="dim")
        header.append(f"Target: {target_display}", style="white")
        header.append("  │  ", style="dim")
        header.append(f"Profile: {self.profile_name}", style="magenta")
        header.append("  │  ", style="dim")
        header.append(f"⏱ {elapsed_str}", style="white")
        header.append("  │  ", style="dim")
        header.append(f"Status: {status_text}", style=status_color)

        return Panel(header, style="bold blue")

    def _make_phases_panel(self) -> Panel:
        """Phase progress with checkmarks and progress bars."""
        if self._controller is None:
            return Panel("Initializing...", title="[bold]Phases", border_style="blue")

        enabled_phases = self._controller.profile_config.get("phases", ["recon"])
        completed = set(self._controller.phases_completed)
        current = self._controller.current_phase
        progress_data = self._controller.get_phase_progress()

        text = Text()
        for phase in enabled_phases:
            if phase in completed:
                text.append(f"  ✅ {phase}", style="bold green")
            elif phase == current:
                # Show progress
                pdata = progress_data.get(phase, {})
                total = pdata.get("total", 0)
                done = pdata.get("done", 0)
                pct = (done / total * 100) if total > 0 else 0
                bar = _progress_bar(pct)
                text.append(f"  ▶ {phase} ", style="bold yellow")
                text.append(f"{bar} {pct:.0f}%", style="yellow")
                text.append(f" ({done}/{total})", style="dim")
            else:
                text.append(f"  ⬜ {phase}", style="dim")
            text.append("   ")

        return Panel(text, title="[bold]Phases", border_style="blue")

    def _make_findings_panel(self) -> Panel:
        """Table of latest findings."""
        table = Table(
            show_header=True,
            header_style="bold",
            expand=True,
            show_lines=False,
        )
        table.add_column("#", style="dim", width=4)
        table.add_column("Severity", width=10)
        table.add_column("Type", width=12)
        table.add_column("Endpoint", ratio=2)
        table.add_column("Detail", ratio=3)
        table.add_column("Time", width=8)

        if self._controller is not None:
            findings = self._controller.get_recent_findings(self._max_findings)
            for idx, f in enumerate(reversed(findings), 1):
                severity = f.get("severity", "INFO").upper()
                sev_style = self.SEVERITY_COLORS.get(severity, "white")
                ftype = f.get("type", f.get("vuln_type", "N/A"))[:12]
                endpoint = f.get("endpoint", f.get("url", "N/A"))
                # Truncate long endpoints (edge case #9)
                if len(endpoint) > 60:
                    endpoint = endpoint[:57] + "..."
                detail = f.get("payload", f.get("detail", f.get("template_id", "N/A")))
                if isinstance(detail, str) and len(detail) > 80:
                    detail = detail[:77] + "..."
                discovered = f.get("discovered_at", "")
                time_short = discovered.split("T")[1][:8] if "T" in discovered else ""

                table.add_row(
                    str(idx),
                    Text(severity, style=sev_style),
                    ftype,
                    endpoint,
                    str(detail),
                    time_short,
                )

                if idx >= self._max_findings:  # edge case #9
                    break

        return Panel(table, title="[bold]Latest Findings", border_style="green")

    def _make_stats_panel(self) -> Panel:
        """Statistics panel."""
        if self._controller is None:
            return Panel("...", title="[bold]Stats", border_style="cyan")

        stats = self._controller.get_stats()

        text = Text()
        text.append("📊 Scan Statistics\n\n", style="bold")
        text.append(f"  Tasks pushed:     {stats.get('tasks_pushed', 0)}\n")
        text.append(f"  Tasks completed:  ", style="")
        text.append(f"{stats.get('tasks_completed', 0)}\n", style="green")
        text.append(f"  Tasks failed:     ", style="")
        failed = stats.get("tasks_failed", 0)
        text.append(f"{failed}\n", style="red" if failed > 0 else "green")
        text.append(f"\n  Findings:         ", style="")
        fc = stats.get("findings_count", 0)
        text.append(f"{fc}\n", style="bold yellow" if fc > 0 else "dim")
        text.append(f"  Requests sent:    {stats.get('requests_sent', 0)}\n")
        text.append(f"  AI calls:         {stats.get('ai_calls', 0)}\n")
        text.append(f"  RAG snippets:     {stats.get('rag_snippets', 0)}\n")

        return Panel(text, title="[bold]Stats", border_style="cyan")

    def _make_errors_panel(self) -> Panel:
        """Recent errors panel."""
        if self._controller is None:
            return Panel("No errors.", title="[bold]Errors", border_style="red")

        errors = self._controller.get_recent_errors(self._max_errors)
        if not errors:
            return Panel(
                Text("No errors ✓", style="green"),
                title="[bold]Errors",
                border_style="green",
            )

        text = Text()
        for err in reversed(errors[-self._max_errors :]):
            ts = err.get("timestamp", "")
            time_short = ts.split("T")[1][:8] if "T" in ts else ""
            msg = err.get("message", "Unknown")
            if len(msg) > 80:
                msg = msg[:77] + "..."
            text.append(f"[{time_short}] ", style="dim")
            text.append(f"{msg}\n", style="red")

        return Panel(text, title=f"[bold]Errors ({len(errors)})", border_style="red")

    def _make_queues_panel(self) -> Panel:
        """Queue status bar."""
        if self._controller is None:
            return Panel("...", title="[bold]Queues", border_style="blue")

        queues = self._controller.get_queue_lengths()
        parts = []
        for q, length in queues.items():
            name = q.split(":")[-1]
            color = "yellow" if length > 0 else "green"
            parts.append(f"[{color}]{name}={length}[/{color}]")

        queue_text = "   ".join(parts) if parts else "No queue data"
        return Panel(queue_text, title="[bold]Queue Status", border_style="blue")

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------
    def stop(self) -> None:
        """Stop the dashboard (terminal cleanup handled by rich)."""
        self._stop_event.set()
        logger.debug("Live dashboard stopped.")


# ===========================================================================
# Helper functions
# ===========================================================================
def _format_duration(seconds: float) -> str:
    """Format seconds into HH:MM:SS."""
    seconds = int(seconds)
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h:02d}:{m:02d}:{s:02d}"
    return f"{m:02d}:{s:02d}"


def _progress_bar(pct: float, width: int = 20) -> str:
    """Create a text-based progress bar."""
    filled = int(width * pct / 100)
    empty = width - filled
    return f"[{'█' * filled}{'░' * empty}]"
