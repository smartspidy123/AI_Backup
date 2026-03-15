#!/usr/bin/env python3
"""
Centaur-Jarvis CLI Entry Point
==============================
Usage:
    python -m cli.main --target https://example.com
    python -m cli.main --target targets.txt --profile full
    python -m cli.main --resume SCAN_123
    python -m cli.main --list-profiles
    python -m cli.main --export findings.json --scan-id SCAN_123

This is the single command interface for all Centaur-Jarvis operations.
It coordinates process management, scan orchestration, live display,
and graceful shutdown with state persistence.
"""

import sys
import os
import signal
import logging
import uuid
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List

import click
import yaml

# ---------------------------------------------------------------------------
# Logging bootstrap – must happen before any module import that logs
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(
            os.path.expanduser("~/.centaur/cli.log"), mode="a", delay=True
        ),
    ],
)
logger = logging.getLogger("cli.main")

# ---------------------------------------------------------------------------
# Internal imports (deferred to allow logging setup first)
# ---------------------------------------------------------------------------
from cli.scan_controller import ScanController
from cli.live_display import LiveDashboard
from cli.process_manager import ProcessManager
from cli.state_manager import StateManager


# ===========================================================================
# Configuration Loader
# ===========================================================================
DEFAULT_CONFIG_PATH = Path(__file__).parent / "config.yaml"


def load_config(config_path: Optional[str] = None) -> dict:
    """
    Load CLI configuration from YAML.
    Falls back to hardcoded defaults if file missing or corrupt.
    Edge case #14: Invalid/missing config → use defaults + warn.
    """
    path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    # Hardcoded fallback config (edge case #5, #14)
    fallback = {
        "redis": {
            "host": "127.0.0.1",
            "port": 6379,
            "db": 0,
            "socket_timeout": 5,
            "retry_on_timeout": True,
            "health_check_interval": 30,
        },
        "state": {
            "directory": "~/.centaur/scans",
            "fallback_directory": "/tmp/centaur_scans",
            "auto_save_interval": 30,
        },
        "reports": {
            "output_directory": "reports/",
            "formats": ["html", "json"],
            "include_raw_data": True,
        },
        "processes": {
            "heartbeat_timeout": 30,
            "kill_timeout": 10,
            "pid_directory": "~/.centaur/pids",
            "services": {
                "orchestrator": {
                    "command": "python -m modules.orchestrator.main",
                    "heartbeat_key": "heartbeat:orchestrator",
                    "queue": "queue:orchestrator",
                },
                "recon_worker": {
                    "command": "python -m modules.recon.worker",
                    "heartbeat_key": "heartbeat:recon_worker",
                    "queue": "queue:recon",
                },
                "smart_fuzzer": {
                    "command": "python -m modules.smart_fuzzer.main",
                    "heartbeat_key": "heartbeat:smart_fuzzer",
                    "queue": "queue:smart_fuzzer",
                },
                "sniper": {
                    "command": "python -m modules.sniper.main",
                    "heartbeat_key": "heartbeat:sniper",
                    "queue": "queue:sniper",
                },
            },
        },
        "profiles": {
            "quick": {
                "description": "Fast recon-only scan",
                "phases": ["recon"],
                "recon_tasks": ["nuclei"],
                "fuzzing": {"enabled": False},
                "sniper": {"enabled": False},
                "timeout": 600,
            },
            "full": {
                "description": "Complete scan",
                "phases": ["recon", "fuzzing", "sniper"],
                "recon_tasks": ["subfinder", "httpx", "nuclei"],
                "fuzzing": {
                    "enabled": True,
                    "vuln_types": ["xss", "sqli", "ssti"],
                    "max_iterations": 3,
                },
                "sniper": {
                    "enabled": True,
                    "feeds": ["github", "packetstorm"],
                },
                "timeout": 7200,
            },
        },
        "notifications": {
            "discord_webhook": "",
            "slack_webhook": "",
            "notify_severities": ["CRITICAL", "HIGH"],
            "rate_limit_seconds": 10,
        },
        "display": {
            "refresh_interval": 2,
            "max_visible_findings": 50,
            "show_queues": True,
            "show_errors": True,
            "max_visible_errors": 20,
        },
    }

    if not path.exists():
        logger.warning(
            "Config file %s not found. Using hardcoded defaults. (Edge case #14)",
            path,
        )
        return fallback

    try:
        with open(path, "r") as fh:
            loaded = yaml.safe_load(fh) or {}
        # Deep-merge loaded over fallback so missing keys get defaults
        merged = _deep_merge(fallback, loaded)
        logger.info("Configuration loaded from %s", path)
        return merged
    except yaml.YAMLError as exc:
        logger.error(
            "Invalid YAML in %s: %s. Using defaults. (Edge case #14)", path, exc
        )
        return fallback
    except OSError as exc:
        logger.error(
            "Cannot read %s: %s. Using defaults. (Edge case #14)", path, exc
        )
        return fallback


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*, returning new dict."""
    merged = base.copy()
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


# ===========================================================================
# Target Resolution
# ===========================================================================
def resolve_targets(target_value: str) -> List[str]:
    """
    Resolve --target to a list of URLs.
    Supports:
      - Single URL (starts with http:// or https://)
      - File path (one URL per line)
      - Comma-separated URLs

    Edge case #13: target file not found → clear error + exit.
    """
    # Check if it looks like a file path
    target_path = Path(target_value)
    if target_path.exists() and target_path.is_file():
        try:
            lines = target_path.read_text().strip().splitlines()
            targets = [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]
            if not targets:
                logger.error("Target file %s is empty.", target_path)
                sys.exit(1)
            logger.info("Loaded %d target(s) from %s", len(targets), target_path)
            return targets
        except OSError as exc:
            logger.error("Cannot read target file %s: %s (Edge case #13)", target_path, exc)
            sys.exit(1)

    # Check for comma-separated
    if "," in target_value:
        targets = [t.strip() for t in target_value.split(",") if t.strip()]
        return targets

    # Single target
    return [target_value]


# ===========================================================================
# PID-based Concurrency Guard
# ===========================================================================
def check_concurrent_scan(targets: List[str], config: dict) -> None:
    """
    Edge case #10: Prevent multiple CLI instances scanning the same target.
    Uses a lockfile in the PID directory.
    """
    pid_dir = Path(os.path.expanduser(config.get("processes", {}).get("pid_directory", "~/.centaur/pids")))
    pid_dir.mkdir(parents=True, exist_ok=True)

    for target in targets:
        # Create a safe filename from target
        safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
        lock_file = pid_dir / f"scan_{safe_name}.lock"
        if lock_file.exists():
            try:
                lock_data = json.loads(lock_file.read_text())
                old_pid = lock_data.get("pid")
                # Check if that PID is still alive
                if old_pid:
                    try:
                        import psutil
                        if psutil.pid_exists(old_pid):
                            proc = psutil.Process(old_pid)
                            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                                logger.error(
                                    "Another scan is already running for target %s (PID %d). "
                                    "Edge case #10: Use --resume or wait for it to finish.",
                                    target,
                                    old_pid,
                                )
                                sys.exit(1)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass  # stale lock, remove it
            except (json.JSONDecodeError, OSError):
                pass  # corrupt lock, remove it
            # Remove stale lock
            lock_file.unlink(missing_ok=True)

        # Write our lock
        lock_file.write_text(json.dumps({"pid": os.getpid(), "target": target, "started": datetime.now(timezone.utc).isoformat()}))


def release_scan_locks(targets: List[str], config: dict) -> None:
    """Release lockfiles for targets."""
    pid_dir = Path(os.path.expanduser(config.get("processes", {}).get("pid_directory", "~/.centaur/pids")))
    for target in targets:
        safe_name = target.replace("://", "_").replace("/", "_").replace(":", "_")
        lock_file = pid_dir / f"scan_{safe_name}.lock"
        lock_file.unlink(missing_ok=True)


# ===========================================================================
# Click CLI Definition
# ===========================================================================
@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--target", "-t",
    type=str,
    default=None,
    help="Target URL, comma-separated URLs, or path to a file with one URL per line.",
)
@click.option(
    "--profile", "-p",
    type=str,
    default="full",
    help="Scan profile name (quick, full, recon_only, custom). Default: full.",
)
@click.option(
    "--resume", "-r",
    type=str,
    default=None,
    help="Resume a previously paused scan by its SCAN_ID.",
)
@click.option(
    "--manual", "-m",
    is_flag=True,
    default=False,
    help="Manual mode: assume all backend services are already running.",
)
@click.option(
    "--list-profiles",
    is_flag=True,
    default=False,
    help="List available scan profiles and exit.",
)
@click.option(
    "--export",
    type=str,
    default=None,
    help="Export findings to the specified file (JSON).",
)
@click.option(
    "--scan-id",
    type=str,
    default=None,
    help="Scan ID to use with --export.",
)
@click.option(
    "--config",
    type=str,
    default=None,
    help="Path to an alternative config.yaml.",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    default=False,
    help="Enable debug logging.",
)
@click.option(
    "--no-display",
    is_flag=True,
    default=False,
    help="Disable live dashboard (useful for CI/piping).",
)
def cli(
    target: Optional[str],
    profile: str,
    resume: Optional[str],
    manual: bool,
    list_profiles: bool,
    export: Optional[str],
    scan_id: Optional[str],
    config: Optional[str],
    verbose: bool,
    no_display: bool,
) -> None:
    """
    Centaur-Jarvis – AI-Powered VAPT Agent CLI

    Start a vulnerability scan, view live results, pause/resume, and generate reports.
    """
    # -----------------------------------------------------------------------
    # Verbosity
    # -----------------------------------------------------------------------
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled.")

    # -----------------------------------------------------------------------
    # Load configuration
    # -----------------------------------------------------------------------
    cfg = load_config(config)

    # -----------------------------------------------------------------------
    # --list-profiles
    # -----------------------------------------------------------------------
    if list_profiles:
        _print_profiles(cfg)
        sys.exit(0)

    # -----------------------------------------------------------------------
    # --export
    # -----------------------------------------------------------------------
    if export:
        if not scan_id:
            click.echo("ERROR: --export requires --scan-id.", err=True)
            sys.exit(1)
        _export_findings(export, scan_id, cfg)
        sys.exit(0)

    # -----------------------------------------------------------------------
    # --resume
    # -----------------------------------------------------------------------
    if resume:
        _run_resume(resume, cfg, manual, no_display)
        return

    # -----------------------------------------------------------------------
    # --target (required for new scan)
    # -----------------------------------------------------------------------
    if not target:
        click.echo("ERROR: --target is required for a new scan. Use -h for help.", err=True)
        sys.exit(1)

    targets = resolve_targets(target)
    if not targets:
        click.echo("ERROR: No valid targets resolved.", err=True)
        sys.exit(1)

    # Validate profile
    profiles = cfg.get("profiles", {})
    if profile not in profiles:
        logger.warning(
            "Profile '%s' not found. Falling back to 'full'. (Edge case #14)",
            profile,
        )
        profile = "full" if "full" in profiles else list(profiles.keys())[0]

    # Concurrency guard (edge case #10)
    check_concurrent_scan(targets, cfg)

    # Generate scan ID
    generated_scan_id = f"SCAN_{uuid.uuid4().hex[:12].upper()}"
    logger.info("Starting scan %s with profile '%s' for %d target(s).", generated_scan_id, profile, len(targets))

    # Run the scan
    _run_scan(
        scan_id=generated_scan_id,
        targets=targets,
        profile_name=profile,
        config=cfg,
        manual=manual,
        no_display=no_display,
    )

    # Release locks
    release_scan_locks(targets, cfg)


# ===========================================================================
# Core Run Functions
# ===========================================================================
def _run_scan(
    scan_id: str,
    targets: List[str],
    profile_name: str,
    config: dict,
    manual: bool,
    no_display: bool,
) -> None:
    """Execute a full scan lifecycle."""
    profile_cfg = config["profiles"][profile_name]
    state_mgr = StateManager(config)
    proc_mgr = ProcessManager(config)
    dashboard: Optional[LiveDashboard] = None

    # ------------------------------------------------------------------
    # 1. Ensure backend services (edge cases #1, #18)
    # ------------------------------------------------------------------
    if not manual:
        required_services = _services_for_profile(profile_cfg)
        click.echo(f"[*] Auto mode: ensuring {len(required_services)} service(s)...")
        for svc in required_services:
            ok = proc_mgr.ensure_service(svc)
            if not ok:
                logger.error(
                    "Cannot start service '%s'. Try --manual if services run externally. "
                    "(Edge case #18)",
                    svc,
                )
                click.echo(
                    f"ERROR: Failed to start '{svc}'. "
                    f"Start it manually and re-run with --manual.",
                    err=True,
                )
                release_scan_locks(targets, config)
                sys.exit(1)
        click.echo("[+] All services running.")
    else:
        click.echo("[*] Manual mode: assuming all services are running.")

    # ------------------------------------------------------------------
    # 2. Initialize scan controller
    # ------------------------------------------------------------------
    controller = ScanController(
        scan_id=scan_id,
        targets=targets,
        profile_name=profile_name,
        profile_config=profile_cfg,
        config=config,
        state_manager=state_mgr,
    )

    # ------------------------------------------------------------------
    # 3. Initialize live display
    # ------------------------------------------------------------------
    if not no_display:
        dashboard = LiveDashboard(
            scan_id=scan_id,
            targets=targets,
            profile_name=profile_name,
            config=config,
            controller=controller,
        )

    # ------------------------------------------------------------------
    # 4. Register signal handlers for graceful shutdown (edge case #7)
    # ------------------------------------------------------------------
    def _shutdown_handler(signum: int, frame) -> None:
        sig_name = signal.Signals(signum).name if hasattr(signal, "Signals") else str(signum)
        logger.info("Received %s – initiating graceful shutdown.", sig_name)
        controller.request_shutdown()

    signal.signal(signal.SIGINT, _shutdown_handler)
    signal.signal(signal.SIGTERM, _shutdown_handler)

    # ------------------------------------------------------------------
    # 5. Run scan with live display
    # ------------------------------------------------------------------
    try:
        if dashboard:
            dashboard.run_with_scan(controller)
        else:
            # No display – just run controller synchronously
            controller.run()
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt caught at top level.")
        controller.request_shutdown()
    finally:
        # ------------------------------------------------------------------
        # 6. Post-scan actions
        # ------------------------------------------------------------------
        if controller.is_paused:
            saved_path = state_mgr.save_state(controller.get_state())
            click.echo(f"\n[!] Scan paused. State saved to {saved_path}")
            click.echo(f"    Resume with: python -m cli.main --resume {scan_id}")
        else:
            click.echo(f"\n[+] Scan {scan_id} completed.")
            # Generate report (edge case #12)
            _generate_report_safe(scan_id, config, controller)

        if dashboard:
            dashboard.stop()

        # Cleanup processes if we started them
        if not manual:
            proc_mgr.stop_all()

        release_scan_locks(targets, config)


def _run_resume(
    scan_id: str,
    config: dict,
    manual: bool,
    no_display: bool,
) -> None:
    """Resume a previously paused scan."""
    state_mgr = StateManager(config)
    state = state_mgr.load_state(scan_id)
    if state is None:
        click.echo(f"ERROR: No saved state found for scan {scan_id}.", err=True)
        sys.exit(1)

    targets = state.get("targets", [])
    profile_name = state.get("profile", "full")
    profiles = config.get("profiles", {})
    profile_cfg = profiles.get(profile_name, profiles.get("full", {}))

    click.echo(f"[*] Resuming scan {scan_id} (profile: {profile_name}, targets: {len(targets)})")

    # Concurrency guard
    check_concurrent_scan(targets, config)

    _run_scan(
        scan_id=scan_id,
        targets=targets,
        profile_name=profile_name,
        config=config,
        manual=manual,
        no_display=no_display,
    )


# ===========================================================================
# Helper Functions
# ===========================================================================
def _services_for_profile(profile_cfg: dict) -> List[str]:
    """Determine which backend services are needed for the given profile."""
    services = ["orchestrator", "recon_worker"]  # always needed
    phases = profile_cfg.get("phases", [])
    if "fuzzing" in phases and profile_cfg.get("fuzzing", {}).get("enabled", False):
        services.append("smart_fuzzer")
    if "sniper" in phases and profile_cfg.get("sniper", {}).get("enabled", False):
        services.append("sniper")
    return services


def _print_profiles(config: dict) -> None:
    """Pretty-print available profiles."""
    from rich.console import Console
    from rich.table import Table

    console = Console()
    table = Table(title="Available Scan Profiles", show_lines=True)
    table.add_column("Name", style="bold cyan")
    table.add_column("Description")
    table.add_column("Phases")
    table.add_column("Timeout")

    for name, pcfg in config.get("profiles", {}).items():
        desc = pcfg.get("description", "N/A")
        phases = ", ".join(pcfg.get("phases", []))
        timeout = str(pcfg.get("timeout", "N/A")) + "s"
        table.add_row(name, desc, phases, timeout)

    console.print(table)


def _export_findings(filepath: str, scan_id: str, config: dict) -> None:
    """Export findings from a saved state to JSON."""
    state_mgr = StateManager(config)
    state = state_mgr.load_state(scan_id)
    if state is None:
        click.echo(f"ERROR: No saved state found for scan {scan_id}.", err=True)
        sys.exit(1)

    findings = state.get("findings", [])
    try:
        out_path = Path(filepath)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(findings, indent=2, default=str))
        click.echo(f"[+] Exported {len(findings)} finding(s) to {out_path}")
    except OSError as exc:
        click.echo(f"ERROR: Cannot write to {filepath}: {exc}", err=True)
        sys.exit(1)


def _generate_report_safe(scan_id: str, config: dict, controller) -> None:
    """
    Generate report with fallback on failure. (Edge case #12)
    """
    try:
        from modules.reporting.generator import generate_report

        output_dir = config.get("reports", {}).get("output_directory", "reports/")
        generate_report(scan_id=scan_id, output_dir=output_dir)
        click.echo(f"[+] Report generated in {output_dir}")
    except ImportError:
        logger.warning(
            "Reporting module not available. Falling back to JSON dump. (Edge case #12)"
        )
        _fallback_report(scan_id, config, controller)
    except Exception as exc:
        logger.error(
            "Report generation failed: %s. Using fallback. (Edge case #12)", exc
        )
        _fallback_report(scan_id, config, controller)


def _fallback_report(scan_id: str, config: dict, controller) -> None:
    """Hardcoded fallback report when the reporting module is unavailable."""
    output_dir = Path(config.get("reports", {}).get("output_directory", "reports/"))
    output_dir.mkdir(parents=True, exist_ok=True)

    state = controller.get_state()
    report = {
        "scan_id": scan_id,
        "targets": state.get("targets", []),
        "profile": state.get("profile", "unknown"),
        "phases_completed": state.get("phases_completed", []),
        "findings_count": len(state.get("findings", [])),
        "findings": state.get("findings", []),
        "stats": controller.get_stats(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    filename = output_dir / f"{scan_id}_report.json"
    try:
        filename.write_text(json.dumps(report, indent=2, default=str))
        click.echo(f"[+] Fallback report saved to {filename}")
    except OSError as exc:
        logger.error("Cannot write fallback report: %s (Edge case #11)", exc)


# ===========================================================================
# Entry Point
# ===========================================================================
def main() -> None:
    """Wrapper for setuptools console_scripts entry point."""
    # Ensure ~/.centaur directories exist
    for d in ["~/.centaur", "~/.centaur/scans", "~/.centaur/pids"]:
        Path(os.path.expanduser(d)).mkdir(parents=True, exist_ok=True)
    cli()


if __name__ == "__main__":
    main()
