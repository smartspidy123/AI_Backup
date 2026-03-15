"""
Centaur-Jarvis CLI Module
=========================
Master controller providing unified CLI, live dashboard, process management,
scan orchestration, state persistence, and graceful shutdown/resume.

Architecture:
    main.py           → CLI entry point (click-based argument parsing)
    scan_controller.py → Phased scan orchestration (recon→fuzzing→sniper→reporting)
    live_display.py    → Real-time rich dashboard with findings, stats, queues
    process_manager.py → Auto/manual service lifecycle management
    state_manager.py   → Scan state save/load for resume after pause/crash
"""

__version__ = "1.0.0"
__module_name__ = "cli"
