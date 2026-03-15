# Centaur-Jarvis CLI Module


## Overview

The CLI module is the **master controller** for Centaur-Jarvis. It provides a
single-command interface to start scans, manage backend services, display
real-time results, and handle graceful shutdown with resume capability.

## Quick Start

```bash
# Install dependencies
pip install click rich psutil tenacity pyyaml redis

# Basic scan (auto mode – starts services automatically)
python -m cli.main --target https://example.com

# Quick recon-only scan
python -m cli.main --target https://example.com --profile quick

# Manual mode (services already running)
python -m cli.main --target https://example.com --manual

# Scan multiple targets from file
python -m cli.main --target targets.txt

# Resume a paused scan
python -m cli.main --resume SCAN_XXXXXX

# List profiles
python -m cli.main --list-profiles

# Export findings
python -m cli.main --export findings.json --scan-id SCAN_XXXXXX

Architecture
text

┌──────────────────────────────────────────────────────────────┐
│                       CLI (main.py)                          │
│  ┌─────────┐  ┌──────────────┐  ┌─────────────┐            │
│  │ Click   │→ │ ProcessMgr   │→ │ ScanCtrl    │            │
│  │ Parser  │  │ (auto mode)  │  │ (phased)    │            │
│  └─────────┘  └──────────────┘  └──────┬──────┘            │
│                                        │                     │
│  ┌─────────────────┐    ┌──────────────┴──────────────┐     │
│  │ LiveDashboard   │←── │ Redis (queues + results)    │     │
│  │ (rich)          │    └─────────────────────────────┘     │
│  └─────────────────┘                                        │
│                                                              │
│  ┌─────────────┐  ┌────────────────┐                        │
│  │ StateMgr    │  │ Signal Handler │                        │
│  │ (save/load) │  │ (Ctrl+C)       │                        │
│  └─────────────┘  └────────────────┘                        │
└──────────────────────────────────────────────────────────────┘
Files
File	Purpose
main.py	CLI entry point, argument parsing, lifecycle
scan_controller.py	Phased scan orchestration, task management
live_display.py	Real-time rich dashboard
process_manager.py	Backend service lifecycle (auto/manual)
state_manager.py	Scan state persistence for pause/resume
config.yaml	Profiles, Redis config, notifications
Scan Profiles
quick – Recon only (Nuclei critical templates), ~10 min
full – Recon + Fuzzing + Sniper, ~2 hours
recon_only – Comprehensive recon without active testing
custom – Override via CLI flags
Graceful Shutdown
Press Ctrl+C during a scan:

Signal handler sets shutdown flag
Current phase completes current poll cycle
State saved to ~/.centaur/scans/SCAN_XXX.json
Terminal restored, resume command displayed
Child processes receive SIGTERM (then SIGKILL after timeout)
