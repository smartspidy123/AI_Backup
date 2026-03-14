# Nuclei Sniper Module

**AI-powered CVE monitoring, Nuclei template generation, validation, and execution.**

Part of the **Centaur-Jarvis** VAPT agent framework.

## Overview

The Nuclei Sniper module automates the entire lifecycle of CVE-to-scan:

1. **Monitor** – Polls RSS feeds for newly disclosed CVEs
2. **Generate** – Uses AI to create Nuclei detection templates
3. **Validate** – Runs `nuclei -validate` with self-healing correction loops
4. **Execute** – Pushes validated templates to the recon worker for scanning

## Architecture
[RSS Feeds] → [Monitor] → [Redis Queue] → [Generator] → [Validator] → [Executor] → [Recon Worker]
↑ │
└──correction───┘

text


## Quick Start

### Prerequisites

- Python 3.9+
- Redis server running
- Nuclei binary installed (`go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`)
- Required Python packages: `feedparser`, `redis`, `PyYAML`, `tenacity`, `requests`

### Installation

```bash
pip install feedparser redis PyYAML tenacity requests
Running Each Component
Each component can run independently as a standalone process:

Bash

# Monitor: Poll RSS feeds for new CVEs
python -m modules.nuclei_sniper.monitor --once

# Generator: Consume CVE tasks and generate templates
python -m modules.nuclei_sniper.generator

# Validator: Validate generated templates
python -m modules.nuclei_sniper.validator

# Executor: Push validated templates for scanning
python -m modules.nuclei_sniper.executor
Testing
Bash

# Inject a test CVE manually
python -m modules.nuclei_sniper.monitor --inject CVE-2021-44228

# Test template generation for a specific CVE
python -m modules.nuclei_sniper.generator --test-cve CVE-2021-44228

# Validate a specific template file
python -m modules.nuclei_sniper.validator --test-file /path/to/template.yaml

# Check nuclei binary availability
python -m modules.nuclei_sniper.validator --check-binary

# Add a target for scanning
python -m modules.nuclei_sniper.executor --add-target https://example.com

# List configured targets
python -m modules.nuclei_sniper.executor --list-targets
Configuration
Edit config.yaml to customize:

feeds: RSS sources, poll interval, rate limits
ai: Generation retries, temperature, prompt length
validation: Nuclei binary path, retry count, timeout
execution: Default targets, queue names
redis: Queue keys, connection settings
Edge Cases Handled
#	Edge Case	Mitigation
1	RSS feed unavailable	Log warning, skip, continue with other feeds
2	Duplicate CVE	Redis SISMEMBER check before processing
3	AI router unavailable	Fallback to static template stub
4	AI returns malformed YAML	Retry with error feedback (up to 3 times)
5	Nuclei validation fails	Feed error back to AI for correction
6	Nuclei binary not found	Log critical, YAML-only validation
7	False positive at runtime	Handled by recon worker
8	CVE flood	Rate limiting on AI calls, entry caps
9	Redis down	In-memory buffer, reconnection logic
10	No targets	Log warning, executor waits
11	Target unreachable	Handled by recon worker
12	Memory explosion	Streaming parse, max_entries_per_feed cap
13	Thread safety	Redis distributed locks for polling
Redis Keys
Key	Type	Purpose
queue:nuclei_sniper	List	CVE tasks from monitor
queue:nuclei_sniper:validate	List	Templates awaiting validation
queue:nuclei_sniper:execute	List	Validated templates for execution
queue:recon	List	Scan tasks for recon worker
results:incoming	List	Execution results
nuclei_sniper:seen_cves	Set	Deduplicated CVE IDs
nuclei_sniper:status:<CVE>	String	Per-CVE processing status
nuclei_sniper:manual_review	List	Templates needing human review
global:targets	Set	Scan targets
