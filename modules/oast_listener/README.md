# OAST Listener Module

## Overview

The **OAST (Out-of-Band Application Security Testing) Listener** is a private
callback server for Centaur-Jarvis. It detects **blind vulnerabilities** —
blind XSS, blind SSRF, blind SQLi, blind XXE, blind RCE — by listening for
out-of-band HTTP and DNS callbacks triggered by injected payloads.

## Architecture

┌──────────────┐ inject payload ┌────────────┐
│ Fuzzer / │ ──────────────────────► │ Target │
│ Sniper │ │ App │
└──────┬───────┘ └─────┬──────┘
│ generate_payload() │
│ │ callback (HTTP/DNS)
▼ ▼
┌──────────────┐ ┌──────────────┐
│ Redis │ ◄───── push callback ──│ OAST Server │
│ oast:payload │ │ (HTTP+DNS) │
│ oast:callbks │ └──────────────┘
└──────┬───────┘
│ BRPOP
▼
┌──────────────┐
│ Correlator │ ──► match payload ──► push finding to results:incoming
└──────────────┘

text


## Quick Start

### 1. Start the OAST Server

```bash
python -m modules.oast_listener.server

2. Start the Correlator

Bash

python -m modules.oast_listener.correlator

3. Generate Payloads (from Fuzzer/Sniper)

Python

from modules.oast_listener import generate_payload

payload = generate_payload(
    task_id="task_001",
    scan_id="scan_42",
    vuln_type="blind_xss"
)

print(payload.url)        # http://oast.example.com:8080/scan_42-blind_xss-a3f2c1d0
print(payload.subdomain)  # scan_42-blind_xss-a3f2c1d0.oast.example.com

# Inject payload.url into target parameters

Configuration

Edit config.yaml or use environment variables:
Env Variable	Description	Default
OAST_REDIS_HOST	Redis host	localhost
OAST_REDIS_PORT	Redis port	6379
OAST_REDIS_PASSWORD	Redis password	null
OAST_HTTP_PORT	HTTP server port	8080
OAST_DNS_PORT	DNS server port	5353
OAST_DOMAIN	Base domain for callbacks	oast.example.com
Edge Cases Handled
#	Edge Case	Mitigation
1	Payload TTL expired	Correlator checks expiry; logs and discards
2	Duplicate callbacks	Redis NX-based dedup with configurable TTL
3	Malformed callback URL	Pattern matching; unmatched logged and discarded
4	Server overload	Async FastAPI + Redis queue; batch processing
5	Redis connection lost	Retry with backoff; callbacks logged if Redis down
6	DNS server fails to start	Logs error; HTTP continues independently
7	Payload ID collision	UUID + scan_id + timestamp ensures uniqueness
8	Large request body	Truncated to configurable max (10KB default)
9	SIGTERM during processing	Graceful shutdown; finishes current batch
Result Format

JSON

{
  "task_id": "task_001",
  "module": "oast_listener",
  "status": "COMPLETED",
  "data": {
    "findings": [{
      "finding_type": "blind_xss",
      "severity": "HIGH",
      "payload_url": "http://oast.example.com:8080/scan_42-blind_xss-a3f2c1d0",
      "callback": { ... },
      "detected_at": "2025-01-15T10:30:00Z"
    }],
    "stats": {
      "total_callbacks": 5,
      "processed": 1,
      "expired": 1,
      "unknown": 3
    }
  }
}
