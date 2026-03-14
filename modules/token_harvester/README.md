# Token Harvester Module

## Overview

The Token Harvester is a **mitmproxy addon** that passively intercepts HTTP/HTTPS
traffic from the user's browser, extracts authentication tokens, and persists
them in Redis. Other Centaur-Jarvis modules (recon, fuzzer, exploit) consume
these tokens for authenticated scanning.

## Quick Start

### Prerequisites

```bash
pip install mitmproxy redis pyyaml



Ensure Redis is running:

Bash

redis-server
# or
docker run -d -p 6379:6379 redis:alpine
Run the Addon
Bash

# Via mitmdump (recommended)
mitmdump -s modules/token_harvester/mitm_addon.py

# Via mitmproxy (interactive UI)
mitmproxy -s modules/token_harvester/mitm_addon.py

# Standalone mode (starts mitmdump internally)
python modules/token_harvester/mitm_addon.py --port 8080
Configure Browser
Set your browser HTTP/HTTPS proxy to 127.0.0.1:8080
Visit http://mitm.it through the proxy to install the CA certificate
Browse your target application normally
Verify Token Capture
Bash

# List all token keys
redis-cli KEYS "token:*"

# List harvested domains
redis-cli SMEMBERS "tokens:domains"

# Inspect a token
redis-cli HGETALL "token:example.com:abc123def456"

# List tokens for a specific domain
redis-cli SMEMBERS "tokens:domain:example.com"
Architecture
text

┌──────────────┐     HTTP/S      ┌───────────────────┐
│   Browser    │ ──────────────▶ │    mitmproxy      │
│              │ ◀────────────── │  (localhost:8080)  │
└──────────────┘                 └─────────┬─────────┘
                                           │
                                    request() / response()
                                           │
                                 ┌─────────▼─────────┐
                                 │  TokenHarvester    │
                                 │  (addon class)     │
                                 │                    │
                                 │  • Auth headers    │
                                 │  • Cookies         │
                                 │  • Set-Cookie      │
                                 │  • JSON body       │
                                 │  • CSRF tokens     │
                                 │  • Regex patterns   │
                                 └─────────┬─────────┘
                                           │
                               ┌───────────▼───────────┐
                               │   RedisTokenStore     │
                               │                       │
                               │  ┌─────────────────┐  │
                               │  │ Memory Buffer   │  │  (fallback)
                               │  │ (deque, 5000)   │  │
                               │  └────────┬────────┘  │
                               │           │           │
                               │  ┌────────▼────────┐  │
                               │  │     Redis       │  │
                               │  │  token:{d}:{id} │  │
                               │  │  tokens:domains │  │
                               │  │  tokens:domain: │  │
                               │  └─────────────────┘  │
                               └───────────────────────┘
                                           │
                    ┌──────────────────────┬┴──────────────────────┐
                    │                      │                       │
           ┌────────▼──────┐    ┌──────────▼──────┐    ┌──────────▼──────┐
           │ Recon Module  │    │ Fuzzer Module   │    │ Exploit Module  │
           │               │    │                 │    │                 │
           │ get_tokens_   │    │ get_tokens_     │    │ get_tokens_     │
           │ for_domain()  │    │ for_domain()    │    │ for_domain()    │
           └───────────────┘    └─────────────────┘    └─────────────────┘
Configuration
Configuration is loaded from (in order, later overrides earlier):

config/modules.yaml → token_harvester: section
modules/token_harvester/config.yaml
Environment variables
Environment Variables
Variable	Description	Default
JARVIS_REDIS_HOST	Redis host	127.0.0.1
JARVIS_REDIS_PORT	Redis port	6379
JARVIS_REDIS_DB	Redis database	0
JARVIS_REDIS_PASSWORD	Redis password	null
JARVIS_HARVESTER_BUFFER_MAX	Memory buffer size	5000
JARVIS_HARVESTER_CLEANUP_INTERVAL	Cleanup interval (s)	300
JARVIS_HARVESTER_CONFIG	Path to config file	auto-detect
JARVIS_HARVESTER_LOG_TOKEN_VALUES	Log token values	false
Integration API
Other modules consume tokens via the public API:

Python

from modules.token_harvester import get_tokens_for_domain

# Get all tokens for a domain
tokens = get_tokens_for_domain("example.com")

# Get only JWTs
jwts = get_tokens_for_domain("example.com", token_type="jwt")

# Get cookies for a specific path
cookies = get_tokens_for_domain("example.com", token_type="cookie", path="/api/v1")

# List all domains with tokens
from modules.token_harvester import get_all_harvested_domains
domains = get_all_harvested_domains()

# Manual cleanup
from modules.token_harvester import cleanup_expired_tokens
removed = cleanup_expired_tokens()

# Stats
from modules.token_harvester import get_token_stats
stats = get_token_stats()
