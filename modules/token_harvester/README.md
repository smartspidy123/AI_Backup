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
