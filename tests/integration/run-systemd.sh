#!/usr/bin/env bash
# Compatibility entry point: all network mutation now runs in a real QEMU VM.
set -euo pipefail
exec python3 tests/vm/run.py
