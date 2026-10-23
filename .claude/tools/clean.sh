#!/usr/bin/env bash
# Remove one-off artifacts: agy prompts/logs, reviewer scratch dirs, generated eval results.
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
rm -rf /tmp/agy /tmp/rv* "${TEMP:-/tmp}"/rv_* "${TEMP:-/tmp}"/rv1a "${TEMP:-/tmp}"/rv 2>/dev/null
rm -f "$ROOT"/eval/results/*.json 2>/dev/null
find "$ROOT" -name "__pycache__" -not -path "*/.venv/*" -prune -exec rm -rf {} + 2>/dev/null
find "$ROOT" -name ".pytest_cache" -not -path "*/.venv/*" -prune -exec rm -rf {} + 2>/dev/null
echo "clean done"
