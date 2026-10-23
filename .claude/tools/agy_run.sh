#!/usr/bin/env bash
# Usage: .claude/tools/agy_run.sh <task_file> [name] [model]
# Builds preamble + task, runs agy (default gemini-3.8-flash-high), stores the full log in
# /tmp/agy/<name>.out and ONLY the '## REPORT' block in /tmp/agy/<name>.report.
# Run it with Bash run_in_background; then Read just the .report file.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TASK="$1"; NAME="${2:-$(basename "$TASK" .txt)}"; MODEL="${3:-gemini-3.8-flash-high}"
mkdir -p /tmp/agy
cd "$ROOT" || exit 1
PROMPT="$(cat "$ROOT/.claude/tools/agy_preamble.txt"; echo; cat "$TASK")"
timeout 2400 agy --model "$MODEL" --output-format text -p "$PROMPT" > "/tmp/agy/$NAME.out" 2>&1
code=$?
awk '/^## REPORT/{p=1} p' "/tmp/agy/$NAME.out" > "/tmp/agy/$NAME.report"
[ -s "/tmp/agy/$NAME.report" ] || tail -n 40 "/tmp/agy/$NAME.out" > "/tmp/agy/$NAME.report"
echo "agy exit=$code; report: /tmp/agy/$NAME.report ($(wc -l < "/tmp/agy/$NAME.report") lines)"
