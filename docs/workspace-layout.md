# Workspace layout

| Path | Contents |
|---|---|
| `src/safeguard/` | Application code, including Detection, Memory, and the partner demo. |
| `tests/` | Component, schema, and SDK checks with independently authored inputs. |
| `docs/` | Architecture drawings, research, and project documentation. |
| `evaluation/` | Benchmark catalog, audit evidence, and formal evaluation outputs. |
| `data/benchmarks/` | Local benchmark releases. |
| `data/development/` | Local seed preparation material. Development checks block access to it. |
| `.local/runs/` | New local run outputs. Put checks under `checks/` and maintenance evidence under `maintenance/`. Keep inputs, results, and the reproduction command together within each run. |
| `.local/runtime/` | Persistent local demo stores, including conversation state, originals, and the live demo's request ledger. |
| `.local/archive/` | Earlier run bundles under `checks/`, `demo/`, `engineering/`, and `research/`. Original project records are under `history/`. |

Git ignores `.local/`, private evaluation inputs and outputs, and seed preparation material. The [project instructions](../AGENTS.md) govern access and publication. `evaluation/audits/` and `.audit-private/` retain the paths used by archived audit code and manifests. The [benchmark catalog](../evaluation/BENCHMARKS.md) documents evaluation sources and protocols.

## Historical paths

The owner checkout records the exact old-to-new path prefixes in `.local/runs/maintenance/workspace-layout-2026-11-19/migration.json`. Use the longest matching prefix. Former `logs/` runs are indexed by their original run name. Former `history/` is now `.local/archive/history/`. The former `devset/seeds/` is now `data/development/seeds/`. The live preview store moved to `.local/runtime/partner-demo-live/` so it can be reopened using the documented command.

Archived reports retain the paths recorded at the time. For a replay, stage the needed bundle in an isolated checkout with its original relative paths and inputs. Three archived symlink-guard fixtures have absolute link targets and require the original checkout path or equivalent links in a disposable copy. Keep the archived originals intact. Use the recorded approvals and execution limits for any replay involving external services or private data.
