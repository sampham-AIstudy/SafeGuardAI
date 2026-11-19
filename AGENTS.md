# Working on mini-safeguard

## Start here

- Use [README.md](README.md) for the project overview, current commands, and documentation map.
- In the owner checkout, read `PLAN.md` for active scope and `STATUS.md` for verified state. Use `REFERENCE.md` for architecture and contract details.
- Use [the benchmark catalog](evaluation/BENCHMARKS.md) for selected tasks and interpretation. Use the [workspace layout](docs/workspace-layout.md) to locate local runs, runtime data, and archived evidence.

## Work and verify

- Use the discovered g3stack skill when the owner delegates a project goal. Complete bounded tasks directly. For routine work, choose the smallest change that meets the accepted outcome and verify it against the real interfaces. Use extra design or review when a concrete architecture, security, isolation, recovery, or cost concern warrants it.
- Separate proposals, accepted decisions, implementation, and verified results. Record current scope in `PLAN.md` and verified state in `STATUS.md`. Keep original evidence and replace superseded summaries with a link to their history.
- Preserve the application-facing contracts and the owner's architecture drawings. Keep orchestration, evidence access, Memory, and Warning Policy independently replaceable. The selected project phase governs any new behavior.
- Remove code and generated files when caller checks, source identity, or reproducibility establish they are redundant. Preserve historical evidence, originals, and recovery artifacts within their approved scope.
- Use the documented Pixi environment for Python and ML work. Apply the owner and host rules for other dependencies and compute. Run the guarded component and schema checks for affected engine behavior. Run the offline SDK suite for changes to model transport or its integration.

## Authorization and data

- Use prior approval only within its recorded scope. Installation or configuration activation, billing and paid jobs, GPU use, production-data handling, deployment, publication, destructive actions, commits, pushes, and history rewrites require applicable authorization. Commit approval and push approval are separate.
- Keep raw datasets and their source records, local state, logs, credentials, private authoring and review records, and the complete local testset out of publication. The local testset includes its guides, protocols, schemas, scorers, and test tooling. The owner handles any future publication of that material.
- Use independently authored toy inputs for development tests, debugging, prompt or threshold tuning, and development measurements. Keep all benchmark splits, labels, seeds, and per-record results out of those activities. The labeling guide and aggregate evidence may be read. The seed preparation material under `data/development/` may be inspected within its authorized scope.
- Keep formal evaluation separate. Benchmark selection authorizes neither inference nor corpus changes. Preserve the frozen SGC-250 `synthetic-v1` release and the original audit evidence.
- Run only authorized model jobs. Preserve provider, model, venue, limits, and data access. Keep credentials and conversation content out of routine logs. Record failures and uncertainty alongside successful results.
