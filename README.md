<div align="center">

# mini-safeguard

![Python](https://img.shields.io/badge/Python-standard_library-498AF2?style=for-the-badge)
![Stage](https://img.shields.io/badge/Stage-incremental_rebuild-A19654?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-unittest-6B7F4E?style=for-the-badge)

**Research an engine that assesses scam risk from observed conversation history.**

</div>

---

## Scope

Observe a conversation as messages arrive, assess scam risk in an engine, and let a separate
policy decide whether and when to warn. The engine research will compare workflow and agent
control; neither has demonstrated superiority in this rebuild.

---

## Architecture

The architecture diagram supplied by the project owner:

![Application architecture](docs/assets/architecture.png)

Source adapters implement message ingress. The demo is one source implementation; each
adapter hands its events to the shared normalizer.

| Part | Responsibility in the current design |
|---|---|
| Source adapter | Receive source events and hand off source context plus the unchanged native message-event data |
| Data normalizer | Interpret the native data using that source's mapping and produce an internal message representation |
| Engine | Analyze the observed conversation and return an assessment with references to supporting/counterevidence |
| Warning policy | Decide whether/when to warn from the assessment and permitted warning history |
| Interface | Present the policy's action to the user |
| Conversation status | Retained conversation information available to the engine; detailed state ownership and persistence remain design work |

Two input representations must stay distinct:

- **Adapter event:** common handoff metadata plus `payload`, the original source event data.
  A common wrapper does not make the source's content a common internal message.
- **Internal message:** the normalizer's output that the engine understands. Its exact schema
  has not been selected or implemented.

The [current handoff schema](src/safeguard/adapters/contract.schema.json) preserves native payloads. Adding a
source therefore requires its adapter **and** a compatible payload mapping for the normalizer.
The purpose is to keep platform field names out of the engine. Engine analysis and user-facing
warning decisions remain separate. Detailed engine/state/policy behavior is still proposed;
this diagram is not a claim that the application is implemented.

---

## Current implementation

Application code lives under `src/safeguard/`, with architecture components such as `adapters`
and `engine` inside that package. Component tests and their neutral fixtures live under `tests/`;
architecture illustrations live under `docs/assets/`. Active audit tools live under
`src/safeguard/evaluation/`; evaluation evidence and outputs stay under `evaluation/`.
The `src` directory is placed on the import path by the test command below. No package installation
is needed for that command. Package metadata and schema-resource inclusion are in `pyproject.toml`.

The rebuild starts with small, separately checked components. Its executable engine component is
the [observed-history boundary](src/safeguard/engine/history.py): select an observed prefix, preserve its order
and content, and detach its mutable payloads from source history. It is parked for the later
Engine stage and does not perform fraud assessment.

The source-adapter schema, isolated contract checker and [single-message DemoAdapter](src/safeguard/adapters/demo.py)
exist. DemoAdapter receives an already decoded demo-native object and explicit account context;
it returns one detached envelope or a structured field error. It does not deliver messages to
the normalizer or connect to a real source. Source integration, normalizer, full engine, warning
policy and interface integration remain unimplemented.
Work proceeds in input-flow order using separately reviewed small tasks.

DemoAdapter's native required fields are `thread`, `id`, `author` (nonblank strings) and `body`
(a nonempty string, preserved without trimming). Extra JSON fields remain opaque in the payload.
The adapter's clock returns a timezone-aware datetime; observation time is represented in UTC
and never substituted for missing native send time. The implementation uses the standard library.

---

## Development checks

Run from the repository root with Python. The component suite was verified with Python 3.14.4.
Tests additionally use `jsonschema` 4.19.2 to check adapter outputs against the handoff contract;
this test dependency is declared in `pyproject.toml` and is not a runtime dependency:

```sh
timeout 90s env PYTHONPATH=src python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The timeout is an operational bound. Tests use independently authored neutral toy messages.

The separate contract-authoring check requires `jsonschema` (verified with version 4.19.2):

```sh
timeout 90s python3 -I tests/contract_checks.py
```

It validates newly authored toy envelopes, not source integration or normalizer behavior.

> **Note:** Do not use benchmark data from any split for development tests, debugging, fixtures
> or prompt/threshold tuning. Dataset audit tools are separate from development
> tests and must not be run as a component test suite.

---

## Evaluation

The [benchmark catalog](evaluation/BENCHMARKS.md) records the measured suitability checks,
selected tasks, source versions and interpretation limits.

Historical dataset checks live in `evaluation/audits/`, with each dated evidence bundle preserved.
Earlier criteria/interpretation notes live in `evaluation/compatibility/` as catalog redirects.
`evaluation/private/` stays ignored for local construction/QC evidence. Ignored `evaluation/runs/`
holds fresh CPU audit outputs and will also hold separately identified future engine runs.
An engine-evaluation runner is not implemented.

Relocation preserved the old audit scripts rather than silently updating their source identities.
Active path-migrated CPU audit tools now live under `src/safeguard/evaluation/`; archived scripts
remain historical evidence. They use canonical input paths and separate fresh run outputs,
without old-path symlinks. These tools measure dataset/scoring properties, not engine performance,
and must not be run as development tests.

The post-migration CPU audits completed for all six downloaded corpora. Measurement fields match
the preserved earlier reports; changed provenance fields identify the new paths and source code.
The catalog describes the scope and current reproduction command. These are dataset/scoring
diagnostics, not new engine scores or independent semantic validation.

| Dataset | Selected tasks |
|---|---|
| ICFD-31k | Full-conversation classification; released-prefix reference classification |
| BABILong QA2/QA3 | Multi-fact question answering under distracting context through a declared component interface |
| PhishRewrite | Classification robustness across fixed-source rewrite levels |
| SGC-250 (frozen artifact version synthetic-v1) | Guide-reference first-warning timing; joint success on declared scam/benign pairs, as an internal pilot |

Task selection is not an executed engine evaluation. No rebuilt detector performance is reported.
The entire local benchmark directory is withheld, including its conversations, guide, protocol,
schema, scoring tools, seed catalogs, generation material and reviews. Any future dataset
publication is handled separately by the owner.
External raw benchmark downloads are also excluded. Data-audit reproduction requires the separately
retrieved pinned inputs and is distinct from development testing.

Local benchmark material is grouped under ignored `data/benchmarks/`: `SGC-250`, `icfd-31k`,
`babilong` and `phishrewrite`. Previously reviewed `phishvn` and `bothbosu` inputs are preserved
there too; storage does not select them for evaluation. The local SGC-250 name does not change
its `synthetic-v1` manifest, contents or hashes. Dataset storage holds inputs, references,
task/scoring definitions, version and checksums. SGC-250's tools and historical authoring,
review and run evidence live separately under ignored `evaluation/private/SGC-250/`.
Release-QC files also live there. Their physical locations are recorded in
`evaluation/private/SGC-250/release-qc/storage-layout.json`; the active resolver implements the same
member mapping. Original frozen files and checksum text are unchanged, but
the old relative-layout `sha256sum -c` command is superseded by mapped verification. Temporary
old-path symlinks and the legacy view have been removed.

The separate, ignored `devset/` currently contains only an unfinished development seed catalogue.
Its original intended role was to support development conversations distinct from the benchmark.
No such development conversations, QC or manifest exist, and it is not used as test-fixture data.
