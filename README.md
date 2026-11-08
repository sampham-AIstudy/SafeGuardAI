<div align="center">

# mini-safeguard

![Python](https://img.shields.io/badge/Python-standard_library-498AF2?style=for-the-badge)
![Stage](https://img.shields.io/badge/Stage-incremental_rebuild-A19654?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-unittest-6B7F4E?style=for-the-badge)

**Research an engine that assesses scam risk from observed conversation history.**

</div>

---

## Scope

The application boundary is:

```text
Messages -> Data normalizer -> Engine -> Warning policy -> Interface
                                ^  |
                                |  v
                        Conversation status
```

The rebuild starts with small, separately checked components. The current implementation is
the [observed-history boundary](engine/history.py): select an observed prefix, preserve its order
and content, and detach its mutable payloads from source history. It does not perform fraud
assessment. A workflow implementation and an agent-controlled alternative remain design work.

---

## Development checks

Run from the repository root with Python 3.12, the verified execution version. Only the standard
library is required:

```sh
timeout 90s python3 -m unittest discover -s tests -p 'test_*.py' -v
```

The timeout is an operational bound. Tests use independently authored neutral toy messages.

> **Note:** Do not use benchmark data from any split for development tests, debugging, fixtures
> or prompt/threshold tuning. Audit scripts under `evaluation/` are separate from development
> tests and must not be run as a component test suite.

---

## Evaluation

The [benchmark catalog](evaluation/BENCHMARKS.md) records the measured suitability checks,
selected tasks, source versions and interpretation limits.

| Dataset | Selected tasks |
|---|---|
| ICFD-31k | Full-conversation classification; released-prefix reference classification |
| BABILong QA2/QA3 | Multi-fact question answering under distracting context through a declared component interface |
| PhishRewrite | Classification robustness across fixed-source rewrite levels |
| Local synthetic-v1 | Guide-reference first-warning timing; joint success on declared scam/benign pairs, as an internal pilot |

Task selection is not an executed engine evaluation. No rebuilt detector performance is reported.
The [local scoring contract](testset/BENCHMARK_PROTOCOL.md) and deterministic scorer are available;
local conversation data, seed catalogs, generation material and private reviews are withheld.
External raw benchmark downloads are also excluded. Data-audit reproduction requires the separately
retrieved pinned inputs and is distinct from development testing.
