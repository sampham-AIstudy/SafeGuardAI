# ICFD-31k adoption audit

Prepared and approved: 2026-11-07. The owner authorized execution of the described CPU/data/scoring
audit after reviewing its explanation. This does not adopt the benchmark or authorize detector runs.
The shortlist is [BENCHMARKS.md](../../BENCHMARKS.md).
Execution is complete. Original evidence is in [the audit result](REPORT.md).
Its primary-suite framing is superseded by the capability-specific, numerically rechecked assessment
in [BENCHMARKS.md](../../BENCHMARKS.md). No benchmark or model experiment is selected by this audit.

## Purpose and decision

Determine whether the released ICFD-31k can support a later observer-detector comparison, and which
native tasks are usable. This audit is successful if it produces a supported decision, including a
negative or limited decision. It does not have to approve the dataset.

Answer four questions:

1. Are the released files intact, complete and consistent with an identifiable version?
2. Do conversation splits, category holdouts and cumulative chunks support their documented claims?
3. Can the classification scores be computed with a clear, reproducible input/label contract?
4. What does an English/Hinglish synthetic-call result establish for this Vietnamese-chat project?

Sources: [dataset card](https://github.com/SPELLAILab/ICFD-31k/blob/main/DATASET_CARD.md),
[data access](https://github.com/SPELLAILab/ICFD-31k/blob/main/DATA_ACCESS.md),
[data terms](https://github.com/SPELLAILab/ICFD-31k/blob/main/LICENSE-DATA.md),
[release tree](https://huggingface.co/datasets/rishia2220/icfd-31k/tree/main),
[baseline documentation](https://raw.githubusercontent.com/SPELLAILab/ICFD-31k/main/baselines/README.md),
[reproducibility guide](https://github.com/SPELLAILab/ICFD-31k/blob/main/REPRODUCIBILITY.md), and
[paper](https://ijcai.org/proceedings/2026/786).

## Proposed execution scope

### Establish release identity and retrieve evaluation inputs

- Resolve immutable revisions for the author repository and dataset release. Preserve the relevant
  documentation, manifest, checksums and generic loader/scoring code with source URLs and local hashes.
- Read the pinned manifest first and total the compressed download bytes. Verify available disk space;
  compressed size is not an expanded-size estimate. The Hub currently lists 64.7 MB, an unverified
  listing rather than a measured local download. Stop before transfer if the manifest does not support
  the expected release or storage cannot accommodate it.
- Download the released source-conversation and streaming shards needed to check all four splits,
  with checkpointed retrieval and checksum verification. Do not regenerate conversations, download
  model weights or run author training/generation commands. Request required sandbox network access
  through the host's normal permission mechanism.
- Install only missing parsing dependencies in an isolated project environment if required, using
  the existing project tooling rules. Inspect third-party code before execution; prefer data-only
  parsing to imports that initialize providers, models or training jobs.

### Check structure, splits and temporal consistency

- Scan all downloaded rows with deterministic CPU code. Report actual conversation/chunk counts,
  labels, category coverage, missing fields and malformed records per split. Verify declared sizes
  and hashes. A successful download alone does not establish valid dataset contents.
- Check source identifiers across splits and normalized full-conversation text duplicates. Do not
  treat the repeated text of cumulative prefixes as duplicate source conversations. Check category
  holdout against the release's grouping definition; report available grouping evidence and its limits.
- Check chunk-to-source linkage, ordering and consistency with the source transcript and timestamp
  rules. Determine whether chunk references are independently assigned to observed content or merely
  inherit the final conversation label. Identify annotation future access where traceable; row-level
  structural consistency cannot certify absence of hindsight in model-authored labels.
- Read up to 20 training conversations, covering both classes where present, to inspect roles, language
  and label/input meaning. This is a limited usability inspection, not a label-validity estimate.
  Test and cross-domain conversation bodies, labels, identifiers and case-level findings do not enter
  the development discussion. Only aggregate checks on those splits are returned.

### Reconcile versions and check scoring without a detector

- Trace the published baseline split counts and scores to saved configs, evaluation code and release
  versions where possible. Record an explicit unresolved mapping if the artifacts do not explain them.
  Do not silently change splits or choose whichever score is easiest to reproduce.
- Inspect positive-label mapping, input fields, aggregation unit, missing/error handling and formulas.
  Separate full-conversation classification, prefix classification and first-warning measurements.
  An any-warning conversation prediction is not the same metric as pooled chunk classification.
- Exercise generic parsing and deterministic scoring on invented public fixtures, including known
  confusion matrices, empty/undefined denominators and malformed predictions. Use an offline fake
  detector to check that the input adapter exposes only the permitted observed transcript and that
  future text, verdicts, rationales and generation metadata cannot cross its output contract.
- No prediction on real test conversations is needed for this step. These checks establish tool
  behavior, not baseline-model reproduction, annotation correctness or detector quality.

### Produce an adoption recommendation

Deliver reproducible CPU checks, a release lock/manifest, an aggregate audit report and a concise
decision with the exact native tasks supported. Suggested artifact directory after approval:
`evaluation/icfd-31k-audit-2026-11-07/`; raw corpora belong in a separate private artifact directory,
not embedded in reports or automatically committed. Record actual paths and environment versions.

The decision may be:

- suitable for a later pilot under a declared English/Hinglish scope;
- suitable only for specified tasks, such as static classification;
- not ready because release/scoring correspondence remains unresolved;
- unsuitable for the claimed measurement.

Missing files, hash failure, unresolvable split identity, or unintended future/gold input prevent
acceptance of the affected task. Repair the local audit tooling within approved scope; upstream
dataset relabeling, repartitioning or translation requires a separate proposed adaptation. If the
published baseline version remains unidentified, do not claim its result has been reproduced even
when a released task can be evaluated independently.

## Resource and access boundaries

The proposed audit uses local CPU and storage. It launches no GPU job, paid API, detector inference,
LLM judge or model training, and sends no conversation text to an external inference provider.
Runtime is unknown until measured; do not turn an operational timeout into a runtime estimate.
Long scans checkpoint progress, use enforced deadlines and preserve incomplete/failure status.

Keeping test content out of reports is context separation, not proof of an operating-system permission
barrier. Do not claim a filesystem isolation mechanism that has not been implemented. Unexpected raw
test content in a log or return value must not be pasted into the development context. An independent
semantic review of test cases is outside this audit; it needs an explicit access arrangement.

The local 250-conversation benchmark is unchanged. No commit, push, publication, upstream contact or
access-gate acceptance is included. Classification labels remain the original references.

## Later work, separately decided

After this audit, a real-model pilot needs a selected model, execution route, subset, resource ceiling,
development/validation procedure and prefix-runner specification. It can start with a simple direct
classifier under a declared incremental input contract. It does not require implementing an agent.
Any paid job still needs its own verified cost and spending approval.

A workflow-versus-agent experiment follows only after their engine contracts exist. Control the
model, tools, observed input, warning procedure and resources for an orchestration claim; disclose
other differences. Native classification performance, synthetic timing, real execution latency and
Vietnamese transfer are different conclusions. This audit authorizes none of those model runs.
