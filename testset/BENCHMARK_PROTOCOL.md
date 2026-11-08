# Benchmark protocol: guide-reference first warnings

**Status: capability and deterministic metric definitions selected by the owner, 2026-11-04.**
Detector, acceptance thresholds and comparison conditions remain unselected. Local synthetic-v1 is frozen;
its evaluated protocol is the immutable version-owned snapshot. This file is the mutable public reference. The public label
contract is [LABELING_GUIDE.md](LABELING_GUIDE.md); individual test records and judgments stay held out.

## Question and scope

Research question: can an observer warn when deciding evidence first appears in a Vietnamese chat,
while avoiding warnings on earlier prefixes and superficially similar legitimate exchanges?

The proposed contribution is the combination of evidence-based warning boundaries and paired scam/benign
near-misses. Vietnamese language and incremental classification alone are not novelty claims. A systematic
comparison of existing annotation and scoring protocols is still needed before claiming a new capability.

The intended pool is 250 synthetic conversations, balanced by class. Inclusion requires the guide's QC;
the desired count does not justify retaining invalid examples. Text attachment placeholders do not test
perception of actual images, audio or video. Results concern this constructed pool and its reference rule.

## Information boundary

1. Replay each conversation in message order. At message index t, expose messages 0 through t only.
   Sender, channel and attachment placeholders are permitted input. Future messages, gold, features,
   source facts, IDs used for evaluation, and review rationales are not detector inputs.
2. Start each conversation with clean engine state. Persist only information derived from observed messages
   and permitted external capabilities. Keep future text out of summaries and retrieval indexes.
3. Record the first actual warning index, or no warning after the final observed message. The replay can
   stop at the first warning; later warnings cannot repair a premature first warning.
4. Evaluation bookkeeping can use opaque IDs. The detector must not use evaluation metadata to infer labels.
   Per-conversation outputs remain private; developers receive aggregates.

The engine result and warning policy are different interfaces. This protocol scores warnings produced by
the declared policy. Engine-only scoring needs a separate declared mapping from analysis to warning.

## Deterministic measurements

For a scam, the reference index is `gold.alert_turn`. For a benign conversation it is null. All indices
refer to individual messages, not alternating user/contact pairs. A missing warning is never encoded as
index zero. Malformed outputs and execution failures must be counted and reported, not silently removed.

| Measurement | Scoring rule | Interpretation |
|---|---|---|
| Conversation precision, recall and F1 | Predict scam if any warning occurs before the conversation ends | Full-conversation discrimination; report premature warnings separately even when these count as true positives |
| Benign false-alarm rate | Benign conversations with any warning divided by all benign conversations | A conversation is counted once, regardless of its length |
| Premature-warning rate | Scams with first warning before the reference index divided by all scams | Warnings made before the guide's deciding evidence |
| Miss rate | Scams with no warning divided by all scams | Failure to warn by the observed end |
| Evidence-respecting detection rate | Scams with first warning at or after the reference index divided by all scams | Complements premature warnings and misses; does not reward guessing before evidence |
| Warning delay | First-warning index minus reference index, only for evidence-respecting detections | Report median, mean and denominator together with premature-warning and miss rates |
| Exact-boundary detection rate | Scams with first warning exactly at the reference index divided by all scams | Strict agreement with a judgment-based boundary; no arbitrary tolerance selected yet |
| Paired near-miss success | Pairs in which the scam receives an evidence-respecting warning and the benign twin receives no warning, divided by all eligible pairs | Joint discrimination on matched topics; report delay separately |
| Resource use and failures | Model calls, tokens, tool calls, elapsed time and failed conversations under a declared accounting rule | Quality must be interpreted with resource consumption and execution reliability |

Do not collapse these measures into one weighted score without a stated reason and an owner-selected tradeoff.
Agreement tolerances used during annotation are not automatically detector scoring tolerances. An ERDE-style
score would require a separate cost specification and justification; it is not part of this draft.

Label quality can use model reviewers under the guide. Once references are fixed, the measurements above
need only recorded warning indices and references; they do not need an LLM judge. Free-text explanation
quality and semantic tool-use quality are outside these deterministic scores.

### Scorer artifacts and execution checks

`tools/score.py` emits aggregate JSON only. Each prediction line has `id` and `first_warning` (a 0-based
integer, or null after the final message with no warning). Optional `status` is `ok` or `error`; an error
must not be presented as a completed no-warning decision. Optional `resources` contains nonnegative
`model_calls`, `tokens` (total input plus output tokens), `tool_calls`, and `elapsed_seconds` (wall time
for processing the conversation). Report resource coverage; missing accounting is not zero consumption.

Missing, duplicate, unknown, malformed or failed predictions make the run incomplete. The scorer reports
failure counts and diagnostic observed counts but withholds primary metrics. It neither silently removes
those cases nor invents a warning or benign prediction for an execution failure. Undefined ratios and
delay without any eligible detection are null. Exit codes are 0 for complete scoring, 1 for incomplete
predictions and 2 for invalid input artifacts.

The dataset manifest must declare `status: frozen`, `testset_version` and `conversations_sha256`, plus
`protocol_version: "1.0"`, a relative `protocol_path` and `protocol_sha256` for its immutable protocol snapshot.
The prediction run manifest binds `testset_version`, `dataset_sha256` and `predictions_sha256` to the
actual files. The scorer verifies both identities and records its own and this protocol's hashes.
Hash binding does not prove that a detector obeyed prefix isolation; the later runner must establish that.

```sh
python3 -I testset/tools/score.py \
  --data testset/synthetic-v1/conversations.jsonl \
  --manifest testset/synthetic-v1/manifest.json \
  --predictions PRIVATE_RUN/predictions.jsonl \
  --run-manifest PRIVATE_RUN/manifest.json \
  --out PRIVATE_RUN/aggregate.json
```

This command is for a later authorized detection run. The scorer is verified on public toy conversations
in `tools/test_score.py`; it has not been used to evaluate a detector on the frozen local test pool.

## Comparison conditions to settle

For an orchestration comparison, use a shared input boundary, model, available capabilities, warning-policy
procedure and declared resource ceilings. Specify which control decisions differ between workflow and agent
variants. Record context construction and state behavior; if these differ, attribute results to the broader
architecture rather than control alone. The detailed engine contract remains a separate design task.

Choose thresholds, prompts and resources on development/validation data, before the frozen test run. Never
tune them against this pool. A shared policy procedure does not imply that differently scaled scores need
the same numeric threshold. The detector model and its overlap with generator/reviewer families must be
disclosed before an evaluation.

The unit of reporting is the conversation. Prefixes from one conversation are dependent observations.
Pairs and shared source cases also introduce dependence. Small per-type slices are descriptive, and any
uncertainty analysis must state its sampling unit. No minimum winning margin or statistical test is selected.

## Limits and outstanding choices

- The first-warning boundary is a reference judgment under this guide, not an observed real-user outcome.
- Balanced synthetic data do not establish deployment precision or protection from real scams.
- Most second-pass labels share a model family with the generator; agreement is not human validation.
- Human review availability, source-copy/privacy coverage, unresolved QC findings and freeze identity must be
  reported with the eventual dataset version.
- The owner selected this capability focus and the deterministic metric definitions above. Implement and
  verify them on public toy cases. Comparison conditions, resource ceilings and any winner criterion remain
  unselected; this does not authorize a detector run.

The current selected external tasks and local pilot interpretation are maintained in the
[benchmark catalog](../evaluation/BENCHMARKS.md). No model run is authorized by this document.
