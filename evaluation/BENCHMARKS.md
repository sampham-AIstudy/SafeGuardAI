# Benchmark catalog

Four datasets and six tasks were selected on 2026-11-08. Existing results cover CPU audits of data and scoring. SafeGuard's held-out detector performance awaits a formal run. Model choice, thresholds, budget, and execution require a separate decision.

## Selected benchmark tasks, 2026-11-08

| Dataset and task | Model input and measurement |
|---|---|
| ICFD-31k, complete-call classification | Provide the complete synthetic English/Hinglish transcript. Report conversation-level confusion counts, precision, recall, and F1 by class, plus benign false-positive rate. |
| ICFD-31k, streaming classification | Provide the cumulative observed prefix at each native three-second boundary. Report chunk-level classification against the released YES/NO references. Keep conversation false alarms separate from chunk errors. |
| BABILong, distributed-fact QA | Exercise a declared context/QA component using the narrative and question. Report native accuracy for QA2 and QA3 separately by length, with QA1 and short-context controls. Pair only verified matching stories. |
| PhishRewrite, rewrite robustness | Classify original English test emails and each rewrite independently. For each provider, use the same eligible parents at all four levels and the same unchanged ham controls. Report absolute phishing recall and F1, benign false-positive rate, and paired changes. |
| SGC-250 `synthetic-v1`, first-warning timing | Replay observed messages in order with the declared Warning Policy. Report matches to the guide-defined evidence boundary, premature warnings, misses, benign false warnings, and delay in messages conditional on a nonpremature detection. |
| SGC-250 `synthetic-v1`, near-miss pairs | Score the 28 declared scam/benign pairs. A pair passes when the scam receives a nonpremature warning and the benign case receives none. Report delay separately. |

## Interpretation and evidence

### ICFD-31k: assess native tasks separately

The static test has 4,477 positive and 23 negative conversations. Always predicting YES yields 99.74% positive F1 and a 100% false-positive rate. A single benign error changes that rate by 4.35 percentage points. The streaming test instead has 115,157 YES and 64,670 NO chunks, with 78.08% positive F1 for constant YES. Its prefix references follow the released keyword/time rule. The native majority-filtered timing calculation excludes 1,809 of 4,476 source-labeled scams with chunks. Adopted scope covers the two classification tasks. Earliest-warning timing and category transfer require separate protocols. [Audit report](audits/icfd-31k-audit-2026-11-07/REPORT.md) · [Numerical cross-check](audits/capability-audit-2026-11-07/icfd.json)

### BABILong

The audit covered QA1–QA3 at 0k, 4k, and 16k, with 100 records per cell. Same-index pairing across short and long contexts held for 100/100 QA2 and 86/100 QA3 cases. Use a fixed answer vocabulary and record the native parser; report stricter parsing separately. Interpret the result as performance of the tested QA path. Persistent conversation memory and scam detection require their own tests. [Aggregate audit](audits/capability-audit-2026-11-07/babilong.json)

### PhishRewrite

Within-provider native cohorts contain 270 Claude and 308 Gemini parents that pass the strict URL filter, non-refusal, and nonempty checks at every level. Exclude source metadata from model input. The filter checks URL retention under its own matching rules, and semantic preservation remains unverified. Report stricter adaptations separately. The native fixed-FPR operating point comes from test ham scores, so deployment calibration requires an independent split. [Aggregate audit](audits/capability-audit-2026-11-07/phishrewrite.json)

### SGC-250

The frozen internal pilot has 125 scam and 125 benign conversations. Its scores measure agreement with the synthetic warning reference and joint success on declared pairs. Existing reviewers saw full conversations, and an earlier allocation excerpt reached development context. Disclose that access incident in reports and limit claims of developer independence. Human-optimal timing, real-world validity, and causal use of a single distinguishing cue remain open. [Local suitability audit](audits/local-suitability-audit-2026-11-08/aggregate.json)

## Selection basis

Choose a task for a defined capability and observable input, with a defensible reference, informative baselines, interpretable denominators, and a pinned protocol. Keep native scores separate from adaptations and component results separate from end-to-end results. Access and cost constrain execution. [Project data rules](../AGENTS.md)

PhishVN overlaps the rewrite task and has shared source IDs across its released train/test variant roles. BothBosu added no established capability beyond complete-conversation discrimination. SCAMBENCH is parked because raw-data access remained unresolved at selection. [PhishVN audit](audits/capability-audit-2026-11-07/phishvn.json) · [BothBosu audit](audits/bothbosu-audit-2026-11-07/aggregate.json) · [SCAMBENCH public review](audits/scambench-review-2026-11-07/review.json)

## Run and evidence locations

- **Formal engine evaluation.** Pin the release and split, model, allowed inputs and tools, warning policy, scorer, and resource limits before running. Keep references on the scoring side and benchmark data out of development tests. Record native versus adapted results and failures. [Agent study protocol](../docs/research/agent-evaluation.md)
- **CPU audit reproduction.** Use the maintained controller below with the pinned inputs and ICFD parser environment. The default identifier is `benchmark-measurements-2026-11-08`. Set `SAFEGUARD_AUDIT_RUN` for a fresh run and use the matching manifest to resume. The controller performs CPU data and scorer checks with no automatic downloads or model inference. [Controller](../src/safeguard/evaluation/remeasure.py)
- **Evidence.** `evaluation/audits/` holds dated aggregate reports and locks. Local `evaluation/runs/` holds rerun receipts, and `evaluation/private/` holds private review and release evidence. The original catalog, including the search notes, numerical derivations, and source history, is preserved in the owner checkout at `.local/archive/research/benchmark-catalog-2026-11-19/BENCHMARKS.before.md`.

```sh
timeout 2400s pixi run --as-is env PYTHONPATH=src python -B -m safeguard.evaluation.remeasure
```

Upstream reference code licenses are preserved with the snapshots. [ICFD MIT](audits/icfd-31k-audit-2026-11-07/upstream/LICENSE) · [BABILong Apache-2.0](audits/capability-audit-2026-11-07/sources/LICENSE-BABILong) · [PhishRewrite MIT](audits/capability-audit-2026-11-07/sources/LICENSE-PhishRewrite)
