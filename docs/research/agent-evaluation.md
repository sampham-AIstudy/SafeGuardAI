# Evaluation protocol for AI agent research

Proposed protocol, 2026-11-19. The [architecture study](agent-architecture.md) explains the candidate selection. This protocol defines comparisons and reporting requirements for a separately authorized experiment. The existing [benchmark catalog](../../evaluation/BENCHMARKS.md#selected-benchmark-tasks-2026-11-08) retains authority over benchmark selection, native inputs, and metrics.

## Comparisons

| Order | Change under test | Controls and eligible claim |
|---|---|---|
| 1 | Compare the existing Agent Controller with the stateful agent. Use Flash-Lite for both arms. | Hold the conversation prefix, source permissions, tool catalog, provider settings, resource ceilings, and Warning Policy constant. Attribute differences to the combined state and control changes. If the combined candidate improves, repeat with persistence alone and check selection alone before assigning either effect. |
| 2 | Add a new evidence processor or source with the stateful agent and fixed model. | Hold the agent, model, all other sources, and policy constant. Log exactly what the new capability made observable. Separate retrieval or extraction failures from reasoning failures. |
| 3 | Compare fixed Flash-Lite with fixed Hydrogen on the same agent. Add one cross-family or self-hosted candidate only when an authorized venue can run the same interface. | Hold inputs, tools, state, policy, and ceilings constant. Record provider capability differences and any unsupported modalities. Attribute results to the tested model and configuration together. |
| 4 | Compare routed use of complementary models with the best eligible fixed-model arm and the low-resource fixed-model arm. | Freeze routing before evaluation. Keep the candidate provider list, data access, and per-run ceilings fixed. Record route choice, escalations, skipped checks, and the outcomes of routed cases under the fixed controls. |

Use the same eligible observation boundaries for paired arms. Run each arm with fresh, isolated conversation state. Feed each conversation in arrival order. Within an arm, retain state across its permitted observations. Record the actual call count and delay. A shared ceiling bounds what each arm may consume. Actual resource use is part of the comparison.

## Inputs and scoring reference

Use independently authored material for development and functional checks. Freeze and hash the case set before a comparison. Keep separate cohorts for development and evaluation, grouped by scenario family and source to prevent related cases from appearing on both sides. Formal benchmark inputs and labels belong in an authorized evaluation run. Supply only the observed prefix and permitted metadata to Detection. Keep labels, evidence boundaries, annotator notes, and future turns on the scoring side.

Cover benign, scam, and genuinely unresolved prefixes. Include relevant evidence distributed across turns or formats. Include distractors, duplicate sources, contradictory observations, missing or unsupported inputs, and unavailable tools. Cover both cases where an additional check can change the verdict and cases where further retrieval cannot resolve ambiguity. Use abstract coverage categories in the public record. Keep individual evaluation inputs outside it.

Before evaluating a new cohort, define the first reference point where an alert is warranted, or mark the conversation as having no reference point. Annotate which source parts support or contradict the relevant assessment, and identify material unknowns. For a new custom reference, have two reviewers label independently and record disagreement and adjudication before seeing model results. Preserve selected benchmark references and native scoring rules separately from these diagnostics.

## Measures

| Measure | Unit and denominator |
|---|---|
| Benign false warnings | Benign conversations with any new warning divided by all eligible benign conversations. |
| Scam misses and premature warnings | Count misses among scam conversations with a reference warning point. Count first warnings before that point separately. For first warnings at or after that point, report their delay in observation steps. Report late detections and cases without a detection. |
| Uncertainty and operational coverage | Report valid `insufficient_evidence` assessments, other valid assessments, and non-assessment outcomes per evaluated prefix. Break down non-assessments by failure type. Show their effect on end-to-end missed warnings as well. |
| Evidence quality | Independently review whether the references support the material claims in the assessment and whether the assessment omits relevant counterevidence. Report valid source locations separately from semantic support. [ALCE](https://aclanthology.org/2023.emnlp-main.398/) |
| Value of checks | Record which material unresolved question a check addressed, whether it produced usable information, and whether it changed an assessment for the better. Use the paired control to separate improved assessments from additional activity. |
| Resources | Record elapsed time, model and tool calls, tokens where available, failed attempts, and billed units where applicable. Report central and tail latency and separate retries from original calls. |

Report matched counts and differences by conversation, with uncertainty intervals clustered by conversation when the sample supports inference. Include per-modality and per-language results where denominators allow. A small functional sample supports mechanism checks. A quality or generalization claim requires sufficient independent evaluation data with a declared sampling procedure. [SelectiveNet](https://proceedings.mlr.press/v97/geifman19a.html) · [AI Agents That Matter](https://arxiv.org/abs/2407.01502)

## Run acceptance and interpretation

- Pin implementation, instructions, provider and model version, tools, input identity, output schema, scoring version, and authorized ceilings before a run. Fix the comparison order and review rubric before looking at results. Record missing versions or ambiguous provider aliases.
- Require safe rejection of wrong-account and future references, preserved outgoing-content restrictions, correct storage of repeated evidence, and rejection of stale writes. Exercise missing and malformed inputs, unsuccessful tools, cancellation, deadline exhaustion, and restart. Boundary violations invalidate the affected arm. Preserve the failed run and repair the boundary before a new comparison.
- Classify outcomes as improved, worse, or inconclusive relative to the paired control. Advance the stateful agent when grounded decisions and warning behavior improve without evidence of a meaningful regression within the preregistered limits. Keep the current agent when the evidence is inconclusive. Set product risk and latency tolerances before any production adoption decision.
- Treat routing as a separate research decision. Advance it when it improves the quality and resource trade-off over the fixed model comparisons. Inspect wrong routing and missed escalation directly. A lower average cost alone cannot establish that the affected conversations were handled acceptably.

Retain the run manifest, terminal receipts, aggregate scores, and redacted failure summaries in their authorized evidence locations. Keep the original run immutable. Record missing checks with their prerequisite and effect on interpretation. This protocol has no executed model comparisons yet.
