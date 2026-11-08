# External benchmark shortlist

Reviewed: 2026-11-07; task allocation finalized 2026-11-08. Scope: identify existing measurements before investing
further in a new benchmark. This records source/suitability reviews and the approved measurement scope;
it is not an executed experiment suite.
The initial shortlist inspected documentation, paper methods and release listings without downloading
corpora or running a detector. The subsequently approved ICFD-31k CPU audit is complete:
[historical audit result](audits/icfd-31k-audit-2026-11-07/REPORT.md). Its measurements remain unchanged;
current selection criteria and numerical task-specific interpretations are maintained in this file.
The Selected benchmark tasks section is authoritative for the current allocation; dated search
and audit findings below retain their original measurement scope and limitations.
Other candidates remain documentation/access reviews; SCAMBENCH also has aggregate arithmetic
checks, with its raw data unavailable and adoption parked. BothBosu has a bounded CPU/data audit,
including structural ranking diagnostics; no engine, LLM or learned text classifier was run.

Reference source copies retain the upstream code licenses: [ICFD MIT](audits/icfd-31k-audit-2026-11-07/upstream/LICENSE),
[BABILong Apache-2.0](audits/capability-audit-2026-11-07/sources/LICENSE-BABILong), and
[PhishRewrite MIT](audits/capability-audit-2026-11-07/sources/LICENSE-PhishRewrite). These notices accompany
reference code; the raw datasets and local authoring/review records are not published here.

## Evaluation artifact layout and execution status

Current organization separates preserved corpus evidence, active audit code and fresh outputs:

| Location | Contents and status |
|---|---|
| `BENCHMARKS.md` | Current selected tasks, scoring interpretation and limits |
| `audits/` | Preserved dated dataset-audit bundles, the ICFD audit protocol and the SCAMBENCH public review |
| `compatibility/` | The two earlier interpretation/criteria notes, kept as redirects to this catalog |
| `private/` | Ignored SGC-250 construction, review and release-QC evidence/tools; not engine-run results |
| `runs/` | Ignored fresh CPU audit outputs; future engine runs require separate identities and approval |
| `../src/safeguard/evaluation/` | Active path-migrated CPU audit tools; not an engine-evaluation runner |

The four original dated audit bundles retain all 97 original file contents, hashes and modes.
The SCAMBENCH review metadata also remain unchanged. Link updates in this catalog and protocol/
redirect documents do not change measured results. Temporary old-path symlinks, including root
`testset`, the SGC-250 QC link and its legacy view, are removed. The unchanged local checksum
members resolve through explicit physical paths; frozen release content was not edited.

**Current reproduction boundary:** archived scripts retain their original source identities and
root assumptions. Use the migrated tools, not archived commands, for canonical paths. With pinned
data, source snapshots and the ICFD parser environment present, repeat the formal CPU measurements
from the repository root:

```sh
timeout 2400s env PYTHONPATH=src python3 -m safeguard.evaluation.remeasure
```

The default run identity is `benchmark-measurements-2026-11-08`. The controller resumes completed
stages only under its matching source manifest. To start another clean run, set
`SAFEGUARD_AUDIT_RUN` to a new purpose/date name. Deadlines are operational limits. No automatic
downloads, model inference, engine execution or paid calls are part of this command. Older inline
read-only snippets below describe historical calculations; their stored paths are not the current
execution interface. Historical locks are interpreted by the explicit resolver, without aliases.

| Checked after final path migration, 2026-11-08 | Supported conclusion |
|---|---|
| All eight fresh measurement/verification stages completed successfully | ICFD raw scan/derivations, BABILong, PhishRewrite, PhishVN, BothBosu and SGC-250 CPU diagnostics reproduced |
| Aggregate comparison with original reports | All measurement fields match; changed provenance consists of source/signature/path fields and two added license hashes |
| Final component suite: 38 tests, 64 subcases, zero benchmark-access attempts | Independent toy checks cover the adapter, history utility and explicit audit path mapping |
| Original data and all 97 archived bundle files retain hashes/sizes/modes; 21 local checksum members verified by mapped paths | Relocation preserved frozen data and evidence |

Fresh outputs, source/lock manifest, per-stage logs and comparison evidence are under ignored
`evaluation/runs/benchmark-measurements-2026-11-08/`, especially `stages.json`, `comparison.json`
and `icfd/supplementary.json`. The initial capability-path failure and the scoped mapping repair
remain in `repairs/release-source-path/`. The corrected run reused only its already completed
fresh ICFD stages after verifying that their code, data and path behavior were unchanged.
The original reports below remain historical references. The rerun adds reproducibility evidence,
not new semantic validation, stronger task claims or engine performance. SCAMBENCH remains parked;
its public arithmetic review is not a raw-data or model result.

No rebuilt-engine evaluation runner is implemented. Future engine task adapters/scorers belong
under `src/safeguard/evaluation/`, outside the production messaging pipeline. Development checks
must use independent toy inputs, never benchmark samples from any split.

## Selection basis

The owner requests evidence for specific engine capabilities, not primary/secondary benchmarks.
Owner clarification, 2026-11-07: an additional corpus should add a justified measurement beyond
the adopted ICFD scope. BothBosu is not selected because no such contribution was established.
SCAMBENCH is parked because the owner considers access approval unlikely; this is not evidence of
a confirmed rejection. Neither is part of the current executable measurement set. Preserve the
audit results, but do not continue execution merely because data were already inspected.
Assess each benchmark/task/metric by capability, allowed input/output, reference, baseline, conditions
and supported claim. The application observes conversations, but a relevant component capability may
have a separate benchmark. The mapping includes candidates; ICFD's adopted tasks are specified below:

| Selection criterion | Required interpretation |
|---|---|
| Defined relevant capability | Name the engine/component behavior. A task need not expose every engine weakness. |
| Task elicits the capability | Check simple baselines, shortcuts and alternative explanations. A long transcript alone is not a memory test. |
| Reference supports the task | Assess provenance and ambiguity against the native task. Human/model authorship alone does not establish validity. |
| Score is interpretable | State units, denominators, class effects and comparisons. A high majority-class score alone does not demonstrate discrimination; imbalance does not invalidate every task/metric. |
| Reproducible compatible protocol | Pin data, splits and scoring; disclose language, tools, resources, failures and adaptations. |

Access and cost govern execution feasibility, not capability validity. No universal cutoff or winning
margin is selected. Execution order is not a primary/secondary scientific hierarchy. Keep native
scores and additional diagnostics separate. Component benchmarks can test relevant language, context
or tool capabilities. Control other changing factors before attributing a workflow/agent difference
to control strategy. Do not invent a new task merely to justify retaining a dataset.

Methodological references: [CheckList](https://aclanthology.org/2020.acl-main.442/) organizes tests by
capability/behavior; [HELM](https://arxiv.org/abs/2211.09110) distinguishes scenarios and multiple
metrics. They support the approach, not this project's exact list or acceptance thresholds.

## Selected benchmark tasks, 2026-11-08

Assign specific tasks from measured evidence; do not invent roles to retain redundant datasets.
The external allocation was finalized first. The owner's subsequent conditional local-inclusion
instruction was assessed through the local audit below. The current allocation is four datasets
and six tasks, including two explicitly reference-based internal pilot tasks. Local inclusion does
not establish human-optimal warning timing, causal discrimination or benchmark novelty. This is
a task-selection decision, not model/run or implementation approval.

| Benchmark and specific task | Measured basis | Measurements and supported interpretation |
|---|---|---|
| ICFD static: complete transcript to fraud/normal decision | Test: 4,477 positive / 23 negative conversations; constant YES positive F1 99.74% | Confusion counts, both-class precision/recall/F1 and benign FPR against constant references; discrimination on this synthetic-call release |
| ICFD streaming: observed prefix to current YES/NO reference prediction | Test: 115,157 YES / 64,670 NO chunks; constant YES positive F1 78.08%; all labels match the native keyword/time rule | Classification against released prefix references, not validated earliest-warning recognition |
| BABILong QA2/QA3: narrative plus question to an answer requiring two/three supporting facts, with distracting text | Nine audited 100-record cells. At 16k, last-location accuracy: QA2 29%, QA3 15%; six-label uniform expectation 16.67%. Same-index verified short/long story pairs: QA2 100/100, QA3 86/100 | Accuracy by task and length with QA1/short-context controls and verified pairing; a declared context/QA component task, not a generic engine-memory score |
| PhishRewrite: separately classify original test email and its four rewrite levels, then compare fixed eligible parents with unchanged ham controls | 4,000 rewrites from 500 sources; four-level native intersections: 270 Claude / 308 Gemini parents. Test: 1,078 phishing / 4,563 ham; always ham accuracy 80.89% with zero phishing recall | Absolute recall/F1, benign FPR and paired changes; robustness on the specified English-email transformation/filter population |
| Local synthetic-v1: replay observed messages and score the first warning against the guide-defined evidence boundary | 125 scam / 125 benign; all 125 annotated-kind completion indices equal the reference; 754 pre-boundary scam prefixes, 727 at/after-boundary scam prefixes and 1,481 benign prefixes | Premature warnings, misses, exact-boundary detection and conditional delay, with benign false alarms; agreement of engine plus warning policy with this synthetic reference contract |
| Local synthetic-v1: jointly evaluate the declared scam/benign near-miss pair | 28 reciprocal opposite-class pairs; all share channel/message count, 16 share first message text/role, 25 share saved-contact status, 27 share the declared resemblance type | Pair succeeds only with a nonpremature scam warning and no benign warning; report delay separately. A joint paired diagnostic, not evidence of a single causal deciding feature |

**Selection from the measured structure:** use PhishRewrite for the rewrite-robustness task,
comparing each provider's native all-severity eligible parent set with itself and unchanged ham.
It supplies original test-source separation, substantial unchanged ham controls and
reproducible fixed-parent eligibility across four levels. Its URL filter remains a limitation:
all 4,000 flags reproduced, but 114 URL-pass variants lack literal normalized URL inclusion. It
does not semantically establish preservation of the malicious request. Preserve native versus
stricter adapted filters; native fixed-FPR points use the test-ham score distribution.

**PhishVN is not selected additionally:** it overlaps in rewrite robustness. Its 336 originals
(193 phishing / 143 benign) are ASCII-only; each 386-variant group shares 193/193 source IDs across
train/test roles. Length AUC is 0.786768 and both reviewers accept preservation on 44/50 reviewed
pairs. These measured limits do not establish a separate general-language task. Preserve the
candidate and evidence for a later justified Vietnamese-language replication; do not invent a
different purpose merely to retain both rewrite datasets. No original data are removed.

For BABILong, the QA evaluation must exercise a declared engine context-processing path; running
the base model alone measures that model. Specify the finite-answer interface and native parser.
Four of six deliberately selected public parser probes disagree with intended interpretation;
this is not a natural-output error-rate estimate. Full-context QA does not by itself prove
retention across engine updates or resistance to every reasoning shortcut.

Keep ICFD static/streaming units separate. Its native majority-filtered time metric excludes
1,809/4,476 source scams with chunks (40.42%) in test; do not treat it as coverage of all source
scams. Category transfer remains outside the adopted tasks. Report resource use on actual runs;
no combined score, cutoff, model, adapter or execution budget is selected by this mapping.

BothBosu remains unselected and SCAMBENCH parked. Local is now included for the two bounded
internal pilot tasks above, following the owner's conditional instruction and the completed audit
below. The selected external tasks supply neither guide-index first-warning scoring nor this
declared-pair joint score. This is complementarity within the reviewed set, not proof of novelty
or absence of comparable benchmarks elsewhere. The local access incident and semantic limits
remain disclosed; inclusion does not close them or authorize tuning on the test set.

### Local inclusion audit, 2026-11-08

Question: can the frozen local corpus add an interpretable task beyond the selected external
measurements? The supported claim is reference-based behavior on a constructed synthetic pool,
not an independently validated real-world warning boundary. Evidence: [aggregate results](audits/local-suitability-audit-2026-11-08/aggregate.json),
[audit script](audits/local-suitability-audit-2026-11-08/audit.py), [computational cross-checks](audits/local-suitability-audit-2026-11-08/verify.py)
and [check log](audits/local-suitability-audit-2026-11-08/checks.log).

| Measurement | Result | Consequence for task/interpretation |
|---|---|---|
| Frozen identity | All 21 managed SHA-256 entries match; all current record and scorer identities match | Use synthetic-v1 unchanged; this is not a new data version |
| Evidence-kind completion | All 125 scam reference indices match the earliest prefix containing annotated OTP-request evidence or annotated harmful-request plus illegitimacy kinds; 106 have additional later annotations | Later tagged evidence is not needed for this necessary-kind reconstruction. It does not prove tag correctness, common-scheme linkage, completeness or lack of annotator hindsight |
| Prefix conflicts | 2,962 prefixes; zero conflicting reference groups for either full allowed input or normalized message text | No measured deterministic contradiction on identical observed input; this does not semantically validate the references |
| Reference boundary distribution | 13/125 at the first message, 11/125 at the last; median index 5, range 0–28 | The task has both pre-reference and post-reference observations; do not equate message delay to wall-clock delay |
| Pair structure | 28 reciprocal opposite-class pairs; channel/length match 28/28; opening text/role 16/28, saved contact 25/28, resemblance type 27/28; shared opening median one message; zero shared openings extend through the scam boundary | Score the declared 28 pairs, disclose covariates/type mismatch. Do not describe them as strict minimal edits or infer causal evidence recognition from paired success |
| Surface associations | Message-count AUC 0.5000; total-character AUC 0.541632; digit-share AUC 0.714912; saved-contact AUC 0.3160 with larger values meaning scam | Balanced length does not remove all correlations. Some features may also reflect legitimate task information; association alone is not proof of a shortcut |
| Train-only surface threshold diagnostic | Five folds keeping shared seeds and pair links together, 115 connected groups; accuracy 157/250 (62.8%), scam recall 96/125, benign false alarms 64/125; only 5/28 pairs both classified correctly | Surface cues predict some class membership but do not explain all pair success. One grouped split and one-threshold rule do not exclude richer shortcuts. No threshold or learned rule is transferred to engine development |
| Constant warning controls | Never warn: 100% misses. Warn immediately: 89.6% premature warnings and 100% benign false alarms. Warn at the final message: 100% benign false alarms and median delay four messages. All three achieve zero paired successes | The timing, false-alarm and pair measures expose different trivial policies; do not collapse them into one favorable score |
| Gold-informed scorer control | 125/125 exact boundaries, 28/28 pair successes; missing output withholds metrics; nine existing public scorer tests pass | Scorer arithmetic and failure handling work; an oracle is not detector performance |
| Current-input review reconciliation | All 250 final inputs have hash-matched review rows; all labels and 125 scam indices match final gold | Final gold incorporates review/adjudication, so this is traceability and reconciliation, not a fresh independent agreement estimate |

The extra computations do **not** measure hindsight bias. No new blinded prefix-only semantic
annotations were produced. Existing reviews saw full conversations, most share the generator
family, and the conditional human spot check remains unavailable. Initial historical agreement
247/250 and kappa 0.976 must not be presented as a fresh result on the final version. Pair lexical
similarity does not establish semantic matching. The two tasks therefore retain the explicit
synthetic-reference and declared-pair scope; stronger claims remain unsupported.

**Decision:** include local synthetic-v1 as an internal pilot for these two bounded tasks. Its
fixed references, current review identities, consistent index construction, nontrivial policy
controls and deterministic scorer support reporting agreement with the declared contract.
The measurements do not justify interpreting those scores as human-optimal intervention timing,
real-world scam competence or causal use of the deciding difference. Scores concern engine plus
the declared warning policy. No fresh labeling, frozen edits or actual detector run occurred.

Current formal reproduction, from the repository root (operational bounds):

```sh
timeout 90s env PYTHONPATH=src python3 -m safeguard.evaluation.audits.local.audit
timeout 90s env PYTHONPATH=src python3 -m safeguard.evaluation.audits.local.verify
```

## Capability-directed follow-up search, 2026-11-07

The owner requested this search after restating the engine's target capabilities. The working question
is what adds evidence beyond ICFD's adopted conversation/prefix classification tasks. Search terms
included conversational fraud with earliest evidence/turn annotations, matched or counterfactual benign
controls, Vietnamese phishing, and distributed-fact long-context reasoning. Primary papers, official
repositories and publisher/archive APIs were checked; no test records, model predictions or per-case
judgments were inspected. All candidate counts below are author-reported or metadata counts, not
an independent corpus scan. No new benchmark is adopted and no new detector experiment was run.

| Engine capability sought | Useful candidate and native measurement | Verified access and limit | Proposed disposition |
|---|---|---|---|
| Join evidence distributed through context | BABILong QA2/QA3 accuracy, with QA1 retrieval and short-context controls | Ungated official HF release and deterministic scorer inspected; English synthetic narrative QA | Audit as a component benchmark, conditional on identifying the engine context/QA boundary |
| Native Vietnamese message discrimination and rewrite robustness | PhishVN content-study original versus rewritten phishing/benign classification | Open Zenodo v1.1.0 files and CC BY 4.0 metadata verified; messages are entirely synthetic | Inspect the message/rewrite protocol before adoption; exclude webpage classification from this scope |
| Rewrite robustness on another source distribution | PhishRewrite severity curves and detection at a fixed benign FPR | Open Zenodo archive now verified through API; English email, not dialogue | Available alternative to investigate; do not automatically add alongside another rewrite benchmark |
| Warning at deciding evidence; matched benign counterexamples | No ready external benchmark established in this search | PreScam targets progression; FedHeartShield is explicitly not a detection-effectiveness benchmark | Keep the gap open rather than invent references or count unavailable full data as runnable |

### BABILong: combine facts amid distracting context

The [NeurIPS 2024 paper](https://proceedings.neurips.cc/paper_files/paper/2024/hash/c0d62e70dbc659cc9bd44cbcf1cb652f-Abstract-Datasets_and_Benchmarks_Track.html)
and [author methods](https://arxiv.org/html/2406.10149v2) describe synthetic bAbI reasoning facts
interleaved with PG-19 book text. QA1 needs one supporting fact; QA2 and QA3 need two and three.
The same task families have no-background and longer-context variants. The useful question here
is whether a context-processing component preserves and combines the needed facts despite
irrelevant material, rather than merely accepting a long string.

The [official repository](https://github.com/booydar/babilong) publishes 100- and 1,000-sample
evaluation releases, with sample count per task/length and distinct training data. Anonymous API
inspection of `RMT-team/babilong` returned `gated: false`, revision
`ee0d588794c7ac098062ee0d247c733d62e94fe2` and 137 listed files. Source rows were not downloaded
or counted. Metadata confirms QA1/QA2/QA3 length files; choose and pin a specific release and cell
before a run. Counts from different release sizes must not be pooled. The repository tree observed
was `7a6efee29f5cac03c3c410e6799c80fd2ffe3610` (tree identity, not a commit hash).

The inspected [native scorer](https://github.com/booydar/babilong/blob/main/babilong/metrics.py)
normalizes model output, extracts task-vocabulary labels, excludes labels mentioned in the question,
and checks the remaining prediction against the target. Accuracy aggregates those Boolean outcomes;
this is deterministic parsing, not LLM-judge grading or unrestricted exact-string matching. A scorer
audit still needs to check its parsing behavior before execution. The paper/repository state Apache
2.0 for code and PG-19, and BSD for bAbI; the HF metadata did not provide a separate license field.

**Supported claim and boundary:** performance on a distributed-fact QA component task. Report QA2/
QA3 separately and interpret long-context performance alongside short-context and QA1 controls.
Do not import the paper's 85% satisfactory-performance heuristic as an owner acceptance threshold.
These variants are not necessarily identical paired instances; exact pairing needs verification.
The task is not conversational scam detection, Vietnamese understanding, a gold first-warning time
or proof of persistent memory across engine updates. The current detector interface does not answer
arbitrary QA, so an eventual context-component evaluation requires an explicit QA adapter; no adapter,
model or run is selected by this search. Feeding full narratives to a base model would establish that
model's score, not automatically the engine's memory quality.

### PhishVN content study: Vietnamese messages and paraphrase robustness

The [Zenodo v1.1.0 release](https://zenodo.org/records/23634300), DOI
`10.5281/zenodo.23634300`, is distinct from the larger PhishVN URL-table release and from the
unrelated `wikiepeidia/vnphish-dataset`. Its public API returned HTTP 200, `access_right: open`,
CC BY 4.0 and ten files. The [release README](https://zenodo.org/records/23634300/files/README.md?download=1)
was retrieved and read without retrieving message rows. It reports:

| Released part | Author-reported scale and role |
|---|---|
| Original text messages | 209 SMS plus 127 emails: 193 phishing and 143 benign total |
| Uncontrolled paraphrases | 386 variants, two per phishing source; `a` is used for training and `b` for attack in the study |
| Similarity-banded paraphrases | Another 386 variants with token Jaccard similarity in [0.20, 0.30] |
| Human rewrite review | Two annotators rate 50 source/rewrite pairs for preserved meaning, usability and persuasion |
| Separate webpage task | 1,919 Vietnamese-content webpages; outside the selected message-analysis question |

Both original message classes were written by one LLM under different instructions; they are not
real traffic or fully human-labeled data. All message links use the same inert placeholder. Thus
the message task can investigate text classification and transformation effects without live URL
verification, but cannot establish URL-analysis skill. The README's generator identifier is an
author-reported string; its provider identity/inference provenance was not independently verified.
The 50-pair human review is partial and its aggregate outcomes have not been audited here.

Potential measurement: classify original Vietnamese phishing versus benign texts, then evaluate
the released rewrites while retaining benign controls and source identities. Report recall/F1 and
benign false alarms; compare original-to-rewrite changes, not degradation alone. These are proposed
classification diagnostics pending verification of the native split, thresholds and transformation
validity. Lexical Jaccard similarity controls word overlap, not semantic preservation or equivalent
attack strength. Prevent variants of the same source from becoming an undisclosed train/test shortcut;
the author's `a`/`b` assignment is not proof of source-disjoint generalization. The same-model/different-
prompt generation may leave style cues, which have not been measured here.

The referenced reconstruction notebook is named in the README, but the current GitHub tree endpoint
for `vuthainguyen1602/phishvn` returned 404. Therefore data access is verified, while end-to-end
code reproduction and the exact native scoring contract are not. The correct next step is a bounded
protocol/data audit, not a claim that these small synthetic sets prove real-world Vietnamese fraud
detection, near-miss discrimination, conversation memory or evidence-relative warning timing.

### Other findings and exclusions from this follow-up

- **PhishRewrite access correction:** anonymous [Zenodo API metadata](https://zenodo.org/api/records/21018700)
  now returned HTTP 200, `access_right: open`, CC BY 4.0 and `phishrewrite-benchmark-v1.0.zip`
  (21,371,735 bytes). The archive description reports 28,201 source emails and 4,000 LLM rewrites.
  Earlier web-tool failure was not an access-gate finding. Archive bytes and per-record integrity
  remain unchecked; its detailed methods and upstream-term limits are retained below.
- **VNPhish (`wikiepeidia`)**: [official card](https://huggingface.co/datasets/wikiepeidia/vnphish-dataset)
  reports 2,097 synthetic Vietnamese messages, including a 220-message test, four labels, seed-group
  separation, and labels assigned through generation. It also discloses only 1,395/2,097 passing all
  judge checks, with failing records retained, and a one-reviewer 100-case check. Anonymous metadata
  confirms no gate at revision `06412ab3d6104d70eca6a692526ca57ec113a3f3`, seven files and CC BY-NC
  4.0. Do not treat availability, model agreement or generated evidence spans as validated human
  references. Label-quality findings remain unresolved; it is not currently recommended for adoption.
- **Vietnamese SMS 300-sample release**: the [author card](https://huggingface.co/datasets/trannguyenthaituan/vietnamese_sms_phishing_sample/raw/main/README.md)
  still defines HAM versus SPAM/phishing. It does not resolve the existing full dataset's merged
  spam/scam target. The card's listed sample columns also do not establish an available scoring
  reference. A new sample release alone does not establish pure fraud-detection suitability.
- **FedHeartShield**: [Zenodo metadata](https://zenodo.org/api/records/20740263) describe 404 synthetic
  conversations with matched/counterfactual benign controls, but only ten bounded examples are open
  and full dialogues require a request. The retrieved primary
  [separability disclosure](https://zenodo.org/records/20740263/files/SEPARABILITY.md?download=1)
  explicitly states development-only, not a detection benchmark. It reports style-only held-out
  AUC 0.836 after contamination purging and stronger separation with other probes, including early
  turns. Do not adopt it as scam-detection evidence despite superficially relevant temporal/control
  annotations. These are author-reported diagnostics, not this project's independent measurement.
- **PreScam, ConScamBench and ViScamDial** retain their task/access limits below. Their presence in
  search results did not establish a newly available, unrestricted first-warning/near-miss benchmark.

**Search outcome:** two useful audit directions are a context-component benchmark (BABILong) and
an openly released Vietnamese message/rewrite study (PhishVN content study). PhishRewrite is an
accessible alternative for English email rewrite robustness. No external benchmark meeting the
exact evidence-relative warning-time plus matched-benign requirement was established by this
bounded search. This is not a proof of nonexistence or automatic justification for new data generation.

## Measured capability audit, 2026-11-07

The owner requested numerical evidence for what each candidate can measure and why that matters
to the engine. This CPU/data/scoring audit supersedes the earlier unmeasured readiness statements
in the search section. Twenty fixed inputs (45,283,043 bytes) were retrieved, each with a durable
size/hash checkpoint; Zenodo publisher checksums were verified. The PhishRewrite archive CRC was
checked in full. Additional public method code was inspected at commit
`e840fa3be67661d8857a5ac60af0dda851c8a331`. Individual records and judgments stayed outside the
development LLM context. No model, engine, synthetic generation or semantic relabeling was run.

Reproduction assets: [release lock](audits/capability-audit-2026-11-07/release-lock.json),
[retrieval](audits/capability-audit-2026-11-07/retrieve.py),
[analysis](audits/capability-audit-2026-11-07/analyze.py),
[independent verification](audits/capability-audit-2026-11-07/verify.py), and
[check results](audits/capability-audit-2026-11-07/checks.log).
Raw inputs stay under ignored `.audit-private/capability-audit-2026-11-07/`; aggregate outputs bind
the lock, analysis script and method-source hashes. ICFD's original frozen audit was not edited.

**Confidence boundary, clarified 2026-11-08:** the completed work establishes reproducible numerical
properties and a conditional task-fit assessment. It is not full construct validation: the audit has
not established that a score uniquely reflects the intended capability rather than other cues.
Here, "independent verification" means alternative calculations/public-fixture checks in a second
script written by the same assistant; it does not mean an independent research team or a new human
annotation review. Semantic label validity, comprehensive shortcut tests, sensitivity to changes in
deciding evidence, and the bridge from a QA component task to this engine remain unestablished.
The bounded audit can be complete without full construct validation. The subsequent task allocation
is finalized in Selected benchmark tasks; it does not turn the unchecked properties into verified
ones. ICFD's two tasks retain their recorded scope and limits. On 2026-11-08, all 25 frozen evidence-file hashes and all 20 fixed-input
hashes/sizes were rechecked unchanged; no new model or engine evidence was generated.

| Measurement question | Numerically supported assessment | Engine relevance and boundary |
|---|---|---|
| Can a context component answer using distributed facts despite distractors? | BABILong has reproducible short/long task cells, nontrivial rule baselines and deterministic references; conditional fit | Relevant to context construction/retrieval/retained facts, after a declared QA interface; not a direct scam or persistent-memory score |
| Does detection survive rewriting of these fixed Vietnamese-language source messages? | PhishVN has complete source/variant links and a checked lexical transformation band; conditional fit | Tests a small synthetic ASCII message distribution. It does not establish accented Vietnamese, real traffic, unseen-source transfer or validated first-warning timing |
| Does detection survive English-email rewrites satisfying the native retention filter? | PhishRewrite's native URL flags and fixed-parent intersections reproduced; conditional fit | Tests transformation robustness under a specified filter, not semantic preservation of every scam or changed malicious destinations |
| Can the engine classify complete/prefix synthetic calls? | ICFD's existing numerical references remain verified, with task-specific class/reference limits | The two adopted tasks remain as scoped; accuracy/positive F1 alone do not establish discrimination and native time metrics do not cover all source scams |

### BABILong measurements and claim limits

[Aggregate evidence](audits/capability-audit-2026-11-07/babilong.json): QA1/QA2/QA3 at 0k, 4k and 16k,
100 records per cell, 900 file records total. All have nonempty input/question/target, no exact
duplicate full records within a cell, and 100% native-score acceptance of the target itself.
The target vocabulary has six locations; uniform guessing has expected accuracy 16.67%.
The most frequent target accounts for 20–23% depending on cell. These are arithmetic references,
not detector measurements or task acceptance thresholds.

| Native task | Last-location rule, 0k | 4k | 16k | What the control tests |
|---|---:|---:|---:|---|
| QA1: one supporting fact | 53% | 47% | 37% | Retrieval/recency reference |
| QA2: two supporting facts | 36% | 30% | 29% | Joining information beyond a simple recency rule |
| QA3: three supporting facts | 15% | 14% | 15% | More complex dependency; the simple rule does not solve it |

The fixed rule returns the last task-vocabulary location in the narrative; it does not inspect the
question semantically. These results rule out that particular shortcut as a complete solution;
they do not prove that every possible shortcut fails or that a model must reason in a specific way.

Ordered sentence matching verifies the same source story/question/target at the same row across
0k-to-4k and 0k-to-16k for 100/100 QA1 and 100/100 QA2 records, but 86/100 QA3 records. Thus QA1/QA2
permit a checked paired length comparison on this release; do not silently treat all 100 QA3 rows
as identical paired stories. A global search identifies 92 uniquely matching QA2 short stories in
each long cell; none of their 16k versions retains every short-story sentence in a last-1,024-word
window. This is coverage of all story sentences, not proof that minimal deciding evidence is absent
or that a suffix-based engine necessarily fails. Words are not model tokens.

Four of six constructed public parser probes disagree with the intended answer interpretation.
Examples: with toy target `office`, native scoring accepts `not office` and `officer`; it also
ignores a contradiction after a period. These are deliberately chosen parser probes, not a 66.7%
error estimate on natural model outputs. A canonical one-label response interface avoids these
particular explanation-format traps; report native and any stricter diagnostic scoring separately.

**Conclusion:** useful candidate for asking whether a context component preserves and combines
facts as irrelevant context grows. A model or engine-component run is still required to measure
that capability. The detector currently has no QA adapter, so adoption/execution needs an explicit
component boundary. This audit does not show that the engine has memory, handles Vietnamese or
detects scams, nor that the benchmark exhaustively isolates semantic reasoning.

### PhishVN content-study measurements and claim limits

[Aggregate evidence](audits/capability-audit-2026-11-07/phishvn.json): 336 originals, 193 phishing and
143 benign; 209 SMS and 127 emails. No empty text, normalized duplicate originals or conflicting
normalized original labels were found. Both labels occur in all seven scenario categories. This
helps avoid the fully disjoint-topic construction observed in BothBosu, but it is not evidence of
matched counterfactual pairs. All 336 original texts are ASCII-only despite `lang=vi` metadata;
the data do not test accented Vietnamese orthography. This is not a claim that ASCII text cannot
be Vietnamese; full semantic language validation was not performed.

Length alone has in-corpus ROC-AUC **0.786768** (median 23 word tokens for phishing, 18 for benign).
This is a structural correlation and an in-corpus ranking diagnostic, not 78.68% classification
accuracy or held-out detector quality. Always predicting phishing gives accuracy 57.44%, positive
F1 72.97%, recall 100% and FPR 100%. `gen_model`, `source` and `label_source` each have pure class
groups, giving an in-sample metadata lookup 100% accuracy. These fields must not enter detector
input; their association is not proof that an actual detector saw them.

Each rewrite file contains 386 nonempty variants linked to all 193 phishing originals, exactly
two per source. There are no normalized unchanged rewrites or duplicate rewrite texts within either
file. All originals are marked `train`; each rewrite file has 193 `train` variants and 193 `test`
variants with **193/193 shared source IDs**, and every test variant's original is marked train.
This supports a seen-source transformation experiment, not an unseen-source generalization claim.
It is not automatically an invalid robustness protocol: for an untuned engine, the entire fixed
release could be treated as evaluation data under a declared protocol. The current labels do not
by themselves supply an independent development/evaluation split for that use.

The banded file's stored Jaccard values are all in [0.20, 0.30]. A reconstructed calculation
(lowercase, remove HTTP(S) URLs, then whitespace-token sets) matches **386/386** within four-decimal
rounding. A Unicode-word tokenizer gives different values; this is tokenization sensitivity, not
evidence that the declared band is violated. Jaccard controls lexical overlap, not equivalent intent
or human-perceived difficulty. Every original's URL field has the same value, so URL metadata alone
does not distinguish the classes or measure live-link verification.

| Human-review question, 50 pairs | Agreement | Cohen's kappa | Supported interpretation |
|---|---:|---:|---|
| Meaning preserved? | 49/50 = 98% | 0.000 | Mostly positive judgments; one rater always says yes, so agreement is not evidence of strong chance-corrected reliability |
| Lure remains intact? | 45/50 = 90% | -0.033 | Positive-skewed and a small sample; preserve disagreements |
| Which version is more persuasive? | 16/50 = 32% | 0.014 | Does not support reliable persuasion-strength ordering |

Both raters accept meaning and lure preservation for **44/50** pairs; all 50 source/rewrite texts
were linked back to the released files. This validates only the scope of those recorded judgments,
not all 772 rewrites or the originals' binary labels. The pair file contains 300 empty rating cells
as a template; the separate completed ratings file supplies the judgments. Nonempty shared fields
have zero conflicts. The initial raw equality diagnostic was therefore a template/completed-file
distinction, not a conflicting-annotation finding.

**Conclusion:** conditional use for classification/robustness on these fixed synthetic, unaccented
Vietnamese-language messages, with actual false alarms and length references visible. It cannot
establish real traffic quality, accented-language coverage, stronger human persuasion, unseen-source
transfer, matched scam/benign near-miss skill or evidence-relative warning timing. A source-group
holdout would be a new disclosed protocol, not an original-release result. No automatic relabeling,
filtering or regeneration was performed.

### PhishRewrite measurements and claim limits

[Aggregate evidence](audits/capability-audit-2026-11-07/phishrewrite.json): the complete archive has 28,201
source emails and 4,000 rewrites. Original train/test counts are 22,560/5,641. The test has 1,078
phishing and 4,563 ham emails, with zero normalized test-text overlaps with train and no normalized
duplicate/conflicting test texts. Length-only test AUC is **0.517076**; this weak length correlate
does not rule out source/style shortcuts. Source metadata alone maps perfectly to labels because
positives come from Nazario and negatives from the two ham corpora; exclude it from model input.
Always predicting ham gives **80.89% accuracy and 0% scam recall**. Always phishing gives 19.11%
accuracy, 32.09% positive F1 and 100% FPR. Accuracy alone is insufficient here.

Every rewrite joins uniquely through `emails.original_id` to an original test phishing email;
joining to `emails.id` matches 0/4,000. There are 500 unique source emails across both providers,
not 4,000 independent scam cases. Each provider has four severity variants for every source.

| Native filter across all four severities | Claude/Anthropic | Gemini |
|---|---:|---:|
| Candidate source emails | 500 | 500 |
| All-severity strict URL retention, non-refusal, nonempty | 270 (54.0%) | 308 (61.6%) |
| Primary-URL variant with the same conditions | 331 (66.2%) | 345 (69.0%) |

Each provider has 106/500 sources with null strict-URL checks at each severity, excluded from the
native headline set. Refusal counts across severities are 3/3/3/28 for Claude and 2/1/0/0 for Gemini;
there is one empty highest-severity Gemini text. Fixed-parent intersections make a paired severity
comparison possible; using different passing sources at each severity would change the denominator.
The two providers' intersection populations also differ and must not be treated as the same cases.

The native checker was reproduced through both a reconstruction and the inspected pure original
functions: **0/4,000 disagreements** with released URL flags. However, it permits substring matches
in either direction. **114 URL-pass variants** lack literal inclusion of all normalized source URLs.
Two of four public checker probes accept a dropped path or changed hostname suffix despite the
probe's intended identical-URL requirement. These do not establish 114 changed malicious destinations
or 114 wrong scam labels; they establish that native URL retention is weaker than verbatim URL
preservation. The earlier independent strict regex disagreed on 299/3,152 comparable cases; native
reproduction resolves this as a checker-definition difference, not an upstream label-error count.

The filter does not semantically verify preservation of the malicious request, and no human semantic
reference table or detector-score table is included in the archive. The native fixed-1%-FPR method
sets the cutoff from the same test-ham score distribution. That is an empirical ROC operating-point
comparison, not proof of deployment FPR at a threshold fixed on independent calibration data.
Do not repeat the source document's claim that class imbalance itself dominates ROC-AUC: uniformly
duplicating a class does not alter the ROC pair-ranking probability. Recall at a fixed threshold,
PR metrics, calibration and ROC-AUC answer different questions.

**Conclusion:** conditional candidate for asking how classification changes under these particular
English email rewrites that pass a declared retention filter. It is more structured than an arbitrary
collection of paraphrases, but is not validated evidence of semantic-preserving evasion, Vietnamese
performance or conversational timing. Preserve the native filter and disclose stricter diagnostics;
changing the eligibility filter creates an adapted evaluation population.

### ICFD reassessment under the same capability questions

[Current audit cross-check](audits/capability-audit-2026-11-07/icfd.json) verifies all 55 earlier snapshot
hashes unchanged and recomputes the class/denominator references. The earlier direct-shard pass
already checked 83 data files and counted all 31,000 conversations/1,111,071 chunks; those unchanged
measurements were reused, not presented as a new detector experiment.

| Intended question | Quantified evidence | Claim retained or limited |
|---|---|---|
| Complete-call classification | Static test: 4,477 YES / 23 NO; constant YES accuracy 99.49%, positive F1 99.74%, balanced accuracy 50%; one benign error changes FPR by 4.35 points | Retain the adopted synthetic-call task, with both-class metrics/reference comparisons; high accuracy/F1 alone does not show discrimination |
| Prefix classification | Test: 115,157 YES / 64,670 NO; constant YES positive F1 78.08%; every released chunk label matches the keyword/time rule | Retain native reference classification; do not present it as independently validated evidence-relative first-warning recognition |
| Native early-detection coverage | Majority filter omits 1,809/4,476 source scams with chunks (40.42%) on this release | Not a detection-rate/delay estimate covering all source scams; published historical split identity remains separate |
| Context memory, Vietnamese or near-miss skill | These measurements contain no controlled proof of those capabilities; language is English/Hinglish and no matched-benign timing contract was verified | Do not attribute them from the two adopted classification scores |

The prior 626 test conflicting-prefix groups and 846-error bound remain scoped to stateless,
deterministic text-only prefix classification without clock input. They are not an error bound for
every stateful engine. No new adoption, threshold, model or warning-policy decision follows from
this reassessment; it preserves the owner's two ICFD tasks with the measured limits.

Offline reproduction (deadlines are operational bounds, not runtime estimates):

```sh
timeout 240s env PYTHONPATH=src python3 -m safeguard.evaluation.audits.capability.analyze
timeout 120s env PYTHONPATH=src python3 -m safeguard.evaluation.audits.capability.verify
```

These commands require the current run's completed ICFD scan/derivations and all pinned canonical
inputs. The full controller above establishes that order. Historical retrieval scripts retain
their original layout assumptions; the migrated audit command does not retrieve missing files.
Passing mechanical checks verifies this audit's calculations, not full semantic reference validity
or actual engine capability. Those remaining limits are part of the result, not silently passed checks.

## Candidate tasks and evidence

### ICFD-31k: assess native tasks separately

**Owner decision, 2026-11-07:** adopt full-conversation classification and cumulative-prefix
classification against the pinned release's references. Preserve the classification metrics and
the class-sensitive interpretation below. This is not adoption of a validated first-warning-time
standard or the native majority-filtered early-detection rate. Category-transfer adoption remains
open. Model, run budget, thresholds and comparison conditions are not selected by this decision.

Native tasks are full-call classification, cumulative three-second classification and category holdout.
The [paper, Section 5](https://ijcai.org/proceedings/2026/786) uses those tasks to test in-domain
classification, decisions with incomplete information, and transfer to held-out scam types. It also
reports first-detection time/rate. These are conversational-fraud measurements, not general agent
intelligence or a demonstration of every engine capability.
The [dataset card](https://github.com/SPELLAILab/ICFD-31k/blob/main/DATASET_CARD.md) describes 31,000
synthetic English/Hinglish conversations and 1,111,071 chunks: 21,000 train, 4,500 validation, 4,500 test,
and 1,000 cross-domain conversations. Chunks inherit conversation splits. A detector must receive the
observed transcript, excluding generation context, rationales and verdict fields.

The [release tree](https://huggingface.co/datasets/rishia2220/icfd-31k/tree/main) lists source shards,
streaming shards, a manifest and checksums. [Data access documentation](https://github.com/SPELLAILab/ICFD-31k/blob/main/DATA_ACCESS.md)
describes JSONL/Zstandard and Parquet. [Data terms](https://github.com/SPELLAILab/ICFD-31k/blob/main/LICENSE-DATA.md)
allow defensive academic benchmarking and require separate permission for commercial deployment.

The [paper](https://ijcai.org/proceedings/2026/786) reports precision/recall/F1, streaming results and
detection-time measures. Use native classification first; separate chunk metrics from conversation
false alarms. Synthetic timestamps do not measure real application latency, and prefix labels are not
automatically equivalent to a human-validated earliest-warning boundary.

There is a concrete reproducibility question. The [baseline README](https://raw.githubusercontent.com/SPELLAILab/ICFD-31k/main/baselines/README.md)
reports 24,800 static training conversations and 129,116 streaming test chunks, whereas the dataset
card specifies 21,000 and 179,827. Static F1 also differs between the baseline README and paper.
This may reflect different versions, but the relationship is not established. The
[reproducibility guide](https://github.com/SPELLAILab/ICFD-31k/blob/main/REPRODUCIBILITY.md) points to
baseline scripts; their execution has not been verified. Resolve split/version identities before
treating a published score as directly comparable. The repository also reports only moderate human
agreement, mean pairwise kappa 0.534, in its [overview](https://github.com/SPELLAILab/ICFD-31k).

The original audit's primary-benchmark rejection framing is superseded. Classification, incremental
classification and category transfer are separate measurements. The numerical reassessment below
uses pinned artifacts, not recollection of the audit or a new detector result.

#### Numerical reassessment, 2026-11-07

A direct-shard pass reverified all 83 byte counts/checksums and the unchanged 55-file audit snapshot,
recounted labels in all 31,000 sources and 1,111,071 chunks, and independently cross-checked the
streaming-test prefix conflicts. These recounts match the original aggregate artifacts.

| Native task and split | Reference unit | YES | NO |
|---|---|---:|---:|
| Static test | Complete conversation | 4,477 | 23 |
| Streaming test | Cumulative chunk | 115,157 | 64,670 |
| Static cross-domain | Complete conversation | 961 | 39 |
| Streaming cross-domain | Cumulative chunk | 27,919 | 17,196 |

**Do not apply static-test imbalance to streaming metrics.** NO chunks include early prefixes of
eventual scams; they are not a count of benign conversations. The constant-YES references below
are arithmetic from labels, not model inference or a tuned baseline. Their false-positive rate
against the negative reference units is 100%.

| Task and split | Constant-YES accuracy | Positive-class F1 | Macro-F1 | Balanced accuracy |
|---|---:|---:|---:|---:|
| Static test | 99.49% | 99.74% | 49.87% | 50.00% |
| Streaming test | 64.04% | 78.08% | 39.04% | 50.00% |
| Static cross-domain | 96.10% | 98.01% | 49.01% | 50.00% |
| Streaming cross-domain | 61.88% | 76.45% | 38.23% | 50.00% |

For P positive and N negative units, constant-YES accuracy is P/(P+N), positive F1 is 2P/(2P+N),
macro-F1 is P/(2P+N), and balanced accuracy is (1+0)/2. Macro-F1 averages the two class F1 values;
balanced accuracy averages their recalls. These additional diagnostics are proposals for interpreting
scores, not a silent replacement of the native metric or an adopted experiment protocol.

One additional false alarm changes static-test conversation FPR by 4.35 percentage points with its
23 benign cases. The 39 cross-domain benign cases give a 2.56-point step. This limits those estimates
without making every classification measurement unusable.

The 1,942 conflicting-prefix conversations in the original audit cover all splits. The streaming
test alone has 626 such conversations/groups. Summing min(YES, NO) within those identical-observation
groups gives at least 846 errors out of 179,827 chunks, or 0.47045%. The accuracy ceiling from these
groups is 99.52955%; this is not evidence that most streaming labels conflict. The bound applies to
a stateless deterministic prefix-text classifier without current-clock input, like the inspected
baseline formatter. It is not a ceiling for every engine with state or timing inputs.

All released chunk labels still match the keyword/time rule. That establishes reference construction,
not semantic correctness or an independently validated earliest-warning standard. It does not alone
prove that the native prefix-classification task measures no useful behavior.

| Intended capability | Assessment supported by numbers |
|---|---|
| Discriminate scam/normal on complete synthetic calls | Adopted with limits. Raw accuracy/positive F1 alone are weak evidence on this split. Preserve native scores, compare constant references and report both classes with uncertainty. Semantic reference quality remains unvalidated here. |
| Classify an ongoing call from observed prefixes | Adopted native task with limits. Class distribution differs from static test, and the quantified text-only conflict bound is limited. Report performance against these heuristic references; do not equate it with validated earliest evidence recognition or general contextual reasoning. |
| Transfer to the release's held-out category groups | Conditional candidate. Domain metadata are disjoint; semantic category novelty and exact published baseline split identity remain unestablished. Static and streaming transfer require their respective baselines above, not one shared class-prior argument. |

The stored published streaming result concerns 129,116 chunks, whereas the release test has 179,827.
Do not directly compare its F1 with these new constant references as if the data were identical.
No engine performance, winning margin or detector run is claimed. The task-adoption decision above
does not establish baseline reproduction or resolve the published split identity.

#### Direct implications for the authors' intended measurements

The native early-detection code selects fraud sessions by majority of chunk reference labels, rather
than by the source conversation verdict. A fresh read-only query on the pinned test gives 4,477
source-labeled scam conversations, of which 4,476 have chunks. Majority selection includes 2,667
and excludes 1,809, or 40.42% of the source-labeled scams with chunks. Thus that metric would not
measure detection of all source-labeled scams on this release. A late-emerging scam can be excluded
because its earlier NO prefixes outnumber its later YES prefixes. This is an audit of applying the
code to the current release, not proof that the historical published run omitted that same fraction.

The two annotation layers disagree at 5,774 of 51,674 comparable timestamps (11.17%). Neither layer
was independently adjudicated in this audit. This bounds confidence in treating the released time
labels as a verified fraud-onset standard; it does not establish that every disagreeing item is wrong.

Even a constant-YES classifier's static F1 drops 1.73257 percentage points between the released
in-domain and cross-domain tests, from 99.74379% to 98.01122%, solely because the class counts change.
A measured transfer gap therefore needs per-class/reference comparisons before attribution to novel
scam semantics. Do not subtract this gap from the paper's reported gap: split identities differ.

Current decision by capability: complete-call discrimination and prefix classification are adopted
with native scores, constant references and explicit label-quality limits. Category transfer remains
conditional on the category definition and split mapping, without adoption. Do not currently
use the native majority-based early-detection rate/mean time as proof of detecting all scams promptly.
If replacing its denominator with source verdicts or adding other metrics, name the adaptation and
report native versus adapted results separately. No engine execution is authorized by this advice.

The read-only code below reproduces the table and conflict calculation from the checkpoint whose
counts were independently checked against the raw shards. It prints no conversations or case IDs
and creates no files.

<!-- icfd-numeric-recompute -->
```python
from pathlib import Path
import hashlib, json, sqlite3
root = Path('evaluation/audits/icfd-31k-audit-2026-11-07')
evidence = json.loads((root / 'execution-evidence.json').read_text())
assert all(hashlib.sha256((root / p).read_bytes()).hexdigest() == h
           for p, h in evidence['artifact_sha256'].items())
report = json.loads((root / 'data-audit.json').read_text())
db = sqlite3.connect(Path(report['private_checkpoint_db']).resolve().as_uri()
                     + '?mode=ro', uri=True)
assert db.execute('SELECT count(*) FROM sources').fetchone()[0] == 31000
assert db.execute('SELECT count(*) FROM chunks').fetchone()[0] == 1111071
rows = []
for task in ('static', 'streaming'):
    for split in ('test', 'cross_domain'):
        query = ("SELECT json_extract(payload,'$.final_verdict'),count(*) "
                 "FROM sources WHERE split=? GROUP BY 1") if task == 'static' else (
                 'SELECT label,count(*) FROM chunks WHERE split=? GROUP BY label')
        counts = dict(db.execute(query, (split,)))
        pos, neg = counts['YES'], counts['NO']
        assert counts == report['aggregate'][task][split]['labels']
        rows.append({'task': task, 'split': split, 'positive': pos, 'negative': neg,
                     'constant_yes_accuracy': pos / (pos + neg),
                     'constant_yes_positive_f1': 2 * pos / (2 * pos + neg),
                     'constant_yes_macro_f1': pos / (2 * pos + neg),
                     'constant_yes_balanced_accuracy': 0.5})
groups = db.execute("""SELECT count(DISTINCT uid),count(*),sum(min(y,n)) FROM
    (SELECT uid,prefix_digest,sum(label='YES') AS y,sum(label='NO') AS n
     FROM chunks WHERE split='test' GROUP BY uid,prefix_digest
     HAVING count(DISTINCT label)>1)""").fetchone()
assert groups == (626, 626, 846)
print(json.dumps({'constant_references': rows, 'text_only_conflict_groups': groups,
                  'minimum_error_share': groups[2] / 179827,
                  'accuracy_upper_bound_from_these_groups': 1 - groups[2] / 179827}, indent=2))
```

### LoveFraud02: real-chat scam recall

The [version 1 release](https://data.mendeley.com/datasets/kmhvb4x5d8/1), DOI 10.17632/kmhvb4x5d8.1,
describes 83 real scam conversations recorded from January 2021 through June 2024 by an author posing
as a victim. It is CC BY 4.0. The page offers a download, but files and parsers were not tested here.
On 2026-11-07 both the website public-metadata endpoint and the documented API endpoint returned
HTTP 403 in this environment; no file was retrieved. This is an access failure here, not evidence
that the public release requires individual approval.

The original [linguistic study](https://www.sciencedirect.com/science/article/abs/pii/S2666799125000024) uses the corpus for frame
and discourse analysis, rather than specifying a detector benchmark. A later
[conversational-detection paper, Sections 4.2 and 5.3](https://arxiv.org/html/2607.11707v1)
reports 83/83 detected scams on a separately truncated version. That is an author-reported adapted
evaluation, not a reproduced score on the original files. Its truncation/turn-count protocol and
input identities would need verification before comparison; preserve the release's collection dates
rather than replacing them with the later paper's inconsistent 2021–2025 description.

Potential use is a scam-recall check after validating chronology and the available conversation
portion. The release description does not provide benign controls or an earliest-warning annotation.
Always warning obtains perfect scam recall; this corpus cannot establish useful detection alone.
First-warning position is descriptive, not delay after a validated evidence boundary. Cleaning or
truncating it creates a disclosed adaptation with a separate identity.

Potential supported measurement: recall on these real scam chats. High recall alone does not establish
memory retention, because always warning also has perfect recall. A context-retention claim would
need a task or controlled comparison that actually requires earlier evidence. Benign discrimination,
validated first-warning timing and Vietnamese transfer are not established by this corpus alone.

### SCAMBENCH: cue-reduction robustness

**Review status, 2026-11-07:** public-methodology/metadata review and aggregate arithmetic complete;
raw-data audit unavailable. Parked after the owner's access update; progress does not depend on approval.
The owner reports approval is unlikely, rather than a confirmed rejection. Evidence and transcribed
inputs are in [SCAMBENCH aggregate evidence](audits/scambench-review-2026-11-07/review.json). No CSV or detector
prediction was inspected, and no model was run. Counts and detector scores below are author-reported;
the arithmetic and rounding-consistency checks are this project's work.

**Capability and native task.** Test whether binary scam detection remains effective when annotated
persuasion/red-flag cues are softened. Evaluate each message separately. Original setting: original
scam texts plus legitimate controls. Rewritten setting: their cue-reduced variants plus the same
controls. Use only the selected message text as input, excluding annotations, category, loss and report
metadata. The original and rewrite are separate inference inputs, not a comparison shown to the engine.
Native scores are scam-positive precision, recall, F1 and accuracy; the change between settings
describes sensitivity to this transformation. [Paper Sections 5.1–5.4 and Appendix D](https://aclanthology.org/2026.findings-emnlp.404.pdf).

**Provenance and reference checks.** The paper describes BBB reports filtered from 252,981 to 1,836
scammer messages; legitimate sources supply 1,834 controls. Claude-Sonnet-4.6 supplies structured cue
annotations after human calibration; GPT-5.3-chat-latest generates rewrites. These are annotation and
generation operations, not an LLM judge scoring detector outputs. Two authors reviewed 120 rewrites
(20 per type) alongside their originals, retaining 115 after excluding five borderline/non-scam cases.
Reported agreement is 96.7%, kappa 0.56. This checks label retention on a subset; because reviewers
also saw originals, it does not independently establish rewrite-only decidability for every example.

**Published numerical evidence.** Recall is the fraction of scam messages detected. Drops below are
percentage points, calculated from the paper's rounded Tables 2 and 3, not independently reproduced
model measurements. The validated subset uses its corresponding original messages as the comparison.

| Detector | Full original recall | Full rewritten recall | Full drop | Drop on 115 validated pairs |
|---|---:|---:|---:|---:|
| GPT-5.4-nano | 99.4% | 94.3% | 5.1 | 7.8 |
| GPT-4.1-nano | 92.4% | 55.2% | 37.2 | 37.4 |
| GPT-4o-mini | 97.8% | 81.4% | 16.4 | 20.8 |
| Claude-Haiku-4.5 | 98.2% | 83.9% | 14.3 | 16.5 |
| Claude-Sonnet-4.5 | 95.4% | 69.3% | 26.1 | 29.6 |

The publication also reports decreases under a structured-criteria prompt (Table 27). This supports
investigating the transformation's effect; it does not prove that every missed rewrite results from
surface-cue reliance. Table 26 dates full binary runs to April 2026 and validated/structured runs to
July 2026; the subset and full results are not necessarily same-snapshot API experiments.

**Score interpretation, checked here.** Using the reported 1,836/1,834 class counts, constant YES
gets 50.027% accuracy, 66.691% positive F1, 100% recall, 100% false-positive rate and zero recall
drop. Constant NO also has zero drop, with zero recall. Thus a small drop alone cannot establish
robust detection. Read original/rewritten recall with precision/F1 and benign false alarms. The latter
is an additional diagnostic, not a claim that the paper reports a separate native false-alarm metric.

Reported controls are concentrated: employment and tech support supply 1,807/1,834 (98.53%).
Imposter has nine, investment six and lottery 12; advance fee loan has none (Tables 6–7). Aggregate
false alarms therefore mainly describe two categories. Do not infer reliable category-specific benign
performance from the overall balance. The paper omits some per-category metrics for advance fee loan;
its scam recall remains measurable. The 115 validated rewrites cover 6.26% of all reported rewrites.

An integer-confusion-matrix check found all five Table 2 model pairs compatible, within three-decimal
rounding, with unchanged false-positive counts between settings. This is aggregate arithmetic
consistency, not recovery or verification of actual predictions. Raw CSV counts, duplicates, missing
rewrites, pairing and semantic validity remain unverified.

**Access and reproducibility.** Anonymous [Hugging Face API metadata](https://huggingface.co/api/datasets/Shouninger/ScamBench)
returned revision `48c8cb284a7f454644f4006103587da13c05a2ed`, `gated: manual`, CC BY-NC 4.0,
and 14 files including 11 CSVs. The [access page](https://huggingface.co/datasets/Shouninger/ScamBench)
requires sharing Hugging Face account information and accepting conditions. No account was used and
no access request was submitted. The listed configs package both classes under `train`; this does
not establish an official evaluation holdout or authorize training on evaluation examples. No
separately named scorer or validated-subset membership file appears in this listing. Membership
could still be embedded in inaccessible CSVs. Output parsing, failures, decoding settings and exact
model snapshots are not established by the inspected public protocol.

**Proposed use for this engine.** Retain as a candidate for single-message robustness under the
released cue-reduction transformation, reporting both settings and the validated subset if its exact
membership can be verified. Keep non-scam performance visible so always-warning behavior cannot
appear successful. This measures neither conversational memory nor evidence-relative warning timing;
an English result also does not establish Vietnamese transfer or an orchestration advantage.

**Remaining work before adoption.** First obtain access through the owner-controlled Hugging Face
process. Then pin and hash files, mechanically check aggregate counts, empty fields, original/rewrite
pairing and duplicates without exposing held-out text to development context. Verify the 115-case
membership and available judgments; if absent, do not claim to reproduce that subset. Establish the
scoring/parser/failure contract and evaluation holdout before any engine run. New human annotation,
model selection and model execution would be separate work, not an automatic consequence of access.

To recheck the count-based references without opening individual messages:

```sh
python3 -I - <<'PY'
import json
from pathlib import Path
d = json.loads(Path('evaluation/audits/scambench-review-2026-11-07/review.json').read_text())
a = d['author_reported']
p = sum(a['table_6_final_scam_counts'].values())
n = sum(a['table_7_non_scam_counts'].values())
r = d['derived_from_reported_counts']
assert (p, n) == (r['positive'], r['negative']) == (1836, 1834)
assert r['constant_yes']['accuracy'] == p / (p + n)
assert r['constant_yes']['positive_f1'] == 2 * p / (2 * p + n)
assert r['non_scam_employment_and_tech_support_share'] == (899 + 908) / n
assert r['human_validated_share_of_all_rewrites'] == 115 / p
for name, pair in a['table_2_rounded_metrics'].items():
    assert round(100 * (pair[0][1] - pair[1][1]), 6) == r['full_recall_drop_percentage_points'][name]
print(json.dumps(r, indent=2))
PY
```

## Other candidates and unresolved task conditions

### BothBosu: synthetic conversation discrimination, audited 2026-11-07

**Purpose and status.** The audit assessed whether this accessible dataset supports a concrete
full-conversation scam/non-scam measurement. It is complete for byte identity, CSV structure,
split relationships and aggregate diagnostics. The dataset is not selected after the owner's
complementary-capability clarification; the evidence below remains valid.
This is a classification dataset with published train/test CSVs, not a verified official scoring
harness or leaderboard. Binary classification with fixed references can supply deterministic scores;
an LLM judge is not needed to score predictions.

**Source and provenance.** The [author card](https://huggingface.co/datasets/BothBosu/multi-agent-scam-conversation/raw/709db2b6c37f424c3070f29138abb33971e21ab9/README.md)
describes English synthetic caller/receiver dialogues generated using AutoGen and the Together
Inference API. It declares Apache-2.0. Scenario metadata determines the intended binary class; the
card does not establish independent expert/human verification of every realized conversation's
label. Exact generator model/version and prompts were not established. The dataset's agentic
generation does not require an agent-controlled detector.

**Reproducible evidence.** Revision `709db2b6c37f424c3070f29138abb33971e21ab9` was ungated in
anonymous API metadata. [Release lock](audits/bothbosu-audit-2026-11-07/release-lock.json) pins all four
retrieved files by URL, byte count and SHA-256. Total downloaded CSV/card bytes were 9,660,265;
the API `usedStorage` value of 1,937,365 was not the transfer size. Raw CSVs stay under ignored
`.audit-private/bothbosu-audit-2026-11-07/data/`; individual records were not displayed to the
development LLM. [Aggregate result](audits/bothbosu-audit-2026-11-07/aggregate.json) records the input-lock
and script hashes. [Audit code](audits/bothbosu-audit-2026-11-07/audit.py) uses only Python's standard
library. It does not train or run an engine, LLM or learned text classifier.

| Measured split | Scam | Non-scam | Total |
|---|---:|---:|---:|
| Train | 640 | 640 | 1,280 |
| Test | 160 | 160 | 320 |
| All | 800 | 800 | 1,600 |

All rows parsed as four-column CSV with binary references and no empty required fields. The actual
reference column is `labels`, while the card calls it `label`; the audit explicitly handles that
alias. The first singular-only parsing attempt stopped before analysis; its log is preserved as
`execution-initial-schema-failure.log`. A public toy reproduced the mismatch, the alias repair
passed regression checks, and the final full pass succeeded in `execution.log`. This was a parser
assumption, not a claim of invalid data. The released eighth personality, `trusting`, is absent from
the card's seven-item list; measured personality distributions are in the aggregate result.

There were zero duplicate excess rows or train/test overlaps for full four-field records, exact
dialogue strings, and dialogue strings normalized with Unicode NFKC, case folding and whitespace
collapse. The all-file equals the multiset union of train and test for all three checks. These
checks do not establish absence of paraphrases or shared generation templates.

**Numerical limits on the capability claim.** The test has 40 examples for each of eight types.
All four intended scam types and all four intended legitimate types are disjoint. A lookup that
selects the majority label for each `type` on train gets 320/320 on test. This is a metadata
association diagnostic, not a text-only detector score or evidence that metadata leaked into a run.
Exclude `type`, `personality` and `labels` from detector inputs. Topic recognition could still
explain part of text-only performance; its actual contribution is not measured here.

Serialized dialogue length also separates classes. Test median Unicode-word counts are 582 for
scam and 291.5 for non-scam. Using length alone as a ranking score gives test ROC-AUC 0.784570;
the score direction was selected on train (train AUC 0.792196), with no threshold selected on test.
AUC is the probability that a randomly selected scam ranks above a randomly selected non-scam,
with ties counted as one half; it is not 78.457% classification accuracy. This is evidence of a
structural class correlate, not proof that any engine exploits it or that all semantic evaluation is
invalid. Compare a future continuous detector score with this reference using the same AUC metric;
do not compare AUC numerically with accuracy/F1.

The word `scam` appears in 76/160 scam and 7/160 legitimate test dialogues. Both speaker markers
`Suspect` and `Innocent` occur in all 320 test dialogues. These are aggregate text diagnostics;
word presence alone does not establish accidental annotation leakage. Semantic review was not done.

On the balanced test, constant scam predictions have accuracy 50%, positive F1 66.67%, recall 100%
and false-positive rate 100%. Constant non-scam predictions have accuracy 50% and recall 0%.
One benign false alarm changes the observed test FPR by 0.625 percentage points (160 controls).
That resolution does not establish population reliability or representativeness.

**Proposed measured capability.** Use complete `dialogue` text to test discrimination on this
synthetic English call distribution, with deterministic confusion counts, per-class precision/
recall/F1, accuracy and benign FPR. These are proposed standard classification measurements, not
verified author leaderboard metrics. If continuous scores are available, add ROC-AUC with the
length reference above. Keep original train/test identities; never evaluate on the all-file after
training/tuning on train. This corpus supports a different distribution from ICFD and more benign
test observations, but does not establish near-miss discrimination within the same scam topic,
validated first-warning timing, conversational memory, real-world transfer or Vietnamese quality.
High classification scores alone cannot separate scam-content understanding from topic/length cues.

**Current disposition after owner clarification.** Do not select BothBosu for the current measurement
set. Its demonstrated task is synthetic full-conversation classification, which overlaps the adopted
ICFD task; no complementary capability was established. More balanced controls and different data
can improve coverage, but do not by themselves define another capability. This is a selection
decision, not a claim that the datasets contain identical records or that the measured integrity
checks failed. Preserve the audit; label semantics and shortcut sensitivity remain unresolved.

Offline reproduction after the pinned downloads are present (180 seconds is an operational limit):

```sh
timeout 2400s env PYTHONPATH=src python3 -m safeguard.evaluation.remeasure
```

The controller includes the BothBosu audit and its verification after preparing the run lock and
execution log. It emits aggregate statistics only and does not download missing inputs. The
archived audit's `--download` option describes its historical retrieval method. Public
fixtures checked schema aliases and ambiguity, multiline CSV, invalid labels/ragged rows, normalized
duplicates, and AUC against independent pairwise calculations. The final verification also recounts
all rows and checks the test AUC directly from every scam/non-scam pair; see `checks.log`.
The independent [verification script](audits/bothbosu-audit-2026-11-07/verify.py) is included for that
cross-check; the 30-second timeout is an operational limit. The all-file has a UTF-8 byte-order mark,
which the audit and final independent verification both handle explicitly.

| Candidate | Verified source and useful property | Task constraints and unresolved evidence |
|---|---|---|
| BothBosu Multi-Agent Scam Conversation | Pinned CSVs and CPU audit above; [release](https://huggingface.co/datasets/BothBosu/multi-agent-scam-conversation). | Not selected: no established complementary capability beyond ICFD. Preserve audit evidence. |
| Vietnamese Quality-Assured SMS Scam Dataset | [Author repository](https://github.com/trannguyenthaituan251209/vietnamese_sms_dataset) declares real Vietnamese SMS, CC BY 4.0, 2,991 total records and 2,394/597 train/test files. [Quickstart](https://github.com/trannguyenthaituan251209/vietnamese_sms_dataset/blob/main/QUICKSTART_GUIDE.md) supplies a character-TFIDF/SVM example. | Useful language diagnostic only after resolving labels: positive class is explicitly Spam/Scam, not scam alone. A scam observer must not silently flag all advertising as fraud. README baseline uses deduplicated five-fold CV; a fixed-test result is a different protocol. Article attribution to IEEE Access is author-declared; no publisher article/DOI was verified. |
| ConScamBench-278 | [Paper, Sections 4.2 and 5](https://arxiv.org/html/2607.11707v1) describes 128 scam conversations (110 real-sourced, 18 LLM-generated), 150 benign and eight scam families, with conversation and detection-turn analyses. | Highly relevant mixed-class lead. The paper alternates release claims with future-release wording. This review did not locate a downloadable dataset, license or runnable harness; do not count it as available. No verified evidence-relative warning reference. |
| ViScamDial | [Repository](https://github.com/Anonymous-Submission-xyz123/ViScamDial_Submission_ARR2026) documents Vietnamese dialogue detection, training/evaluation code, 200 synthetic sample dialogues and 63 real-call sample dialogues. | Current license states anonymous peer review only. Full corpus/private evaluation splits and generation pipeline are not shipped. Translated external corpora must not be counted as independent native Vietnamese data. Not eligible for immediate adoption on the inspected terms. |

### New leads for capabilities beyond the adopted ICFD scope

These are bounded primary-source leads, not adopted benchmarks, measured engine results or raw-data
audits. Investigate access and native task fit before downloading a corpus. No new generation,
credit purchase, model call or paid execution follows from listing them.

**PhishRewrite — phishing-email rewrite robustness.** The
[author repository](https://github.com/gaurangkatyal/phishrewrite) describes original/rewritten email
evaluation at multiple rewrite severities, preserving the malicious request and URLs. Its intended
capability is robustness to textual rewriting, distinct from ICFD's adopted classification and prefix
tasks. Standard detection scores and changes at a fixed benign false-positive operating point are
reported. The author [results](https://github.com/gaurangkatyal/phishrewrite/blob/main/RESULTS.md)
show that the effect depends on detector and corpus, so do not assume every detector degrades.
Code and results are publicly visible; the README identifies a separately packaged archive under
DOI `10.5281/zenodo.21018700`. The follow-up public API check verified an open 21,371,735-byte
archive with CC BY 4.0 metadata; earlier web-tool failure did not establish a gate. The generated
release is not committed in the repository. Archive contents and executable reproduction remain
unchecked. [Data terms](https://github.com/gaurangkatyal/phishrewrite/blob/main/DATA_LICENSE)
depend on upstream corpora and differ from the MIT code license. Email-only English input and
rewrite/reference validity need assessment before calling this a replacement for SCAMBENCH.

**Active voice-agent honeypot corpus — real-call scam versus spam.** The
[October 2026 preprint, v2](https://arxiv.org/html/2609.29528v2) describes an automatically labeled
corpus of inbound real callers interacting with an AI honeypot, including a purported 1,000-call
de-identified release balanced between scam and spam. The complementary question is whether an
engine separates outright fraud from unwanted/predatory sales calls rather than treating every
unwanted call as fraud. The proposed protocol groups folds by originating caller, avoiding repeated
callers across development/test. Human review only partially corroborates the automatic binary
labels (75% reported agreement); neither the labels nor the release counts were independently
verified here. Despite the paper's openly downloadable wording, the current canonical
[Scam.AI Research portal](https://scam.ai/research) says dataset downloads require an account credit
purchase. Treat it as unavailable for a free runnable suite at present. No purchase, author contact
or access request was made. Do not silently generalize a scam-versus-spam score to legitimate calls.

The earlier shortlist linked the [AI-in-the-Loop paper](https://petsymposium.org/popets/2026/popets-2026-0006.pdf)
for BothBosu's classification use. That PDF timed out during this follow-up; no new paper-method or
baseline verification is claimed. Conversation labels are not prefix gold. No published detector
performance above was reproduced locally; the structural length ranking is this audit's diagnostic.

## References outside the initial suite

- [PreScam v1](https://arxiv.org/html/2605.12243v1) models termination-stage and next-action prediction
  from LLM-structured scam reports. It is a progression reference, not a benign-versus-scam detector
  evaluation. A usable data/code release was not located. Its test-based threshold selection and judge-based
  next-action scoring must not silently become this project's detection protocol.
- [TeleAntiFraud](https://github.com/JimmyMa99/TeleAntiFraud) ships audio/text classification and
  reasoning-evaluation utilities. Keep it secondary while the application is a text observer; audio
  perception and judge-based reasoning quality are separate questions. A release listing is verified,
  not execution or split integrity.
- Fraud-R1 and COVA-X remain task-mismatch references from the earlier review: assistant resistance
  and victim-outcome modeling do not directly measure observer detection. Their earlier sources and
  limitations remain recorded in project reference material; no new release audit was performed here.
- General tool-use, coding and agent benchmarks do not replace domain detection measurements.
  Investigate a component benchmark only if a concrete engine capability and failure make it relevant.

## Capability coverage and remaining work

1. The ICFD-31k audit is complete and its two classification tasks are adopted with the limits above.
   SCAMBENCH is parked for access and BothBosu is not selected for lack of an established
   complementary capability. Do not reduce this to one primary-benchmark choice.
2. For any adopted candidate, use its declared development split and keep test/category holdouts
   separate. Fix model, allowed information, tools, warning procedure and resources before attributing
   differences to workflow versus agent control.
3. Use BABILong for the declared context/QA component task and PhishRewrite for fixed-source
   rewrite robustness. PhishVN is not additionally selected for the overlapping task. The selected
   task map and bounded audits above supersede the earlier candidate-only dispositions.
4. Include local synthetic-v1 for the two reference-based internal pilot tasks in Local inclusion
   audit. Its additional measurements do not establish human-optimal timing, semantic reference
   validity or causal deciding-feature recognition. Keep these limits attached to reported scores.

The local contribution is complementary to the reviewed external tasks, not a requirement imposed
on every benchmark or proof of global novelty. Preserve its frozen inputs. Further semantic
validation is a separate activity; do not describe the computational audit as a new blinded review.

Calls, tokens, tool use, elapsed time and execution failures should be measured on the same task runs.
Streaming workload depends on the number of exposed prefixes, not just conversation count. No runtime,
cost, subset size, acceptance threshold or winning margin is estimated or selected here. Published
chunk-level and conversation-level scores must remain distinct; repeated prefixes are not independent
new conversations. The next reproducibility audit and any model execution remain separate work.
