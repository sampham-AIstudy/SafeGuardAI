"""Alternative recounts and public fixtures, by the same assistant as audit.py."""

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

HERE = output("local")
CODE = Path(__file__).resolve().parent
ROOT = PROJECT


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    audit = load_module('local_audit', CODE / 'audit.py')
    a = json.loads((HERE / 'aggregate.json').read_text())
    assert a['identity']['script_sha256'] == audit.sha(CODE / 'audit.py')
    for item in a['identity']['managed_files']:
        assert audit.sha(ROOT / item['path']) == item['sha256']
    print('PASS: final audit script and all frozen managed identities match.')
    # Public fixtures contain no benchmark records or allocated scenarios.
    assert audit.auc([0, 1], [0, 1]) == 1
    assert audit.auc([1, 0], [0, 1]) == 0
    assert audit.auc([1, 1], [0, 1]) == .5
    assert audit.auc([1, 1, 2], [0, 1, 1]) == .75
    assert audit.first_kind_completion([]) is None
    assert audit.first_kind_completion([{'message_index': 2, 'kind': ['request_credentials_or_otp']}]) == 2
    assert audit.first_kind_completion([{'message_index': 1, 'kind': ['request_money_transfer']},
                                        {'message_index': 3, 'kind': ['recipient_mismatch']}]) == 3
    assert audit.first_kind_completion([{'message_index': 0, 'kind': ['recipient_mismatch']}]) is None
    assert audit.first_kind_completion([{'message_index': 5, 'kind': ['request_money_transfer']},
                                        {'message_index': 1, 'kind': ['advance_fee']}]) == 5
    print('PASS: public tie-AUC and necessary-kind completion fixtures.')
    records = [json.loads(s) for s in (audit.DATA / 'conversations.jsonl').read_text().splitlines() if s.strip()]
    assert len(records) == 250
    scams = [r for r in records if r['gold']['label'] == 'scam']
    benign = [r for r in records if r['gold']['label'] == 'benign']
    assert len(scams) == len(benign) == 125
    independently_equal = 0
    for r in scams:
        first = None
        for t in range(len(r['input']['messages'])):
            kinds = {kind for e in r['gold']['evidence'] if e['message_index'] <= t for kind in e['kind']}
            complete = 'request_credentials_or_otp' in kinds or (bool(kinds & audit.HARM) and bool(kinds & audit.INDICATORS))
            if complete:
                first = t
                break
        independently_equal += first == r['gold']['alert_turn']
    assert independently_equal == a['timing']['kind_completion']['same'] == 125
    assert sum(r['gold']['alert_turn'] for r in scams) == a['timing']['prefix_units']['before_reference']
    print('PASS: all 125 boundaries independently recounted from gold kind tags; no text-semantic claim.')
    by_id = {r['id']: r for r in records}
    pairs = [(r, by_id[r['gold']['paired_with']]) for r in scams if r['gold'].get('paired_with')]
    assert len(pairs) == a['counts']['pairs'] == 28
    assert sum(x['input']['channel'] == y['input']['channel'] for x, y in pairs) == a['pairs']['counts']['same_channel']
    assert sum(x['gold']['scam_type'] == y['gold']['resembles_scam_type'] for x, y in pairs) == a['pairs']['counts']['same_resemblance_type']
    for mode in ['full_input', 'normalized_text']:
        prefix_sets = {}
        for r in records:
            for t in range(len(r['input']['messages'])):
                if mode == 'full_input':
                    key = audit.canonical({**r['input'], 'messages': r['input']['messages'][:t+1]})
                else:
                    key = tuple(audit.norm(m['text']) for m in r['input']['messages'][:t+1])
                target = r['gold']['alert_turn'] is not None and t >= r['gold']['alert_turn']
                prefix_sets.setdefault(key, []).append(target)
        assert len(prefix_sets) == a['prefix_conflicts'][mode]['unique_prefixes']
        assert sum(len(set(v)) > 1 for v in prefix_sets.values()) == a['prefix_conflicts'][mode]['conflicting_groups']
    print('PASS: 28 pair links/types and both complete prefix-conflict recounts.')
    sx = [audit.surface(r) for r in scams]
    bx = [audit.surface(r) for r in benign]
    for feature, measured in a['surface_associations'].items():
        expected = sum((x[feature] > y[feature]) + .5 * (x[feature] == y[feature]) for x in sx for y in bx) / (len(sx) * len(bx))
        assert abs(expected - measured['auc_higher_means_scam']) < 1e-12
    folds, groups = audit.component_folds(records)
    seed_folds = {}
    for r in records:
        seed_folds.setdefault(r['provenance']['seed']['seed_id'], set()).add(folds[r['id']])
        paired = r['gold'].get('paired_with')
        assert paired is None or folds[r['id']] == folds[paired]
    assert all(len(v) == 1 for v in seed_folds.values())
    assert len(groups) == a['surface_rule_group_cv']['group_count']
    # The threshold rule itself is verified on public, perfectly separable numbers.
    toy = [{'id': 'toy-' + str(i), 'gold': {'label': 'scam' if i % 2 else 'benign'}} for i in range(20)]
    features = [{'public_number': i % 2} for i in range(20)]
    cv, _ = audit.stump_cv(toy, features, {r['id']: i // 4 for i, r in enumerate(toy)})
    assert cv['surface_stump']['accuracy'] == 1
    print('PASS: every numeric AUC via direct class pairs; seed/pair fold separation; public threshold-rule fixture.')
    c = a['scorer_controls']
    assert c['never_warn']['metrics']['miss_rate'] == 1
    assert c['warn_on_first_message']['metrics']['premature_warning_rate'] == 112 / 125
    assert c['warn_on_final_message']['metrics']['exact_boundary_detection_rate'] == 11 / 125
    assert all(c[name]['successful_pairs'] == 0 for name in ['never_warn', 'warn_on_first_message', 'warn_on_final_message'])
    assert c['label_and_boundary_oracle']['successful_pairs'] == 28
    assert a['missing_prediction_withholds_metrics']
    review = a['existing_review']['current_input_review_vs_final']
    assert review['distinct_current_inputs'] == 250
    print('PASS: degenerate-policy controls and current-input review reconciliation coverage.')
    print('LIMIT: same-assistant computational cross-checks; no new blinded prefix annotation, semantic label validation or engine evaluation.')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Verification failed: ' + type(exc).__name__ + '. No case data displayed.', file=sys.stderr)
        sys.exit(1)
