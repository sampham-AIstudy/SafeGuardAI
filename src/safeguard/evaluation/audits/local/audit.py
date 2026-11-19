"""Aggregate-only suitability diagnostics. Never print held-out inputs or case outputs.

This audits references and surface associations, not semantic label validity. No
LLM, embedding model, lexical classifier, external service or generation is used.
"""

import collections
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import unicodedata

from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json

ROOT = PROJECT
OUT = output("local")
DATA = inputs("SGC-250") / "synthetic-v1"
PRIVATE = private_output("local")
HARM = {
    'request_money_transfer', 'request_credentials_or_otp',
    'request_app_install_or_remote_access', 'request_link_with_data_entry',
    'request_identity_documents_or_biometrics', 'request_qr_scan_login',
}
INDICATORS = {
    'authority_outside_procedure', 'lookalike_or_unofficial_domain',
    'recipient_mismatch', 'advance_fee', 'unrealistic_gain',
    'secrecy_or_isolation', 'verification_refused', 'identity_inconsistency',
    'threat_or_coercion', 'escalating_payment', 'unsolicited_claim',
}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'))


def norm(text):
    return ' '.join(unicodedata.normalize('NFC', text).lower().split())


def summary(values):
    return {'n': len(values), 'min': min(values) if values else None,
            'median': statistics.median(values) if values else None,
            'mean': statistics.mean(values) if values else None,
            'max': max(values) if values else None}


def auc(values, labels):
    """Mann-Whitney AUC with average ranks for ties; higher score predicts scam."""
    ordered = sorted(zip(values, labels))
    npos = sum(labels)
    nneg = len(labels) - npos
    if not npos or not nneg:
        return None
    rank_sum = 0
    start = 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and ordered[end][0] == ordered[start][0]:
            end += 1
        rank_sum += ((start + 1 + end) / 2) * sum(y for _, y in ordered[start:end])
        start = end
    return (rank_sum - npos * (npos + 1) / 2) / (npos * nneg)


def first_kind_completion(evidence):
    """Necessary-kind reconstruction; does not verify meaning or same-scheme link."""
    seen = set()
    for index in sorted({e['message_index'] for e in evidence}):
        seen.update(k for e in evidence if e['message_index'] == index for k in e['kind'])
        if 'request_credentials_or_otp' in seen or (seen & HARM and seen & INDICATORS):
            return index
    return None


def surface(record, limit=None):
    inp = record['input']
    messages = inp['messages'][:limit]
    text = '\n'.join(m.get('text', '') for m in messages)
    chars = max(1, len(text))
    n = max(1, len(messages))
    attachments = [a for m in messages for a in m.get('attachments', [])]
    return {
        'message_count': len(messages), 'text_characters': len(text),
        'mean_text_characters': len(text) / n,
        'contact_message_share': sum(m['role'] == 'contact' for m in messages) / n,
        'digit_share': sum(c.isdigit() for c in text) / chars,
        'nonascii_share': sum(ord(c) > 127 for c in text) / chars,
        'link_message_share': sum('http://' in m.get('text', '').lower() or
                                  'https://' in m.get('text', '').lower() or
                                  any(a.get('type') == 'link' for a in m.get('attachments', []))
                                  for m in messages) / n,
        'attachment_count': len(attachments),
        'timestamp_share': sum('timestamp' in m for m in messages) / n,
        'saved_contact': int(inp['contact']['is_saved_contact']),
        **{'channel_' + channel: int(inp['channel'] == channel)
           for channel in ['zalo', 'messenger', 'sms', 'telegram']},
    }


def component_folds(records):
    """Keep shared seed IDs and linked pairs in a single fold (transitive)."""
    parent = {r['id']: r['id'] for r in records}
    def find(k):
        while parent[k] != k:
            parent[k] = parent[parent[k]]
            k = parent[k]
        return k
    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b)] = min(a, b)
    seeds = collections.defaultdict(list)
    for r in records:
        seeds[r['provenance']['seed']['seed_id']].append(r['id'])
        if r['gold'].get('paired_with'):
            union(r['id'], r['gold']['paired_with'])
    for members in seeds.values():
        for item in members[1:]:
            union(members[0], item)
    groups = collections.defaultdict(list)
    for r in records:
        groups[find(r['id'])].append(r['id'])
    # No label stratification or held-out metric is used to choose the assignment.
    ordered = sorted(groups.values(), key=lambda ids: hashlib.sha256(
        ('local-surface-folds-2026-11-08:' + '|'.join(sorted(ids))).encode()).hexdigest())
    assignments = {item: i % 5 for i, ids in enumerate(ordered) for item in ids}
    return assignments, list(groups.values())


def stump_cv(records, surfaces, folds):
    """Train-only choice of a single threshold; audit diagnostic, never a detector."""
    y = [int(r['gold']['label'] == 'scam') for r in records]
    predictions = [None] * len(records)
    majority_predictions = [None] * len(records)
    per_fold = []
    for fold in range(5):
        train = [i for i, r in enumerate(records) if folds[r['id']] != fold]
        test = [i for i, r in enumerate(records) if folds[r['id']] == fold]
        majority = int(sum(y[i] for i in train) * 2 >= len(train))
        best = None
        for key in sorted(surfaces[0]):
            values = sorted({surfaces[i][key] for i in train})
            thresholds = [values[0] - 1] + values
            for threshold in thresholds:
                for polarity in [0, 1]:
                    errors = sum(int(surfaces[i][key] > threshold) ^ polarity != y[i] for i in train)
                    candidate = (errors, key, threshold, polarity)
                    if best is None or candidate < best:
                        best = candidate
        errors, key, threshold, polarity = best
        for i in test:
            predictions[i] = int(surfaces[i][key] > threshold) ^ polarity
            majority_predictions[i] = majority
        # Do not publish selected thresholds or case-level predictions to development context.
        per_fold.append({'test_rows': len(test), 'test_positive': sum(y[i] for i in test),
                         'train_rows': len(train), 'train_errors': errors,
                         'test_correct': sum(predictions[i] == y[i] for i in test)})
    def counts(pred):
        tp = sum(a == 1 and b == 1 for a, b in zip(pred, y))
        tn = sum(a == 0 and b == 0 for a, b in zip(pred, y))
        fp = sum(a == 1 and b == 0 for a, b in zip(pred, y))
        fn = sum(a == 0 and b == 1 for a, b in zip(pred, y))
        return {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                'accuracy': (tp + tn) / len(y), 'recall': tp / (tp + fn),
                'fpr': fp / (fp + tn), 'f1': 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else None}
    return {'folds': per_fold, 'surface_stump': counts(predictions),
            'train_majority': counts(majority_predictions)}, predictions


def prefix_conflicts(records, mode):
    groups = collections.defaultdict(list)
    for r in records:
        for t in range(len(r['input']['messages'])):
            inp = {**r['input'], 'messages': r['input']['messages'][:t+1]}
            value = inp if mode == 'full_input' else [norm(m['text']) for m in inp['messages']]
            key = hashlib.sha256(canonical(value).encode()).hexdigest()
            alert = r['gold']['alert_turn']
            groups[key].append(int(alert is not None and t >= alert))
    conflicting = [x for x in groups.values() if len(set(x)) > 1]
    return {'prefix_rows': sum(map(len, groups.values())), 'unique_prefixes': len(groups),
            'duplicate_groups': sum(len(x) > 1 for x in groups.values()),
            'conflicting_groups': len(conflicting),
            'minimum_errors_for_deterministic_stateless_mapping': sum(min(sum(x), len(x)-sum(x)) for x in conflicting)}


def main():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((DATA / 'manifest.json').read_text())
    assert sha(DATA / 'conversations.jsonl') == manifest['conversations_sha256']
    assert sha(DATA / manifest['protocol_path']) == manifest['protocol_sha256']
    assert sha(QC / 'qc_report.json') == manifest['qc_report_sha256']
    assert sha(SCORER) == manifest['scorer_sha256']
    managed = []
    for line in (DATA / 'SHA256SUMS').read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        path = local_artifact(relative.lstrip('*'))
        assert sha(path) == expected
        managed.append({'path': path.relative_to(ROOT).as_posix(), 'sha256': expected})
    records = [json.loads(s) for s in (DATA / 'conversations.jsonl').read_text().splitlines() if s.strip()]
    qc = json.loads((QC / 'qc_report.json').read_text())
    assert all(hashlib.sha256(canonical(r).encode()).hexdigest() == manifest['per_record_sha256'][r['id']]
               for r in records), 'Canonical record identity mismatch'
    scams = [r for r in records if r['gold']['label'] == 'scam']
    benign = [r for r in records if r['gold']['label'] == 'benign']
    consistency = collections.Counter()
    private_findings = []
    offsets = []
    for r in scams:
        gold = r['gold']
        alert = gold['alert_turn']
        reconstructed = first_kind_completion(gold['evidence'])
        offsets.append(alert)
        relation = 'same' if reconstructed == alert else 'no_kind_completion' if reconstructed is None else 'earlier' if reconstructed < alert else 'later'
        consistency[relation] += 1
        consistency['boundary_message_has_annotation'] += any(e['message_index'] == alert for e in gold['evidence'])
        consistency['has_annotations_after_boundary'] += any(e['message_index'] > alert for e in gold['evidence'])
        before = [e for e in gold['evidence'] if e['message_index'] < alert]
        consistency['pre_boundary_kind_condition_absent'] += first_kind_completion(before) is None
        if relation != 'same':
            private_findings.append({'id': r['id'], 'kind_completion_relation': relation,
                                     'reference': alert, 'kind_completion': reconstructed})
    by_id = {r['id']: r for r in records}
    review_rows = [json.loads(s) for s in (QC / 'second_pass.jsonl').read_text().splitlines() if s.strip()]
    current_reviews = []
    review_match = collections.Counter()
    for row in review_rows:
        record = by_id[row['id']]
        input_sha = hashlib.sha256(canonical(record['input']).encode()).hexdigest()
        if row['input_sha256'] != input_sha:
            continue
        current_reviews.append(row)
        review_match['review_rows_on_current_input'] += 1
        review_match['label_matches_final'] += row['review']['label'] == record['gold']['label']
        if row['review']['label'] == record['gold']['label'] == 'scam':
            review_match['joint_scam'] += 1
            delta = abs(row['review']['alert_turn'] - record['gold']['alert_turn'])
            review_match['boundary_exact'] += delta == 0
            review_match['boundary_within_one'] += delta <= 1
    review_match['distinct_current_inputs'] = len({row['id'] for row in current_reviews})
    assert review_match['distinct_current_inputs'] == len(records)
    pairs = [(r, by_id[r['gold']['paired_with']]) for r in scams if r['gold'].get('paired_with')]
    pair_counts = collections.Counter()
    similarity = []
    common_lengths = []
    for a, b in pairs:
        am, bm = a['input']['messages'], b['input']['messages']
        common = 0
        for x, z in zip(am, bm):
            if (x['role'], norm(x['text']), canonical(x.get('attachments', []))) != \
                    (z['role'], norm(z['text']), canonical(z.get('attachments', []))):
                break
            common += 1
        common_lengths.append(common)
        atokens = set(norm(' '.join(m['text'] for m in am)).split())
        btokens = set(norm(' '.join(m['text'] for m in bm)).split())
        similarity.append(len(atokens & btokens) / len(atokens | btokens) if atokens | btokens else 1)
        pair_counts['reciprocal_opposite_class'] += b['gold']['label'] == 'benign' and b['gold'].get('paired_with') == a['id']
        pair_counts['same_channel'] += a['input']['channel'] == b['input']['channel']
        pair_counts['same_saved_contact_status'] += a['input']['contact']['is_saved_contact'] == b['input']['contact']['is_saved_contact']
        pair_counts['same_message_count'] += len(am) == len(bm)
        pair_counts['same_first_message_role_and_normalized_text'] += am[0]['role'] == bm[0]['role'] and norm(am[0]['text']) == norm(bm[0]['text'])
        pair_counts['same_resemblance_type'] += a['gold']['scam_type'] == b['gold']['resembles_scam_type']
        pair_counts['shared_prefix_includes_scam_boundary'] += common > a['gold']['alert_turn']
    surfaces = [surface(r) for r in records]
    labels = [int(r['gold']['label'] == 'scam') for r in records]
    all_features = {}
    for key in surfaces[0]:
        values = [s[key] for s in surfaces]
        all_features[key] = {'auc_higher_means_scam': auc(values, labels),
                             'scam': summary([v for v, y in zip(values, labels) if y]),
                             'benign': summary([v for v, y in zip(values, labels) if not y])}
    folds, components = component_folds(records)
    cv, pred = stump_cv(records, surfaces, folds)
    cv['paired_both_classified_correctly'] = sum(pred[records.index(a)] == 1 and pred[records.index(b)] == 0 for a, b in pairs)
    cv['paired_denominator'] = len(pairs)
    cv['group_count'] = len(components)
    cv['largest_group'] = max(map(len, components))
    cv['interpretation'] = 'One fixed five-fold grouping; train-only surface rule. A diagnostic with task-relevant covariates, not an engine result or proof of shortcuts.'
    spec = importlib.util.spec_from_file_location('local_frozen_scorer', SCORER)
    scorer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(scorer)
    policies = {
        'never_warn': lambda r: None,
        'warn_on_first_message': lambda r: 0,
        'warn_on_final_message': lambda r: len(r['input']['messages']) - 1,
        'label_and_boundary_oracle': lambda r: r['gold']['alert_turn'],
    }
    controls = {}
    for name, policy in policies.items():
        result = scorer.score(records, [{'id': r['id'], 'first_warning': policy(r)} for r in records])
        assert result['status'] == 'complete'
        controls[name] = {'metrics': result['metrics'], 'successful_pairs': result['successful_pairs']}
    incomplete = scorer.score(records, [{'id': r['id'], 'first_warning': None} for r in records[:-1]])
    assert incomplete['metrics'] is None
    prefix_counts = {
        'before_reference': sum(r['gold']['alert_turn'] for r in scams),
        'at_or_after_reference': sum(len(r['input']['messages']) - r['gold']['alert_turn'] for r in scams),
        'benign': sum(len(r['input']['messages']) for r in benign),
    }
    result = {
        'date': '2026-11-08', 'scope': 'Frozen-reference consistency, pair structure, surface diagnostics and scorer controls. No fresh semantic review or detector inference.',
        'counts': {'conversations': len(records), 'scam': len(scams), 'benign': len(benign), 'pairs': len(pairs)},
        'identity': {'dataset_sha256': manifest['conversations_sha256'], 'managed_files_verified': len(managed),
                     'managed_files': managed, 'script_sha256': sha(Path(__file__)), 'scorer_sha256': manifest['scorer_sha256']},
        'timing': {'kind_completion': dict(consistency), 'boundary_message_index': summary(offsets),
                   'boundary_at_zero': offsets.count(0), 'boundary_at_final_message': sum(r['gold']['alert_turn'] == len(r['input']['messages']) - 1 for r in scams),
                   'prefix_units': prefix_counts,
                   'interpretation': 'Kind tags are gold, not detector inputs. Necessary-kind consistency cannot establish text meaning, common scheme, completeness of evidence annotations, or absence of annotator hindsight.'},
        'prefix_conflicts': {mode: prefix_conflicts(records, mode) for mode in ['full_input', 'normalized_text']},
        'pairs': {'counts': dict(pair_counts), 'shared_opening_message_count': summary(common_lengths),
                  'whole_text_whitespace_token_jaccard': summary(similarity),
                  'interpretation': 'Topic-matched diagnostics; lexical similarity does not validate deciding differences or establish minimal causal pairs.'},
        'surface_associations': all_features, 'surface_rule_group_cv': cv,
        'scorer_controls': controls, 'missing_prediction_withholds_metrics': incomplete['metrics'] is None,
        'existing_review': {'initial_agreement': qc['initial_agreement'], 'current_input_reviews': manifest['reviewer_provenance'],
                            'current_input_review_vs_final': dict(review_match),
                            'agreement_interpretation': 'Final gold incorporates review/adjudication; this is reconciliation, not fresh independent validity evidence.',
                            'human_spot_check': manifest['human_spot_check'], 'semantic_qc': qc['semantic_qc'],
                            'unresolved_findings': qc['unresolved_findings']},
        'limits': ['No new blinded prefix-only annotations; hindsight has not been empirically tested.',
                   'No semantic verification of every pair or independent human validation.',
                   'Synthetic balanced sample; no deployment, causal or benchmark-novelty claim.',
                   'Full-transcript surface associations do not prove an online warning shortcut.',
                   'Surface diagnostic fitting is audit-only; no learned rule, thresholds or case predictions enter detector development.',
                   'Existing developer-access incident remains disclosed; a strict never-seen claim is unavailable.'],
    }
    (PRIVATE / 'annotation-consistency-findings.json').write_text(json.dumps(private_findings, indent=2) + '\n')
    (OUT / 'aggregate.json').write_text(json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + '\n')
    print('Completed aggregate-only audit. Results saved to the configured fresh local-audit output directory')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Exceptions must not dump a record or text-bearing local variables.
        print('Audit failed: ' + type(exc).__name__ + '. No case data displayed.', file=sys.stderr)
        raise SystemExit(1)
