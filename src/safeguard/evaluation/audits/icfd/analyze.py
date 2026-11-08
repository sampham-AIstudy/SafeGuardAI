"""Derive aggregate consequences and baseline provenance from completed checkpoints."""

import hashlib
import json
from pathlib import Path
import sqlite3
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json


ROOT=output("icfd")


def main():
    report=json.loads((ROOT/'data-audit.json').read_text())
    database=Path(report['private_checkpoint_db'])
    connection=sqlite3.connect(f'file:{database}?mode=ro',uri=True)
    fraction=lambda numerator,denominator:numerator/denominator if denominator else None
    consequences={}
    for split in ['train','validation','test','cross_domain']:
        source=report['aggregate']['static'][split]
        label=source['labels']; yes=label.get('YES',0); no=label.get('NO',0)
        consequences[split]={'scam':yes,'benign':no,'scam_share':fraction(yes,yes+no),
                              'always_scam_accuracy_arithmetic':fraction(yes,yes+no),
                              'always_scam_f1_arithmetic':fraction(2*yes,2*yes+no)}
    source_majority={}
    for split in ['train','validation','test','cross_domain']:
        rows=connection.execute('''SELECT json_extract(s.payload,'$.final_verdict'),
                 sum(c.label='YES'),count(*)
                 FROM sources s JOIN chunks c ON s.uid=c.uid WHERE s.split=? GROUP BY s.uid''',(split,))
        counters={'source_fraud_conversations':0,'source_fraud_not_majority_positive_chunks':0,
                  'source_fraud_without_positive_chunk':0,'source_benign_majority_positive_chunks':0}
        for label,positive,count in rows:
            if label=='YES':
                counters['source_fraud_conversations']+=1
                counters['source_fraud_not_majority_positive_chunks']+=int(positive<=count/2)
                counters['source_fraud_without_positive_chunk']+=int(positive==0)
            elif positive>count/2:
                counters['source_benign_majority_positive_chunks']+=1
        source_majority[split]=counters
    exact_annotation_total=sum(r['counts'].get('source_annotation_time_overlap',0) for r in report['aggregate']['streaming'].values())
    exact_annotation_match=sum(r['counts'].get('source_annotation_label_match',0) for r in report['aggregate']['streaming'].values())
    native_match=sum(r['counts'].get('native_rule_label_match',0) for r in report['aggregate']['streaming'].values())
    chunks=sum(r['counts']['rows'] for r in report['aggregate']['streaming'].values())
    artifact_metrics={}
    raw=PROJECT/'.audit-private/icfd-31k-audit-2026-11-07/upstream-results'
    def numbers_only(value):
        if isinstance(value,dict):
            output={}
            for key,item in value.items():
                if type(item) in (int,float,bool):
                    output[key]=item
                elif isinstance(item,dict):
                    nested=numbers_only(item)
                    if nested:output[key]=nested
            return output
        return {}
    for path in sorted(raw.rglob('*.json')):
        artifact_metrics[str(path.relative_to(raw))]={'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                                                      'numeric_aggregates':numbers_only(json.loads(path.read_text()))}
    result={'source_data_audit_signature':report['input_signature'],
            'class_balance':consequences,'native_majority_denominator_consequences':source_majority,
            'chunks':chunks,'labels_matching_native_keyword_or_duration_rule':native_match,
            'matching_rule_share':fraction(native_match,chunks),
            'source_annotation_exact_time_overlap':exact_annotation_total,
            'source_annotation_exact_time_disagreements':exact_annotation_total-exact_annotation_match,
            'source_annotation_exact_time_disagreement_share':fraction(exact_annotation_total-exact_annotation_match,exact_annotation_total),
            'saved_baseline_numeric_evidence':artifact_metrics,
            'interpretation_limits':['Constant-classifier arithmetic is not model inference.',
              'Matching the pinned chunker does not validate its semantic labels.',
              'Saved published results were inspected, not reproduced with models.']}
    save_json(ROOT/'interpretation.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='saved_baseline_numeric_evidence'},indent=2))


if __name__=='__main__':
    main()
