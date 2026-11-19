"""Checkpointed aggregate-only structural and temporal scan of pinned ICFD data."""

from collections import Counter
import hashlib
import io
import json
import math
from pathlib import Path
import sqlite3
import sys
import time
import unicodedata

import pyarrow.parquet as pq
import zstandard

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_core import annotation_map, chunker, observed_input, source_issues, verdict
from safeguard.evaluation.paths import ROOT as PROJECT, archive, output, private_output, inputs, release_input, local_artifact, QC, SCORER, save_json


ROOT = archive("icfd")
OUT = output("icfd")
LOCK = json.loads((ROOT / 'release-lock.json').read_text())
DATA = inputs("icfd-31k")
PRIVATE = private_output("icfd")
MANIFEST = [json.loads(line) for line in (ROOT / 'release-metadata/dataset_manifest.jsonl').read_text().splitlines()]


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def normalized_text(turns):
    return ' '.join(' '.join(
                        unicodedata.normalize('NFC', str(turn.get('text',''))).casefold().split()) for turn in turns)


def source_rows(path):
    with path.open('rb') as raw, zstandard.ZstdDecompressor().stream_reader(raw) as reader:
        for line in io.TextIOWrapper(reader, encoding='utf-8'):
            if line.strip():
                yield json.loads(line)


def messages(turns):
    return [(turn.get('speaker'), turn.get('text'), turn.get('timestamp_end')) for turn in turns]


def scan():
    signature = digest({'manifest':hashlib.sha256((ROOT/'release-metadata/dataset_manifest.jsonl').read_bytes()).hexdigest(),
                        'scan':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                        'core':hashlib.sha256((ROOT/'audit_core.py').read_bytes()).hexdigest(),
                        'chunker':hashlib.sha256((ROOT/'upstream/src/generators/chunk_expander.py').read_bytes()).hexdigest()})
    connection = sqlite3.connect(PRIVATE / ('audit-' + signature[:12] + '.sqlite'))
    connection.executescript('''
      PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS sources(uid TEXT, split TEXT, payload TEXT, digest TEXT, last_time REAL, domain TEXT);
      CREATE INDEX IF NOT EXISTS source_uid ON sources(uid);
      CREATE TABLE IF NOT EXISTS chunks(uid TEXT, split TEXT, t REAL, label TEXT, prefix_digest TEXT);
      CREATE TABLE IF NOT EXISTS completed(path TEXT PRIMARY KEY, summary TEXT);
    ''')
    completed = dict(connection.execute('SELECT path,summary FROM completed'))
    engine = chunker(ROOT/'upstream')
    started = time.monotonic()
    for shard in [r for r in MANIFEST if r['task']=='static']:
        name = shard['path']
        if name in completed:
            continue
        counter = Counter()
        domains, labels, fields = Counter(), Counter(), Counter()
        with connection:
            for row in source_rows(DATA/name):
                counter['rows'] += 1
                fields.update(row.keys())
                release = row.get('release_metadata',{})
                uid = release.get('conversation_uid')
                turns = row.get('transcript',[])
                issues, max_time = source_issues(row)
                counter.update(issues)
                labels[str(row.get('final_verdict'))] += 1
                domains[release.get('domain','missing')] += 1
                if not uid:
                    counter['missing_uid'] += 1
                if release.get('split') != shard['split']:
                    counter['release_split_mismatch'] += 1
                # Retain every raw source even when an annotation is malformed. Otherwise
                # an annotation fault would incorrectly appear as an orphaned chunk.
                connection.execute('INSERT INTO sources VALUES(?,?,?,?,?,?)',
                    (str(uid),shard['split'],json.dumps(row),hashlib.sha256(normalized_text(turns).encode()).hexdigest(),
                     max_time,release.get('domain','missing')))
                try:
                    verdict(row.get('final_verdict'))
                    annotations=row.get('chunk_level_analysis',[])
                    if row['final_verdict']=='YES':
                        counter['fraud_sources'] += 1
                        threshold=engine._find_fraud_start_time(turns,row.get('scenario',{}),row)
                        counter['fraud_boundary_finite'] += int(type(threshold) in (int,float) and math.isfinite(threshold))
                        positive_times=[t for t,label in annotation_map(row).items() if label=='YES']
                        counter['fraud_without_positive_source_annotation'] += int(not positive_times)
                        if positive_times:
                            counter['native_threshold_equals_source_first_yes'] += int(threshold==min(positive_times))
                except (KeyError,ValueError,TypeError):
                    counter['uncheckable_source_rule_or_annotation'] += 1
            summary={'task':'static','split':shard['split'],'counts':dict(counter),'labels':dict(labels),
                     'domains':dict(domains),'fields':dict(fields),'expected_rows':shard['records']}
            connection.execute('INSERT INTO completed VALUES(?,?)',(name,json.dumps(summary)))
        print(json.dumps({'phase':'sources','completed_shard':name,'rows':counter['rows']}),flush=True)
    sources={}
    for uid,split,payload,_,_,_ in connection.execute('SELECT * FROM sources'):
        row=json.loads(payload)
        row['_split']=split
        try:
            row['_fraud_start']=engine._find_fraud_start_time(row['transcript'],row.get('scenario',{}),row)
        except (KeyError,ValueError,TypeError):
            row['_fraud_start']=None
        row['_valid_timing']=bool(row['transcript']) and all(type(t.get('timestamp_end')) in (int,float)
                  and math.isfinite(t['timestamp_end']) and t['timestamp_end']>=0 for t in row['transcript'])
        row['_annotation_by_time']=annotation_map(row)
        sources[uid]=row
    for shard in [r for r in MANIFEST if r['task']=='streaming']:
        name=shard['path']
        if name in completed:
            continue
        counter,labels,domains=Counter(),Counter(),Counter()
        parquet=pq.ParquetFile(DATA/name)
        with connection:
            for batch in parquet.iter_batches(batch_size=2048):
                inserts=[]
                for row in batch.to_pylist():
                    counter['rows'] += 1
                    uid=row.get('conversation_uid')
                    source=sources.get(uid)
                    try:
                        verdict(row.get('final_verdict'))
                        labels[row['final_verdict']] += 1
                        domains[row.get('domain','missing')] += 1
                        if row.get('split')!=shard['split']:
                            counter['release_split_mismatch'] += 1
                        if source is None:
                            counter['unlinked_source'] += 1
                            continue
                        if source['_split']!=shard['split']:
                            counter['source_split_mismatch'] += 1
                        observed=json.loads(row['cumulative_transcript_json'])
                        timestamp=row['chunk_timestamp']
                        inserts.append((uid,shard['split'],timestamp,row['final_verdict'],digest(messages(observed))))
                        counter['empty_prefix'] += int(not observed)
                        counter['off_three_second_grid'] += int(timestamp%3 != 0)
                        try:
                            observed_input(row)
                        except (KeyError,ValueError,TypeError):
                            counter['input_contract_rejected'] += 1
                        if source['_valid_timing']:
                            expected=[t for t in source['transcript'] if t['timestamp_end']<=timestamp]
                            counter['checkable_source_prefix'] += 1
                            counter['prefix_exact_source_match'] += int(observed==expected)
                            counter['prefix_content_source_match'] += int(messages(observed)==messages(expected))
                            counter['chunk_after_source_end'] += int(timestamp>max(t['timestamp_end'] for t in source['transcript']))
                        else:
                            counter['uncheckable_source_prefix'] += 1
                        if source['final_verdict']=='NO' or type(source['_fraud_start']) in (float,int):
                            native='NO' if source['final_verdict']=='NO' else ('YES' if timestamp>=source['_fraud_start'] else 'NO')
                            counter['checkable_native_rule_label'] += 1
                            counter['native_rule_label_match'] += int(native==row['final_verdict'])
                        else:
                            counter['uncheckable_native_rule_label'] += 1
                        counter['same_as_conversation_label'] += int(row['final_verdict']==source['final_verdict'])
                        if timestamp in source['_annotation_by_time']:
                            counter['source_annotation_time_overlap'] += 1
                            counter['source_annotation_label_match'] += int(row['final_verdict']==source['_annotation_by_time'][timestamp])
                        formatted='\n'.join(f"{t.get('speaker','Unknown')}: {t.get('text','')}" for t in observed)
                        counter['cumulative_text_matches_newline_format'] += int(formatted==row['cumulative_text'])
                    except (KeyError,ValueError,TypeError):
                        counter['invalid_chunk_records'] += 1
                connection.executemany('INSERT INTO chunks VALUES(?,?,?,?,?)',inserts)
            summary={'task':'streaming','split':shard['split'],'counts':dict(counter),
                     'labels':dict(labels),'domains':dict(domains),'expected_rows':shard['records'],
                     'schema':str(parquet.schema_arrow)}
            connection.execute('INSERT INTO completed VALUES(?,?)',(name,json.dumps(summary)))
        print(json.dumps({'phase':'chunks','completed_shard':name,'rows':counter['rows']}),flush=True)
    per_shard={name:json.loads(payload) for name,payload in connection.execute('SELECT path,summary FROM completed')}
    aggregate={}
    for task in ['static','streaming']:
        aggregate[task]={}
        for split in ['train','validation','test','cross_domain']:
            totals,labels,domains=Counter(),Counter(),Counter()
            matching=[r for r in per_shard.values() if r['task']==task and r['split']==split]
            for entry in matching:
                totals.update(entry['counts']); labels.update(entry['labels']); domains.update(entry['domains'])
            aggregate[task][split]={'counts':dict(totals),'labels':dict(labels),'domains':dict(domains),
                                    'expected_rows':sum(r['expected_rows'] for r in matching)}
    sql=lambda query:connection.execute(query).fetchone()[0]
    overlap={
      'duplicate_source_uid_groups':sql('SELECT count(*) FROM (SELECT uid FROM sources GROUP BY uid HAVING count(*)>1)'),
      'source_uid_cross_split_groups':sql('SELECT count(*) FROM (SELECT uid FROM sources GROUP BY uid HAVING count(DISTINCT split)>1)'),
      'normalized_transcript_duplicate_groups':sql('SELECT count(*) FROM (SELECT digest FROM sources GROUP BY digest HAVING count(*)>1)'),
      'normalized_transcript_cross_split_groups':sql('SELECT count(*) FROM (SELECT digest FROM sources GROUP BY digest HAVING count(DISTINCT split)>1)'),
      'chunk_uid_cross_split_groups':sql('SELECT count(*) FROM (SELECT uid FROM chunks GROUP BY uid HAVING count(DISTINCT split)>1)'),
      'duplicate_uid_timestamp_groups':sql('SELECT count(*) FROM (SELECT uid,t FROM chunks GROUP BY uid,t HAVING count(*)>1)'),
      'identical_observed_prefix_with_conflicting_labels_groups':sql('SELECT count(*) FROM (SELECT uid,prefix_digest FROM chunks GROUP BY uid,prefix_digest HAVING count(DISTINCT label)>1)'),
      'conversations_with_conflicting_identical_prefix':sql('SELECT count(DISTINCT uid) FROM (SELECT uid,prefix_digest FROM chunks GROUP BY uid,prefix_digest HAVING count(DISTINCT label)>1)'),
      'sources_without_chunks':sql('SELECT count(*) FROM sources s LEFT JOIN (SELECT DISTINCT uid FROM chunks) c ON s.uid=c.uid WHERE c.uid IS NULL'),
      'sources_final_utterance_not_in_any_chunk':sql('SELECT count(*) FROM sources s JOIN (SELECT uid,max(t) AS last_chunk FROM chunks GROUP BY uid) c ON s.uid=c.uid WHERE s.last_time>c.last_chunk')}
    source_domains={split:set(aggregate['static'][split]['domains']) for split in aggregate['static']}
    overlap['cross_domain_domain_names_overlap_main_count']=len(source_domains['cross_domain'] & set.union(*(source_domains[s] for s in ['train','validation','test'])))
    report={'input_signature':signature,'release_lock_sha256':hashlib.sha256((ROOT/'release-lock.json').read_bytes()).hexdigest(),
            'completed_shards':len(per_shard),'expected_shards':len(MANIFEST),'aggregate':aggregate,
            'cross_checks':overlap,'elapsed_seconds_this_invocation':time.monotonic()-started,
            'private_checkpoint_db':str(PRIVATE/('audit-'+signature[:12]+'.sqlite')),
            'scope':'Mechanical data/temporal checks; no detector and no independent semantic validation'}
    save_json(OUT/'data-audit.json',report)
    save_json(OUT/'shard-checks.json',per_shard)
    print(json.dumps({'completed_shards':len(per_shard),'cross_checks':overlap,
                      'report':str(OUT/'data-audit.json'),'elapsed_seconds':report['elapsed_seconds_this_invocation']},indent=2))


if __name__=='__main__':
    try:
        scan()
    except Exception as exc:
        save_json(OUT/'scan-failure.json',{'type':type(exc).__name__,
                  'message':'Scan failed; raw exception text withheld to protect case content'})
        print(json.dumps({'status':'failed','error_type':type(exc).__name__}),flush=True)
        raise SystemExit(1)
