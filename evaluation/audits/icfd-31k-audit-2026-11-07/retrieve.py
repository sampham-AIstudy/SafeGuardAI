"""Retrieve pinned ICFD artifacts without displaying conversation content."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT.parents[1] / '.audit-private' / ROOT.name
GITHUB = 'SPELLAILab/ICFD-31k'
DATASET = 'rishia2220/icfd-31k'
AUTHOR_REVISION = '5d02311657b2ca6454b5fb1c67bcdeb056b589c3'


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    with temp.open('w') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)


def fetch(url, path):
    """Preserve completed units; never print a response body on failure."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes()
    failure = None
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': 'mini-safeguard-icfd-audit'})
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()
            temp = path.with_suffix(path.suffix + '.part')
            with temp.open('wb') as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            temp.replace(path)
            return data
        except (urllib.error.URLError, TimeoutError) as exc:
            failure = {'url': url, 'error_type': type(exc).__name__,
                       'http_status': getattr(exc, 'code', None)}
            if getattr(exc, 'code', None) in (401, 403, 404):
                break
            time.sleep(attempt + 1)
    save_json(ROOT / 'retrieval-failure.json', failure)
    raise RuntimeError(json.dumps(failure)) from None


def metadata():
    PRIVATE.mkdir(parents=True, exist_ok=True)
    (PRIVATE.parent / '.gitignore').write_text('*\n')
    lock_path = ROOT / 'release-lock.json'
    if lock_path.exists():
        return json.loads(lock_path.read_text())
    dataset_api = f'https://huggingface.co/api/datasets/{DATASET}/revision/main'
    hf_info = json.loads(fetch(dataset_api, PRIVATE / 'dataset-api.json'))
    hf_revision = hf_info['sha']
    tree_url = f'https://api.github.com/repos/{GITHUB}/git/trees/{AUTHOR_REVISION}?recursive=1'
    tree = json.loads(fetch(tree_url, PRIVATE / 'github-tree.json'))
    if tree.get('truncated'):
        raise RuntimeError('Author tree is truncated; selection cannot be verified')
    docs = ['README.md', 'DATASET_CARD.md', 'DATA_ACCESS.md', 'LICENSE-DATA.md',
            'REPRODUCIBILITY.md', 'baselines/README.md']
    generic = [entry['path'] for entry in tree['tree']
               if entry['type'] == 'blob' and
               ((entry['path'].startswith('baselines/') and entry['path'].endswith(('.py', '.md')))
                or entry['path'] in ('scripts/download_data.py', 'scripts/verify_checksums.py'))]
    inventory = []
    for name in sorted(set(docs + generic)):
        url = f'https://raw.githubusercontent.com/{GITHUB}/{AUTHOR_REVISION}/{urllib.parse.quote(name)}'
        path = ROOT / 'upstream' / name
        data = fetch(url, path)
        inventory.append({'path': str(path.relative_to(ROOT)), 'url': url,
                          'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    for name in ('README.md', 'dataset_manifest.jsonl', 'checksums.sha256', 'release_summary.json'):
        url = f'https://huggingface.co/datasets/{DATASET}/resolve/{hf_revision}/{name}'
        path = ROOT / 'release-metadata' / name
        data = fetch(url, path)
        inventory.append({'path': str(path.relative_to(ROOT)), 'url': url,
                          'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    lock = {'author_repository': GITHUB, 'author_revision': AUTHOR_REVISION,
            'dataset': DATASET, 'dataset_revision': hf_revision,
            'private_data_root': str(PRIVATE / 'data'), 'retrieved_at_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'artifacts': inventory}
    save_json(lock_path, lock)
    return lock


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--metadata-only', action='store_true')
    parser.add_argument('--download', action='store_true')
    parser.add_argument('--extra-evidence', action='store_true')
    args = parser.parse_args()
    lock = metadata()
    if args.extra_evidence:
        names = ['src/generators/chunk_expander.py', 'src/core/models.py',
                 'baselines/gemma-0shot-a/results/metrics.json',
                 'baselines/gemma-0shot-a/results/summary.json',
                 'baselines/roberta-2a/full_dataset_results/full_dataset_results.json',
                 'baselines/roberta-2a/test_results/retest_results.json',
                 'baselines/roberta-2b/final_model/results/data_splits.json',
                 'baselines/roberta-2b/final_model/results/test_results.json',
                 'baselines/roberta-2b/final_model/results/training_metrics.json']
        evidence = []
        for name in names:
            public = name.endswith('.py')
            path = (ROOT / 'upstream' if public else PRIVATE / 'upstream-results') / name
            url = f'https://raw.githubusercontent.com/{GITHUB}/{lock["author_revision"]}/{name}'
            blob = fetch(url, path)
            evidence.append({'path':str(path), 'url':url, 'bytes':len(blob),
                             'sha256':hashlib.sha256(blob).hexdigest(), 'contains_private_results':not public})
        save_json(ROOT / 'extra-evidence-inventory.json', evidence)
        print(json.dumps({'extra_evidence_files':len(evidence)}))
        return
    manifest_path = ROOT / 'release-metadata/dataset_manifest.jsonl'
    rows = [json.loads(line) for line in manifest_path.read_text().splitlines() if line.strip()]
    keys = sorted(set().union(*(row.keys() for row in rows)))
    summary = {'author_revision': lock['author_revision'], 'dataset_revision': lock['dataset_revision'],
               'manifest_rows': len(rows), 'manifest_keys': keys,
               'document_and_code_files': len(lock['artifacts']),
               'disk_free_bytes': shutil.disk_usage(ROOT).free}
    for key in ('bytes', 'size', 'size_bytes'):
        if all(isinstance(row.get(key), int) for row in rows):
            summary['manifest_total_bytes'] = sum(row[key] for row in rows)
            summary['size_field'] = key
            break
    save_json(ROOT / 'metadata-summary.json', summary)
    print(json.dumps(summary, indent=2))
    if args.download:
        total = summary['manifest_total_bytes']
        if total * 20 > summary['disk_free_bytes']:
            raise RuntimeError('Storage preflight failed; allow space beyond compressed files')
        checksums = {}
        for line in (ROOT / 'release-metadata/checksums.sha256').read_text().splitlines():
            if line.strip():
                digest, name = line.split(maxsplit=1)
                checksums[name.lstrip('*')] = digest
        for row in rows:
            relative = Path(row['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise RuntimeError('Unsafe manifest path')
            if checksums.get(row['path']) != row['sha256']:
                raise RuntimeError('Manifest and checksum list disagree')
        receipts_path = ROOT / 'download-receipts.json'
        receipts = json.loads(receipts_path.read_text()) if receipts_path.exists() else {}

        def retrieve_row(row):
            name = row['path']
            url = f'https://huggingface.co/datasets/{DATASET}/resolve/{lock["dataset_revision"]}/{name}'
            data = fetch(url, PRIVATE / 'data' / name)
            digest = hashlib.sha256(data).hexdigest()
            if len(data) != row['bytes'] or digest != row['sha256']:
                raise RuntimeError('Shard identity verification failed: ' + name)
            return name, {'bytes': len(data), 'sha256': digest, 'verified': True}

        failures = []
        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as executor:
            jobs = {executor.submit(retrieve_row, row): row['path'] for row in rows}
            for job in as_completed(jobs):
                name = jobs[job]
                try:
                    name, receipt = job.result()
                    receipts[name] = receipt
                    save_json(receipts_path, receipts)
                    if len(receipts) % 10 == 0:
                        print(json.dumps({'verified_shards': len(receipts), 'total': len(rows)}), flush=True)
                except Exception as exc:
                    failures.append({'path': name, 'error_type': type(exc).__name__})
        result = {'expected_shards': len(rows), 'verified_shards': len(receipts),
                  'verified_bytes': sum(item['bytes'] for item in receipts.values()),
                  'failures': failures, 'elapsed_seconds': time.monotonic() - started}
        save_json(ROOT / 'retrieval-report.json', result)
        print(json.dumps(result, indent=2))
        if failures or len(receipts) != len(rows):
            raise RuntimeError('Corpus retrieval is incomplete')
    elif not args.metadata_only:
        raise RuntimeError('Select --metadata-only or --download')


if __name__ == '__main__':
    main()
