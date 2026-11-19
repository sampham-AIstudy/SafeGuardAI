"""Small offline contracts used to audit the ICFD release; no model execution."""

import ast
from collections import Counter
from copy import deepcopy
import json
import math
from pathlib import Path
from typing import Any


def verdict(value):
    if value not in ('YES', 'NO'):
        raise ValueError('Unknown verdict')
    return int(value == 'YES')


def source_issues(row):
    """Report field faults without discarding a source needed for chunk linkage."""
    issues = Counter()
    turns = row.get('transcript', [])
    stamps = [turn.get('timestamp_end') for turn in turns]
    valid = bool(stamps) and all(type(t) in (int, float) and math.isfinite(t) and t >= 0 for t in stamps)
    if not valid:
        issues['invalid_transcript_timestamps'] += 1
    elif stamps != sorted(stamps):
        issues['unordered_transcript_timestamps'] += 1
    max_time = max((t for t in stamps if type(t) in (int, float) and math.isfinite(t)), default=0)
    yes_seen = False
    for annotation in row.get('chunk_level_analysis', []):
        label = annotation.get('verdict_at_chunk')
        if label not in ('YES', 'NO'):
            issues['nonbinary_source_annotations'] += 1
        timestamp = annotation.get('timestamp')
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp):
            issues['invalid_annotation_timestamps'] += 1
        elif timestamp > max_time:
            issues['annotation_after_conversation'] += 1
        if yes_seen and label == 'NO':
            issues['annotation_yes_to_no_transitions'] += 1
        yes_seen |= label == 'YES'
    return issues, max_time


def annotation_map(row):
    return {entry['timestamp']:entry['verdict_at_chunk']
            for entry in row.get('chunk_level_analysis', [])
            if type(entry.get('timestamp')) in (int,float)
            and math.isfinite(entry['timestamp']) and entry.get('verdict_at_chunk') in ('YES','NO')}


def chunker(upstream_root):
    """Execute only the inspected pure ChunkExpander class, without upstream imports."""
    path = Path(upstream_root) / 'src/generators/chunk_expander.py'
    tree = ast.parse(path.read_text())
    node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == 'ChunkExpander')
    selected = ast.Module(body=[node], type_ignores=[])
    namespace = {'Dict': dict, 'List': list, 'Any': Any, 'Console': object,
                 'CHUNK_INTERVAL_SECONDS': 3}
    exec(compile(ast.fix_missing_locations(selected), str(path), 'exec'), namespace)
    return namespace['ChunkExpander'](None)


def observed_input(chunk):
    """Enforce the proposed text-only input contract, including its time boundary."""
    time = chunk['chunk_timestamp']
    if isinstance(time, bool) or not isinstance(time, (float, int)) or not math.isfinite(time) or time < 0:
        raise ValueError('Invalid observation time')
    transcript = json.loads(chunk['cumulative_transcript_json'])
    if not isinstance(transcript, list):
        raise ValueError('Transcript must be a list')
    result = []
    previous = -math.inf
    for turn in transcript:
        end = turn['timestamp_end']
        if isinstance(end, bool) or not isinstance(end, (float, int)) or not math.isfinite(end):
            raise ValueError('Invalid turn timestamp')
        if end > time or end < previous:
            raise ValueError('Future or out-of-order turn')
        if not isinstance(turn['speaker'], str) or not isinstance(turn['text'], str):
            raise ValueError('Invalid message fields')
        result.append({'speaker': turn['speaker'], 'text': turn['text'], 'timestamp_end': end})
        previous = end
    return {'messages': deepcopy(result)}


def score_binary(labels, predictions):
    """Explicit failure handling; undefined ratios remain null in the audit contract."""
    if len(labels) != len(predictions) or any(type(v) is not int or v not in (0, 1) for v in labels):
        raise ValueError('Invalid reference or prediction count')
    if any(type(v) is not int or v not in (0, 1) for v in predictions):
        return {'complete': False, 'metrics': None}
    tp = sum(y == p == 1 for y, p in zip(labels, predictions))
    tn = sum(y == p == 0 for y, p in zip(labels, predictions))
    fp = sum(y == 0 and p == 1 for y, p in zip(labels, predictions))
    fn = sum(y == 1 and p == 0 for y, p in zip(labels, predictions))
    ratio = lambda numerator, denominator: numerator / denominator if denominator else None
    return {'complete': True, 'metrics': {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
            'accuracy': ratio(tp + tn, len(labels)), 'precision': ratio(tp, tp + fp),
            'recall': ratio(tp, tp + fn), 'f1': ratio(2 * tp, 2 * tp + fp + fn),
            'false_positive_rate': ratio(fp, fp + tn)}}
