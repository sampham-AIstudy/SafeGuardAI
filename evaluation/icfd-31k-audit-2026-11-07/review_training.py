"""Reconstruct the training-only usability sample without printing conversations."""

import hashlib
import io
import json
from pathlib import Path
import zstandard

ROOT=Path(__file__).resolve().parent
DATA=Path(json.loads((ROOT/'release-lock.json').read_text())['private_data_root'])
selected={'YES':[],'NO':[]}
for path in sorted((DATA/'source_conversations').glob('train-*.zst')):
    with path.open('rb') as raw,zstandard.ZstdDecompressor().stream_reader(raw) as stream:
        for line in io.TextIOWrapper(stream,encoding='utf-8'):
            row=json.loads(line)
            label=row['final_verdict']
            key=hashlib.sha256(row['release_metadata']['conversation_uid'].encode()).hexdigest()
            selected[label].append((key,row))
            selected[label].sort(key=lambda item:item[0])
            selected[label]=selected[label][:2]
review=[]
for label,items in selected.items():
    for _,row in items:
        review.append({'split':'train','label':label,'uid':row['release_metadata']['conversation_uid'],
                       'messages':row['transcript'],'annotations':row.get('chunk_level_analysis',[])})
encoded=(json.dumps(review,ensure_ascii=False,indent=2)+'\n').encode()
path=DATA.parent/'training-usability-review-input.json'
if path.exists():
    assert path.read_bytes()==encoded, 'Training sample identity mismatch'
else:
    path.write_bytes(encoded)
print(json.dumps({'training_records':len(review),'sha256':hashlib.sha256(encoded).hexdigest()}))
