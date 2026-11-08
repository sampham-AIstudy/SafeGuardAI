---
license: other
language:
  - en
  - hi
task_categories:
  - text-classification
tags:
  - fraud-detection
  - conversational-ai
  - hinglish
  - streaming
  - synthetic-data
  - responsible-ai
pretty_name: ICFD-31k
size_categories:
  - 10K<n<100K
---

# ICFD-31k

**ICFD-31k** is a large-scale synthetic Indian conversational fraud dataset for static, streaming, and cross-domain fraud detection.

It contains **31,000** English/Hinglish phone-call style conversations and **1,111,071** cumulative 3-second streaming chunks.

## Files

- `source_conversations/` - full source conversations as compressed JSONL files.
- `streaming_chunks/` - cumulative streaming chunks as Parquet files.
- `dataset_manifest.jsonl` - shard metadata and checksums.
- `checksums.sha256` - SHA-256 checksums for released files.
- `release_summary.json` - split-level release summary.

## Dataset Statistics

| Split | Source conversations | Streaming chunks |
|---|---:|---:|
| Train | 21,000 | 712,316 |
| Validation | 4,500 | 173,813 |
| Test | 4,500 | 179,827 |
| Cross-domain | 1,000 | 45,115 |
| **Total** | **31,000** | **1,111,071** |

## Download

```python
from huggingface_hub import snapshot_download

dataset_dir = snapshot_download(
    repo_id="rishia2220/icfd-31k",
    repo_type="dataset"
)
```

## Responsible Use

ICFD-31k is released for defensive research and education only. Do not use it to generate scam scripts, automate social engineering, train offensive systems, or support any activity that facilitates fraud.

## Citation

```bibtex
@inproceedings{ahuja2026icfd31k,
  title     = {{ICFD-31k}: A Large-Scale Dataset and Benchmark for Real-Time Conversational Fraud Detection},
  author    = {Ahuja, Rishi and Prateek, Kumar and Singh, Simranjit},
  booktitle = {Proceedings of the Thirty-Fifth International Joint Conference on Artificial Intelligence (IJCAI-ECAI)},
  year      = {2026}
}
```

## Project Repository

https://github.com/SPELLAILab/ICFD-31k
