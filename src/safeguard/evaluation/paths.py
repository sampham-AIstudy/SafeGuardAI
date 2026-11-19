"""Explicit canonical paths for archived inputs and fresh audit outputs."""

import json
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
RUN = ROOT / "evaluation/runs" / os.environ.get("SAFEGUARD_AUDIT_RUN", "benchmark-measurements-2026-11-08")
ARCHIVES = {
    "icfd": "icfd-31k-audit-2026-11-07",
    "capability": "capability-audit-2026-11-07",
    "bothbosu": "bothbosu-audit-2026-11-07",
    "local": "local-suitability-audit-2026-11-08",
}
QC = ROOT / "evaluation/private/SGC-250/release-qc/synthetic-v1"
SCORER = ROOT / "evaluation/private/SGC-250/tools/score.py"


def archive(name):
    return ROOT / "evaluation/audits" / ARCHIVES[name]


def output(name):
    path = RUN / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def private_output(name):
    path = RUN / "private" / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def inputs(name):
    return ROOT / "data/benchmarks" / name


def safe_join(root, relative):
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Expected a relative artifact path without traversal")
    return root / relative


def release_input(relative):
    """Resolve unchanged historical release-lock paths without filesystem aliases."""
    source_prefix = "evaluation/capability-audit-2026-11-07/sources/"
    if relative.startswith(source_prefix):
        return safe_join(archive("capability") / "sources", relative[len(source_prefix):])
    mapping = {
        ".audit-private/capability-audit-2026-11-07/babilong/": "babilong",
        ".audit-private/capability-audit-2026-11-07/phishrewrite-release/": "phishrewrite",
        ".audit-private/capability-audit-2026-11-07/phishvn-content/": "phishvn",
    }
    for prefix, name in mapping.items():
        if relative.startswith(prefix):
            return safe_join(inputs(name), relative[len(prefix):])
    raise ValueError("Unknown pinned release input location")


def local_artifact(relative):
    """Resolve original SHA256SUMS members after the physical QC separation."""
    if relative.startswith("qc/"):
        return safe_join(QC, relative[3:])
    return safe_join(inputs("SGC-250") / "synthetic-v1", relative)


def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temp.replace(path)
