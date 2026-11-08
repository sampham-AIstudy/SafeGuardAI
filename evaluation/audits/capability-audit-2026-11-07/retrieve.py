"""Retrieve fixed public inputs; checkpoint each file without displaying records."""
import base64
import hashlib
import json
import os
from pathlib import Path
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PRIVATE = ROOT / ".audit-private/capability-audit-2026-11-07"
SOURCES = HERE / "sources"
LOCK = HERE / "release-lock.json"


def atomic(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".part")
    with tmp.open("wb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())
    tmp.replace(path)


def fetch(url, limit=100_000_000):
    with urllib.request.urlopen(url, timeout=40) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Operational download limit exceeded")
    return data


def main():
    lock = json.loads(LOCK.read_text()) if LOCK.exists() else {"date": "2026-11-07", "files": {}}
    metadata = {}
    for name in ["phishvn-content", "phishrewrite-release", "babilong-hf", "babilong-tree"]:
        saved = SOURCES / (name + "-metadata.json")
        src = saved if saved.exists() else Path("/tmp") / (name + "-metadata-2026-11-07.json")
        metadata[name] = json.loads(src.read_text())
        target = SOURCES / (name + "-metadata.json")
        raw = src.read_bytes()
        if target.exists() and target.read_bytes() != raw:
            raise ValueError("Metadata snapshot changed: " + name)
        atomic(target, raw)
    jobs = []
    for name in ["phishvn-content", "phishrewrite-release"]:
        for record in metadata[name]["files"]:
            if record["key"] == "pages.csv.xz":
                continue
            jobs.append((name + "/" + record["key"], record["links"]["self"],
                         PRIVATE / name / record["key"], record.get("checksum"), record.get("size"), False))
    hf = metadata["babilong-hf"]
    revision = hf["sha"]
    for task in ["qa1", "qa2", "qa3"]:
        for length in ["0k", "4k", "16k"]:
            rel = f"data/{task}/{length}.json"
            assert any(x["rfilename"] == rel for x in hf["siblings"])
            jobs.append((f"babilong/{task}/{length}.json",
                         f"https://huggingface.co/datasets/RMT-team/babilong/resolve/{revision}/{rel}",
                         PRIVATE / "babilong" / task / (length + ".json"), None, None, False))
    blob = next(x for x in metadata["babilong-tree"]["tree"] if x["path"] == "babilong/metrics.py")
    jobs.append(("babilong/metrics.py", blob["url"], SOURCES / "babilong_metrics.py", None, None, True))
    failures = []
    for key, url, path, checksum, size, encoded in jobs:
        try:
            if key in lock["files"]:
                raw = path.read_bytes()
                assert hashlib.sha256(raw).hexdigest() == lock["files"][key]["sha256"]
                assert len(raw) == lock["files"][key]["bytes"]
                print("Verified saved input: " + key, flush=True)
                continue
            raw = fetch(url)
            if encoded:
                obj = json.loads(raw)
                raw = base64.b64decode(obj["content"])
                assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == blob["sha"]
            if checksum:
                algorithm, expected = checksum.split(":", 1)
                assert hashlib.new(algorithm, raw).hexdigest() == expected
            if size is not None:
                assert len(raw) == size
            atomic(path, raw)
            lock["files"][key] = {"url": url, "path": str(path.relative_to(ROOT)), "bytes": len(raw),
                                   "sha256": hashlib.sha256(raw).hexdigest(),
                                   "upstream_checksum": checksum, "upstream_size": size}
            atomic(LOCK, (json.dumps(lock, indent=2) + "\n").encode())
            print(f"Retrieved {key}: {len(raw)} bytes", flush=True)
        except Exception as exc:
            failures.append({"input": key, "error_type": type(exc).__name__, "detail": str(exc)})
            print("FAILED " + key + ": " + type(exc).__name__, flush=True)
    atomic(HERE / "retrieval-result.json", (json.dumps({"completed": len(lock["files"]),
           "required": len(jobs), "failures": failures}, indent=2) + "\n").encode())
    if failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
