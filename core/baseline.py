import json
from pathlib import Path

from core.file_utils import finding_fingerprint


def load_baseline(path: str) -> set[str]:
    if not path:
        return set()
    baseline_path = Path(path).expanduser()
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")
    data = json.loads(baseline_path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, dict):
        values = data.get("fingerprints") or data.get("findings") or []
    elif isinstance(data, list):
        values = data
    else:
        return set()

    fingerprints: set[str] = set()
    for item in values:
        if isinstance(item, str):
            fingerprints.add(item)
        elif isinstance(item, dict):
            fingerprints.add(str(item.get("fingerprint") or finding_fingerprint(item)))
    return fingerprints


def apply_baseline(findings: list[dict], fingerprints: set[str]) -> tuple[list[dict], int]:
    if not fingerprints:
        return findings, 0
    kept = []
    suppressed = 0
    for finding in findings:
        fingerprint = finding.setdefault("fingerprint", finding_fingerprint(finding))
        if fingerprint in fingerprints:
            suppressed += 1
            continue
        kept.append(finding)
    return kept, suppressed
