import os
import re
import hashlib
from pathlib import Path

from core.config import LANG_MAP, SKIP_DIRS, SKIP_EXTS, MAX_FILE_BYTES


def detect_language(path: Path) -> str:
    return LANG_MAP.get(path.suffix.lower(), "Unknown")


def is_code_file(path: Path) -> bool:
    return detect_language(path) not in (
        "Unknown", "JSON", "YAML", "XML", "Env"
    )


def collect_files(root: Path) -> list[Path]:
    """Recursively collect scannable files under root, or return single file if root is a file."""
    # If root is a single file, return it directly (if not skipped)
    if root.is_file():
        if root.suffix.lower() not in SKIP_EXTS:
            try:
                if root.stat().st_size <= MAX_FILE_BYTES:
                    return [root]
            except OSError:
                pass
        return []
    
    # Otherwise, walk directory tree
    files = []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        for fn in fns:
            p = Path(dp) / fn
            if p.suffix.lower() in SKIP_EXTS:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            files.append(p)
    return files


def read_file(path: Path) -> str:
    """Read a file trying multiple encodings; always returns a string."""
    for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return path.read_text(encoding=enc, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return path.read_text(encoding="utf-8", errors="replace")


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings by type + file + line."""
    seen, out = set(), []
    for f in findings:
        key = hashlib.md5(
            f"{f['type']}:{f['file']}:{f['location']['from_line']}".encode()
        ).hexdigest()
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def normalise_severity(raw) -> str:
    s = str(raw).lower().strip()
    if s in ("critical", "high", "medium", "low"):
        return s
    try:
        sc = float(s)
        if sc >= 9: return "critical"
        if sc >= 7: return "high"
        if sc >= 4: return "medium"
        return "low"
    except ValueError:
        return "medium"


def impact_for(sev: str) -> str:
    return {
        "critical": "Full system compromise, remote code execution, or data breach",
        "high":     "Significant data exposure, privilege escalation, or service disruption",
        "medium":   "Partial data exposure, account takeover, or functionality abuse",
        "low":      "Limited information disclosure or minor security degradation",
    }.get(sev, "Unknown impact")


def parse_version(v: str) -> tuple:
    try:
        return tuple(int(x) for x in re.sub(r"[^0-9.]", "", v).split(".")[:3])
    except Exception:
        return (0, 0, 0)


def version_below(installed: str, threshold: str) -> bool:
    return parse_version(installed) < parse_version(threshold)
