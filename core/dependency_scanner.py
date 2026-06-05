import re
import json
import urllib.error
import urllib.request
from pathlib import Path

from core.config     import KNOWN_VULN_PACKAGES, SKIP_DIRS
from core.file_utils import version_below, impact_for


def _dep_finding(file: str, name: str, ver: str, vuln: dict, lang: str, source: str = "dependency") -> dict:
    return {
        "type":           "Dependency Vulnerability",
        "severity":       vuln["severity"],
        "severity_score": vuln["score"],
        "confidence":     "high",
        "cwe":            vuln["cwe"],
        "capec":          "CAPEC-13",
        "cve_id":         vuln.get("cve"),
        "file":           file,
        "location":       {"from_line": 1, "to_line": 1},
        "code":           {"language": lang, "snippet": f"{name}=={ver}"},
        "attack_path": {
            "entry_point":   "Third-party dependency",
            "prerequisites": ["Package installed and in use"],
            "impact":        impact_for(vuln["severity"]),
            "likelihood":    "High — publicly known vulnerable version",
        },
        "explanation":  vuln["desc"],
        "remediation":  f"Upgrade {name} to >= {vuln['below']}.",
        "evidence": {
            "input_source": "Dependency manifest",
            "sink": name,
            "missing_control": f"Installed version is below {vuln['below']}",
            "reason": f"{name} {ver} matches {source} vulnerability metadata",
        },
        "validation": {
            "status": "trusted_source",
            "notes": "Matched by dependency scanner",
        },
        "source":       "dependency",
    }


def scan_dependencies(root: Path, use_osv: bool = False) -> list[dict]:
    findings = []

    # ── npm: package.json ─────────────────────────────────────────────────────
    for pkg_file in root.rglob("package.json"):
        if any(p in pkg_file.parts for p in SKIP_DIRS):
            continue
        try:
            data = json.loads(
                pkg_file.read_text(encoding="utf-8", errors="replace")
            )
            deps = {
                **data.get("dependencies", {}),
                **data.get("devDependencies", {}),
            }
            for name, ver_raw in deps.items():
                ver = re.sub(r"[^0-9.]", "", str(ver_raw))
                if name in KNOWN_VULN_PACKAGES:
                    v = KNOWN_VULN_PACKAGES[name]
                    if version_below(ver, v["below"]):
                        findings.append(
                            _dep_finding(str(pkg_file), name, ver, v, "JavaScript")
                        )
            if use_osv:
                findings.extend(_scan_osv_manifest(str(pkg_file), deps, "npm", "JavaScript"))
        except Exception:
            pass

    # ── pip: requirements*.txt ────────────────────────────────────────────────
    for req_file in root.rglob("requirements*.txt"):
        if any(p in req_file.parts for p in SKIP_DIRS):
            continue
        try:
            for line in req_file.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines():
                m = re.match(
                    r"^([A-Za-z0-9_\-]+)[>=<!\s]*([0-9][0-9.]*)", line.strip()
                )
                if m:
                    name, ver = m.group(1).lower(), m.group(2)
                    if name in KNOWN_VULN_PACKAGES:
                        v = KNOWN_VULN_PACKAGES[name]
                        if version_below(ver, v["below"]):
                            findings.append(
                                _dep_finding(str(req_file), name, ver, v, "Python")
                            )
                    if use_osv and m:
                        findings.extend(_scan_osv_manifest(str(req_file), {name: ver}, "PyPI", "Python"))
        except Exception:
            pass

    return findings


def _scan_osv_manifest(file: str, deps: dict, ecosystem: str, lang: str) -> list[dict]:
    findings = []
    for name, ver_raw in deps.items():
        ver = re.sub(r"[^0-9.]", "", str(ver_raw))
        if not ver:
            continue
        for vuln in _query_osv(name, ver, ecosystem):
            severity = _osv_severity(vuln)
            finding = _dep_finding(
                file,
                name,
                ver,
                {
                    "below": "a non-vulnerable version",
                    "cve": _osv_cve(vuln),
                    "severity": severity,
                    "score": _osv_score(vuln, severity),
                    "cwe": _osv_cwe(vuln),
                    "desc": vuln.get("summary") or vuln.get("details") or "OSV vulnerability match",
                },
                lang,
                source="OSV",
            )
            finding["remediation"] = f"Upgrade {name} to a fixed version listed by OSV."
            findings.append(finding)
    return findings


def _query_osv(name: str, version: str, ecosystem: str) -> list[dict]:
    payload = json.dumps({
        "package": {"name": name, "ecosystem": ecosystem},
        "version": version,
    }).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as res:
            data = json.loads(res.read())
        vulns = data.get("vulns", [])
        return vulns if isinstance(vulns, list) else []
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return []


def _osv_cve(vuln: dict) -> str | None:
    aliases = vuln.get("aliases", [])
    for alias in aliases if isinstance(aliases, list) else []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return vuln.get("id")


def _osv_cwe(vuln: dict) -> str:
    database_specific = vuln.get("database_specific", {})
    cwe_ids = database_specific.get("cwe_ids", []) if isinstance(database_specific, dict) else []
    if isinstance(cwe_ids, list) and cwe_ids:
        return str(cwe_ids[0])
    return "CWE-Unknown"


def _osv_severity(vuln: dict) -> str:
    score = _osv_score(vuln, "medium")
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _osv_score(vuln: dict, fallback_severity) -> float:
    severities = vuln.get("severity", [])
    if isinstance(severities, list):
        for item in severities:
            if not isinstance(item, dict):
                continue
            score = str(item.get("score", ""))
            match = re.search(r"(\d+(?:\.\d+)?)", score)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    pass
    return {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5}.get(fallback_severity, 5.0)
