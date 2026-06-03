import re
import json
from pathlib import Path

from core.config     import KNOWN_VULN_PACKAGES, SKIP_DIRS
from core.file_utils import version_below, impact_for


def _dep_finding(file: str, name: str, ver: str, vuln: dict, lang: str) -> dict:
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
        "source":       "dependency",
    }


def scan_dependencies(root: Path) -> list[dict]:
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
        except Exception:
            pass

    return findings
