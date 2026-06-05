import json
from pathlib import Path


SEVERITY_LEVELS = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def build_sarif(result: dict) -> str:
    rules: dict[str, dict] = {}
    sarif_results = []

    for finding in result.get("findings", []):
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": finding.get("type", "AVAPT Finding"),
                "shortDescription": {"text": finding.get("type", "AVAPT Finding")},
                "fullDescription": {"text": finding.get("explanation", "")[:1000]},
                "help": {"text": finding.get("remediation", "")},
                "properties": {
                    "security-severity": str(finding.get("severity_score", "")),
                    "precision": finding.get("confidence", "medium"),
                    "tags": [finding.get("cwe", "")],
                },
            }

        location = finding.get("location", {})
        sarif_results.append({
            "ruleId": rule_id,
            "level": SEVERITY_LEVELS.get(finding.get("severity"), "warning"),
            "message": {"text": finding.get("explanation") or finding.get("type", "")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _uri(finding.get("file", ""))},
                    "region": {
                        "startLine": int(location.get("from_line", 1)),
                        "endLine": int(location.get("to_line", location.get("from_line", 1))),
                    },
                }
            }],
            "partialFingerprints": {
                "avapt": finding.get("fingerprint", ""),
            },
            "properties": {
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "source": finding.get("source"),
                "validation": finding.get("validation", {}),
                "evidence": finding.get("evidence", {}),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "aVAPT",
                    "version": result.get("meta", {}).get("version", ""),
                    "informationUri": "https://github.com/Ronald-PH/avapt",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(sarif, indent=2)


def _rule_id(finding: dict) -> str:
    cwe = str(finding.get("cwe") or "CWE-Unknown").replace(" ", "-")
    vuln_type = str(finding.get("type") or "Finding").lower().replace(" ", "-")
    return f"AVAPT.{cwe}.{vuln_type}"


def _uri(path: str) -> str:
    try:
        return Path(path).as_posix()
    except Exception:
        return path.replace("\\", "/")
