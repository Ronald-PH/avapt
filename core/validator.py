import json
import re
import textwrap

from core.file_utils import normalise_severity
from core.ollama_client import OllamaClient


MAX_FINDINGS_PER_VALIDATION = 12


def validate_findings(
    findings: list[dict],
    ollama: OllamaClient,
    project_context: str = "",
) -> list[dict]:
    """Ask the model to validate AI findings and drop likely false positives."""
    ai_findings = [f for f in findings if f.get("source") == "ai"]
    other_findings = [f for f in findings if f.get("source") != "ai"]
    if not ai_findings:
        return findings

    validated: list[dict] = []
    by_id = {str(i): f for i, f in enumerate(ai_findings)}

    for offset in range(0, len(ai_findings), MAX_FINDINGS_PER_VALIDATION):
        chunk = ai_findings[offset:offset + MAX_FINDINGS_PER_VALIDATION]
        payload = []
        for idx, finding in enumerate(chunk, start=offset):
            payload.append({
                "id": str(idx),
                "type": finding.get("type"),
                "severity": finding.get("severity"),
                "confidence": finding.get("confidence"),
                "file": finding.get("file"),
                "location": finding.get("location"),
                "cwe": finding.get("cwe"),
                "attack_path": finding.get("attack_path"),
                "explanation": finding.get("explanation"),
                "remediation": finding.get("remediation"),
                "evidence": finding.get("evidence", {}),
            })

        prompt = _build_validation_prompt(payload, project_context)
        try:
            raw = ollama.generate(prompt)
        except Exception:
            for finding in chunk:
                finding["validation"] = {
                    "status": "validation_error",
                    "notes": "Validation pass could not complete",
                }
                validated.append(finding)
            continue

        decisions = _parse_decisions(raw)
        for item_id, finding in [(str(i), by_id[str(i)]) for i in range(offset, offset + len(chunk))]:
            decision = decisions.get(item_id)
            if not decision:
                finding["validation"] = {"status": "unvalidated", "notes": "No validator decision returned"}
                validated.append(finding)
                continue
            if str(decision.get("status", "")).lower() == "drop":
                continue
            _apply_decision(finding, decision)
            validated.append(finding)

    return validated + other_findings


def _build_validation_prompt(findings: list[dict], project_context: str) -> str:
    context = project_context or "No project context was available."
    return textwrap.dedent(f"""
        You are validating candidate SAST findings for false positives.

        PROJECT SECURITY CONTEXT:
        {context}

        CANDIDATE FINDINGS:
        {json.dumps(findings, indent=2)}

        Return ONLY a JSON array. For each candidate, return:
        {{
          "id": "<candidate id>",
          "status": "<keep|revise|drop>",
          "severity": "<critical|high|medium|low>",
          "confidence": "<high|medium|low>",
          "notes": "<brief evidence-based validation note>",
          "evidence": {{
            "input_source": "<attacker-controlled source or empty>",
            "sink": "<dangerous sink or empty>",
            "missing_control": "<missing auth/sanitizer/control or empty>",
            "reason": "<short evidence summary>"
          }}
        }}

        Keep only findings with a plausible reachable attack path. Drop findings
        when the source, sink, or missing control is not supported by the provided
        finding and project context. Do not output markdown or prose.
    """).strip()


def _parse_decisions(raw: str) -> dict[str, dict]:
    raw = raw.strip()
    raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
    raw = re.sub(r"\s*```$", "", raw).strip()
    match = re.search(r"\[.*\]", raw, re.DOTALL)
    if not match:
        return {}
    try:
        data = json.loads(match.group(0))
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, list):
        return {}
    return {
        str(item.get("id")): item
        for item in data
        if isinstance(item, dict) and item.get("id") is not None
    }


def _apply_decision(finding: dict, decision: dict) -> None:
    status = str(decision.get("status", "keep")).lower()
    if status not in {"keep", "revise"}:
        status = "keep"
    finding["severity"] = normalise_severity(decision.get("severity", finding.get("severity", "medium")))
    finding["confidence"] = str(decision.get("confidence", finding.get("confidence", "medium")))
    if isinstance(decision.get("evidence"), dict):
        finding["evidence"] = {
            **finding.get("evidence", {}),
            **decision["evidence"],
        }
    finding["validation"] = {
        "status": status,
        "notes": str(decision.get("notes", "")),
    }
