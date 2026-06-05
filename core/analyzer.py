import re
import json
import textwrap
from pathlib import Path

from core.config       import AI_SYSTEM_PROMPT
from core.ollama_client import OllamaClient
from core.file_utils   import (
    detect_language, read_file,
    normalise_severity, impact_for,
)


MAX_LINES_PER_CHUNK = 100
CHUNK_OVERLAP = 10


def _build_prompt(
    path: Path,
    language: str,
    lines: list[str],
    start_line: int = 0,
    project_context: str = "",
) -> str:
    numbered = "\n".join(
        f"{start_line + i + 1:>4} | {l}"
        for i, l in enumerate(lines)
    )
    context_block = ""
    if project_context:
        context_block = textwrap.dedent(f"""
            === PROJECT SECURITY CONTEXT ===

            {project_context}

            === END PROJECT SECURITY CONTEXT ===

        """)
    return textwrap.dedent(f"""
        FILE PATH : {path}
        LANGUAGE  : {language}
        LINES     : {len(lines)}

        {context_block}
        === FULL SOURCE CODE (with line numbers) ===

        {numbered}

        === END OF FILE ===

        Perform a complete security audit of the entire file above.
        Use the project security context to connect routes, inputs, auth checks,
        sanitizers, config, and dangerous sinks across files. Only report a
        finding when the current file or project context supports exploitability.
        Return ONLY a JSON array of findings. If clean, return [].
    """).strip()


def _parse_response(raw: str, lines: list[str], language: str,
                    path: Path) -> list[dict]:
    """Parse Ollama JSON response into normalised finding dicts."""
    raw = raw.strip()
    # strip markdown fences
    raw = re.sub(r"^```[a-zA-Z]*\s*", "", raw)
    raw = re.sub(r"\s*```$",          "", raw)
    raw = raw.strip()

    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return []

    try:
        items = json.loads(m.group(0))
    except json.JSONDecodeError:
        try:
            items = json.loads(m.group(0).rsplit(",", 1)[0] + "]")
        except Exception:
            return []

    if not isinstance(items, list):
        return []

    SEV_DEFAULT_SCORE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5}
    findings = []

    for item in items:
        if not isinstance(item, dict):
            continue

        sev = normalise_severity(item.get("severity", "medium"))
        fl  = max(1, int(item.get("from_line", 1)))
        tl  = max(fl, int(item.get("to_line", fl)))

        snip = "\n".join(lines[max(0, fl - 1): tl])

        try:
            score = float(item.get("severity_score", SEV_DEFAULT_SCORE[sev]))
        except (TypeError, ValueError):
            score = SEV_DEFAULT_SCORE[sev]

        ap = item.get("attack_path", {})
        if not isinstance(ap, dict):
            ap = {}

        findings.append({
            "type":           str(item.get("type", "Unknown Vulnerability")),
            "severity":       sev,
            "severity_score": score,
            "confidence":     str(item.get("confidence", "medium")),
            "cwe":            str(item.get("cwe", "CWE-Unknown")),
            "capec":          str(item.get("capec", "")),
            "cve_id":         None,          # never trust AI-fabricated CVEs
            "file":           str(path),
            "location":       {"from_line": fl, "to_line": tl},
            "code":           {"language": language, "snippet": snip},
            "attack_path": {
                "entry_point":   str(ap.get("entry_point",  "User-supplied input")),
                "prerequisites": (ap.get("prerequisites", [])
                                  if isinstance(ap.get("prerequisites"), list) else []),
                "impact":        str(ap.get("impact",      impact_for(sev))),
                "likelihood":    str(ap.get("likelihood",  "Medium")),
            },
            "explanation":  str(item.get("explanation", "")),
            "remediation":  str(item.get("remediation", "")),
            "evidence": {
                "input_source": str(item.get("input_source", "")),
                "sink":         str(item.get("sink", "")),
                "missing_control": str(item.get("missing_control", "")),
                "reason":       str(item.get("evidence", "")),
            },
            "validation": {
                "status": "unvalidated",
                "notes": "",
            },
            "source":       "ai",
        })

    return findings


def analyse_file(
    path: Path,
    ollama: OllamaClient,
    system_prompt: str,
    project_context: str = "",
) -> list[dict]:
    """
    Read the full file, send it to Ollama in chunks if needed, and return a list of findings.
    Returns [] if the file is empty, unreadable, or Ollama fails.
    """
    language = detect_language(path)
    text     = read_file(path)
    if not text or not text.strip():
        return []

    lines = text.splitlines()
    if not system_prompt:
        system_prompt = AI_SYSTEM_PROMPT

    findings: list[dict] = []
    if len(lines) <= MAX_LINES_PER_CHUNK:
        prompt = _build_prompt(path, language, lines, 0, project_context)
        try:
            raw = ollama.generate(prompt, system=system_prompt)
        except Exception as exc:
            raise RuntimeError(f"Ollama error on {path.name}: {exc}") from exc
        findings.extend(_parse_response(raw, lines, language, path))
    else:
        for chunk_start in range(0, len(lines), MAX_LINES_PER_CHUNK - CHUNK_OVERLAP):
            chunk_lines = lines[chunk_start:chunk_start + MAX_LINES_PER_CHUNK]
            prompt = _build_prompt(
                path,
                language,
                chunk_lines,
                chunk_start,
                project_context,
            )
            try:
                raw = ollama.generate(prompt, system=system_prompt)
            except Exception as exc:
                raise RuntimeError(f"Ollama error on {path.name}: {exc}") from exc
            findings.extend(_parse_response(raw, lines, language, path))

    return findings
