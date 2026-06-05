from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config import (
    VERSION, MAX_AI_WORKERS, SEV_ORDER,
    SCAN_PROFILES, DEFAULT_SCAN_PROFILE,
)
from core.ollama_client import OllamaClient
from core.file_utils import (
    collect_files, is_code_file, detect_language,
    dedup_findings, finding_fingerprint, read_file,
)
from core.analyzer import analyse_file
from core.dependency_scanner import scan_dependencies
from core.project_context import build_project_context
from core.validator import validate_findings
from core.baseline import load_baseline, apply_baseline


PREFILTER_PATTERNS = (
    "request.", "req.", "$_GET", "$_POST", "$_REQUEST",
    "execute(", "query(", "raw(", "eval(", "exec(",
    "subprocess", "system(", "shell_exec", "unserialize",
    "innerHTML", "dangerouslySetInnerHTML", "render_template_string",
    "secret", "token", "password", "api_key", "jwt",
)


def run_scan(
    root: str,
    prompt: str,
    ollama: OllamaClient,
    workers: int = MAX_AI_WORKERS,
    profile: str = DEFAULT_SCAN_PROFILE,
    baseline_path: str = "",
    progress_cb=None,
) -> dict:
    """
    Full scan pipeline:
      Phase 1: AI analysis of code files
      Phase 2: optional AI validation
      Phase 3: dependency manifest scan
      Phase 4: deduplication, baseline filtering, and summary
    """
    root_path = Path(root).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Path not found: {root}")

    if not ollama.is_available():
        raise ConnectionError(
            f"Cannot reach Ollama at {ollama.base_url}.\n"
            f"  Start Ollama:      ollama serve\n"
            f"  Pull the model:    ollama pull {ollama.model}"
        )

    profile_name = profile if profile in SCAN_PROFILES else DEFAULT_SCAN_PROFILE
    profile_cfg = SCAN_PROFILES[profile_name]

    all_files = collect_files(root_path)
    code_files = [f for f in all_files if is_code_file(f)]
    original_code_count = len(code_files)
    if profile_cfg.get("prefilter"):
        code_files = _prefilter_code_files(code_files)

    langs = sorted({detect_language(f) for f in code_files})
    project_context = (
        build_project_context(root_path, code_files)
        if profile_cfg.get("use_context")
        else ""
    )

    _log(f"\n{'=' * 64}")
    _log(f"  avapt v{VERSION}  -  AI-Powered Security Scanner")
    _log(f"{'=' * 64}")
    _log(f"  Target    : {root_path}")
    _log(f"  AI Model  : {ollama.model}  @  {ollama.base_url}")
    models = ollama.list_models()
    if models:
        if ollama.model not in models:
            fallback = models[0]
            _log(f"  WARNING  : requested model '{ollama.model}' not available; falling back to '{fallback}'")
            ollama.model = fallback
        _log(f"  Models    : {', '.join(models[:6])}")
    _log(f"  Workers   : {workers}")
    _log(f"  Profile   : {profile_cfg['label']}")
    _log(f"{'=' * 64}\n")
    _log(f"  Files found   : {len(all_files)}")
    _log(f"  Code files    : {len(code_files)}")
    if profile_cfg.get("prefilter"):
        _log(f"  Prefiltered   : {original_code_count - len(code_files)} skipped")
    _log(f"  Languages     : {', '.join(langs) or 'none detected'}")
    if project_context:
        _log(f"  Context map   : {len(project_context)} chars")
    _log("")

    all_findings: list[dict] = []

    _log(f"[1/3] Sending {len(code_files)} file(s) to AI for semantic analysis...\n")

    def _analyse(f: Path):
        return f, analyse_file(
            f,
            ollama,
            system_prompt=prompt,
            project_context=project_context,
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_analyse, f): f for f in code_files}
        done = 0
        for fut in as_completed(futures):
            done += 1
            f = futures[fut]
            try:
                _, results = fut.result()
                if results:
                    all_findings.extend(results)
                    sevs = ", ".join(
                        f"{r['severity']}({r['severity_score']})" for r in results
                    )
                    _log(f"  [{done:>3}/{len(code_files)}] {f.name}: {len(results)} finding(s)  [{sevs}]")
                else:
                    _log(f"  [{done:>3}/{len(code_files)}] {f.name}: clean")

                if progress_cb:
                    progress_cb(done, len(code_files), f.name, len(results) if results else 0)
            except Exception as exc:
                _log(f"  [{done:>3}/{len(code_files)}] {f.name}: ERROR - {exc}")
                if progress_cb:
                    progress_cb(done, len(code_files), f.name, 0)

    _log(f"\n  AI findings   : {len(all_findings)}\n")

    if profile_cfg.get("validate") and all_findings:
        _log("[2/3] Validating AI findings...\n")
        before_validation = len(all_findings)
        all_findings = validate_findings(all_findings, ollama, project_context)
        _log(f"  Validation kept: {len(all_findings)} / {before_validation}\n")
    else:
        _log("[2/3] Validation skipped by scan profile.\n")

    _log("[3/3] Scanning dependency manifests...\n")
    dep_findings = scan_dependencies(root_path, use_osv=profile_cfg.get("osv", False))
    all_findings.extend(dep_findings)
    _log(f"  Dependency findings: {len(dep_findings)}\n")

    all_findings = dedup_findings(all_findings)
    for finding in all_findings:
        finding.setdefault("fingerprint", finding_fingerprint(finding))

    baseline_count = 0
    if baseline_path:
        baseline_fingerprints = load_baseline(baseline_path)
        all_findings, baseline_count = apply_baseline(all_findings, baseline_fingerprints)
        _log(f"  Baseline suppressed: {baseline_count}\n")

    all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
    counts, src_counts = _summarise(all_findings)

    _log(f"{'-' * 64}")
    _log(
        f"  TOTAL : {len(all_findings)} findings  "
        f"(C:{counts['critical']}  H:{counts['high']}  "
        f"M:{counts['medium']}  L:{counts['low']})"
    )
    _log(f"  FROM  : ai={src_counts.get('ai', 0)}  deps={src_counts.get('dependency', 0)}")
    _log(f"{'-' * 64}\n")

    return {
        "meta": {
            "tool": "avapt",
            "version": VERSION,
            "scan_root": str(root_path),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(all_files),
            "code_files": len(code_files),
            "code_files_before_prefilter": original_code_count,
            "languages": langs,
            "ai_model": ollama.model,
            "ollama_url": ollama.base_url,
            "project_context": bool(project_context),
            "scan_profile": profile_name,
            "validation": bool(profile_cfg.get("validate")),
            "osv": bool(profile_cfg.get("osv")),
            "baseline_suppressed": baseline_count,
        },
        "summary": counts,
        "source_counts": src_counts,
        "findings": all_findings,
    }


def _log(msg: str):
    print(msg, flush=True)


def _prefilter_code_files(files: list[Path]) -> list[Path]:
    selected = []
    for path in files:
        text = read_file(path).lower()
        if any(pattern.lower() in text for pattern in PREFILTER_PATTERNS):
            selected.append(path)
    return selected or files


def _summarise(findings: list[dict]) -> tuple[dict, dict]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    src_counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "medium")
        counts[severity] = counts.get(severity, 0) + 1
        source = finding.get("source", "ai")
        src_counts[source] = src_counts.get(source, 0) + 1
    return counts, src_counts
