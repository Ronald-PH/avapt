import sys
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.config               import VERSION, MAX_AI_WORKERS, SEV_ORDER
from core.ollama_client        import OllamaClient
from core.file_utils           import collect_files, is_code_file, detect_language, dedup_findings
from core.analyzer             import analyse_file
from core.dependency_scanner   import scan_dependencies


def run_scan(
    root: str,
    prompt: str,
    ollama: OllamaClient,
    workers: int = MAX_AI_WORKERS,
    progress_cb=None,       # optional callback(done, total, filename, findings)
) -> dict:
    """
    Full scan pipeline:
      Phase 1 — AI analysis of every code file (parallel)
      Phase 2 — Dependency manifest scan

    progress_cb signature: (done: int, total: int, filename: str, count: int)
    """
    root_path = Path(root).resolve()
    if not root_path.exists():
        print(f"[ERROR] Path not found: {root}", file=sys.stderr)
        sys.exit(1)

    if not ollama.is_available():
        raise ConnectionError(
            f"Cannot reach Ollama at {ollama.base_url}.\n"
            f"  Start Ollama:      ollama serve\n"
            f"  Pull the model:    ollama pull {ollama.model}"
        )

    all_files  = collect_files(root_path)
    code_files = [f for f in all_files if is_code_file(f)]
    langs      = sorted({detect_language(f) for f in code_files})

    _log(f"\n{'═'*64}")
    _log(f"  avapt v{VERSION}  —  AI-Powered Security Scanner")
    _log(f"{'═'*64}")
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
    _log(f"{'═'*64}\n")
    _log(f"  Files found   : {len(all_files)}")
    _log(f"  Code files    : {len(code_files)}")
    _log(f"  Languages     : {', '.join(langs) or 'none detected'}\n")

    all_findings: list[dict] = []

    # ── Phase 1: AI analysis ─────────────────────────────────────────────────
    _log(f"[1/2] Sending {len(code_files)} file(s) to AI for full semantic analysis...\n")

    def _analyse(f: Path):
        return f, analyse_file(f, ollama, system_prompt=prompt)

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
                    _log(f"  [{done:>3}/{len(code_files)}] {f.name}: "
                         f"{len(results)} finding(s)  [{sevs}]")
                else:
                    _log(f"  [{done:>3}/{len(code_files)}] {f.name}: clean")

                if progress_cb:
                    progress_cb(done, len(code_files), f.name,
                                len(results) if results else 0)
            except Exception as exc:
                _log(f"  [{done:>3}/{len(code_files)}] {f.name}: ERROR — {exc}")
                if progress_cb:
                    progress_cb(done, len(code_files), f.name, 0)

    ai_count = len(all_findings)
    _log(f"\n  AI findings   : {ai_count}\n")

    # ── Phase 2: dependency scan ─────────────────────────────────────────────
    _log("[2/2] Scanning dependency manifests...\n")
    dep_findings = scan_dependencies(root_path)
    all_findings.extend(dep_findings)
    _log(f"  Dependency findings: {len(dep_findings)}\n")

    # ── dedup + summarise ─────────────────────────────────────────────────────
    all_findings = dedup_findings(all_findings)
    all_findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    src_counts: dict[str, int] = {}
    for f in all_findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        k = f.get("source", "ai")
        src_counts[k] = src_counts.get(k, 0) + 1

    _log(f"{'─'*64}")
    _log(f"  TOTAL : {len(all_findings)} findings  "
         f"(C:{counts['critical']}  H:{counts['high']}  "
         f"M:{counts['medium']}  L:{counts['low']})")
    _log(f"  FROM  : ai={src_counts.get('ai', 0)}  "
         f"deps={src_counts.get('dependency', 0)}")
    _log(f"{'─'*64}\n")

    return {
        "meta": {
            "tool":          "avapt",
            "version":       VERSION,
            "scan_root":     str(root_path),
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(all_files),
            "code_files":    len(code_files),
            "languages":     langs,
            "ai_model":      ollama.model,
            "ollama_url":    ollama.base_url,
        },
        "summary":       counts,
        "source_counts": src_counts,
        "findings":      all_findings,
    }


def _log(msg: str):
    print(msg, flush=True)
