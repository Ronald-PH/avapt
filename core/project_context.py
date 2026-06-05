import json
import re
from pathlib import Path

from core.file_utils import read_file


MAX_CONTEXT_FILES = 80
MAX_ITEMS_PER_SECTION = 40
MAX_CONTEXT_CHARS = 12_000


SOURCE_PATTERNS = [
    r"\brequest\.(?:args|form|json|data|files|values|get_json)\b",
    r"\breq\.(?:body|query|params|headers|files)\b",
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b",
    r"\binput\s*\(",
]

SINK_PATTERNS = [
    r"\b(?:execute|executemany|raw|query)\s*\(",
    r"\b(?:eval|exec|compile|Function)\s*\(",
    r"\b(?:system|popen|subprocess|shell_exec|passthru|proc_open)\b",
    r"\b(?:open|readFile|writeFile|send_file)\s*\(",
    r"\b(?:render_template_string|innerHTML|dangerouslySetInnerHTML)\b",
]

SANITIZER_PATTERNS = [
    r"\b(?:escape|sanitize|clean|validate|validator|bleach|DOMPurify)\b",
    r"\b(?:parameterized|prepared statement|bind_param)\b",
]

AUTH_PATTERNS = [
    r"\b(?:login_required|permission_required|jwt_required|require_auth)\b",
    r"\b(?:authenticate|authorize|is_authenticated|current_user)\b",
    r"\b(?:auth|middleware|guard)\b",
]

ROUTE_PATTERNS = [
    r"@\w+\.route\([^)]+\)",
    r"\bapp\.(?:get|post|put|patch|delete)\([^)]+\)",
    r"\bRoute::(?:get|post|put|patch|delete|resource)\([^)]+\)",
    r"\brouter\.(?:get|post|put|patch|delete)\([^)]+\)",
]

CONFIG_PATTERNS = [
    r"\b(?:SECRET_KEY|DEBUG|DATABASE_URL|JWT_SECRET|API_KEY|TOKEN)\b",
    r"\b(?:os\.environ|getenv|process\.env|env\()\b",
]


def build_project_context(root: Path, code_files: list[Path]) -> str:
    """Build a compact map of security-relevant project signals."""
    items = {
        "routes": [],
        "input_sources": [],
        "dangerous_sinks": [],
        "auth_controls": [],
        "sanitizers": [],
        "config_and_secrets": [],
        "manifests": [],
    }

    for manifest in _find_manifests(root):
        items["manifests"].append(_rel(root, manifest))

    for path in code_files[:MAX_CONTEXT_FILES]:
        text = read_file(path)
        if not text:
            continue
        lines = text.splitlines()
        for idx, line in enumerate(lines, start=1):
            compact = line.strip()
            if not compact:
                continue
            _collect_match(items["routes"], root, path, idx, compact, ROUTE_PATTERNS)
            _collect_match(items["input_sources"], root, path, idx, compact, SOURCE_PATTERNS)
            _collect_match(items["dangerous_sinks"], root, path, idx, compact, SINK_PATTERNS)
            _collect_match(items["auth_controls"], root, path, idx, compact, AUTH_PATTERNS)
            _collect_match(items["sanitizers"], root, path, idx, compact, SANITIZER_PATTERNS)
            _collect_match(items["config_and_secrets"], root, path, idx, compact, CONFIG_PATTERNS)

    compact_items = {
        section: values[:MAX_ITEMS_PER_SECTION]
        for section, values in items.items()
        if values
    }
    if not compact_items:
        return ""

    context = json.dumps(compact_items, indent=2)
    if len(context) > MAX_CONTEXT_CHARS:
        context = context[:MAX_CONTEXT_CHARS].rsplit("\n", 1)[0] + "\n..."
    return context


def _collect_match(
    bucket: list[str],
    root: Path,
    path: Path,
    line_no: int,
    line: str,
    patterns: list[str],
) -> None:
    if len(bucket) >= MAX_ITEMS_PER_SECTION:
        return
    if any(re.search(pattern, line, re.IGNORECASE) for pattern in patterns):
        bucket.append(f"{_rel(root, path)}:{line_no}: {_shorten(line)}")


def _find_manifests(root: Path) -> list[Path]:
    if root.is_file():
        return [root] if root.name in {"package.json", "requirements.txt", "pyproject.toml"} else []
    manifests = []
    for name in ("package.json", "requirements.txt", "pyproject.toml", "Pipfile", "composer.json"):
        manifests.extend(root.rglob(name))
    return sorted(manifests)


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _shorten(value: str, limit: int = 220) -> str:
    value = " ".join(value.split())
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
