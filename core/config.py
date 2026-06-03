VERSION          = "1.0.0"
MAX_FILE_BYTES   = 200_000
MAX_AI_WORKERS   = 3
AI_TIMEOUT_SECS  = 180
AI_TEMPERATURE   = 0.1
AI_NUM_PREDICT   = 4096
DEFAULT_MODEL    = "deepseek-r1:7b"
DEFAULT_OLLAMA   = "http://localhost:11434"
HAS_REPORTLAB = True
LANG_MAP = {
    ".py":"Python",    ".js":"JavaScript", ".ts":"TypeScript",
    ".jsx":"JavaScript",".tsx":"TypeScript",".php":"PHP",
    ".java":"Java",    ".rb":"Ruby",       ".go":"Go",
    ".cs":"C#",        ".cpp":"C++",       ".c":"C",
    ".rs":"Rust",      ".kt":"Kotlin",     ".swift":"Swift",
    ".sh":"Shell",     ".bash":"Shell",    ".html":"HTML",
    ".xml":"XML",      ".yaml":"YAML",     ".yml":"YAML",
    ".env":"Env",      ".tf":"Terraform",  ".sol":"Solidity",
    ".lua":"Lua",      ".pl":"Perl",       ".r":"R",
    ".scala":"Scala",  ".ex":"Elixir",     ".exs":"Elixir",
    ".vue":"Vue",      ".svelte":"Svelte", ".dart":"Dart",
}

SKIP_DIRS = {
    ".git","node_modules","__pycache__",".venv","venv",
    ".tox","dist","build",".idea",".vscode","coverage",
    "vendor",".next",".nuxt","target","out","public/build",
}

SKIP_EXTS = {
    ".png",".jpg",".jpeg",".gif",".svg",".ico",
    ".woff",".woff2",".ttf",".eot",".otf",
    ".pdf",".zip",".tar",".gz",".rar",".7z",
    ".exe",".bin",".pyc",".class",".o",".so",".dll",
    ".lock",".map",".min.js",
}

KNOWN_VULN_PACKAGES = {
    "lodash":               {"below":"4.17.21","cve":"CVE-2021-23337","severity":"high",    "score":7.2,"cwe":"CWE-78", "desc":"Prototype pollution / command injection via lodash.template"},
    "axios":                {"below":"0.21.2", "cve":"CVE-2021-3749", "severity":"high",    "score":7.5,"cwe":"CWE-918","desc":"SSRF via URL normalization bypass"},
    "express":              {"below":"4.18.2", "cve":None,            "severity":"medium",  "score":5.0,"cwe":"CWE-400","desc":"Multiple DoS and prototype pollution issues"},
    "jsonwebtoken":         {"below":"9.0.0",  "cve":"CVE-2022-23529","severity":"high",    "score":8.1,"cwe":"CWE-347","desc":"JWT algorithm confusion / secret injection"},
    "serialize-javascript": {"below":"6.0.2",  "cve":"CVE-2022-25878","severity":"medium",  "score":6.1,"cwe":"CWE-94", "desc":"Arbitrary code execution via malicious serialized input"},
    "django":               {"below":"4.2.0",  "cve":"CVE-2023-23969","severity":"medium",  "score":5.3,"cwe":"CWE-400","desc":"Potential DoS via multipart form parsing"},
    "flask":                {"below":"2.3.0",  "cve":None,            "severity":"low",     "score":3.1,"cwe":"CWE-200","desc":"Debug mode information disclosure"},
    "requests":             {"below":"2.28.0", "cve":"CVE-2023-32681","severity":"medium",  "score":6.1,"cwe":"CWE-601","desc":"Proxy authentication header leak via redirect"},
    "pyyaml":               {"below":"6.0",    "cve":"CVE-2022-1471", "severity":"critical","score":9.8,"cwe":"CWE-502","desc":"Arbitrary code execution via yaml.load()"},
    "pillow":               {"below":"10.0.0", "cve":"CVE-2023-44271","severity":"high",    "score":7.5,"cwe":"CWE-400","desc":"Uncontrolled resource consumption in ImageFont"},
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

AI_SYSTEM_PROMPT = """You are a senior application security engineer performing a full manual code review.
You will be given the COMPLETE source code of a file with line numbers.

YOUR TASK:
Read the entire file and identify every real, exploitable security vulnerability.
Do not assume any framework unless it is explicit in the code.

IMPORTANT:
- Return ONLY a valid JSON array of findings.
- Do not output markdown, prose, comments, or analysis.
- Do not output chain-of-thought, reasoning, or internal notes.
- If there are no vulnerabilities, return exactly [].

Each finding must use this schema exactly:
{
  "type": "<vulnerability class>",
  "severity": "<critical|high|medium|low>",
  "severity_score": <float 1.0-10.0>,
  "confidence": "<high|medium|low>",
  "cwe": "<CWE-NNN>",
  "capec": "<CAPEC-NNN or empty string>",
  "cve_id": null,
  "from_line": <int>,
  "to_line": <int>,
  "explanation": "<root cause and why this is exploitable>",
  "attack_path": {
    "entry_point": "<where attacker input enters>",
    "prerequisites": ["<condition>"],
    "impact": "<what attacker achieves>",
    "likelihood": "<High|Medium|Low>"
  },
  "remediation": "<specific actionable fix>"
}

VULNERABILITY CLASSES TO DETECT (not limited to):
- Injection: SQL, NoSQL, LDAP, OS Command, Code, Template, XPath, PHP eval/include/require
- XSS: Reflected, Stored, DOM-based
- SSRF, CSRF, XXE, Open Redirect
- Authentication Bypass, Broken Auth, Weak Credentials, Hardcoded Secrets
- Authorization Flaws, IDOR, Privilege Escalation, Mass Assignment
- Insecure Deserialization, Type Confusion, PHP unserialize/object injection
- Path Traversal, LFI, RFI, unsafe file operations
- JWT Weaknesses, Weak Cryptography, Insecure Randomness
- Race Conditions, Business Logic Flaws
- Information Disclosure, Debug Exposure, phpinfo exposure
- PHP-specific: unsafe extract(), variable variables ($$var), preg_replace /e, etc.
"""
