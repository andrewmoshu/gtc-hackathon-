import os
import re
from core.sse_manager import SSEManager

PATTERNS = [
    {
        "name": "AWS Access Key",
        "pattern": r"(?:^|['\"\s=])(?P<match>AKIA[0-9A-Z]{16})(?:['\"\s]|$)",
        "severity": "CRITICAL",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?(?P<match>[A-Za-z0-9/+=]{40})['\"]?",
        "severity": "CRITICAL",
    },
    {
        "name": "GitHub Token",
        "pattern": r"(?P<match>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})",
        "severity": "CRITICAL",
    },
    {
        "name": "GitHub PAT (fine-grained)",
        "pattern": r"(?P<match>github_pat_[A-Za-z0-9_]{22,255})",
        "severity": "CRITICAL",
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"(?P<match>sk_live_[A-Za-z0-9]{24,99})",
        "severity": "CRITICAL",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": r"(?P<match>pk_live_[A-Za-z0-9]{24,99})",
        "severity": "MEDIUM",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"(?P<match>https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+)",
        "severity": "HIGH",
    },
    {
        "name": "RSA Private Key",
        "pattern": r"(?P<match>-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)",
        "severity": "CRITICAL",
    },
    {
        "name": "Generic API Key Assignment",
        "pattern": r"(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[=:]\s*['\"](?P<match>[A-Za-z0-9_\-]{16,})['\"]",
        "severity": "HIGH",
    },
    {
        "name": "Generic Secret/Token Assignment",
        "pattern": r"(?:secret|token|password|passwd|pwd)\s*[=:]\s*['\"](?P<match>[^\s'\"]{8,})['\"]",
        "severity": "HIGH",
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?P<match>(?:mysql|postgres|postgresql|mongodb|redis|amqp)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)",
        "severity": "CRITICAL",
    },
    {
        "name": "JWT Secret",
        "pattern": r"(?:jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*['\"](?P<match>[^\s'\"]{8,})['\"]",
        "severity": "HIGH",
    },
    {
        "name": "Google API Key",
        "pattern": r"(?P<match>AIza[0-9A-Za-z_-]{35})",
        "severity": "HIGH",
    },
    {
        "name": "Heroku API Key",
        "pattern": r"(?:heroku[_-]?api[_-]?key)\s*[=:]\s*['\"]?(?P<match>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"(?P<match>SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})",
        "severity": "HIGH",
    },
]

SKIP_DIRS = {".git", "node_modules", "vendor", "__pycache__", "dist", "build", ".venv", "venv"}

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".rs",
    ".php", ".cs", ".c", ".cpp", ".h", ".yml", ".yaml", ".json", ".xml",
    ".toml", ".ini", ".cfg", ".conf", ".env", ".sh", ".bash", ".zsh",
    ".tf", ".hcl", ".properties", ".gradle", ".dockerfile",
    "", # files with no extension (Dockerfile, Makefile, etc.)
}


async def scan_secrets(repo_dir: str, sse: SSEManager) -> list[dict]:
    await sse.emit_status("secret_scanner", "running", "Scanning for exposed secrets...")
    findings = []
    finding_id = 0

    compiled = [(p, re.compile(p["pattern"], re.IGNORECASE | re.MULTILINE)) for p in PATTERNS]

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            basename = fname.lower()

            if ext not in SCAN_EXTENSIONS and basename not in {"dockerfile", "makefile", ".env", ".env.local", ".env.production"}:
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, repo_dir)

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except (OSError, UnicodeDecodeError):
                continue

            # Special case: .env files committed to repo
            if basename in {".env", ".env.local", ".env.production", ".env.development"}:
                finding_id += 1
                finding = {
                    "id": f"SECRET-{finding_id:03d}",
                    "source": "secrets",
                    "severity": "HIGH",
                    "title": f"Environment file committed to repo: {rel_path}",
                    "file": rel_path,
                    "line": 1,
                    "description": f"The file `{rel_path}` appears to be an environment configuration file that may contain secrets. These files should be added to .gitignore.",
                    "details": {"pattern": ".env file", "matched_text": f"[file: {rel_path}]"},
                }
                findings.append(finding)
                await sse.emit_finding(finding)

            for pattern_def, regex in compiled:
                for match in regex.finditer(content):
                    line_num = content[:match.start()].count("\n") + 1
                    matched_text = match.group("match") if "match" in match.groupdict() else match.group(0)

                    # Mask the middle of the secret for display
                    if len(matched_text) > 8:
                        display = matched_text[:4] + "*" * (len(matched_text) - 8) + matched_text[-4:]
                    else:
                        display = matched_text[:2] + "*" * (len(matched_text) - 2)

                    finding_id += 1
                    finding = {
                        "id": f"SECRET-{finding_id:03d}",
                        "source": "secrets",
                        "severity": pattern_def["severity"],
                        "title": f"{pattern_def['name']} in {rel_path}:{line_num}",
                        "file": rel_path,
                        "line": line_num,
                        "description": f"Found a potential {pattern_def['name']} ({display}) at line {line_num}.",
                        "details": {
                            "pattern": pattern_def["name"],
                            "matched_text": display,
                        },
                    }
                    findings.append(finding)
                    await sse.emit_finding(finding)

    await sse.emit_status("secret_scanner", "complete", f"Found {len(findings)} potential secrets")
    return findings
