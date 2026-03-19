import json
from agents.nemotron_client import chat_completion
from core.sse_manager import SSEManager

PATCHER_SYSTEM_PROMPT = """You are a security patch generator. You receive findings from multiple scanning layers:
- Exposed secrets (hardcoded credentials, API keys, tokens)
- Dependency CVEs (with known fix versions)
- Code-level vulnerabilities (injection, XSS, auth bypass, etc.)
- Configuration issues (Dockerfile, IaC misconfigurations)

For each finding, generate the appropriate fix. Output a JSON array wrapped in <patches> tags:

<patches>
[
  {
    "vuln_id": "VULN-001",
    "finding_source": "secret_scanner|osv_cve|code_analysis|config_audit",
    "file": "path/to/file.py",
    "fix_type": "code_patch|version_bump|config_change|gitignore_add",
    "original_code": "the vulnerable code block",
    "patched_code": "the fixed code block",
    "explanation": "What this fix does and why",
    "commands": ["npm install lodash@4.17.21"],
    "breaking_risk": "LOW|MEDIUM|HIGH",
    "breaking_notes": "what might break (if medium/high)"
  }
]
</patches>

FIX STRATEGIES BY TYPE:
- Secrets: Move to environment variables, add to .gitignore, show .env.example pattern
- Dependency CVEs: Recommend exact safe version, provide install command
- Code vulns: Minimal code patch using established security patterns (parameterized queries, etc.)
- Config issues: Fixed config snippet (e.g., non-root Dockerfile USER directive)

RULES:
- Minimal changes only. Don't refactor unrelated code.
- The patch must be syntactically valid in the target language.
- Prefer well-established security patterns.
- If you're not confident in a fix, say so.
- IMPORTANT: Return ONLY the <patches> block, no other text.
"""


async def run_patcher(
    all_findings: list[dict],
    repo_context: str,
    sse: SSEManager,
) -> list[dict]:
    if not all_findings:
        await sse.emit_status("patcher_agent", "complete", "No findings to patch")
        return []

    await sse.emit_status("patcher_agent", "running", f"Generating patches for {len(all_findings)} findings...")

    findings_summary = json.dumps(all_findings, indent=2)

    messages = [
        {"role": "system", "content": PATCHER_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"## Security Findings\n{findings_summary}\n\n"
                f"## Repository Code (for context)\n{repo_context[:200000]}"
            ),
        },
    ]

    try:
        response = await chat_completion(messages, temperature=0.3, max_tokens=16384)
        content = response.get("content", "")
        patches = _parse_patches(content)
    except Exception as e:
        await sse.emit_error("patcher_agent", f"Patcher failed: {str(e)}")
        patches = _generate_fallback_patches(all_findings)

    for patch in patches:
        await sse.emit_patch(patch)

    await sse.emit_status("patcher_agent", "complete", f"Generated {len(patches)} patches")
    return patches


def _parse_patches(text: str) -> list[dict]:
    start_tag = "<patches>"
    end_tag = "</patches>"
    start = text.find(start_tag)
    end = text.find(end_tag)

    if start >= 0 and end > start:
        json_str = text[start + len(start_tag):end].strip()
    else:
        json_str = text.strip()
        arr_start = json_str.find("[")
        arr_end = json_str.rfind("]") + 1
        if arr_start >= 0 and arr_end > arr_start:
            json_str = json_str[arr_start:arr_end]
        else:
            return []

    try:
        patches = json.loads(json_str)
        if isinstance(patches, list):
            return patches
    except json.JSONDecodeError:
        pass

    return []


def _generate_fallback_patches(findings: list[dict]) -> list[dict]:
    patches = []
    for f in findings:
        source = f.get("source", "")
        patch = {
            "vuln_id": f.get("id", ""),
            "finding_source": source,
            "file": f.get("file", ""),
            "fix_type": "code_patch",
            "original_code": f.get("evidence", ""),
            "patched_code": "",
            "explanation": "",
            "commands": [],
            "breaking_risk": "LOW",
            "breaking_notes": "",
        }

        if source == "secrets":
            patch["fix_type"] = "gitignore_add"
            patch["explanation"] = f"Move secret to environment variable. Add {f.get('file', '')} to .gitignore if it's a .env file."
            patch["patched_code"] = f"os.environ.get('{f.get('details', {}).get('pattern', 'SECRET_KEY')}')"

        elif source == "osv":
            details = f.get("details", {})
            patch["fix_type"] = "version_bump"
            fix_ver = details.get("fix_version", "latest")
            pkg = details.get("package", "")
            ecosystem = details.get("ecosystem", "")

            if ecosystem == "npm":
                patch["commands"] = [f"npm install {pkg}@{fix_ver}"]
            elif ecosystem == "PyPI":
                patch["commands"] = [f"pip install {pkg}=={fix_ver}"]
            elif ecosystem == "Go":
                patch["commands"] = [f"go get {pkg}@v{fix_ver}"]

            patch["explanation"] = f"Upgrade {pkg} to {fix_ver} to fix {details.get('cve_id', 'known CVE')}"

        else:
            patch["explanation"] = f"Review and fix: {f.get('description', f.get('title', ''))}"

        patches.append(patch)

    return patches
