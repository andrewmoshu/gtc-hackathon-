import json
import logging
from agents.nemotron_client import chat_completion
from tools.run_command import run_command_tool
from core.sse_manager import SSEManager

logger = logging.getLogger("codesentinel.verifier")

VERIFIER_SYSTEM_PROMPT = """You are a senior security engineer performing a final review of vulnerability findings.
Another AI agent found these vulnerabilities. Your job is to verify each one and dismiss false positives.

For each finding, you can use run_command to inspect the actual code and verify:
1. Is the vulnerable code pattern actually present at the reported location?
2. Is user input actually reaching the dangerous sink without sanitization?
3. Are there framework protections (CSRF tokens, parameterized queries, input validation) that make this safe?
4. Is this a test file, example, or dead code that isn't actually deployed?

After reviewing, call verify_finding for EACH finding with your verdict.

TOOLS:
- run_command(command): Execute shell commands to inspect the code.
- verify_finding(finding_id, verdict, reason): Submit your verdict for a finding.
  verdict must be "confirmed", "downgraded", or "dismissed".
  If "downgraded", also provide new_severity.

Be strict. Only confirm findings that are genuinely exploitable. Dismiss anything that:
- Has proper sanitization/escaping in place
- Uses parameterized queries or ORM methods correctly
- Is behind authentication/authorization checks that prevent exploitation
- Is in test/example code not used in production
- Relies on assumptions that don't hold (e.g., "attacker needs admin access" when admin is trusted)

When you've reviewed ALL findings, stop calling tools.
"""

VERIFY_FINDING_SCHEMA = {
    "type": "function",
    "function": {
        "name": "verify_finding",
        "description": "Submit your verification verdict for a finding.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "The finding ID (e.g., 'VULN-001')"},
                "verdict": {
                    "type": "string",
                    "enum": ["confirmed", "downgraded", "dismissed"],
                    "description": "confirmed=real vuln, downgraded=real but lower severity, dismissed=false positive",
                },
                "reason": {"type": "string", "description": "Explanation of your verdict"},
                "new_severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                    "description": "New severity if downgraded",
                },
            },
            "required": ["finding_id", "verdict", "reason"],
        },
    },
}

RUN_COMMAND_SCHEMA = {
    "type": "function",
    "function": {
        "name": "run_command",
        "description": "Execute a shell command in the repo to verify findings. Use grep, cat, etc.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to execute"},
            },
            "required": ["command"],
        },
    },
}


async def run_verifier(
    findings: list[dict],
    repo_dir: str,
    sse: SSEManager,
) -> list[dict]:
    if not findings:
        await sse.emit_status("verifier_agent", "complete", "No findings to verify")
        return findings

    # Only verify code-level findings (secrets and CVEs are deterministic)
    code_findings = [f for f in findings if f.get("source") == "code" or f.get("cwe_id")]
    other_findings = [f for f in findings if f not in code_findings]

    if not code_findings:
        await sse.emit_status("verifier_agent", "complete", "No code findings to verify")
        return findings

    await sse.emit_status("verifier_agent", "running", f"Verifying {len(code_findings)} code-level findings...")

    findings_summary = json.dumps(code_findings, indent=2)
    messages = [
        {"role": "system", "content": VERIFIER_SYSTEM_PROMPT},
        {"role": "user", "content": f"Review these findings:\n\n{findings_summary}"},
    ]

    tools = [RUN_COMMAND_SCHEMA, VERIFY_FINDING_SCHEMA]
    verdicts = {}  # finding_id → verdict dict
    total_tool_calls = 0

    iteration = 0
    while True:
        try:
            response = await chat_completion(
                messages, tools=tools, temperature=0.3, max_tokens=8192, thinking=True,
            )
        except Exception as e:
            logger.error(f"Verifier API call failed: {e}")
            await sse.emit_error("verifier_agent", f"Verifier failed: {str(e)}")
            break

        tool_calls = response.get("tool_calls", [])
        content = response.get("content", "")
        thinking = response.get("thinking", "")

        if thinking:
            await sse.emit_reasoning("verifier_agent", thinking)
        if content:
            await sse.emit_reasoning("verifier_agent", content)

        if not tool_calls:
            break

        assistant_msg = {"role": "assistant", "content": content, "tool_calls": []}
        for tc in tool_calls:
            assistant_msg["tool_calls"].append({
                "id": tc["id"], "type": "function",
                "function": {"name": tc["function"]["name"], "arguments": tc["function"]["arguments"]},
            })
        messages.append(assistant_msg)

        for tc in tool_calls:
            tool_name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                args = {}

            total_tool_calls += 1

            if tool_name == "verify_finding":
                fid = args.get("finding_id", "")
                verdict = args.get("verdict", "confirmed")
                reason = args.get("reason", "")
                verdicts[fid] = args
                logger.info(f"Verifier: {fid} → {verdict}: {reason}")
                await sse.emit_tool_call("verifier", tool_name, args, {"status": "recorded"})
                messages.append({
                    "role": "tool", "tool_call_id": tc["id"],
                    "content": json.dumps({"status": "recorded"}),
                })

            elif tool_name == "run_command":
                result = await run_command_tool(repo_dir, args.get("command", ""))
                await sse.emit_tool_call("verifier", tool_name, args, result)
                # Cap result for context
                result_str = json.dumps(result)
                if len(result_str) > 8000:
                    result_str = result_str[:8000] + '..."}'
                messages.append({
                    "role": "tool", "tool_call_id": tc["id"],
                    "content": result_str,
                })

        iteration += 1

    # Apply verdicts
    verified_findings = list(other_findings)  # keep secrets/CVEs as-is
    dismissed_count = 0
    downgraded_count = 0

    for f in code_findings:
        fid = f.get("id", "")
        v = verdicts.get(fid)

        if v and v.get("verdict") == "dismissed":
            dismissed_count += 1
            logger.info(f"Dismissed: {fid} - {v.get('reason', '')}")
            await sse.emit("retract_finding", {"id": fid, "reason": v.get("reason", "False positive")})
            continue

        if v and v.get("verdict") == "downgraded":
            downgraded_count += 1
            new_sev = v.get("new_severity", f.get("severity"))
            f["severity"] = new_sev
            f["verifier_note"] = v.get("reason", "")
            logger.info(f"Downgraded: {fid} → {new_sev}")

        if v and v.get("verdict") == "confirmed":
            f["verified"] = True
            f["verifier_note"] = v.get("reason", "")

        verified_findings.append(f)

    await sse.emit_status(
        "verifier_agent", "complete",
        f"Verification complete: {len(code_findings) - dismissed_count} confirmed, {dismissed_count} dismissed, {downgraded_count} downgraded"
    )

    return verified_findings
