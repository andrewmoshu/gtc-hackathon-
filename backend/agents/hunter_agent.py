import json
import logging
from agents.nemotron_client import chat_completion, TOOL_SCHEMAS
from tools.cwe_lookup import cwe_lookup_tool
from tools.osv_query import osv_query_tool
from tools.web_search import web_search_tool
from tools.run_command import run_command_tool
from core.sse_manager import SSEManager

logger = logging.getLogger("codesentinel.hunter")

REPORT_FINDING_SCHEMA = {
    "type": "function",
    "function": {
        "name": "report_finding",
        "description": "Report a confirmed security vulnerability. Call this AS SOON AS you confirm a vulnerability — don't wait until the end. Each call reports one finding. You can continue investigating after reporting.",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Short title (e.g., 'SQL Injection in login handler')"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
                "cwe_id": {"type": "string", "description": "CWE ID (e.g., 'CWE-89')"},
                "cwe_name": {"type": "string", "description": "CWE name (e.g., 'SQL Injection')"},
                "file": {"type": "string", "description": "File path"},
                "line_start": {"type": "integer", "description": "Starting line number"},
                "line_end": {"type": "integer", "description": "Ending line number"},
                "description": {"type": "string", "description": "Plain English explanation"},
                "evidence": {"type": "string", "description": "The actual vulnerable code snippet"},
                "data_flow_trace": {"type": "string", "description": "How user input reaches the dangerous sink"},
                "exploitation_scenario": {"type": "string", "description": "How an attacker would exploit this"},
                "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
            },
            "required": ["title", "severity", "file", "description", "evidence", "confidence"],
        },
    },
}

RETRACT_FINDING_SCHEMA = {
    "type": "function",
    "function": {
        "name": "retract_finding",
        "description": "Retract a previously reported finding if you determine it's a false positive after further investigation.",
        "parameters": {
            "type": "object",
            "properties": {
                "finding_id": {"type": "string", "description": "The ID of the finding to retract (e.g., 'VULN-001')"},
                "reason": {"type": "string", "description": "Why this is a false positive"},
            },
            "required": ["finding_id", "reason"],
        },
    },
}

SPAWN_HUNTER_SCHEMA = {
    "type": "function",
    "function": {
        "name": "spawn_hunter",
        "description": "Spawn a parallel sub-agent to investigate a specific area of the codebase concurrently. "
                       "Use this to parallelize your investigation — e.g., spawn one agent for injection patterns, "
                       "another for auth issues, another for config problems. Each sub-agent gets its own shell access "
                       "and reports findings independently. You can spawn multiple and continue your own investigation.",
        "parameters": {
            "type": "object",
            "properties": {
                "hunter_id": {
                    "type": "string",
                    "description": "Short unique ID for this sub-agent (e.g., 'injection', 'auth', 'config', 'crypto')",
                },
                "focus": {
                    "type": "string",
                    "description": "Detailed description of what this sub-agent should investigate. Be specific about "
                                   "what patterns to search for, what files/directories to look at, and what types of "
                                   "vulnerabilities to focus on.",
                },
            },
            "required": ["hunter_id", "focus"],
        },
    },
}

HUNTER_SYSTEM_PROMPT = """You are an autonomous security researcher. You have full shell access to a
cloned repository and can run any command to investigate it.

TOOLS:
- run_command(command): Execute ANY shell command in the repo directory.
  grep, cat, find, sed, awk, wc, ls, head, tail — anything you need.
  IMPORTANT: When you want to examine a file, read the WHOLE file with `cat filename` instead of
  making many small `sed -n` or `grep` calls on the same file. Reading the full file in one call
  is much faster and gives you complete context. Only use sed/grep for targeted searches ACROSS
  multiple files, not to nibble at a single file piece by piece.

- report_finding(...): Report a confirmed vulnerability IMMEDIATELY when you find one.
  Don't wait until the end — report each finding as you confirm it.
  You can continue investigating after reporting.

- retract_finding(finding_id, reason): If further investigation reveals a previously
  reported finding is a false positive, retract it.

- spawn_hunter(hunter_id, focus): Spawn a parallel sub-agent to investigate a specific area
  concurrently. Each sub-agent has its own shell access and works independently.
  Example: spawn_hunter("injection", "Search for SQL injection, command injection, XSS...")
  You can spawn multiple sub-agents and continue your own investigation.
  Sub-agents report findings independently — you don't need to wait for them.

- cwe_lookup(query?, cwe_id?): Classify vulnerabilities using the MITRE CWE database.
- osv_query(package_name, ecosystem, version?): Check packages for known CVEs.
- web_search(query): Search for recent security advisories.
- get_existing_findings(): See what deterministic scanners already found. Call this FIRST.

INVESTIGATION STRATEGY:
1. Call get_existing_findings() to see what's already covered.
2. Explore the repo structure: find . -type f | head -50, ls -la
3. Based on the repo size and complexity, consider spawning sub-agents for parallel investigation.
   For medium/large repos, spawn 2-3 sub-agents with different focus areas, then continue
   investigating yourself. For small repos, just do everything yourself.
4. Search systematically for dangerous patterns:
   - grep -rn "eval\|exec\|system\|popen\|subprocess" --include="*.py"
   - grep -rn "innerHTML\|dangerouslySetInnerHTML\|v-html" --include="*.js" --include="*.jsx"
   - grep -rn "SELECT.*FROM\|INSERT.*INTO\|DELETE.*FROM\|UPDATE.*SET" -r
   - grep -rn "pickle\|yaml\.load\|deserialize\|readObject\|unserialize" -r
   - grep -rn "os\.path\.join.*request\|open(.*request\|send_file" --include="*.py"
4. Read suspicious files with cat. Examine the full context.
5. Trace data flows: does user input reach dangerous sinks without sanitization?
6. When you CONFIRM a vulnerability, call report_finding() immediately.
7. If later investigation shows a reported finding is actually safe, call retract_finding().
8. When you've thoroughly covered all high-risk areas, stop calling tools and say "Investigation complete."

RULES:
- Do NOT re-report secrets or dependency CVEs already found by deterministic scanners.
- Consider context: parameterized queries are safe. Framework protections count.
- Only report what you have EVIDENCE for — include the actual vulnerable code.
- Report findings AS YOU FIND THEM, don't batch them at the end.

IMPORTANT COMMUNICATION STYLE:
- ALWAYS include your reasoning as text content alongside tool calls.
- Before each tool call, explain WHAT you're looking for and WHY.
- After receiving tool results, analyze what you found before making the next call.
- Example flow:
  "I see this repo uses Express.js. Let me check for common Express vulnerabilities..."
  → run_command(grep -rn "app.get\|app.post" ...)
  "Found 12 route handlers. Several use req.params directly. Let me check if input is sanitized..."
  → run_command(cat src/routes/user.js)
  "Line 45 passes req.params.id directly into a SQL query without parameterization. This is SQL injection."
  → report_finding(...)
- Never just silently chain tool calls without explaining your thought process.
"""

async def run_hunter(
    repo_context: str,
    recon_data: dict,
    repo_dir: str,
    sse: SSEManager,
    existing_findings: list[dict] | None = None,
    hunter_id: str = "hunter",
    focus_area: str = "",
    spawn_fn=None,
) -> list[dict]:
    await sse.emit_status("hunter_agent", "running", f"[{hunter_id}] Investigation started...")

    _existing = existing_findings or []

    file_tree = recon_data.get("file_tree", "")

    focus_instruction = ""
    if focus_area:
        focus_instruction = (
            f"\n\n## YOUR FOCUS AREA\n"
            f"You are one of multiple parallel security investigators. "
            f"Your specific focus: **{focus_area}**\n"
            f"Other investigators are covering other areas, so stay focused on yours. "
            f"Be thorough within your scope.\n"
        )

    initial_context = (
        f"## Repository File Tree\n{file_tree}\n\n"
        f"{focus_instruction}"
        "Begin your investigation. Start with get_existing_findings(), "
        "then explore the codebase structure and search for vulnerabilities."
    )

    logger.info(f"[{hunter_id}] starting with {len(initial_context):,} chars of context, focus={focus_area or 'general'}")

    messages = [
        {"role": "system", "content": HUNTER_SYSTEM_PROMPT},
        {"role": "user", "content": initial_context},
    ]

    # Add report_finding and retract_finding to tool schemas
    all_tools = TOOL_SCHEMAS + [REPORT_FINDING_SCHEMA, RETRACT_FINDING_SCHEMA]
    if spawn_fn:
        all_tools = all_tools + [SPAWN_HUNTER_SCHEMA]

    findings = []
    finding_counter = 0
    total_tool_calls = 0

    tool_dispatch = {
        "run_command": lambda args: run_command_tool(repo_dir, args.get("command", "")),
        "cwe_lookup": lambda args: cwe_lookup_tool(args.get("query", ""), args.get("cwe_id", "")),
        "osv_query": lambda args: osv_query_tool(args.get("package_name", ""), args.get("ecosystem", ""), args.get("version", "")),
        "web_search": lambda args: web_search_tool(args.get("query", "")),
        "get_existing_findings": lambda args: _handle_existing_findings(_existing),
    }

    iteration = 0
    while True:
        # Compress old messages before each API call
        _compress_context(messages)

        try:
            response = await chat_completion(
                messages,
                tools=all_tools,
                temperature=0.6,
                max_tokens=16384,
                thinking=True,
            )
        except Exception as e:
            logger.error(f"Hunter API call failed on iteration {iteration}: {e}")
            iteration += 1
            await sse.emit_error("hunter_agent", f"API call failed: {str(e)}")
            break

        tool_calls = response.get("tool_calls", [])
        content = response.get("content", "")
        thinking = response.get("thinking", "")

        if thinking:
            await sse.emit_reasoning(hunter_id, thinking)

        if content:
            await sse.emit_reasoning(hunter_id, content)

        if not tool_calls:
            # No more tool calls — agent is done
            # Also check content for any <findings> block (backward compat)
            if content:
                parsed = _parse_findings(content)
                for f in parsed:
                    finding_counter += 1
                    f["id"] = f.get("id", f"{hunter_id}-{finding_counter:03d}")
                    findings.append(f)
                    await sse.emit_hunter_finding(f)
            break

        # Build assistant message
        assistant_msg = {"role": "assistant", "content": content, "tool_calls": []}
        for tc in tool_calls:
            assistant_msg["tool_calls"].append({
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                },
            })
        messages.append(assistant_msg)

        # Execute each tool call
        for tc in tool_calls:
            tool_name = tc["function"]["name"]
            try:
                args = json.loads(tc["function"]["arguments"])
            except json.JSONDecodeError:
                args = {}

            total_tool_calls += 1

            # Handle report_finding specially
            if tool_name == "report_finding":
                finding_counter += 1
                finding = {
                    "id": f"{hunter_id}-{finding_counter:03d}",
                    **args,
                }
                findings.append(finding)
                logger.info(f"Hunter reported finding: {finding['title']} [{finding.get('severity', '?')}]")
                await sse.emit_hunter_finding(finding)
                await sse.emit_tool_call(hunter_id, tool_name, args, {"status": "reported", "id": finding["id"]})
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps({"status": "reported", "id": finding["id"]}),
                })
                continue

            # Handle retract_finding
            if tool_name == "retract_finding":
                fid = args.get("finding_id", "")
                reason = args.get("reason", "")
                findings = [f for f in findings if f.get("id") != fid]
                logger.info(f"Hunter retracted finding {fid}: {reason}")
                await sse.emit_tool_call(hunter_id, tool_name, args, {"status": "retracted", "id": fid, "reason": reason})
                # Emit a special event so frontend can remove it
                await sse.emit("retract_finding", {"id": fid, "reason": reason})
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps({"status": "retracted", "id": fid}),
                })
                continue

            # Handle spawn_hunter
            if tool_name == "spawn_hunter" and spawn_fn:
                sub_id = f"hunter-{args.get('hunter_id', 'sub')}"
                sub_focus = args.get("focus", "")
                logger.info(f"[{hunter_id}] spawning sub-agent: {sub_id} → {sub_focus[:100]}")
                result = await spawn_fn(sub_id, sub_focus)
                await sse.emit_tool_call(hunter_id, tool_name, args, result)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": json.dumps(result),
                })
                continue

            # Regular tools
            handler = tool_dispatch.get(tool_name)
            if handler:
                result = await handler(args)
            else:
                result = {"error": f"Unknown tool: {tool_name}"}

            logger.info(f"[{hunter_id}] tool #{total_tool_calls}: {tool_name}({json.dumps(args)[:200]})")
            await sse.emit_tool_call(hunter_id, tool_name, args, result)

            messages.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": _cap_tool_result(result),
            })

        # Periodic nudge every 15 tool calls if no findings reported yet
        if total_tool_calls > 0 and total_tool_calls % 15 == 0 and len(findings) == 0:
            messages.append({
                "role": "user",
                "content": (
                    "REMINDER: You've made many tool calls but haven't reported any findings yet. "
                    "If you've identified vulnerabilities, call report_finding() NOW for each one. "
                    "Don't wait — report as you go. If you haven't found anything yet, keep investigating."
                ),
            })
            logger.info(f"[{hunter_id}] Injected nudge at {total_tool_calls} tool calls")

        iteration += 1

    # Fallback: if Hunter made many calls but reported 0 findings, ask it to summarize
    if len(findings) == 0 and total_tool_calls >= 5:
        logger.info(f"[{hunter_id}] ended with 0 findings after {total_tool_calls} tool calls — running fallback extraction")
        await sse.emit_status("hunter_agent", "running", f"[{hunter_id}] Extracting findings...")

        messages.append({
            "role": "user",
            "content": (
                "Your investigation is complete. You made many tool calls and examined the code. "
                "Now list ALL security vulnerabilities you found. For each one, call report_finding() with the details. "
                "If you truly found nothing, just say 'No vulnerabilities found.'"
            ),
        })

        try:
            response = await chat_completion(
                messages, tools=all_tools, temperature=0.6, max_tokens=16384, thinking=True,
            )

            content = response.get("content", "")
            thinking = response.get("thinking", "")
            tool_calls = response.get("tool_calls", [])

            if thinking:
                await sse.emit_reasoning("hunter_agent", thinking)
            if content:
                await sse.emit_reasoning("hunter_agent", content)

            # Process any report_finding calls
            if tool_calls:
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

                    if tool_name == "report_finding":
                        finding_counter += 1
                        finding = {"id": f"{hunter_id}-{finding_counter:03d}", **args}
                        findings.append(finding)
                        logger.info(f"[{hunter_id}] Fallback finding: {finding['title']} [{finding.get('severity', '?')}]")
                        await sse.emit_hunter_finding(finding)

            # Also try parsing <findings> from content
            if content and len(findings) == 0:
                parsed = _parse_findings(content)
                for f in parsed:
                    finding_counter += 1
                    f["id"] = f.get("id", f"{hunter_id}-{finding_counter:03d}")
                    findings.append(f)
                    await sse.emit_hunter_finding(f)

        except Exception as e:
            logger.error(f"[{hunter_id}] Fallback extraction failed: {e}")

    await sse.emit_status(
        "hunter_agent", "complete",
        f"[{hunter_id}] Complete: {len(findings)} vulnerabilities, {total_tool_calls} tool calls"
    )

    return findings


# Max chars for a tool result when first inserted
MAX_TOOL_RESULT_CHARS = 12000
# For older messages, truncate to this (but keep actual content, not summaries)
OLD_MSG_TRUNCATE = 3000
# Keep this many recent messages at full size
KEEP_RECENT_FULL = 20


def _cap_tool_result(result: dict) -> str:
    """Cap a tool result to a reasonable size before inserting into messages."""
    text = json.dumps(result)
    if len(text) <= MAX_TOOL_RESULT_CHARS:
        return text

    # For run_command, keep first and last lines of stdout
    if "stdout" in result:
        stdout = result.get("stdout", "")
        lines = stdout.split("\n")
        if len(lines) > 40:
            kept = lines[:30] + [f"\n... [{len(lines) - 35} lines omitted] ...\n"] + lines[-5:]
            result = {**result, "stdout": "\n".join(kept)}
        text = json.dumps(result)
        if len(text) <= MAX_TOOL_RESULT_CHARS:
            return text

    # Generic truncation — keep the beginning (most relevant)
    return text[:MAX_TOOL_RESULT_CHARS] + '..."}'


def _compress_context(messages: list[dict]):
    """Gently truncate old tool results but KEEP the actual content.
    Only shortens very long outputs in older messages — never replaces
    content with summaries, so the model can still reference past results."""
    if len(messages) <= 2 + KEEP_RECENT_FULL:
        return

    cutoff = len(messages) - KEEP_RECENT_FULL
    total_before = sum(len(str(m.get("content", ""))) for m in messages)

    for i in range(2, cutoff):
        msg = messages[i]
        if msg.get("role") != "tool":
            continue

        content = msg.get("content", "")
        if len(content) <= OLD_MSG_TRUNCATE:
            continue

        # Truncate but keep real content — just shorter
        try:
            data = json.loads(content)
            if "stdout" in data:
                stdout = data.get("stdout", "")
                lines = stdout.split("\n")
                if len(lines) > 15:
                    # Keep first 10 and last 3 lines
                    truncated_stdout = "\n".join(lines[:10]) + f"\n... [{len(lines)} lines total] ...\n" + "\n".join(lines[-3:])
                    data["stdout"] = truncated_stdout
                    msg["content"] = json.dumps(data)
                else:
                    msg["content"] = content[:OLD_MSG_TRUNCATE]
            elif "content" in data and len(data.get("content", "")) > OLD_MSG_TRUNCATE:
                # File content — keep first chunk
                data["content"] = data["content"][:OLD_MSG_TRUNCATE] + f"\n... [truncated, {data.get('line_count', '?')} lines total]"
                msg["content"] = json.dumps(data)
            else:
                msg["content"] = content[:OLD_MSG_TRUNCATE] + "...[truncated]"
        except (json.JSONDecodeError, KeyError):
            msg["content"] = content[:OLD_MSG_TRUNCATE] + "...[truncated]"

    total_after = sum(len(str(m.get("content", ""))) for m in messages)
    if total_before != total_after:
        logger.info(f"Context trimmed: {total_before:,} → {total_after:,} chars ({total_before - total_after:,} saved)")


async def _handle_existing_findings(findings: list[dict]) -> dict:
    summary = {
        "total": len(findings),
        "secrets": [],
        "dependency_cves": [],
    }
    for f in findings:
        entry = {
            "id": f.get("id", ""),
            "title": f.get("title", ""),
            "severity": f.get("severity", ""),
            "file": f.get("file", ""),
        }
        if f.get("source") == "secrets":
            summary["secrets"].append(entry)
        elif f.get("source") == "osv":
            entry["cve_id"] = f.get("details", {}).get("cve_id", "")
            entry["package"] = f.get("details", {}).get("package", "")
            summary["dependency_cves"].append(entry)
    summary["note"] = "These are already reported. Focus on NEW code-level vulnerabilities."
    return summary


def _parse_findings(text: str) -> list[dict]:
    start_tag = "<findings>"
    end_tag = "</findings>"
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
        findings = json.loads(json_str)
        if isinstance(findings, list):
            return findings
    except json.JSONDecodeError:
        pass

    return []
