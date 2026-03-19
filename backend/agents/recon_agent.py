import json
from agents.nemotron_client import chat_completion
from core.sse_manager import SSEManager

RECON_SYSTEM_PROMPT = """You are a security reconnaissance agent. You have been given the file tree,
dependency manifests, configuration files, and key entry points of a software repository.
Your job is to map the attack surface.

Analyze the codebase and produce a JSON response with:
{
  "entry_points": [
    {"file": "path", "line": 0, "type": "api_route|form_handler|cli|websocket|graphql", "method": "GET|POST|etc", "description": "..."}
  ],
  "data_flows": [
    {"source": "entry_point description", "sink": "file:line", "data_type": "user_input|credential|pii|file_upload", "transforms": ["..."]}
  ],
  "dependencies": [
    {"name": "pkg", "version": "x.y.z", "risk_notes": "..."}
  ],
  "risk_tiers": {
    "critical": ["file1.py"],
    "high": ["file2.py"],
    "medium": ["file3.py"],
    "low": ["file4.py"]
  },
  "tech_stack": {
    "language": "python|javascript|go|etc",
    "framework": "flask|express|django|etc",
    "database": "sqlite|postgres|mongodb|etc"
  }
}

Focus on: authentication, authorization, input handling, database queries,
file operations, cryptographic operations, configuration/secrets management,
and external API calls.

IMPORTANT: Return ONLY the JSON object, no markdown fencing, no explanation.
"""


async def run_recon(repo_context: str, file_list: list[dict], sse: SSEManager) -> dict:
    await sse.emit_status("recon_agent", "running", "Mapping attack surface...")

    messages = [
        {"role": "system", "content": RECON_SYSTEM_PROMPT},
        {"role": "user", "content": f"Analyze this repository:\n\n{repo_context}"},
    ]

    try:
        response = await chat_completion(messages, temperature=0.3, max_tokens=8192)
        content = response["content"] or ""

        # Try to parse JSON from the response
        recon_data = _parse_json(content)

        if not recon_data:
            recon_data = _fallback_recon(file_list)

    except Exception as e:
        await sse.emit_error("recon_agent", f"Recon agent failed: {str(e)}")
        recon_data = _fallback_recon(file_list)

    # Build graph data from recon
    nodes, edges = _build_graph(recon_data, file_list)

    await sse.emit_recon(recon_data)
    await sse.emit_graph_data(nodes, edges)
    await sse.emit_status("recon_agent", "complete", f"Mapped {len(recon_data.get('entry_points', []))} entry points")

    return recon_data


def _parse_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = lines[1:]  # skip ```json
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Try to find JSON block in text
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                return None
    return None


def _fallback_recon(file_list: list[dict]) -> dict:
    risk_tiers = {"critical": [], "high": [], "medium": [], "low": []}
    entry_points = []

    risk_keywords = {
        "critical": ["auth", "login", "password", "crypto", "secret", "key", "token"],
        "high": ["user", "admin", "api", "route", "handler", "middleware", "session"],
        "medium": ["model", "schema", "database", "db", "query", "config"],
    }

    for f in file_list:
        path_lower = f["path"].lower()
        classified = False
        for tier, keywords in risk_keywords.items():
            if any(kw in path_lower for kw in keywords):
                risk_tiers[tier].append(f["path"])
                classified = True
                break
        if not classified:
            risk_tiers["low"].append(f["path"])

        if any(kw in path_lower for kw in ["route", "view", "handler", "controller", "api", "endpoint"]):
            entry_points.append({
                "file": f["path"],
                "line": 0,
                "type": "api_route",
                "method": "UNKNOWN",
                "description": f"Potential entry point: {f['path']}",
            })

    return {
        "entry_points": entry_points,
        "data_flows": [],
        "dependencies": [],
        "risk_tiers": risk_tiers,
        "tech_stack": {},
    }


def _build_graph(recon_data: dict, file_list: list[dict]) -> tuple[list[dict], list[dict]]:
    nodes = []
    edges = []
    node_ids = set()

    risk_tiers = recon_data.get("risk_tiers", {})
    risk_map = {}
    for tier, files in risk_tiers.items():
        for f in files:
            risk_map[f] = tier

    for ep in recon_data.get("entry_points", []):
        node_id = ep["file"]
        if node_id not in node_ids:
            nodes.append({
                "id": node_id,
                "label": node_id.split("/")[-1],
                "type": ep.get("type", "file"),
                "risk": risk_map.get(node_id, "medium"),
                "full_path": node_id,
            })
            node_ids.add(node_id)

    for df in recon_data.get("data_flows", []):
        sink = df.get("sink", "").split(":")[0]
        if sink and sink not in node_ids:
            nodes.append({
                "id": sink,
                "label": sink.split("/")[-1],
                "type": "sink",
                "risk": risk_map.get(sink, "low"),
                "full_path": sink,
            })
            node_ids.add(sink)

    # Add high-risk files that aren't already nodes
    for tier in ("critical", "high"):
        for f in risk_tiers.get(tier, [])[:10]:
            if f not in node_ids:
                nodes.append({
                    "id": f,
                    "label": f.split("/")[-1],
                    "type": "file",
                    "risk": tier,
                    "full_path": f,
                })
                node_ids.add(f)

    for df in recon_data.get("data_flows", []):
        source_file = None
        for ep in recon_data.get("entry_points", []):
            if ep.get("description", "") in df.get("source", "") or ep["file"] in df.get("source", ""):
                source_file = ep["file"]
                break

        sink_file = df.get("sink", "").split(":")[0]
        if source_file and sink_file and source_file in node_ids and sink_file in node_ids:
            edges.append({
                "from": source_file,
                "to": sink_file,
                "label": df.get("data_type", "data"),
            })

    return nodes, edges
