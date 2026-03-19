import asyncio
import json
from datetime import datetime, timezone


class SSEManager:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()

    async def emit(self, event_type: str, data: dict):
        event = {"type": event_type, "data": data}
        await self.queue.put(event)

    async def emit_status(self, layer: str, state: str, message: str = ""):
        await self.emit("status", {
            "layer": layer,
            "state": state,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def emit_finding(self, finding: dict):
        await self.emit("finding", finding)

    async def emit_recon(self, recon_data: dict):
        await self.emit("recon", recon_data)

    async def emit_graph_data(self, nodes: list, edges: list):
        await self.emit("graph_data", {"nodes": nodes, "edges": edges})

    async def emit_tool_call(self, agent: str, tool: str, args: dict, result: dict):
        await self.emit("tool_call", {
            "agent": agent,
            "tool": tool,
            "args": args,
            "result": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def emit_reasoning(self, agent: str, text: str):
        await self.emit("reasoning", {
            "agent": agent,
            "text": text,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    async def emit_hunter_finding(self, finding: dict):
        await self.emit("hunter_finding", finding)

    async def emit_patch(self, patch: dict):
        await self.emit("patch", patch)

    async def emit_file_tree(self, files: list):
        await self.emit("file_tree", {"files": files})

    async def emit_complete(self, summary: dict):
        await self.emit("complete", summary)

    async def emit_error(self, layer: str, message: str):
        await self.emit("error", {"layer": layer, "message": message})

    async def done(self):
        await self.queue.put(None)

    async def generate(self):
        while True:
            event = await self.queue.get()
            if event is None:
                break
            yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
