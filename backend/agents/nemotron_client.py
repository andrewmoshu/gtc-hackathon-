import os
import json
import logging
from openai import AsyncOpenAI
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("codesentinel.llm")

# Provider selection: "nemotron", "openrouter", or "claude"
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "nemotron").lower()

_openai_client = None
_anthropic_client = None

if LLM_PROVIDER == "claude":
    import anthropic
    _anthropic_client = anthropic.AsyncAnthropic(
        api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
    )
    MODEL = os.environ.get("LLM_MODEL", "claude-opus-4-6")
    logger.info(f"Using Claude provider: model={MODEL}")

elif LLM_PROVIDER == "openrouter":
    _openai_client = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.environ.get("OPENROUTER_API_KEY", ""),
    )
    MODEL = os.environ.get("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b:free")
    logger.info(f"Using OpenRouter provider: model={MODEL}")

else:  # nemotron (nvidia direct)
    _nvidia_api_key = os.environ.get("NVIDIA_API_KEY", "")
    _openai_client = AsyncOpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=_nvidia_api_key,
    )
    MODEL = os.environ.get("LLM_MODEL", "nvidia/nemotron-3-super-120b-a12b")
    logger.info(f"Using Nemotron provider: model={MODEL}, key={'yes' if _nvidia_api_key else 'NO'}")


TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Execute a shell command in the repository directory. Use this to explore the codebase freely: grep for patterns, read files, find files, check configs, run static analysis, inspect git history, etc. The working directory is the repo root.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell command to execute (e.g., 'grep -rn \"eval(\" --include=\"*.py\"', 'cat src/auth.py', 'find . -name \"*.config\"', 'ls -la src/')",
                    },
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "cwe_lookup",
            "description": "Search the MITRE CWE database to classify vulnerabilities and discover related weakness patterns.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search term (e.g., 'SQL injection', 'race condition')",
                    },
                    "cwe_id": {
                        "type": "string",
                        "description": "Specific CWE ID for direct lookup (e.g., 'CWE-89')",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "osv_query",
            "description": "Query the OSV vulnerability database for known CVEs affecting a specific package. Only use for dependencies not already found by the deterministic scanner.",
            "parameters": {
                "type": "object",
                "properties": {
                    "package_name": {
                        "type": "string",
                        "description": "Package name",
                    },
                    "ecosystem": {
                        "type": "string",
                        "description": "Package ecosystem: npm, PyPI, Go, crates.io, Maven, RubyGems, NuGet",
                    },
                    "version": {
                        "type": "string",
                        "description": "Specific version to check (optional)",
                    },
                },
                "required": ["package_name", "ecosystem"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the web for recent security advisories and exploit techniques.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_existing_findings",
            "description": "Get findings already discovered by deterministic scanners (secrets + CVEs). Call FIRST to avoid duplicating work.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    },
]


def _tool_schemas_to_anthropic(schemas: list[dict]) -> list[dict]:
    """Convert OpenAI tool schemas to Anthropic format."""
    tools = []
    for s in schemas:
        f = s["function"]
        tools.append({
            "name": f["name"],
            "description": f["description"],
            "input_schema": f["parameters"],
        })
    return tools


def _prepare_nemotron_messages(messages: list[dict], use_thinking: bool) -> list[dict]:
    """Nemotron Super requires system prompt to be ONLY 'detailed thinking on/off'.
    All other instructions must go in the user message."""
    thinking_directive = "detailed thinking on" if use_thinking else "detailed thinking off"

    processed = []
    system_content = ""

    for m in messages:
        if m["role"] == "system":
            # Extract system content to prepend to first user message
            system_content = m.get("content", "")
            processed.append({"role": "system", "content": thinking_directive})
        else:
            processed.append(m)

    # Prepend original system content to the first user message
    if system_content and system_content != thinking_directive:
        for i, m in enumerate(processed):
            if m["role"] == "user":
                processed[i] = {
                    **m,
                    "content": f"## Instructions\n{system_content}\n\n## Task\n{m['content']}",
                }
                break

    return processed


async def _chat_nemotron(
    messages: list[dict],
    tools: list[dict] | None = None,
    temperature: float = 0.6,
    max_tokens: int = 16384,
    thinking: bool = False,
) -> dict:
    is_openrouter = LLM_PROVIDER == "openrouter"

    # OpenRouter handles reasoning natively — no system prompt manipulation needed.
    # NVIDIA direct (120B) supports tools + reasoning together.
    # System prompt must be ONLY "detailed thinking on/off" — move other content to user msg.
    use_thinking = thinking
    if is_openrouter:
        processed_messages = messages  # OpenRouter manages reasoning via its own layer
    else:
        processed_messages = _prepare_nemotron_messages(messages, use_thinking)

    kwargs = {
        "model": MODEL,
        "messages": processed_messages,
        "max_tokens": max_tokens,
    }
    if tools:
        kwargs["tools"] = tools
        kwargs["temperature"] = temperature
    elif use_thinking:
        kwargs["temperature"] = 0.6
        kwargs["top_p"] = 0.95
        kwargs["extra_body"] = {
            "chat_template_kwargs": {"enable_thinking": True},
            "reasoning_effort": "high",
        }
    else:
        kwargs["temperature"] = temperature

    response = await _openai_client.chat.completions.create(**kwargs)
    choice = response.choices[0]
    msg = choice.message

    # Debug: log the full raw response structure
    logger.debug(f"Raw response keys: message attrs={[a for a in dir(msg) if not a.startswith('_')]}")
    logger.info(f"Raw content type={type(msg.content)}, content={repr(msg.content)[:300] if msg.content else 'None'}")

    # Some providers put reasoning in different fields
    content = msg.content or ""
    reasoning = getattr(msg, 'reasoning', None) or getattr(msg, 'reasoning_content', None) or ""

    if reasoning:
        logger.info(f"Found reasoning field: {len(reasoning)} chars")

    # Extract thinking content from <think> tags if present
    thinking_content = str(reasoning) if reasoning else ""
    visible_content = content
    if "<think>" in content:
        think_start = content.find("<think>")
        think_end = content.find("</think>")
        if think_start >= 0 and think_end > think_start:
            thinking_content = content[think_start + 7:think_end].strip()
            visible_content = (content[:think_start] + content[think_end + 8:]).strip()

    return {
        "content": visible_content,
        "thinking": thinking_content,
        "tool_calls": [
            {
                "id": tc.id,
                "function": {
                    "name": tc.function.name,
                    "arguments": tc.function.arguments,
                },
            }
            for tc in (msg.tool_calls or [])
        ],
        "finish_reason": choice.finish_reason,
    }


async def _chat_claude(
    messages: list[dict],
    tools: list[dict] | None = None,
    temperature: float = 0.6,
    max_tokens: int = 16384,
    thinking: bool = False,
) -> dict:
    # Convert OpenAI message format to Anthropic format
    system_prompt = ""
    anthropic_messages = []

    for m in messages:
        if m["role"] == "system":
            system_prompt = m.get("content", "")
        elif m["role"] == "user":
            anthropic_messages.append({"role": "user", "content": m.get("content", "")})
        elif m["role"] == "assistant":
            content_blocks = []
            if m.get("content"):
                content_blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls", []):
                try:
                    tool_input = json.loads(tc["function"]["arguments"])
                except (json.JSONDecodeError, KeyError):
                    tool_input = {}
                content_blocks.append({
                    "type": "tool_use",
                    "id": tc["id"],
                    "name": tc["function"]["name"],
                    "input": tool_input,
                })
            if content_blocks:
                anthropic_messages.append({"role": "assistant", "content": content_blocks})
        elif m["role"] == "tool":
            anthropic_messages.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": m["tool_call_id"],
                    "content": m.get("content", ""),
                }],
            })

    # Merge consecutive user messages (Anthropic requires alternating roles)
    merged = []
    for msg in anthropic_messages:
        if merged and merged[-1]["role"] == msg["role"]:
            prev_content = merged[-1]["content"]
            curr_content = msg["content"]
            if isinstance(prev_content, str):
                prev_content = [{"type": "text", "text": prev_content}]
            if isinstance(curr_content, str):
                curr_content = [{"type": "text", "text": curr_content}]
            merged[-1]["content"] = prev_content + curr_content
        else:
            merged.append(msg)
    anthropic_messages = merged

    kwargs = {
        "model": MODEL,
        "max_tokens": max_tokens,
        "messages": anthropic_messages,
    }
    if system_prompt:
        kwargs["system"] = system_prompt
    if tools:
        kwargs["tools"] = _tool_schemas_to_anthropic(tools)
    if thinking:
        kwargs["temperature"] = 1  # required for extended thinking
        kwargs["thinking"] = {"type": "adaptive"}
    else:
        kwargs["temperature"] = temperature

    response = await _anthropic_client.messages.create(**kwargs)

    # Parse response
    visible_content = ""
    thinking_content = ""
    tool_calls = []

    for block in response.content:
        if block.type == "text":
            visible_content += block.text
        elif block.type == "thinking":
            thinking_content += block.thinking
        elif block.type == "tool_use":
            tool_calls.append({
                "id": block.id,
                "function": {
                    "name": block.name,
                    "arguments": json.dumps(block.input),
                },
            })

    return {
        "content": visible_content,
        "thinking": thinking_content,
        "tool_calls": tool_calls,
        "finish_reason": response.stop_reason,
    }


async def chat_completion(
    messages: list[dict],
    tools: list[dict] | None = None,
    temperature: float = 0.6,
    max_tokens: int = 16384,
    thinking: bool = False,
) -> dict:
    total_chars = sum(len(str(m.get("content", ""))) for m in messages)
    logger.info(f"LLM call ({LLM_PROVIDER}): {len(messages)} messages, ~{total_chars:,} chars, tools={bool(tools)}, thinking={thinking}")

    try:
        if LLM_PROVIDER == "claude":
            result = await _chat_claude(messages, tools, temperature, max_tokens, thinking)
        elif LLM_PROVIDER == "openrouter":
            # OpenRouter uses OpenAI-compatible API, no thinking mode
            result = await _chat_nemotron(messages, tools, temperature, max_tokens, thinking=False)
        else:
            result = await _chat_nemotron(messages, tools, temperature, max_tokens, thinking)
    except Exception as e:
        logger.error(f"LLM error: {type(e).__name__}: {e}")
        raise

    logger.info(f"LLM response: content_len={len(result.get('content', ''))}, thinking_len={len(result.get('thinking', ''))}, tool_calls={len(result.get('tool_calls', []))}")
    return result
