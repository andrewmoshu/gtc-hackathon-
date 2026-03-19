import asyncio
import os
import logging

logger = logging.getLogger("codesentinel.tools.cmd")

MAX_OUTPUT = 15_000  # chars


async def run_command_tool(repo_dir: str, command: str, timeout: int = 30) -> dict:
    """Execute a shell command in the repo directory."""
    logger.info(f"Running command: {command}")

    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=repo_dir,
            env={**os.environ, "HOME": os.environ.get("HOME", "/tmp")},
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": f"Command timed out after {timeout}s",
            }

        stdout_str = stdout.decode("utf-8", errors="replace")
        stderr_str = stderr.decode("utf-8", errors="replace")

        # Truncate long output
        truncated = False
        if len(stdout_str) > MAX_OUTPUT:
            stdout_str = stdout_str[:MAX_OUTPUT] + f"\n... [truncated, {len(stdout.decode('utf-8', errors='replace'))} total chars]"
            truncated = True

        if len(stderr_str) > 2000:
            stderr_str = stderr_str[:2000] + "\n... [truncated]"

        return {
            "exit_code": proc.returncode,
            "stdout": stdout_str,
            "stderr": stderr_str if stderr_str else "",
            "truncated": truncated,
        }

    except Exception as e:
        logger.error(f"Command execution error: {e}")
        return {
            "exit_code": -1,
            "stdout": "",
            "stderr": str(e),
        }
