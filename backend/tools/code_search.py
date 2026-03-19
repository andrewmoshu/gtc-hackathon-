import os
import re
import subprocess


async def search_code_tool(repo_dir: str, pattern: str, file_glob: str = "", max_results: int = 30) -> dict:
    """Search for a regex pattern across the codebase. Like grep."""
    try:
        cmd = ["grep", "-rn", "--include=*.py", "--include=*.js", "--include=*.ts",
               "--include=*.jsx", "--include=*.tsx", "--include=*.java", "--include=*.go",
               "--include=*.rb", "--include=*.rs", "--include=*.php", "--include=*.cs",
               "--include=*.c", "--include=*.cpp", "--include=*.h",
               "--include=*.yml", "--include=*.yaml", "--include=*.json",
               "--include=*.xml", "--include=*.toml", "--include=*.cfg",
               "--include=*.conf", "--include=*.ini", "--include=*.env",
               "--include=*.sh", "--include=*.sql", "--include=*.html",
               "-E", pattern]

        if file_glob:
            cmd = ["grep", "-rn", f"--include={file_glob}", "-E", pattern]

        cmd.append(repo_dir)

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=repo_dir,
        )

        matches = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            # Parse grep output: file:line:content
            parts = line.split(":", 2)
            if len(parts) >= 3:
                file_path = os.path.relpath(parts[0], repo_dir)
                matches.append({
                    "file": file_path,
                    "line": int(parts[1]) if parts[1].isdigit() else 0,
                    "content": parts[2].strip()[:200],
                })

            if len(matches) >= max_results:
                break

        return {
            "pattern": pattern,
            "total_matches": len(matches),
            "matches": matches,
            "truncated": len(result.stdout.strip().split("\n")) > max_results,
        }

    except subprocess.TimeoutExpired:
        return {"error": "Search timed out", "pattern": pattern, "matches": []}
    except Exception as e:
        return {"error": str(e), "pattern": pattern, "matches": []}


async def list_directory_tool(repo_dir: str, path: str = "") -> dict:
    """List files and directories at a given path in the repo."""
    target = os.path.normpath(os.path.join(repo_dir, path))

    if not target.startswith(os.path.normpath(repo_dir)):
        return {"error": "Path traversal detected"}

    if not os.path.exists(target):
        return {"error": f"Path not found: {path}"}

    if not os.path.isdir(target):
        return {"error": f"Not a directory: {path}"}

    entries = []
    try:
        for entry in sorted(os.listdir(target)):
            full = os.path.join(target, entry)
            if entry.startswith("."):
                continue
            if os.path.isdir(full):
                # Count children
                try:
                    child_count = len(os.listdir(full))
                except OSError:
                    child_count = 0
                entries.append({
                    "name": entry,
                    "type": "directory",
                    "children": child_count,
                })
            else:
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                entries.append({
                    "name": entry,
                    "type": "file",
                    "size": size,
                    "extension": os.path.splitext(entry)[1],
                })
    except OSError as e:
        return {"error": str(e)}

    return {
        "path": path or "/",
        "entries": entries,
        "total": len(entries),
    }
