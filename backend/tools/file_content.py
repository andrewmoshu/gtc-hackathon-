import os

LANGUAGE_MAP = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "jsx", ".tsx": "tsx", ".java": "java", ".go": "go",
    ".rb": "ruby", ".rs": "rust", ".php": "php", ".cs": "csharp",
    ".c": "c", ".cpp": "cpp", ".h": "c", ".hpp": "cpp",
    ".yml": "yaml", ".yaml": "yaml", ".json": "json", ".xml": "xml",
    ".toml": "toml", ".ini": "ini", ".sh": "bash", ".bash": "bash",
    ".sql": "sql", ".html": "html", ".css": "css", ".md": "markdown",
    ".tf": "hcl", ".hcl": "hcl", ".dockerfile": "dockerfile",
}


async def file_content_tool(repo_dir: str, file_path: str) -> dict:
    full_path = os.path.normpath(os.path.join(repo_dir, file_path))

    if not full_path.startswith(os.path.normpath(repo_dir)):
        return {"error": "Path traversal detected"}

    if not os.path.exists(full_path):
        return {"error": f"File not found: {file_path}"}

    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except OSError as e:
        return {"error": str(e)}

    ext = os.path.splitext(file_path)[1].lower()
    language = LANGUAGE_MAP.get(ext, ext.lstrip(".") or "text")

    return {
        "content": content,
        "language": language,
        "line_count": content.count("\n") + 1,
    }
