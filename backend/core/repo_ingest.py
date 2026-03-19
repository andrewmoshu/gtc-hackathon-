import asyncio
import os
import tempfile
import shutil
import logging

logger = logging.getLogger("codesentinel.ingest")

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "__pycache__", "dist", "build",
    ".next", ".nuxt", ".svelte-kit", "target", "bin", "obj", ".venv",
    "venv", "env", ".env", ".tox", ".mypy_cache", ".pytest_cache",
    "coverage", ".coverage", ".nyc_output", ".terraform", ".gradle",
    "bower_components", "jspm_packages",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".mkv",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".o", ".so", ".dll", ".exe",
    ".woff", ".woff2", ".ttf", ".eot",
    ".min.js", ".min.css",
    ".lock", ".map",
}

MAX_FILE_SIZE = 80_000  # 80KB per file

# Per-chunk budget: ~200K tokens = ~800K chars (leaves room for prompts + completion)
CHUNK_CHAR_BUDGET = 800_000

HIGH_PRIORITY_KEYWORDS = {
    "auth", "login", "password", "secret", "token", "session", "crypto",
    "key", "credential", "security", "middleware", "route", "handler",
    "controller", "api", "admin", "user", "config", "setting", "env",
    "db", "database", "query", "sql", "upload", "file", "input",
    "sanitize", "validate", "cors", "csrf", "cookie", "jwt", "oauth",
    "permission", "role", "access", "docker", "compose", "nginx",
    "server", "app", "main", "index", "model", "schema",
}

MANIFEST_BASENAMES = {
    "package.json", "requirements.txt", "requirements-dev.txt",
    "go.mod", "cargo.toml", "gemfile", "gemfile.lock", "pom.xml",
    "build.gradle", "build.gradle.kts", "composer.json",
}

CONFIG_BASENAMES = {
    "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    ".env.example", ".env.sample", "nginx.conf",
    "config.yaml", "config.yml", "config.json", "config.toml",
    "settings.py", "application.properties", "application.yml",
    "application.yaml", ".eslintrc", ".eslintrc.json", "tsconfig.json",
    "webpack.config.js", "vite.config.js", "vite.config.ts",
}


async def clone_repo(url: str, target_dir: str) -> str:
    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    repo_path = os.path.join(target_dir, repo_name)
    proc = await asyncio.create_subprocess_exec(
        "git", "clone", "--depth", "1", url, repo_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {stderr.decode()}")
    return repo_path


def _priority_score(rel_path: str) -> int:
    path_lower = rel_path.lower()
    basename = os.path.basename(path_lower)
    score = 0

    if basename in MANIFEST_BASENAMES:
        score += 200
    if basename in CONFIG_BASENAMES:
        score += 150

    # Entry points
    if basename in {"app.py", "main.py", "server.py", "index.js", "index.ts",
                    "app.js", "app.ts", "server.js", "server.ts", "main.go",
                    "main.rs", "main.java", "urls.py", "routes.py", "views.py"}:
        score += 100

    for kw in HIGH_PRIORITY_KEYWORDS:
        if kw in path_lower:
            score += 10

    ext = os.path.splitext(path_lower)[1]
    if ext in {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb",
               ".rs", ".php", ".cs", ".c", ".cpp"}:
        score += 5

    # Deprioritize test files
    if "test" in path_lower or "spec" in path_lower or "mock" in path_lower:
        score -= 50

    # Deprioritize docs
    if "doc" in path_lower or "readme" in path_lower or "changelog" in path_lower:
        score -= 40

    return score


def collect_all_files(repo_dir: str) -> list[dict]:
    """Collect metadata for all files in the repo."""
    all_files = []

    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        dirs.sort()

        for fname in sorted(files):
            if any(fname.endswith(ext) for ext in SKIP_EXTENSIONS):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, repo_dir)

            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue

            if size > MAX_FILE_SIZE or size == 0:
                continue

            ext = os.path.splitext(fname)[1].lstrip(".")
            score = _priority_score(rel_path)

            all_files.append({
                "path": rel_path,
                "language": ext,
                "size": size,
                "priority": score,
                "abs_path": fpath,
            })

    all_files.sort(key=lambda x: -x["priority"])
    return all_files


def build_file_tree_summary(all_files: list[dict]) -> str:
    """Build a compact file tree listing for the recon agent."""
    lines = ["# Repository File Tree\n"]
    for f in all_files:
        lines.append(f"  {f['path']} ({f['language']}, {f['size']} bytes)")
    return "\n".join(lines)


def flatten_manifests_and_configs(repo_dir: str, all_files: list[dict]) -> str:
    """Extract just manifests, configs, and entry points — small context for recon."""
    parts = []
    total = 0

    for f in all_files:
        basename = os.path.basename(f["path"]).lower()
        is_manifest = basename in MANIFEST_BASENAMES
        is_config = basename in CONFIG_BASENAMES
        is_entry = f["priority"] >= 100

        if not (is_manifest or is_config or is_entry):
            continue

        try:
            with open(f["abs_path"], "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            continue

        parts.append(f"=== FILE: {f['path']} ===\n{content}\n")
        total += len(content)

    logger.info(f"Manifests/configs/entries: {len(parts)} files, {total:,} chars")
    return "\n".join(parts)


def flatten_chunks(repo_dir: str, all_files: list[dict]) -> list[str]:
    """Split the full repo into chunks that each fit within the token budget.
    Files are ordered by priority so the most important code comes first."""
    chunks = []
    current_parts = []
    current_chars = 0

    for f in all_files:
        try:
            with open(f["abs_path"], "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except (OSError, UnicodeDecodeError):
            continue

        file_text = f"=== FILE: {f['path']} ===\n{content}\n"

        if current_chars + len(file_text) > CHUNK_CHAR_BUDGET:
            if current_parts:
                chunks.append("\n".join(current_parts))
                current_parts = []
                current_chars = 0

            # If single file exceeds budget, truncate it
            if len(file_text) > CHUNK_CHAR_BUDGET:
                file_text = file_text[:CHUNK_CHAR_BUDGET - 100] + "\n... [TRUNCATED]\n"

        current_parts.append(file_text)
        current_chars += len(file_text)

    if current_parts:
        chunks.append("\n".join(current_parts))

    logger.info(f"Split repo into {len(chunks)} chunks ({', '.join(f'{len(c):,} chars' for c in chunks)})")
    return chunks


def flatten_repo(repo_dir: str) -> tuple[str, list[dict]]:
    """Legacy single-string flatten. Returns first chunk + full file list."""
    all_files = collect_all_files(repo_dir)
    chunks = flatten_chunks(repo_dir, all_files)

    file_list = [
        {"path": f["path"], "language": f["language"], "lines": 0, "size": f["size"]}
        for f in all_files
    ]

    flattened = chunks[0] if chunks else ""
    logger.info(f"Flattened {len(file_list)} files, first chunk: {len(flattened):,} chars (~{len(flattened) // 4:,} tokens)")
    return flattened, file_list


def create_temp_dir() -> str:
    return tempfile.mkdtemp(prefix="codesentinel_")


def cleanup_temp_dir(path: str):
    shutil.rmtree(path, ignore_errors=True)
