import asyncio
import logging
import time
import traceback
from core.sse_manager import SSEManager
from core.repo_ingest import (
    clone_repo, create_temp_dir, cleanup_temp_dir,
    collect_all_files, build_file_tree_summary,
    flatten_manifests_and_configs,
)
from scanners.secret_scanner import scan_secrets
from scanners.dependency_scanner import scan_dependencies
from agents.hunter_agent import run_hunter
from agents.verifier_agent import run_verifier
from agents.patcher_agent import run_patcher

logger = logging.getLogger("codesentinel")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


async def run_scan(repo_url: str, sse: SSEManager):
    start_time = time.time()
    all_findings = []
    repo_dir = ""
    temp_dir = ""

    try:
        # Step 1: Clone the repo
        logger.info(f"Cloning {repo_url}")
        await sse.emit_status("ingestion", "running", f"Cloning {repo_url}...")
        temp_dir = create_temp_dir()
        repo_dir = await clone_repo(repo_url, temp_dir)
        await sse.emit_status("ingestion", "complete", "Repository cloned")

        # Step 2: Collect file metadata
        logger.info("Collecting file metadata...")
        await sse.emit_status("ingestion", "running", "Analyzing repository structure...")
        all_files = await asyncio.to_thread(collect_all_files, repo_dir)
        file_tree_summary = build_file_tree_summary(all_files)
        manifests_context = await asyncio.to_thread(flatten_manifests_and_configs, repo_dir, all_files)

        file_list = [
            {"path": f["path"], "language": f["language"], "lines": 0, "size": f["size"]}
            for f in all_files
        ]
        await sse.emit_file_tree(file_list)
        logger.info(f"Found {len(all_files)} files")
        await sse.emit_status("ingestion", "complete", f"Found {len(all_files)} files")

        # Step 3: Run deterministic scanners in parallel
        await sse.emit_status("deterministic", "running", "Running deterministic scanners...")
        secret_findings, dep_findings = await asyncio.gather(
            scan_secrets(repo_dir, sse),
            scan_dependencies(repo_dir, sse),
        )
        all_findings.extend(secret_findings)
        all_findings.extend(dep_findings)
        logger.info(f"Deterministic scan done: {len(secret_findings)} secrets, {len(dep_findings)} CVEs")

        # Step 4: Spawn focused hunter agents in parallel
        HUNTER_FOCUSES = [
            ("hunter-injection",
             "Focus on injection vulnerabilities: SQL injection, NoSQL injection, "
             "command injection, code injection (eval/exec), LDAP injection, XPath injection, "
             "template injection. Trace user input from request parameters, headers, body "
             "through the code to dangerous sinks like database queries, shell commands, "
             "eval() calls, template rendering."),
            ("hunter-auth",
             "Focus on authentication, authorization, and session management: weak password "
             "storage, missing authentication on endpoints, broken access control, privilege "
             "escalation, insecure session handling, JWT issues, OAuth misconfiguration, "
             "IDOR vulnerabilities."),
            ("hunter-web",
             "Focus on web application vulnerabilities: XSS (stored, reflected, DOM-based), "
             "CSRF, SSRF, open redirects, path traversal, file upload vulnerabilities, "
             "insecure deserialization, CORS misconfiguration, missing security headers, "
             "information disclosure."),
            ("hunter-config",
             "Focus on configuration and cryptography issues: hardcoded secrets/credentials, "
             "weak encryption, insecure random number generation, debug mode enabled, verbose "
             "errors in production, insecure Docker/infrastructure configs, missing rate "
             "limiting, exposed internal endpoints."),
        ]

        logger.info(f"Starting {len(HUNTER_FOCUSES)} parallel hunter agents...")
        await sse.emit_status("hunter_agent", "running",
                              f"Spawning {len(HUNTER_FOCUSES)} parallel investigators...")

        hunter_tasks = [
            asyncio.create_task(
                run_hunter(
                    "", {"file_tree": file_tree_summary}, repo_dir, sse,
                    existing_findings=all_findings,
                    hunter_id=hid,
                    focus_area=focus,
                )
            )
            for hid, focus in HUNTER_FOCUSES
        ]

        hunter_results = await asyncio.gather(*hunter_tasks, return_exceptions=True)

        # Collect findings from all hunters
        all_hunter_findings = []
        for i, result in enumerate(hunter_results):
            hid = HUNTER_FOCUSES[i][0]
            if isinstance(result, Exception):
                logger.error(f"{hid} failed: {result}")
            else:
                all_hunter_findings.extend(result)
                logger.info(f"{hid} found {len(result)} vulnerabilities")

        # Dedup findings by file+title
        seen = set()
        hunter_findings = []
        for f in all_hunter_findings:
            key = (f.get("file", ""), f.get("title", ""))
            if key not in seen:
                seen.add(key)
                hunter_findings.append(f)

        all_findings.extend(hunter_findings)
        logger.info(f"Hunters complete: {len(hunter_findings)} code-level findings (deduped)")

        # Step 5: Verifier agent
        logger.info("Starting Verifier agent...")
        all_findings = await run_verifier(all_findings, repo_dir, sse)
        logger.info(f"Verifier complete: {len(all_findings)} findings remaining")

        # Step 6: Patcher agent
        logger.info("Starting Patcher agent...")
        patches = await run_patcher(all_findings, manifests_context, sse)
        logger.info(f"Patcher complete: {len(patches)} patches")

        # Final summary
        duration = time.time() - start_time
        secret_count = len([f for f in all_findings if f.get("source") == "secrets"])
        osv_count = len([f for f in all_findings if f.get("source") == "osv"])
        code_count = len([f for f in all_findings if f.get("source") == "code" or f.get("cwe_id")])
        summary = {
            "total_findings": len(all_findings),
            "by_source": {
                "secrets": secret_count,
                "osv": osv_count,
                "code": code_count,
            },
            "patches_generated": len(patches),
            "duration_seconds": round(duration, 1),
            "files_scanned": len(all_files),
        }
        logger.info(f"Scan complete in {duration:.1f}s: {summary}")
        await sse.emit_complete(summary)

    except Exception as e:
        logger.error(f"Scan failed: {e}\n{traceback.format_exc()}")
        await sse.emit_error("orchestrator", f"Scan failed: {str(e)}")

    finally:
        if temp_dir:
            cleanup_temp_dir(temp_dir)
        await sse.done()
