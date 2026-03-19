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
        repo_dir = clone_repo(repo_url, temp_dir)
        await sse.emit_status("ingestion", "complete", "Repository cloned")

        # Step 2: Collect file metadata
        logger.info("Collecting file metadata...")
        await sse.emit_status("ingestion", "running", "Analyzing repository structure...")
        all_files = collect_all_files(repo_dir)
        file_tree_summary = build_file_tree_summary(all_files)
        manifests_context = flatten_manifests_and_configs(repo_dir, all_files)

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

        # Step 4: Lead Hunter agent — can spawn sub-hunters dynamically
        logger.info("Starting lead Hunter agent...")
        sub_hunter_tasks = []

        async def spawn_sub_hunter(hunter_id: str, focus: str):
            """Called by the lead hunter to spawn a parallel sub-agent."""
            logger.info(f"Lead hunter spawning sub-agent: {hunter_id} → {focus}")
            await sse.emit_status("hunter_agent", "running", f"Spawned {hunter_id}: {focus[:60]}...")
            task = asyncio.create_task(
                run_hunter(
                    "", {"file_tree": file_tree_summary}, repo_dir, sse,
                    existing_findings=all_findings,
                    hunter_id=hunter_id,
                    focus_area=focus,
                )
            )
            sub_hunter_tasks.append(task)
            return {"status": "spawned", "hunter_id": hunter_id}

        lead_findings = await run_hunter(
            "", {"file_tree": file_tree_summary}, repo_dir, sse,
            existing_findings=all_findings,
            hunter_id="lead",
            spawn_fn=spawn_sub_hunter,
        )

        # Wait for all sub-hunters to finish
        if sub_hunter_tasks:
            logger.info(f"Waiting for {len(sub_hunter_tasks)} sub-hunters to finish...")
            await sse.emit_status("hunter_agent", "running", f"Waiting for {len(sub_hunter_tasks)} sub-agents...")
            sub_results = await asyncio.gather(*sub_hunter_tasks, return_exceptions=True)
            for i, result in enumerate(sub_results):
                if isinstance(result, Exception):
                    logger.error(f"Sub-hunter {i} failed: {result}")
                else:
                    lead_findings.extend(result)

        # Dedup findings by file+title
        seen = set()
        hunter_findings = []
        for f in lead_findings:
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
