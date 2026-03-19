import json
import os
import re
import httpx
from core.sse_manager import SSEManager

OSV_API = "https://api.osv.dev/v1/query"


def parse_package_json(repo_dir: str) -> list[dict]:
    deps = []
    pkg_path = os.path.join(repo_dir, "package.json")
    if not os.path.exists(pkg_path):
        return deps

    with open(pkg_path, "r") as f:
        data = json.load(f)

    for section in ("dependencies", "devDependencies"):
        for name, version_spec in data.get(section, {}).items():
            version = re.sub(r"[^0-9.]", "", version_spec).strip(".")
            if version:
                deps.append({"name": name, "ecosystem": "npm", "version": version})
    return deps


def parse_requirements_txt(repo_dir: str) -> list[dict]:
    deps = []
    for fname in ("requirements.txt", "requirements-dev.txt", "requirements_dev.txt"):
        req_path = os.path.join(repo_dir, fname)
        if not os.path.exists(req_path):
            continue

        with open(req_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                match = re.match(r"^([A-Za-z0-9_.-]+)\s*==\s*([0-9.]+)", line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "ecosystem": "PyPI",
                        "version": match.group(2),
                    })
    return deps


def parse_go_mod(repo_dir: str) -> list[dict]:
    deps = []
    gomod_path = os.path.join(repo_dir, "go.mod")
    if not os.path.exists(gomod_path):
        return deps

    with open(gomod_path, "r") as f:
        in_require = False
        for line in f:
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require:
                parts = line.split()
                if len(parts) >= 2:
                    deps.append({
                        "name": parts[0],
                        "ecosystem": "Go",
                        "version": parts[1].lstrip("v"),
                    })
    return deps


def parse_gemfile_lock(repo_dir: str) -> list[dict]:
    deps = []
    path = os.path.join(repo_dir, "Gemfile.lock")
    if not os.path.exists(path):
        return deps

    with open(path, "r") as f:
        in_specs = False
        for line in f:
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                if not line.startswith("    "):
                    if line.strip() and not line.startswith("      "):
                        in_specs = False
                        continue
                match = re.match(r"^\s{4}(\S+)\s+\(([0-9.]+)\)", line)
                if match:
                    deps.append({
                        "name": match.group(1),
                        "ecosystem": "RubyGems",
                        "version": match.group(2),
                    })
    return deps


async def query_osv(package: dict) -> list[dict]:
    payload = {
        "package": {
            "name": package["name"],
            "ecosystem": package["ecosystem"],
        },
    }
    if package.get("version"):
        payload["version"] = package["version"]

    async with httpx.AsyncClient(timeout=10.0) as client:
        resp = await client.post(OSV_API, json=payload)
        if resp.status_code != 200:
            return []
        data = resp.json()

    vulns = []
    for v in data.get("vulns", []):
        severity = "MEDIUM"
        severity_data = v.get("database_specific", {}).get("severity")
        if severity_data:
            severity = severity_data.upper()
        else:
            for s in v.get("severity", []):
                score = s.get("score", "")
                if "CRITICAL" in str(score).upper():
                    severity = "CRITICAL"
                elif "HIGH" in str(score).upper():
                    severity = "HIGH"

        fix_version = ""
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fix_version = event["fixed"]

        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))

        vulns.append({
            "id": cve_id or v.get("id", ""),
            "summary": v.get("summary", v.get("details", "")[:200]),
            "severity": severity,
            "affected_versions": "",
            "fix_version": fix_version,
            "references": [ref.get("url", "") for ref in v.get("references", [])[:3]],
        })

    return vulns


async def scan_dependencies(repo_dir: str, sse: SSEManager) -> list[dict]:
    await sse.emit_status("dependency_scanner", "running", "Scanning dependencies for known CVEs...")

    all_deps = []
    all_deps.extend(parse_package_json(repo_dir))
    all_deps.extend(parse_requirements_txt(repo_dir))
    all_deps.extend(parse_go_mod(repo_dir))
    all_deps.extend(parse_gemfile_lock(repo_dir))

    if not all_deps:
        await sse.emit_status("dependency_scanner", "complete", "No dependency manifests found")
        return []

    await sse.emit_status("dependency_scanner", "running", f"Checking {len(all_deps)} dependencies against OSV.dev...")

    findings = []
    finding_id = 0

    for dep in all_deps:
        try:
            vulns = await query_osv(dep)
        except Exception:
            continue

        for vuln in vulns:
            finding_id += 1
            finding = {
                "id": f"CVE-{finding_id:03d}",
                "source": "osv",
                "severity": vuln["severity"],
                "title": f"{vuln['id']}: {dep['name']}@{dep.get('version', 'unknown')}",
                "file": _manifest_file(dep["ecosystem"]),
                "line": 0,
                "description": vuln["summary"],
                "details": {
                    "package": dep["name"],
                    "ecosystem": dep["ecosystem"],
                    "installed_version": dep.get("version", "unknown"),
                    "cve_id": vuln["id"],
                    "fix_version": vuln["fix_version"],
                    "references": vuln["references"],
                },
            }
            findings.append(finding)
            await sse.emit_finding(finding)

    await sse.emit_status("dependency_scanner", "complete", f"Found {len(findings)} known CVEs")
    return findings


def _manifest_file(ecosystem: str) -> str:
    return {
        "npm": "package.json",
        "PyPI": "requirements.txt",
        "Go": "go.mod",
        "RubyGems": "Gemfile.lock",
    }.get(ecosystem, "unknown")
