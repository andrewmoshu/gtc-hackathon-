import httpx

OSV_API = "https://api.osv.dev/v1/query"


async def osv_query_tool(package_name: str, ecosystem: str, version: str = "") -> dict:
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ecosystem,
        },
    }
    if version:
        payload["version"] = version

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(OSV_API, json=payload)
            if resp.status_code != 200:
                return {"error": f"OSV API returned status {resp.status_code}", "vulnerabilities": []}
            data = resp.json()
    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}

    vulns = []
    for v in data.get("vulns", []):
        severity = "MEDIUM"
        for s in v.get("severity", []):
            score_str = str(s.get("score", ""))
            if "CRITICAL" in score_str.upper() or (score_str.replace(".", "").isdigit() and float(score_str) >= 9.0):
                severity = "CRITICAL"
            elif "HIGH" in score_str.upper() or (score_str.replace(".", "").isdigit() and float(score_str) >= 7.0):
                severity = "HIGH"

        fix_version = ""
        affected_versions = ""
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        fix_version = event["fixed"]

        aliases = v.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))

        vulns.append({
            "id": cve_id or v.get("id", ""),
            "summary": v.get("summary", v.get("details", "")[:300]),
            "severity": severity,
            "affected_versions": affected_versions,
            "fixed_version": fix_version,
            "references": [ref.get("url", "") for ref in v.get("references", [])[:3]],
        })

    return {"vulnerabilities": vulns[:10]}
