import httpx


async def web_search_tool(query: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://api.duckduckgo.com/",
                params={"q": query, "format": "json", "no_html": "1", "skip_disambig": "1"},
            )
            if resp.status_code != 200:
                return {"results": [], "note": "Web search unavailable"}
            data = resp.json()

        results = []

        if data.get("Abstract"):
            results.append({
                "title": data.get("Heading", ""),
                "url": data.get("AbstractURL", ""),
                "snippet": data["Abstract"],
            })

        for topic in data.get("RelatedTopics", [])[:5]:
            if isinstance(topic, dict) and topic.get("Text"):
                results.append({
                    "title": topic.get("Text", "")[:100],
                    "url": topic.get("FirstURL", ""),
                    "snippet": topic.get("Text", ""),
                })

        if not results:
            return {
                "results": [{
                    "title": f"Search results for: {query}",
                    "url": f"https://duckduckgo.com/?q={query.replace(' ', '+')}",
                    "snippet": "No instant answer available. The agent should consider this search inconclusive and rely on its existing knowledge.",
                }],
            }

        return {"results": results}

    except Exception as e:
        return {"results": [], "error": str(e)}
