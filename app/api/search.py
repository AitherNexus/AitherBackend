from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Query

from app.config import settings

router = APIRouter(prefix="/api/search", tags=["search"])


@router.get("")
async def search(
    q: str = Query(min_length=1, max_length=500),
    page: int = Query(default=1, ge=1, le=10),
    num: int = Query(default=10, ge=1, le=10),
    device: str = Query(default="desktop", pattern="^(desktop|mobile|tablet)$"),
    location: str | None = Query(default=None, max_length=200),
    language: str | None = Query(default=None, max_length=50),
) -> dict[str, Any]:
    """Search the public web through Google's Custom Search JSON API."""
    if not settings.google_search_api_key:
        raise HTTPException(
            status_code=503,
            detail="Google Search is not configured on AitherBackend. Add GOOGLE_SEARCH_API_KEY as a Render secret.",
        )
    if not settings.google_search_engine_id:
        raise HTTPException(
            status_code=503,
            detail="Google Search Engine ID is not configured on AitherBackend. Add GOOGLE_SEARCH_ENGINE_ID as a Render environment variable.",
        )

    start = ((page - 1) * num) + 1
    if start > 91:
        raise HTTPException(
            status_code=400,
            detail="Google Custom Search supports up to 100 results per query.",
        )

    query = q
    if location:
        query = f"{query} {location}"

    params: dict[str, Any] = {
        "key": settings.google_search_api_key,
        "cx": settings.google_search_engine_id,
        "q": query,
        "start": start,
        "num": num,
        "safe": "active",
    }
    if language:
        params["lr"] = language if language.startswith("lang_") else f"lang_{language}"

    try:
        async with httpx.AsyncClient(timeout=settings.google_search_timeout_seconds) as client:
            response = await client.get(
                "https://www.googleapis.com/customsearch/v1",
                params=params,
            )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="Google Search timed out.") from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail="Could not reach Google Search.") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Google Search returned invalid JSON.") from exc

    if response.status_code >= 400:
        error = data.get("error") if isinstance(data, dict) else None
        message = error.get("message") if isinstance(error, dict) else None
        raise HTTPException(status_code=502, detail=message or "Google Search request failed.")

    results = []
    for index, item in enumerate(data.get("items") or [], start=start):
        if not isinstance(item, dict):
            continue
        results.append(
            {
                "position": index,
                "title": item.get("title"),
                "url": item.get("link"),
                "displayed_url": item.get("displayLink"),
                "snippet": item.get("snippet"),
                "html_snippet": item.get("htmlSnippet"),
                "date": (
                    item.get("pagemap", {}).get("metatags", [{}])[0].get("article:published_time")
                    if isinstance(item.get("pagemap"), dict)
                    else None
                ),
            }
        )

    search_info = data.get("searchInformation") or {}

    return {
        "success": True,
        "provider": "google",
        "query": q,
        "page": page,
        "results": results,
        "total_results": search_info.get("totalResults"),
        "search_time": search_info.get("searchTime"),
    }
