from fastapi import APIRouter

from app.config import settings

router = APIRouter(prefix="/api/config", tags=["config"])


@router.get("")
async def public_config() -> dict[str, object]:
    return {
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "environment": settings.environment,
    }


@router.get("/firebase")
async def firebase_web_config() -> dict[str, object]:
    """Return only the public Firebase Web SDK settings.

    The Firebase Web API key is public client configuration.
    Firebase Admin credentials and service-account secrets are never returned.
    """
    return {
        "apiKey": settings.firebase_api_key.strip(),
        "authDomain": f"{settings.firebase_project_id}.firebaseapp.com",
        "projectId": settings.firebase_project_id,
        "storageBucket": f"{settings.firebase_project_id}.firebasestorage.app",
    }
