from __future__ import annotations

import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, HTTPException
from firebase_admin import auth as firebase_auth
from pydantic import BaseModel, Field

from app.config import settings
from app.firebase import firebase_app

router = APIRouter(prefix="/api/config", tags=["config"])

_HANDOFF_TTL_SECONDS = 120
_handoffs: dict[str, tuple[float, dict[str, object]]] = {}


@router.get("")
async def public_config() -> dict[str, object]:
    return {
        "app_name": settings.app_name,
        "app_version": settings.app_version,
        "environment": settings.environment,
    }


@router.get("/firebase")
async def firebase_web_config() -> dict[str, object]:
    """Return only public Firebase Web SDK settings.

    The Firebase Web API key is public client configuration.
    Firebase Admin credentials and service-account secrets are never returned.
    """
    return {
        "apiKey": settings.firebase_api_key.strip(),
        "authDomain": f"{settings.firebase_project_id}.firebaseapp.com",
        "projectId": settings.firebase_project_id,
        "storageBucket": f"{settings.firebase_project_id}.firebasestorage.app",
    }


class AitherSignInCodeRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=10000)
    client_id: str = Field(min_length=1, max_length=200)
    redirect_uri: str = Field(min_length=10, max_length=2000)
    state: str = Field(default="", max_length=1000)


def _allowed_redirect(uri: str) -> bool:
    parsed = urlparse(uri)
    if parsed.scheme != "https":
        return parsed.hostname == "localhost"
    return parsed.hostname == "aitherforge.github.io"


def _cleanup_handoffs() -> None:
    now = time.time()
    for code, (expires, _) in list(_handoffs.items()):
        if expires <= now:
            _handoffs.pop(code, None)


@router.post("/aithersignin/code")
async def create_aithersignin_code(payload: AitherSignInCodeRequest) -> dict[str, str]:
    if not _allowed_redirect(payload.redirect_uri):
        raise HTTPException(status_code=400, detail="Redirect URI is not allowed.")

    try:
        firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.") from exc

    _cleanup_handoffs()
    code = secrets.token_urlsafe(32)
    _handoffs[code] = (
        time.time() + _HANDOFF_TTL_SECONDS,
        {
            "id": str(decoded.get("uid") or ""),
            "username": str(decoded.get("name") or decoded.get("email") or "Aither User"),
            "email": str(decoded.get("email") or ""),
            "photoURL": str(decoded.get("picture") or ""),
            "client_id": payload.client_id,
        },
    )

    parsed = urlparse(payload.redirect_uri)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["aither_code"] = code
    if payload.state:
        query["state"] = payload.state

    return {
        "redirect_uri": urlunparse(parsed._replace(query=urlencode(query))),
        "expires_in": str(_HANDOFF_TTL_SECONDS),
    }


class AitherSignInTokenRequest(BaseModel):
    code: str = Field(min_length=20, max_length=500)
    client_id: str = Field(min_length=1, max_length=200)


@router.post("/aithersignin/token")
async def exchange_aithersignin_code(payload: AitherSignInTokenRequest) -> dict[str, object]:
    _cleanup_handoffs()
    handoff = _handoffs.pop(payload.code, None)
    if not handoff:
        raise HTTPException(status_code=400, detail="Invalid or expired AitherSignIn code.")

    _, account = handoff
    if account["client_id"] != payload.client_id:
        raise HTTPException(status_code=400, detail="AitherSignIn client mismatch.")

    return {
        "authenticated": True,
        "user": {
            "id": account["id"],
            "username": account["username"],
            "email": account["email"],
            "photoURL": account["photoURL"],
        },
    }
