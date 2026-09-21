from __future__ import annotations

import json
import os
import secrets
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import APIRouter, HTTPException
from firebase_admin import auth as firebase_auth
from pydantic import BaseModel, Field
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config import settings
from app.db import connection
from app.firebase import firebase_app

router = APIRouter(prefix="/api/config", tags=["config"])

_HANDOFF_TTL_SECONDS = 120
_DEVICE_CODE_TTL_SECONDS = 120
_handoffs: dict[str, tuple[float, dict[str, object]]] = {}
_device_codes: dict[str, tuple[float, str]] = {}
_passkey_challenges: dict[str, tuple[float, bytes, str | None]] = {}

PASSKEY_RP_ID = os.getenv("PASSKEY_RP_ID", "aithernexus.gitlab.io").strip()
PASSKEY_ORIGIN = os.getenv("PASSKEY_ORIGIN", "https://aithernexus.gitlab.io").strip()


@router.get("")
async def public_config() -> dict[str, object]:
    return {"app_name": settings.app_name, "app_version": settings.app_version, "environment": settings.environment}


@router.get("/firebase")
async def firebase_web_config() -> dict[str, object]:
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


def _cleanup() -> None:
    now = time.time()
    for store in (_handoffs, _device_codes, _passkey_challenges):
        for key, value in list(store.items()):
            if value[0] <= now:
                store.pop(key, None)


def _firebase_user(uid: str, email: str, name: str, photo_url: str = ""):
    firebase_app()
    try:
        return firebase_auth.get_user(uid)
    except Exception:
        try:
            return firebase_auth.get_user_by_email(email)
        except Exception:
            return firebase_auth.create_user(uid=uid, email=email, display_name=name or email, photo_url=photo_url or None)


@router.post("/aithersignin/code")
async def create_aithersignin_code(payload: AitherSignInCodeRequest) -> dict[str, str]:
    if not _allowed_redirect(payload.redirect_uri):
        raise HTTPException(status_code=400, detail="Redirect URI is not allowed.")
    try:
        firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.") from exc

    _cleanup()
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
    return {"redirect_uri": urlunparse(parsed._replace(query=urlencode(query))), "expires_in": str(_HANDOFF_TTL_SECONDS)}


class AitherSignInTokenRequest(BaseModel):
    code: str = Field(min_length=20, max_length=500)
    client_id: str = Field(min_length=1, max_length=200)


@router.post("/aithersignin/token")
async def exchange_aithersignin_code(payload: AitherSignInTokenRequest) -> dict[str, object]:
    _cleanup()
    handoff = _handoffs.pop(payload.code, None)
    if not handoff:
        raise HTTPException(status_code=400, detail="Invalid or expired AitherSignIn code.")
    _, account = handoff
    if account["client_id"] != payload.client_id:
        raise HTTPException(status_code=400, detail="AitherSignIn client mismatch.")
    return {"authenticated": True, "user": {"id": account["id"], "username": account["username"], "email": account["email"], "photoURL": account["photoURL"]}}


class DeviceCodeRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=10000)


@router.post("/aithersignin/device-code")
async def create_device_code(payload: DeviceCodeRequest) -> dict[str, str]:
    try:
        firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.") from exc
    _cleanup()
    code = "".join(secrets.choice("23456789ABCDEFGHJKLMNPQRSTUVWXYZ") for _ in range(8))
    _device_codes[code] = (time.time() + _DEVICE_CODE_TTL_SECONDS, str(decoded["uid"]))
    return {"code": code, "expires_in": str(_DEVICE_CODE_TTL_SECONDS)}


class DeviceCodeRedeemRequest(BaseModel):
    code: str = Field(min_length=6, max_length=32)


@router.post("/aithersignin/device-code/redeem")
async def redeem_device_code(payload: DeviceCodeRedeemRequest) -> dict[str, object]:
    _cleanup()
    entry = _device_codes.pop(payload.code.strip().upper(), None)
    if not entry:
        raise HTTPException(status_code=400, detail="Invalid or expired one-time code.")
    _, uid = entry
    firebase_app()
    user = firebase_auth.get_user(uid)
    custom_token = firebase_auth.create_custom_token(uid)
    return {
        "authenticated": True,
        "custom_token": custom_token.decode("utf-8") if isinstance(custom_token, bytes) else custom_token,
        "user": {"id": uid, "username": user.display_name or user.email or "Aither User", "email": user.email or "", "photoURL": user.photo_url or ""},
    }


class UsernamePasswordRequest(BaseModel):
    username: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=200)


@router.post("/aithersignin/username-password")
async def aither_username_password(payload: UsernamePasswordRequest) -> dict[str, object]:
    from app.api.auth import verify_password

    identifier = payload.username.strip().lower()
    with connection() as conn:
        row = conn.execute(
            "SELECT id,name,email,password_hash,email_verified FROM users WHERE lower(email)=? OR lower(name)=? LIMIT 1",
            (identifier, identifier),
        ).fetchone()
    if not row or not verify_password(payload.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid Aither username/email or password.")

    uid = str(row["id"])
    email = str(row["email"])
    name = str(row["name"])
    try:
        firebase_app()
        try:
            fb = firebase_auth.get_user(uid)
            if fb.email and fb.email.lower() != email.lower():
                fb = firebase_auth.get_user_by_email(email)
        except Exception:
            try:
                fb = firebase_auth.get_user_by_email(email)
            except Exception:
                fb = firebase_auth.create_user(uid=uid, email=email, display_name=name)
        custom_token = firebase_auth.create_custom_token(fb.uid)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Aither account sign-in is temporarily unavailable.") from exc

    return {
        "authenticated": True,
        "custom_token": custom_token.decode("utf-8") if isinstance(custom_token, bytes) else custom_token,
        "user": {"id": fb.uid, "username": name, "email": email, "photoURL": fb.photo_url or ""},
    }


def _store_passkey(user_id: str, credential_id: bytes, public_key: bytes, sign_count: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO passkeys(credential_id,user_id,public_key,sign_count,created_at) VALUES(?,?,?,?,?)",
            (bytes_to_base64url(credential_id), user_id, bytes_to_base64url(public_key), int(sign_count), now),
        )


class PasskeyRegisterRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=10000)


@router.post("/aithersignin/passkey/register/options")
async def passkey_register_options(payload: PasskeyRegisterRequest) -> dict[str, object]:
    try:
        firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.") from exc

    uid = str(decoded["uid"])
    email = str(decoded.get("email") or uid)
    with connection() as conn:
        rows = conn.execute("SELECT credential_id FROM passkeys WHERE user_id=?", (uid,)).fetchall()
    excludes = [PublicKeyCredentialDescriptor(id=base64url_to_bytes(row["credential_id"])) for row in rows]
    options = generate_registration_options(
        rp_id=PASSKEY_RP_ID,
        rp_name="Aither",
        user_id=uid.encode("utf-8"),
        user_name=email,
        user_display_name=str(decoded.get("name") or email),
        authenticator_selection=AuthenticatorSelectionCriteria(resident_key=ResidentKeyRequirement.REQUIRED),
        exclude_credentials=excludes,
    )
    _cleanup()
    challenge_id = secrets.token_urlsafe(24)
    _passkey_challenges[challenge_id] = (time.time() + 300, options.challenge, uid)
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


class PasskeyRegisterVerifyRequest(BaseModel):
    id_token: str = Field(min_length=20, max_length=10000)
    challenge_id: str = Field(min_length=10, max_length=200)
    credential: dict


@router.post("/aithersignin/passkey/register/verify")
async def passkey_register_verify(payload: PasskeyRegisterVerifyRequest) -> dict[str, object]:
    try:
        firebase_app()
        decoded = firebase_auth.verify_id_token(payload.id_token, check_revoked=True)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid Firebase ID token.") from exc
    _cleanup()
    entry = _passkey_challenges.pop(payload.challenge_id, None)
    if not entry or entry[2] != str(decoded["uid"]):
        raise HTTPException(status_code=400, detail="Invalid or expired passkey registration.")
    try:
        verification = verify_registration_response(
            credential=payload.credential,
            expected_challenge=entry[1],
            expected_origin=PASSKEY_ORIGIN,
            expected_rp_id=PASSKEY_RP_ID,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Passkey registration could not be verified.") from exc
    _store_passkey(str(decoded["uid"]), verification.credential_id, verification.credential_public_key, verification.sign_count)
    return {"registered": True}


@router.post("/aithersignin/passkey/auth/options")
async def passkey_auth_options() -> dict[str, object]:
    _cleanup()
    options = generate_authentication_options(
        rp_id=PASSKEY_RP_ID,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    challenge_id = secrets.token_urlsafe(24)
    _passkey_challenges[challenge_id] = (time.time() + 300, options.challenge, None)
    return {"challenge_id": challenge_id, "options": json.loads(options_to_json(options))}


class PasskeyAuthVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=10, max_length=200)
    credential: dict


@router.post("/aithersignin/passkey/auth/verify")
async def passkey_auth_verify(payload: PasskeyAuthVerifyRequest) -> dict[str, object]:
    _cleanup()
    entry = _passkey_challenges.pop(payload.challenge_id, None)
    if not entry:
        raise HTTPException(status_code=400, detail="Invalid or expired passkey challenge.")
    credential_id = str(payload.credential.get("id") or "")
    with connection() as conn:
        row = conn.execute("SELECT user_id,public_key,sign_count FROM passkeys WHERE credential_id=?", (credential_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="That passkey is not registered with Aither.")
    try:
        verification = verify_authentication_response(
            credential=payload.credential,
            expected_challenge=entry[1],
            expected_origin=PASSKEY_ORIGIN,
            expected_rp_id=PASSKEY_RP_ID,
            credential_public_key=base64url_to_bytes(row["public_key"]),
            credential_current_sign_count=int(row["sign_count"]),
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Passkey verification failed.") from exc

    with connection() as conn:
        conn.execute("UPDATE passkeys SET sign_count=? WHERE credential_id=?", (int(verification.new_sign_count), credential_id))
    firebase_app()
    custom_token = firebase_auth.create_custom_token(str(row["user_id"]))
    user = firebase_auth.get_user(str(row["user_id"]))
    return {
        "authenticated": True,
        "custom_token": custom_token.decode("utf-8") if isinstance(custom_token, bytes) else custom_token,
        "user": {"id": user.uid, "username": user.display_name or user.email or "Aither User", "email": user.email or "", "photoURL": user.photo_url or ""},
    }
