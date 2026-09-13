from __future__ import annotations

import httpx
from fastapi import APIRouter, HTTPException, Response
from firebase_admin import auth as firebase_auth
from pydantic import BaseModel, Field

from app.api.auth import create_session, hash_password, set_session_cookie, user_payload
from app.config import settings
from app.db import connection
from app.firebase import firebase_app

router = APIRouter(prefix="/api/auth", tags=["auth"])


class GoogleLoginRequest(BaseModel):
    credential: str = Field(min_length=20, max_length=10000)


@router.post("/google")
async def google_login(payload: GoogleLoginRequest, response: Response) -> dict[str, object]:
    """Verify Google Sign-In and map the identity into shared Firebase Auth.

    The Firebase Admin credential is read only on the Render server from the
    configured Secret File/environment. It is never sent to the browser.
    """
    if not settings.google_client_id:
        raise HTTPException(status_code=503, detail="Google Sign-In is not configured on the Aither Backend.")

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            result = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": payload.credential},
            )
            data = result.json()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Could not verify the Google sign-in token.") from exc

    if result.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid Google sign-in token.")
    if data.get("aud") != settings.google_client_id:
        raise HTTPException(status_code=401, detail="Google sign-in token was issued for a different application.")
    if data.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}:
        raise HTTPException(status_code=401, detail="Invalid Google token issuer.")
    if data.get("email_verified") != "true":
        raise HTTPException(status_code=403, detail="Your Google email must be verified before using it with Aither.")

    email = str(data.get("email", "")).strip().lower()
    name = str(data.get("name") or data.get("given_name") or email.split("@", 1)[0]).strip()[:80]
    if not email or "@" not in email:
        raise HTTPException(status_code=401, detail="Google did not provide a valid email address.")

    # Firebase is now the shared identity source for all Aither apps.
    try:
        firebase_app()
        try:
            firebase_user = firebase_auth.get_user_by_email(email)
            if firebase_user.display_name != name or not firebase_user.email_verified:
                firebase_user = firebase_auth.update_user(
                    firebase_user.uid,
                    display_name=name,
                    email_verified=True,
                )
        except firebase_auth.UserNotFoundError:
            firebase_user = firebase_auth.create_user(
                email=email,
                display_name=name,
                email_verified=True,
            )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Firebase authentication is not configured correctly on the Aither Backend.") from exc

    firebase_uid = firebase_user.uid

    # Keep the existing Aither session/API model, but key Firebase users by
    # their shared Firebase UID so every Aither app resolves to one account.
    with connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            user_id = row["id"]
            conn.execute(
                "UPDATE users SET name = ?, email_verified = 1 WHERE id = ?",
                (name, user_id),
            )
            current_name = name
        else:
            user_id = f"firebase_{firebase_uid}"
            existing_id = conn.execute("SELECT id FROM users WHERE id = ?", (user_id,)).fetchone()
            if existing_id:
                row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
                current_name = row["name"] if row else name
            else:
                conn.execute(
                    "INSERT INTO users(id,name,email,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,datetime('now'))",
                    (user_id, name, email, hash_password(firebase_uid), 1),
                )
                current_name = name

    session_token_value = create_session(user_id)
    set_session_cookie(response, session_token_value)
    return {
        "authenticated": True,
        "session_token": session_token_value,
        "user": user_payload(user_id, current_name, email, True),
        "firebase_uid": firebase_uid,
        "auth_provider": "firebase",
    }
