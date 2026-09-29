"""The console sign-in account and what it may approve."""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ...core.config_storage import get_section, update_raw_section
from .auth import (
    WEAK_PASSWORD_VALUES,
    apply_credentials,
    get_auth,
    hash_password,
    is_password_hash,
    verify_credentials,
)
from .operators_view import approval_groups

router = APIRouter(prefix="/api/operators", tags=["operators"])


class OperatorUpdate(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    username: str = Field(default="", max_length=128)
    new_password: str = Field(default="", max_length=1024)
    confirm_password: str = Field(default="", max_length=1024)


@router.get("")
async def get_operator():
    return {
        "success": True,
        "username": get_auth().config.username,
        "groups": approval_groups(),
    }


@router.post("")
async def update_operator(payload: OperatorUpdate):
    auth = get_auth()
    current_name = auth.config.username
    username = (payload.username or current_name).strip()
    new_password = payload.new_password or ""
    errors = {}
    if not verify_credentials(current_name, payload.current_password):
        errors["current_password"] = "Current password is wrong."
    if not username:
        errors["username"] = "Username is required."
    if new_password:
        if new_password != payload.confirm_password:
            errors["confirm_password"] = "Confirmation does not match the new password."
        if new_password.strip().lower() in WEAK_PASSWORD_VALUES or not new_password.strip():
            errors["new_password"] = "Choose a password that is not a well-known default."
    elif payload.confirm_password:
        errors["confirm_password"] = "Enter the new password before confirming it."
    if not errors and username == current_name and not new_password:
        errors["username"] = "Change the username or the password."
    if errors:
        return JSONResponse(status_code=400, content={"success": False, "errors": errors})

    if new_password:
        password = hash_password(new_password)
    elif is_password_hash(auth.config.password):
        password = auth.config.password
    else:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "errors": {"current_password": "Stored password is not an Argon2id hash."},
            },
        )
    raw = dict(get_section("web", {}))
    raw["username"] = username
    raw["password"] = password
    update_raw_section("web", raw)
    apply_credentials(username, password)
    return {"success": True, "username": username}
