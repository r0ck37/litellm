import base64
import hashlib
import re
import secrets
import time
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
from integration._support.client import JSON_OBJECT, Gateway, object_value, string_value
from integration._support.process import owned_proxy
from pydantic import JsonValue

RESOURCE: Final = "https://gateway.integration.example"
CALLBACK: Final = "https://app.integration.example/callback"


def _authorize(gateway: Gateway, user: str) -> tuple[str, dict[str, JsonValue]]:
    registration: Final = gateway.client.post("/register", json={"redirect_uris": [CALLBACK]})
    assert registration.status_code == 201, registration.text
    client: Final = string_value(JSON_OBJECT.validate_json(registration.content)["client_id"])
    verifier: Final = secrets.token_urlsafe(48)
    challenge: Final = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    cookies: Final = {
        "token": jwt.encode(
            {"user_id": user, "login_method": "username_password", "exp": int(time.time()) + 600},
            gateway.key,
            algorithm="HS256",
        )
    }
    consent: Final = gateway.client.get(
        "/authorize",
        params={
            "client_id": client,
            "redirect_uri": CALLBACK,
            "response_type": "code",
            "state": user,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": RESOURCE,
            "scope": "proxy:admin",
        },
        cookies=cookies,
    )
    assert consent.status_code == 200, consent.text
    flow: Final = re.search(r'name="flow" value="([^"]+)"', consent.text)
    assert flow is not None, consent.text
    approved: Final = gateway.client.post(
        "/authorize/complete",
        data={"flow": flow[1], "decision": "approve"},
        cookies={**cookies, **dict(consent.cookies)},
    )
    assert approved.status_code == 303, approved.text
    callback: Final = parse_qs(urlsplit(approved.headers["location"]).query)
    assert callback["state"] == [user]
    issued: Final = gateway.client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "client_id": client,
            "code": callback["code"][0],
            "redirect_uri": CALLBACK,
            "code_verifier": verifier,
            "resource": RESOURCE,
        },
    )
    assert issued.status_code == 200, issued.text
    return client, JSON_OBJECT.validate_json(issued.content)


def _refresh(gateway: Gateway, client: str, token: str) -> httpx.Response:
    return gateway.client.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client,
            "refresh_token": token,
            "resource": RESOURCE,
        },
    )


def test_delegated_grants_share_rotation_revocation_and_live_role_checks(gateway: Gateway, tmp_path: Path) -> None:
    overrides: Final = {"PROXY_BASE_URL": RESOURCE, "LITELLM_OAUTH_ADMIN_REDIRECT_URIS": CALLBACK}
    with (
        owned_proxy(gateway, tmp_path, overrides) as first,
        owned_proxy(gateway, tmp_path, overrides) as second,
        first.scenario() as scenario,
    ):
        admin: Final = scenario.user(user_role="proxy_admin")
        for outcome in ("replay", "revoke", "demote"):
            client, original = _authorize(first, admin)
            access: Final = string_value(original["access_token"])
            refresh: Final = string_value(original["refresh_token"])
            created: Final = first.post("/key/generate", {"user_id": admin}, key=access)
            key: Final = string_value(created["key"])
            scenario.cleanups.callback(scenario.delete_key, key)
            read: Final = second.request("GET", "/key/info", key=access, params={"key": key})
            assert read.status_code == 200, read.text
            assert object_value(JSON_OBJECT.validate_json(read.content)["info"])["user_id"] == admin
            rotated: Final = _refresh(second, client, refresh)
            assert rotated.status_code == 200, rotated.text
            pair: Final = JSON_OBJECT.validate_json(rotated.content)
            next_access: Final = string_value(pair["access_token"])
            next_refresh: Final = string_value(pair["refresh_token"])
            assert next_refresh != refresh
            warmed: Final = first.request("GET", "/user/info", key=next_access, params={"user_id": admin})
            assert warmed.status_code == 200, warmed.text
            if outcome == "replay":
                assert _refresh(first, client, refresh).status_code == 400
            elif outcome == "revoke":
                revoked: Final = first.client.post("/revoke", data={"client_id": client, "token": next_refresh})
                assert revoked.status_code == 200, revoked.text
            else:
                first.post("/user/update", {"user_id": admin, "user_role": "internal_user"})
            for worker in (first, second):
                for bearer in (access, next_access):
                    denied: Final = worker.request("GET", "/user/info", key=bearer, params={"user_id": admin})
                    assert denied.status_code in (401, 403), denied.text
                renewal: Final = _refresh(worker, client, next_refresh)
                assert renewal.status_code == 400, renewal.text
