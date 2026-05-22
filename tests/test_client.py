"""Tests for bot.swiftness.

The same shape as test_ordernet.py:

1. **Security invariants** (the important ones): the client cannot
   issue any HTTP POST or GET that isn't on its explicit allowlist.
   Adding a path to either allowlist must be a deliberate, reviewable
   change.
2. Behavioral parsing tests with stubbed network.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from swiftness_mcp import client as swiftness
from swiftness_mcp.client import (
    _ALLOWED_GET_PATHS,
    _ALLOWED_POST_PATHS,
    _AUTH_LOGIN_PATH,
    _AUTH_OTP_PATH,
    _bucket_for,
    _extract_jwt_from_login,
    _scan_for_uuid,
    SavingsSnapshot,
    SwiftnessError,
    SwiftnessReadOnlyClient,
    SwiftnessSecurityError,
    parse_saving_concentrations,
    parse_saving_products,
    total_current_saving,
)


def _mock_response(status: int, payload, text: str | None = None):
    r = MagicMock()
    r.status_code = status
    if isinstance(payload, (dict, list)):
        r.json.return_value = payload
        r.text = text if text is not None else json.dumps(payload)
    else:
        r.json.side_effect = ValueError("not json")
        r.text = text if text is not None else (payload or "")
    return r


# ============================== security invariants ===========================


def test_post_allowlist_contains_no_obviously_writeable_paths():
    """Belt and braces: Swiftness POSTs are unfortunately the *normal*
    way to read data from this API, but none of the paths on our list
    should look like a state-changing endpoint."""
    forbidden = ["update", "delete", "transfer", "withdraw", "switch", "create", "submit"]
    for path in _ALLOWED_POST_PATHS:
        # 'createOtp' is allowed (it's part of auth, doesn't mutate user data).
        if path == _AUTH_OTP_PATH:
            continue
        for f in forbidden:
            assert f.lower() not in path.lower(), (
                f"path {path!r} contains write-like substring {f!r}"
            )


def test_get_allowlist_contains_only_doc_download():
    """Today the only GET we issue is the consolidated XML download."""
    assert _ALLOWED_GET_PATHS == frozenset({"helpers/getDocument"})


def test_post_to_unknown_path_is_blocked_before_network(monkeypatch):
    """Calling _post with an off-list path must raise BEFORE any HTTP
    happens. We fake the session so a sneaky network call would
    show up in `network_calls`."""
    c = SwiftnessReadOnlyClient()
    network_calls: list[str] = []

    def fake_post(url, *a, **kw):
        network_calls.append(url)
        return _mock_response(200, {})

    monkeypatch.setattr(c._session, "post", fake_post)

    forbidden = [
        "auth/changePassword",
        "holdings/transferFunds",
        "withdraw/submit",
        "user/delete",
        "policies/cancel",
        "auth/createOtp/../../holdings/transferFunds",  # naive traversal
    ]
    for path in forbidden:
        with pytest.raises(SwiftnessSecurityError):
            c._post(path, {})
    assert network_calls == [], (
        f"client made network calls when it shouldn't have: {network_calls}"
    )


def test_get_to_unknown_path_is_blocked_before_network(monkeypatch):
    c = SwiftnessReadOnlyClient()
    c._token = "x"
    network_calls: list[str] = []

    def fake_get(url, *a, **kw):
        network_calls.append(url)
        return _mock_response(200, {})

    monkeypatch.setattr(c._session, "get", fake_get)

    for path in ["user/profile", "../helpers/getDocument", "holdings/transferFunds"]:
        with pytest.raises(SwiftnessSecurityError):
            c._get(path)
    assert network_calls == []


def test_no_top_level_method_exposes_unsafe_action():
    """Whitebox: there should be no public method whose name suggests a
    write operation. If you added one, this test should embarrass you."""
    forbidden = {"update", "delete", "transfer", "withdraw", "switch", "submit", "cancel", "place"}
    for name in dir(SwiftnessReadOnlyClient):
        if name.startswith("_"):
            continue
        for f in forbidden:
            assert f not in name.lower(), (
                f"public method {name!r} on SwiftnessReadOnlyClient looks write-y"
            )


# ============================== auth flow =====================================


def test_request_otp_posts_correct_payload(monkeypatch):
    c = SwiftnessReadOnlyClient()
    captured: dict = {}

    def fake_post(url, json=None, headers=None, **kw):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers or {}
        return _mock_response(200, {})

    monkeypatch.setattr(c._session, "post", fake_post)
    c.request_otp("123456789", "you@example.com")

    assert captured["url"].endswith("/auth/createOtp")
    assert captured["json"] == {
        "IdNumber": "123456789",
        "PhoneNumber": "",
        "Email": "you@example.com",
        "Token": "",
        "IsNewSaverOtp": False,
        "AuthType": 2,
    }
    # No bearer header on the auth POST (we don't have one yet).
    assert "Authorization" not in captured["headers"]


def test_login_with_otp_extracts_jwt_from_token_field(monkeypatch):
    c = SwiftnessReadOnlyClient()
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJleHAiOjE3Nzg5Njg1MTR9"
        ".sigvalueAB-_"
    )

    def fake_post(url, json=None, headers=None, **kw):
        return _mock_response(200, {"Token": fake_jwt})

    monkeypatch.setattr(c._session, "post", fake_post)
    out = c.login_with_otp("123456789", "745934", "you@example.com")
    assert out == fake_jwt
    assert c._token == fake_jwt


def test_login_with_otp_extracts_jwt_from_redirect_url(monkeypatch):
    """Some Swiftness responses bury the JWT in a Url field instead of
    a top-level Token. Make sure we still find it."""
    c = SwiftnessReadOnlyClient()
    fake_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJleHAiOjE3Nzg5Njg1MTR9"
        ".sigvalueAB-_"
    )

    def fake_post(url, json=None, headers=None, **kw):
        return _mock_response(200, {
            "Url": f"https://savernew.swiftness.co.il/?token={fake_jwt}",
            "Status": "OK",
        })

    monkeypatch.setattr(c._session, "post", fake_post)
    out = c.login_with_otp("123456789", "745934", "you@example.com")
    assert out == fake_jwt


def test_authenticated_post_includes_bearer_header(monkeypatch):
    c = SwiftnessReadOnlyClient()
    c._token = "abcDEF.123"
    captured: dict = {}

    def fake_post(url, json=None, headers=None, **kw):
        captured["headers"] = headers or {}
        return _mock_response(200, {"SwiftnessKey": "11111111-2222-3333-4444-555555555555"})

    monkeypatch.setattr(c._session, "post", fake_post)
    body = c.get_desktop_items()
    assert captured["headers"].get("Authorization") == "BEARER abcDEF.123"
    assert c.swiftness_key == "11111111-2222-3333-4444-555555555555"
    assert body["SwiftnessKey"]


def test_get_event_status_requires_swiftness_key(monkeypatch):
    c = SwiftnessReadOnlyClient()
    c._token = "x"
    with pytest.raises(SwiftnessError):
        c.get_event_status()


def test_get_saving_concentrations_sends_swiftness_key(monkeypatch):
    c = SwiftnessReadOnlyClient()
    c._token = "tok"
    c._swiftness_key = "11111111-2222-3333-4444-555555555555"
    captured: dict = {}

    def fake_post(url, json=None, headers=None, **kw):
        captured["url"] = url
        captured["json"] = json
        return _mock_response(200, {"Concentrations": []})

    monkeypatch.setattr(c._session, "post", fake_post)
    c.get_saving_concentrations()
    assert captured["url"].endswith("/holdings/getSavingConcentrations")
    assert captured["json"] == {"SwiftnessKey": "11111111-2222-3333-4444-555555555555"}


# ============================== parsing =======================================


def test_extract_jwt_helper_handles_bare_string():
    s = "redirect=https://x/?token=eyJabc.eyJdef.sigvalAB-_&keep=1"
    assert _extract_jwt_from_login(s) == "eyJabc.eyJdef.sigvalAB-_"


def test_extract_jwt_helper_handles_no_match():
    assert _extract_jwt_from_login("nothing here") is None
    assert _extract_jwt_from_login({"foo": "bar"}) is None
    assert _extract_jwt_from_login(None) is None


def test_scan_for_uuid_walks_nested_structure():
    body = {
        "Result": {
            "Items": [
                {"Other": "not-a-uuid"},
                {"SwiftnessKey": "6a524f36-c695-4a85-a1e0-99c7bcf3260c"},
            ]
        }
    }
    assert _scan_for_uuid(body) == "6a524f36-c695-4a85-a1e0-99c7bcf3260c"


def test_bucket_for_uses_codes_first_then_name():
    # Codes confirmed live: 1=life_insurance, 4=keren_hishtalmut, 22=pension.
    assert _bucket_for(1, None) == "life_insurance"
    assert _bucket_for(22, None) == "pension"
    assert _bucket_for(4, None) == "keren_hishtalmut"
    assert _bucket_for(7, None) == "keren_hishtalmut"
    assert _bucket_for(3, None) == "gemel"
    # Unknown code, name fallback.
    assert _bucket_for(999, "קרן השתלמות לעצמאים") == "keren_hishtalmut"
    assert _bucket_for(999, "קופת גמל להשקעה") == "gemel"
    assert _bucket_for(999, "קרן פנסיה מקיפה") == "pension"
    assert _bucket_for(999, "פוליסת ביטוח חיים משולב חיסכון") == "life_insurance"
    assert _bucket_for(None, None) == "other"
    assert _bucket_for(None, "משהו לא מוכר") == "other"


def test_parse_saving_concentrations_handles_wrapped_response():
    """Live shape: ``getSavingConcentrations`` returns a wrapper with
    ``savingConcentration.savingConcentrations`` (note inner key is plural)."""
    body = {
        "savingConcentration": {
            "total_CurrentSavings": 1500000.0,
            "savingConcentrations": [
                {
                    "productTypeCode": 22,
                    "currentSaving": 800000.0,
                    "accumulatedBalanceForecast": 4000000.0,
                    "accumulatedOldAgePension": 12000.0,
                    "deathAmountMonthlyPartner": 6000.0,
                    "deathAmountMonthlyChild": 1500.0,
                    "workDisabilityAmountMonthly": 9000.0,
                    "lifeInsuranceOnetimePayment": 0.0,
                },
                {
                    "productTypeCode": 4,
                    "currentSaving": 500000.0,
                },
                {
                    "productTypeCode": 1,
                    "currentSaving": 200000.0,
                    "lifeInsuranceOnetimePayment": 750000.0,
                },
            ],
        }
    }
    rows = parse_saving_concentrations(body)
    assert len(rows) == 3
    assert rows[0].product_type_code == 22
    assert rows[0].current_saving_ils == pytest.approx(800000.0)
    assert rows[0].accumulated_balance_forecast_ils == pytest.approx(4000000.0)
    assert rows[0].monthly_pension_partner_ils == pytest.approx(6000.0)
    assert rows[2].life_insurance_one_time_ils == pytest.approx(750000.0)
    assert total_current_saving(body) == pytest.approx(1500000.0)


def test_parse_saving_concentrations_handles_unwrapped_response():
    """Tolerate the inner-only shape too."""
    body = {
        "savingConcentrations": [
            {"productTypeCode": 22, "currentSaving": 100},
            {"productTypeCode": 4, "currentSaving": 50},
        ]
    }
    rows = parse_saving_concentrations(body)
    assert len(rows) == 2
    assert rows[0].current_saving_ils == 100


def test_parse_saving_concentrations_returns_empty_for_missing_section():
    rows = parse_saving_concentrations({"savingConcentration": {}})
    assert rows == []


def test_parse_saving_products_pulls_per_policy_metadata():
    """``productsDetails.savingProductsdetailsList`` carries the friendly
    HE labels and the per-policy fees / yields / employer info."""
    body = {
        "productsDetails": {
            "savingProductsdetailsList": [
                {
                    "policy_Key": 12345,
                    "productTypeCode": 22,
                    "productTypeName": "פנסיה מקיפה",
                    "manufacturerCorporationId": "512065202",
                    "manufacturerName": "מיטב גמל ופנסיה בע\"מ",
                    "accountShortName": "מיטב דש",
                    "policyName": "מיטב פנסיה מקיפה",
                    "lastDepositAmount": 5000.0,
                    "lastReferDate": "2026-04-01",
                    "lastDepositEmployerName": "Island",
                    "actualManagementFeeAmount": 0.6,
                    "netYieldPercent": 8.4,
                    "retirementAge": 67,
                },
                {
                    "policy_Key": 99999,
                    "productTypeCode": 1,
                    "productTypeName": "פוליסת ביטוח חיים משולב חיסכון",
                    "manufacturerName": "  הראל   ",
                },
            ]
        }
    }
    pols = parse_saving_products(body)
    assert len(pols) == 2
    assert pols[0].product_type_code == 22
    assert pols[0].product_type_name == "פנסיה מקיפה"
    assert pols[0].manufacturer_name == "מיטב גמל ופנסיה בע\"מ"
    assert pols[0].actual_management_fee_pct == pytest.approx(0.6)
    assert pols[0].net_yield_pct == pytest.approx(8.4)
    # Whitespace stripped on policyName/manufacturerName.
    assert pols[1].manufacturer_name == "הראל"


# ============================== credentials ===================================


def test_load_credentials_rejects_missing_fields(tmp_path: Path):
    p = tmp_path / "creds.json"
    p.write_text(json.dumps({"users": [{"label": "X"}]}), encoding="utf-8")
    with pytest.raises(SwiftnessError):
        swiftness.load_credentials(p)


def test_load_credentials_accepts_valid_file(tmp_path: Path):
    p = tmp_path / "creds.json"
    p.write_text(
        json.dumps({
            "users": [
                {
                    "label": "primary",
                    "id_number": "123456789",
                    "email": "you@example.com",
                }
            ]
        }),
        encoding="utf-8",
    )
    cfg = swiftness.load_credentials(p)
    assert cfg["users"][0]["label"] == "primary"


# ============================== gmail otp =====================================


def test_fetch_otp_picks_most_recent_code(monkeypatch):
    """If two OTP emails arrive (Swiftness's known bug), we take the
    one with the larger internalDate."""
    monkeypatch.setattr(
        swiftness, "_refresh_gmail_access_token", lambda **kw: "fake-token"
    )
    monkeypatch.setattr(
        swiftness,
        "_gmail_search_otp_messages",
        lambda *a, **kw: [{"id": "older"}, {"id": "newer"}],
    )

    def fake_get(token, message_id, **kw):
        if message_id == "older":
            return ("הסיסמא החד-פעמית הינה: 111111", 1700000000000)
        return ("הסיסמא החד-פעמית הינה: 222222", 1700000060000)

    monkeypatch.setattr(swiftness, "_gmail_get_message_text", fake_get)
    monkeypatch.setattr(swiftness.time, "sleep", lambda *a, **kw: None)
    monkeypatch.setattr(swiftness.time, "time", _seq_time(start=0.0, step=1.0, until_after=120))
    otp = swiftness.fetch_otp_from_gmail(
        after_epoch=1700000000,
        poll_interval_s=0.0,
        total_timeout_s=60.0,
        settle_s=5.0,
    )
    assert otp == "222222"


def _seq_time(start: float, step: float, until_after: int):
    """Return a callable that emulates time.time() ticking forward."""
    state = {"t": start, "n": 0}

    def now():
        state["n"] += 1
        # First call (the one stored in `started`) returns start; later
        # calls advance by `step` each time.
        if state["n"] == 1:
            return state["t"]
        state["t"] += step
        return state["t"]

    return now
