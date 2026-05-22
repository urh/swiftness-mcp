"""Tests for the read-only Swiftness MCP server."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from swiftness_mcp import server as swiftness_mcp
from swiftness_mcp.client import Policy, SavingConcentration, SavingsSnapshot


def _run(coro):
    return asyncio.run(coro)


def test_tool_names():
    tools = _run(swiftness_mcp.list_tools())
    names = sorted(t.name for t in tools)
    assert names == [
        "get_policies",
        "get_saving_concentrations",
        "get_savings_summary",
        "request_otp",
        "submit_otp",
    ]


def test_tool_descriptions_advertise_read_only():
    tools = _run(swiftness_mcp.list_tools())
    for t in tools:
        if t.name.startswith("get_"):
            assert "READ-ONLY" in t.description.upper()


@pytest.fixture
def fake_creds(monkeypatch):
    cfg = {
        "users": [
            {"label": "primary", "id_number": "123456789", "email": "you@example.com"},
        ]
    }
    monkeypatch.setattr(swiftness_mcp, "load_credentials", lambda *a, **kw: cfg)
    return cfg


@pytest.fixture
def stub_pull(monkeypatch):
    snap = SavingsSnapshot(
        user_label="primary",
        user_id_masked="***789",
        pulled_at_iso="2026-01-01T00:00:00+00:00",
        swiftness_key="key",
        calc_date_iso="2026-01-01",
        pension_total_ils=800_000.0,
        gemel_total_ils=100_000.0,
        keren_hishtalmut_total_ils=500_000.0,
        life_insurance_total_ils=200_000.0,
        other_total_ils=0.0,
        grand_total_ils=1_600_000.0,
        concentrations=[
            SavingConcentration(
                product_type_code=22,
                product_type_name="pension",
                current_saving_ils=800_000.0,
                accumulated_balance_forecast_ils=4_000_000.0,
                accumulated_old_age_pension_ils=0.0,
                monthly_pension_partner_ils=0.0,
                monthly_pension_child_ils=0.0,
                work_disability_monthly_ils=0.0,
                life_insurance_one_time_ils=0.0,
            )
        ],
        policies=[
            Policy(
                policy_key=1,
                product_type_code=22,
                product_type_name="pension",
                manufacturer_id="512065202",
                manufacturer_name="Example Provider",
                account_short_name="Example",
                policy_name="Example Pension",
                last_deposit_amount_ils=5000.0,
                last_deposit_at_iso="2026-04-01",
                last_deposit_employer_name="Employer Ltd",
                actual_management_fee_pct=0.6,
                net_yield_pct=8.4,
                retirement_age=67.0,
            )
        ],
    )

    def fake_pull(user_cfg, *, otp, fetch_xml, auto_request_otp=True):
        if otp or swiftness_mcp._session_client(user_cfg.get("label", "primary")):
            return replace(snap, user_label=user_cfg.get("label", "primary"))
        return None

    monkeypatch.setattr(swiftness_mcp, "_pull_for_user", fake_pull)
    return snap


def test_get_savings_summary(fake_creds, stub_pull):
    out = _run(swiftness_mcp.call_tool("get_savings_summary", {"otp": "123456"}))
    payload = json.loads(out[0].text.split("```json")[1].split("```")[0])
    assert payload["users"][0]["grand_total_ils"] == 1_600_000.0


def test_get_savings_summary_otp_required(fake_creds, stub_pull, monkeypatch):
    monkeypatch.setattr(swiftness_mcp, "trigger_otp", lambda *a, **kw: 1700000000)
    out = _run(swiftness_mcp.call_tool("get_savings_summary", {}))
    assert "otp_required" in out[0].text


def test_request_otp(fake_creds, monkeypatch):
    monkeypatch.setattr(swiftness_mcp, "trigger_otp", lambda *a, **kw: 1700000000)
    out = _run(swiftness_mcp.call_tool("request_otp", {"user_label": "primary"}))
    assert "otp_sent" in out[0].text
    assert "doNotReply@swiftness.co.il" in out[0].text


def test_submit_otp(fake_creds, monkeypatch):
    monkeypatch.setattr(
        swiftness_mcp,
        "_authenticate_user",
        lambda user, otp: None,
    )
    out = _run(swiftness_mcp.call_tool(
        "submit_otp", {"user_label": "primary", "otp": "123456"}
    ))
    assert "authenticated" in out[0].text


def test_get_saving_concentrations(fake_creds, stub_pull):
    out = _run(swiftness_mcp.call_tool(
        "get_saving_concentrations", {"otp": "123456"}
    ))
    assert "pension" in out[0].text


def test_get_policies(fake_creds, stub_pull):
    out = _run(swiftness_mcp.call_tool("get_policies", {"otp": "123456"}))
    assert "Example Pension" in out[0].text
