"""Read-only Swiftness MCP server (stdio).

Exposes tools for reading Israeli pension clearing house (המסלקה
הפנסיונית) data: savings totals, product concentrations, and policy
metadata.

Authentication is email OTP. This server triggers the Swiftness OTP
email and accepts the 6-digit code from the calling agent (which reads
it via a separate email MCP — Gmail, Outlook, etc.). It never holds
mailbox credentials.

Typical agent flow:

1. ``request_otp`` — Swiftness emails a code
2. Agent searches email (e.g. Gmail MCP: ``from:doNotReply@swiftness.co.il``)
3. ``submit_otp`` or any data tool with ``otp=123456`` — completes login
4. Further data calls reuse the cached session (~25 min)

Run as ``python -m swiftness_mcp.server``. Configure in your MCP
client's ``mcp.json`` (see README).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import asdict

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from swiftness_mcp.client import (
    OTP_EMAIL_FROM,
    Policy,
    SavingConcentration,
    SavingsSnapshot,
    SwiftnessError,
    SwiftnessOtpRequired,
    SwiftnessReadOnlyClient,
    SwiftnessSecurityError,
    authenticate,
    extract_otp_from_text,
    load_credentials,
    otp_email_search_hints,
    pull_savings,
    trigger_otp,
)

log = logging.getLogger(__name__)

server: Server = Server("swiftness-readonly")

# Cached authenticated clients per user label (JWT ~30 min; we reuse ~25).
_SESSION_TTL_S = 25 * 60
_sessions: dict[str, tuple[SwiftnessReadOnlyClient, float]] = {}
# When OTP was last requested (Unix seconds), for email search hints.
_otp_requested_at: dict[str, int] = {}


def _label_lookup(cfg: dict, label: str | None) -> list[dict]:
    users = cfg["users"]
    if label is None:
        return list(users)
    needle = label.strip().lower()
    matches = [u for u in users if str(u.get("label", "")).lower() == needle]
    if not matches:
        valid = sorted({str(u.get("label", "")) for u in users})
        raise SwiftnessError(
            f"unknown user label {label!r}; expected one of {valid}"
        )
    return matches


def _user_label(user_cfg: dict) -> str:
    return str(user_cfg.get("label", ""))


def _session_client(label: str) -> SwiftnessReadOnlyClient | None:
    entry = _sessions.get(label)
    if not entry:
        return None
    client, login_at = entry
    if time.monotonic() - login_at >= _SESSION_TTL_S:
        _sessions.pop(label, None)
        return None
    if not client.swiftness_key:
        _sessions.pop(label, None)
        return None
    return client


def _store_session(label: str, client: SwiftnessReadOnlyClient) -> None:
    _sessions[label] = (client, time.monotonic())


def _authenticate_user(user_cfg: dict, otp: str) -> SwiftnessReadOnlyClient:
    label = _user_label(user_cfg)
    client = SwiftnessReadOnlyClient()
    authenticate(
        client,
        id_number=str(user_cfg["id_number"]),
        email=str(user_cfg["email"]),
        otp=otp,
        user_label=label,
    )
    _store_session(label, client)
    log.info("swiftness session established for %s", label)
    return client


def _otp_required_payload(user_cfg: dict, *, auto_requested: bool) -> dict:
    label = _user_label(user_cfg)
    email = str(user_cfg["email"])
    requested_at = _otp_requested_at.get(label)
    return {
        "status": "otp_required",
        "user_label": label,
        "email": email,
        "otp_email_from": OTP_EMAIL_FROM,
        "otp_requested": auto_requested or label in _otp_requested_at,
        "otp_requested_at_unix": requested_at,
        "email_search_hints": otp_email_search_hints(
            requested_after_unix=requested_at
        ),
        "next_steps": [
            f"Search the inbox for {email} for a message from {OTP_EMAIL_FROM}.",
            "Swiftness sometimes sends two emails ~20–30s apart; use the newest code.",
            f"Then call submit_otp(user_label={label!r}, otp='123456') "
            "or pass otp= to any data tool.",
        ],
    }


def _fmt_otp_required(user_cfg: dict, *, auto_requested: bool) -> str:
    payload = _otp_required_payload(user_cfg, auto_requested=auto_requested)
    lines = [
        "Swiftness OTP required.",
        f"  user: {payload['user_label']}",
        f"  email: {payload['email']}",
        f"  from: {payload['otp_email_from']}",
        "",
        "Use your email MCP to find the 6-digit code, then call "
        "submit_otp or retry with otp=.",
        "",
        "```json",
        json.dumps(payload, ensure_ascii=False, indent=2),
        "```",
    ]
    return "\n".join(lines)


def _ensure_otp_or_session(
    user_cfg: dict,
    otp: str | None,
    *,
    auto_request: bool,
) -> SwiftnessReadOnlyClient | None:
    """Return authenticated client, or None if OTP is still needed."""
    label = _user_label(user_cfg)
    cached = _session_client(label)
    if cached is not None:
        return cached
    if otp:
        return _authenticate_user(user_cfg, otp)
    if auto_request and label not in _otp_requested_at:
        requested_at = trigger_otp(
            str(user_cfg["id_number"]),
            str(user_cfg["email"]),
        )
        _otp_requested_at[label] = requested_at
        log.info("swiftness OTP requested for %s", label)
    return None


def _fmt_ils(v: float | None) -> str:
    if v is None:
        return "?"
    return f"{v:,.0f} ₪"


def _serialize_concentration(c: SavingConcentration) -> dict:
    return {
        "product_type_code": c.product_type_code,
        "product_type_name": c.product_type_name,
        "current_saving_ils": c.current_saving_ils,
        "accumulated_balance_forecast_ils": c.accumulated_balance_forecast_ils,
        "accumulated_old_age_pension_ils": c.accumulated_old_age_pension_ils,
        "monthly_pension_partner_ils": c.monthly_pension_partner_ils,
        "monthly_pension_child_ils": c.monthly_pension_child_ils,
        "work_disability_monthly_ils": c.work_disability_monthly_ils,
        "life_insurance_one_time_ils": c.life_insurance_one_time_ils,
    }


def _serialize_policy(p: Policy) -> dict:
    return {
        "policy_key": p.policy_key,
        "product_type_code": p.product_type_code,
        "product_type_name": p.product_type_name,
        "manufacturer_id": p.manufacturer_id,
        "manufacturer_name": p.manufacturer_name,
        "account_short_name": p.account_short_name,
        "policy_name": p.policy_name,
        "last_deposit_amount_ils": p.last_deposit_amount_ils,
        "last_deposit_at_iso": p.last_deposit_at_iso,
        "last_deposit_employer_name": p.last_deposit_employer_name,
        "actual_management_fee_pct": p.actual_management_fee_pct,
        "net_yield_pct": p.net_yield_pct,
        "retirement_age": p.retirement_age,
    }


def _serialize_snapshot(s: SavingsSnapshot, *, include_xml: bool = False) -> dict:
    d = asdict(s)
    if not include_xml:
        d.pop("xml", None)
    d["concentrations"] = [_serialize_concentration(c) for c in s.concentrations]
    d["policies"] = [_serialize_policy(p) for p in s.policies]
    return d


def _pull_for_user(
    user_cfg: dict,
    *,
    otp: str | None,
    fetch_xml: bool,
    auto_request_otp: bool = True,
) -> SavingsSnapshot | None:
    client = _ensure_otp_or_session(
        user_cfg, otp, auto_request=auto_request_otp
    )
    if client is None:
        return None
    return pull_savings(
        user_label=_user_label(user_cfg),
        id_number=str(user_cfg["id_number"]),
        email=str(user_cfg["email"]),
        client=client,
        fetch_xml=fetch_xml,
    )


_LABEL_DESCRIPTION = (
    "Optional user label from your credentials file. Omit to pull all "
    "configured users. Match is case-insensitive."
)

_OTP_DESCRIPTION = (
    "6-digit one-time code from the Swiftness email. Omit only if you "
    "already called submit_otp for this user (session cached ~25 min)."
)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="request_otp",
            description=(
                "Ask Swiftness to email a one-time login code to the "
                "user's registered address. Does not read email — the "
                "calling agent must fetch the code via a separate email "
                "MCP, then call submit_otp or pass otp= to a data tool."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                },
                "required": ["user_label"],
            },
        ),
        Tool(
            name="submit_otp",
            description=(
                "Complete Swiftness login with the 6-digit OTP from email. "
                "Caches the session so later data tools can omit otp."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {
                        "type": "string",
                        "description": "6-digit code from the Swiftness email.",
                    },
                },
                "required": ["user_label", "otp"],
            },
        ),
        Tool(
            name="get_savings_summary",
            description=(
                "READ-ONLY. Fetch pension, keren hishtalmut, gemel, and "
                "life-insurance savings totals from Swiftness (המסלקה "
                "הפנסיונית). Requires OTP on first use (or cached session). "
                "If otp is omitted and no session exists, triggers an OTP "
                "email and returns otp_required instructions."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {"type": "string", "description": _OTP_DESCRIPTION},
                },
            },
        ),
        Tool(
            name="get_saving_concentrations",
            description=(
                "READ-ONLY. Per-product-type savings breakdown from "
                "Swiftness. Requires OTP or cached session."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {"type": "string", "description": _OTP_DESCRIPTION},
                },
            },
        ),
        Tool(
            name="get_policies",
            description=(
                "READ-ONLY. List individual pension/gemel/insurance policies "
                "from Swiftness. Requires OTP or cached session."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {"type": "string", "description": _OTP_DESCRIPTION},
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "request_otp":
            return _do_request_otp(arguments.get("user_label"))
        if name == "submit_otp":
            return _do_submit_otp(
                arguments.get("user_label"), arguments.get("otp")
            )
        label = arguments.get("user_label")
        otp = arguments.get("otp")
        if name == "get_savings_summary":
            return _do_savings_summary(label, otp)
        if name == "get_saving_concentrations":
            return _do_concentrations(label, otp)
        if name == "get_policies":
            return _do_policies(label, otp)
        return [TextContent(type="text", text=f"Unknown tool: {name}")]
    except SwiftnessSecurityError as e:
        log.exception("swiftness security error")
        return [TextContent(
            type="text",
            text=f"SECURITY: swiftness client refused a non-allowlisted call: {e}",
        )]
    except SwiftnessOtpRequired as e:
        return [TextContent(type="text", text=f"Swiftness OTP required: {e}")]
    except SwiftnessError as e:
        log.exception("swiftness error")
        return [TextContent(type="text", text=f"Swiftness error: {e}")]
    except Exception as e:
        log.exception("unexpected error in swiftness MCP")
        return [TextContent(type="text", text=f"Unexpected error: {e}")]


def _do_request_otp(label: str | None) -> list[TextContent]:
    if not label:
        raise SwiftnessError("user_label is required for request_otp")
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if len(users) != 1:
        raise SwiftnessError("request_otp requires exactly one user_label")
    user = users[0]
    user_label = _user_label(user)
    requested_at = trigger_otp(
        str(user["id_number"]),
        str(user["email"]),
    )
    _otp_requested_at[user_label] = requested_at
    payload = {
        "status": "otp_sent",
        "user_label": user_label,
        "email": str(user["email"]),
        "otp_email_from": OTP_EMAIL_FROM,
        "otp_requested_at_unix": requested_at,
        "email_search_hints": otp_email_search_hints(
            requested_after_unix=requested_at
        ),
        "next_steps": [
            "Wait for the Swiftness email (sometimes two arrive; use the newest).",
            "Read the 6-digit code via your email MCP.",
            f"Call submit_otp(user_label={user_label!r}, otp='......') "
            "or pass otp= to a data tool.",
        ],
        "extract_otp_note": (
            "Codes match /\\b(\\d{6})\\b/ in the message body. "
            "Use extract_otp_from_text in the Python client if needed."
        ),
    }
    text = "\n".join([
        f"OTP email requested for {user_label} ({user['email']}).",
        "",
        "```json",
        json.dumps(payload, ensure_ascii=False, indent=2),
        "```",
    ])
    return [TextContent(type="text", text=text)]


def _do_submit_otp(label: str | None, otp: str | None) -> list[TextContent]:
    if not label:
        raise SwiftnessError("user_label is required for submit_otp")
    if not otp or not str(otp).strip():
        raise SwiftnessError("otp is required for submit_otp")
    otp = str(otp).strip()
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if len(users) != 1:
        raise SwiftnessError("submit_otp requires exactly one user_label")
    user = users[0]
    _authenticate_user(user, otp)
    user_label = _user_label(user)
    payload = {
        "status": "authenticated",
        "user_label": user_label,
        "session_ttl_minutes": _SESSION_TTL_S // 60,
        "message": (
            "Session cached. Data tools can omit otp until the session expires."
        ),
    }
    return [TextContent(type="text", text=json.dumps(payload, indent=2))]


def _do_savings_summary(label: str | None, otp: str | None) -> list[TextContent]:
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if otp and len(users) > 1:
        raise SwiftnessError(
            "otp only works with a single user_label (OTP is bound to one identity)"
        )

    rows: list[dict] = []
    pending: list[str] = []
    for u in users:
        snap = _pull_for_user(u, otp=otp, fetch_xml=False)
        if snap is None:
            pending.append(_fmt_otp_required(u, auto_requested=True))
            continue
        rows.append({
            "user_label": snap.user_label,
            "pension_total_ils": snap.pension_total_ils,
            "gemel_total_ils": snap.gemel_total_ils,
            "keren_hishtalmut_total_ils": snap.keren_hishtalmut_total_ils,
            "life_insurance_total_ils": snap.life_insurance_total_ils,
            "other_total_ils": snap.other_total_ils,
            "grand_total_ils": snap.grand_total_ils,
            "calc_date_iso": snap.calc_date_iso,
        })

    if pending and not rows:
        return [TextContent(type="text", text="\n\n".join(pending))]
    if pending:
        return [TextContent(
            type="text",
            text="Partial results — some users still need OTP:\n\n"
            + "\n\n".join(pending),
        )]

    payload = {"users": rows, "currency": "ILS"}
    if len(rows) > 1:
        payload["grand_total_ils"] = sum(r["grand_total_ils"] for r in rows)

    pretty = ["Savings summary (ILS):"]
    for r in rows:
        pretty.append(
            f"  - {r['user_label']}: {_fmt_ils(r['grand_total_ils'])} "
            f"(pension {_fmt_ils(r['pension_total_ils'])}, "
            f"keren {_fmt_ils(r['keren_hishtalmut_total_ils'])}, "
            f"gemel {_fmt_ils(r['gemel_total_ils'])})"
        )
    if len(rows) > 1:
        pretty.append(f"  -- TOTAL: {_fmt_ils(payload['grand_total_ils'])}")
    pretty.extend(["", "```json", json.dumps(payload, ensure_ascii=False, indent=2), "```"])
    return [TextContent(type="text", text="\n".join(pretty))]


def _do_concentrations(label: str | None, otp: str | None) -> list[TextContent]:
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if otp and len(users) > 1:
        raise SwiftnessError(
            "otp only works with a single user_label (OTP is bound to one identity)"
        )

    sections: list[str] = []
    for u in users:
        snap = _pull_for_user(u, otp=otp, fetch_xml=False)
        if snap is None:
            sections.append(_fmt_otp_required(u, auto_requested=True))
            continue
        rows = [_serialize_concentration(c) for c in snap.concentrations]
        sections.append(f"### {snap.user_label}")
        if not rows:
            sections.append("(no concentrations)")
        else:
            for c in rows:
                name = c.get("product_type_name") or f"code {c.get('product_type_code')}"
                sections.append(
                    f"- {name}: {_fmt_ils(c['current_saving_ils'])} "
                    f"(forecast {_fmt_ils(c['accumulated_balance_forecast_ils'])})"
                )
        sections.append("")
        sections.append("```json")
        sections.append(json.dumps(
            {"user_label": snap.user_label, "concentrations": rows},
            ensure_ascii=False,
            indent=2,
        ))
        sections.append("```")
        sections.append("")
    return [TextContent(type="text", text="\n".join(sections).rstrip())]


def _do_policies(label: str | None, otp: str | None) -> list[TextContent]:
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if otp and len(users) > 1:
        raise SwiftnessError(
            "otp only works with a single user_label (OTP is bound to one identity)"
        )

    sections: list[str] = []
    for u in users:
        snap = _pull_for_user(u, otp=otp, fetch_xml=False)
        if snap is None:
            sections.append(_fmt_otp_required(u, auto_requested=True))
            continue
        rows = [_serialize_policy(p) for p in snap.policies]
        sections.append(f"### {snap.user_label}")
        if not rows:
            sections.append("(no policies)")
        else:
            for p in rows:
                mfr = p.get("manufacturer_name") or p.get("account_short_name") or "?"
                name = p.get("policy_name") or p.get("product_type_name") or "?"
                fee = p.get("actual_management_fee_pct")
                fee_s = f", fee {fee:.2f}%" if fee is not None else ""
                yield_pct = p.get("net_yield_pct")
                yld_s = f", yield {yield_pct:.1f}%" if yield_pct is not None else ""
                sections.append(f"- {name} ({mfr}){fee_s}{yld_s}")
        sections.append("")
        sections.append("```json")
        sections.append(json.dumps(
            {"user_label": snap.user_label, "policies": rows},
            ensure_ascii=False,
            indent=2,
        ))
        sections.append("```")
        sections.append("")
    return [TextContent(type="text", text="\n".join(sections).rstrip())]


async def _main() -> None:
    logging.basicConfig(
        level=os.environ.get("SWIFTNESS_MCP_LOGLEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    async with stdio_server() as (read, write):
        await server.run(read, write, server.create_initialization_options())


def main() -> None:
    asyncio.run(_main())


# Re-export for tests / tooling
__all__ = ["extract_otp_from_text", "server"]


if __name__ == "__main__":
    main()
