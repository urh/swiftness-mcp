"""Read-only Swiftness MCP server (stdio).

Exposes tools for reading Israeli pension clearing house (המסלקה
הפנסיונית) data: savings totals, product concentrations, and policy
metadata. Authentication uses email OTP; optionally reads the OTP from
Gmail when OAuth tokens are configured.

Run as ``python -m swiftness_mcp.server``. Configure in your MCP
client's ``mcp.json`` (see README).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from dataclasses import asdict
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from swiftness_mcp.client import (
    Policy,
    SavingConcentration,
    SavingsSnapshot,
    SwiftnessError,
    SwiftnessOtpTimeout,
    SwiftnessSecurityError,
    load_credentials,
    pull_savings,
)

log = logging.getLogger(__name__)

server: Server = Server("swiftness-readonly")


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


def _pull_for_user(user_cfg: dict, *, otp: str | None, fetch_xml: bool) -> SavingsSnapshot:
    return pull_savings(
        user_label=str(user_cfg.get("label", "")),
        id_number=str(user_cfg["id_number"]),
        email=str(user_cfg["email"]),
        otp=otp,
        gmail_token_path=Path(
            user_cfg.get("gmail_token_path")
            or os.environ.get(
                "SWIFTNESS_GMAIL_TOKEN_PATH",
                str(Path.home() / ".config" / "gmail-mcp" / "credentials.json"),
            )
        ),
        gmail_oauth_path=Path(
            user_cfg.get("gmail_oauth_path")
            or os.environ.get(
                "SWIFTNESS_GMAIL_OAUTH_PATH",
                str(Path.home() / ".config" / "gmail-mcp" / "gcp-oauth.keys.json"),
            )
        ),
        fetch_xml=fetch_xml,
    )


_LABEL_DESCRIPTION = (
    "Optional user label from your credentials file. Omit to pull all "
    "configured users. Match is case-insensitive."
)


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="get_savings_summary",
            description=(
                "READ-ONLY. Fetch pension, keren hishtalmut, gemel, and "
                "life-insurance savings totals from Swiftness (המסלקה "
                "הפנסיונית) for one or all configured users. Triggers "
                "email OTP authentication unless otp is supplied. "
                "Returns bucketed ILS totals and a grand total."
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
                        "description": (
                            "Optional 6-digit OTP code if you already "
                            "triggered authentication manually."
                        ),
                    },
                },
            },
        ),
        Tool(
            name="get_saving_concentrations",
            description=(
                "READ-ONLY. Per-product-type savings breakdown from "
                "Swiftness (aggregates across management companies). "
                "Includes current balance and retirement forecasts where "
                "available."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {"type": "string"},
                },
            },
        ),
        Tool(
            name="get_policies",
            description=(
                "READ-ONLY. List individual pension/gemel/insurance policies "
                "from Swiftness with manufacturer, fees, yields, and last "
                "deposit metadata."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "user_label": {
                        "type": "string",
                        "description": _LABEL_DESCRIPTION,
                    },
                    "otp": {"type": "string"},
                },
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    label = arguments.get("user_label")
    otp = arguments.get("otp")
    try:
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
    except SwiftnessOtpTimeout as e:
        log.exception("swiftness OTP timeout")
        return [TextContent(type="text", text=f"Swiftness OTP error: {e}")]
    except SwiftnessError as e:
        log.exception("swiftness error")
        return [TextContent(type="text", text=f"Swiftness error: {e}")]
    except Exception as e:
        log.exception("unexpected error in swiftness MCP")
        return [TextContent(type="text", text=f"Unexpected error: {e}")]


def _do_savings_summary(label: str | None, otp: str | None) -> list[TextContent]:
    cfg = load_credentials()
    users = _label_lookup(cfg, label)
    if otp and len(users) > 1:
        raise SwiftnessError(
            "--otp only works with a single user_label (OTP is bound to one identity)"
        )

    rows: list[dict] = []
    for u in users:
        snap = _pull_for_user(u, otp=otp, fetch_xml=False)
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


if __name__ == "__main__":
    main()
