"""Read-only client for Swiftness (המסלקה הפנסיונית).

Swiftness is the Israeli pension clearing house (המסלקה הפנסיונית).
Users authorize a periodic data-collection job; Swiftness asynchronously
fetches pension, keren hishtalmut, and gemel balances from management
companies. This module reads those aggregated results.

Auth flow (reverse-engineered from the browser HAR):

1. ``POST /api/auth/createOtp``      – ask Swiftness to email a 6-digit
   OTP to the registered address. Annoyingly, they sometimes send
   the OTP twice in two separate emails 20-30s apart. Always take the
   most recent one - the codes can differ.
2. ``POST /api/auth/loginwithotp``   – exchange ID number + OTP for a
   short-lived JWT bearer token (~30 min lifetime).
3. ``POST /api/desktop/getDesktopItems`` – returns the session
   ``swiftnessKey`` (a UUID), plus the most recent collection's metadata.
   Every later read needs the swiftnessKey.
4. ``POST /api/holdings/getSavingConcentrations`` – the headline data:
   per-product totals across all management companies.
5. ``GET  /api/helpers/getDocument?fileType=3`` – optional, downloads
   the consolidated XML for the whole portfolio.

Read-only by construction
-------------------------

Like the Ordernet client, this module restricts the HTTP code paths it
is *capable* of issuing:

- ``_post`` accepts only paths in ``_ALLOWED_POST_PATHS``. The auth
  POSTs (``createOtp``, ``loginwithotp``) are on the list because they
  are required and they don't mutate user data; the data POSTs that
  follow are also reads-by-POST as the API designers chose.
- ``_get`` accepts only paths in ``_ALLOWED_GET_PATHS``.
- There is no method here that could update a beneficiary, switch a
  fund, file a withdrawal request, etc. To add one you'd have to add a
  new path to an allowlist - which is meant to surface obviously in
  code review, and to fail the security tests.

OTP delivery is email-based and provider-agnostic. This module triggers
the Swiftness OTP email and accepts the 6-digit code from the caller
(e.g. an AI agent that read it via a separate email MCP). It never
holds Gmail or other mailbox credentials.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import requests

DEFAULT_CRED_PATH = Path(
    os.environ.get(
        "SWIFTNESS_CREDENTIALS_PATH",
        str(Path.home() / ".config" / "swiftness" / "credentials.json"),
    )
)
PORTAL_API = "https://portalapi.swiftness.co.il/api"

# Swiftness sends OTP from this address. Exposed so agents can search any
# mailbox (Gmail MCP, Outlook, IMAP, etc.) without this module touching email.
OTP_EMAIL_FROM = "doNotReply@swiftness.co.il"
OTP_REGEX = re.compile(r"\b(\d{6})\b")

# Auth flow (POSTs that aren't strictly "reads" but are required to
# authenticate). Listed separately for documentation; the security tests
# verify nothing else can be POSTed.
_AUTH_OTP_PATH = "auth/createOtp"
_AUTH_LOGIN_PATH = "auth/loginwithotp"

# All non-auth POSTs the client is allowed to issue. Every one is
# logically a read - the API designers just chose POST for the data
# endpoints. Adding to this list must pass review + the test suite.
_ALLOWED_DATA_POST_PATHS = frozenset({
    "desktop/getDesktopItems",
    "desktop/getDesktopEventStatus",
    "holdings/getManagementCompaniesResponses",
    "holdings/getSavingConcentrations",
})

_ALLOWED_POST_PATHS = frozenset(
    {_AUTH_OTP_PATH, _AUTH_LOGIN_PATH} | _ALLOWED_DATA_POST_PATHS
)

# GET endpoints (currently just the document downloader).
_ALLOWED_GET_PATHS = frozenset({
    "helpers/getDocument",
})

# Identity headers - Swiftness's WAF is finicky about the ones the
# browser sends; we copy them verbatim so we look like a normal client.
_BROWSER_HEADERS = {
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9,he;q=0.8",
    "Origin": "https://auth.swiftness.co.il",
    "Referer": "https://auth.swiftness.co.il/",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
    ),
}

log = logging.getLogger(__name__)


class SwiftnessError(Exception):
    pass


class SwiftnessSecurityError(SwiftnessError):
    """Raised when something tries to take a code path that would let
    this module write to Swiftness (an unknown POST/GET path).
    Should be impossible at runtime; if you see it in a log it's a
    serious bug."""


class SwiftnessOtpRequired(SwiftnessError):
    """Caller must supply an OTP (after reading it from email elsewhere)."""


# ---------------------------------------------------------- data classes


@dataclass(frozen=True)
class SavingConcentration:
    """One row from ``getSavingConcentrations.savingConcentration.savingConcentrations``.
    These are aggregates **by product type code**, not by individual
    policy. For example you might see separate rows for pension,
    keren hishtalmut, and life-insurance savings products.

    ``current_saving_ils`` is "money in the account today".
    ``accumulated_balance_forecast_ils`` is the forecast at retirement.
    ``raw`` keeps the rest (insurance covers, monthly forecasts, etc.).
    """

    product_type_code: int | None
    product_type_name: str | None  # filled in from productsDetails when possible
    current_saving_ils: float
    accumulated_balance_forecast_ils: float
    accumulated_old_age_pension_ils: float
    monthly_pension_partner_ils: float
    monthly_pension_child_ils: float
    work_disability_monthly_ils: float
    life_insurance_one_time_ils: float
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    """One row from ``productsDetails.savingProductsdetailsList`` - one
    individual policy at one management company. Notably this list does
    NOT carry per-policy current balance (only last deposit + yield +
    fees); per-product-type aggregates live in ``SavingConcentration``."""

    policy_key: int | None
    product_type_code: int | None
    product_type_name: str | None        # e.g. "פוליסת ביטוח חיים משולב חיסכון"
    manufacturer_id: str | None          # legal-entity ID (e.g. 512065202)
    manufacturer_name: str | None        # e.g. "מיטב גמל ופנסיה בע\"מ"
    account_short_name: str | None       # short brand (e.g. "מיטב דש")
    policy_name: str | None              # e.g. "מיטב פנסיה מקיפה"
    last_deposit_amount_ils: float | None
    last_deposit_at_iso: str | None
    last_deposit_employer_name: str | None
    actual_management_fee_pct: float | None
    net_yield_pct: float | None
    retirement_age: float | None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class SavingsSnapshot:
    """Output of a single Swiftness pull."""

    user_label: str
    user_id_masked: str            # last 3 digits only, for logs
    pulled_at_iso: str
    swiftness_key: str | None
    calc_date_iso: str | None
    pension_total_ils: float
    gemel_total_ils: float
    keren_hishtalmut_total_ils: float
    life_insurance_total_ils: float
    other_total_ils: float
    grand_total_ils: float
    concentrations: list[SavingConcentration]
    policies: list[Policy]
    xml: str | None = None         # only set if get_document_xml() was called


# ============================================================ OTP helpers


def extract_otp_from_text(text: str) -> str | None:
    """Pull a 6-digit Swiftness OTP out of an email body (any provider)."""
    m = OTP_REGEX.search(text)
    return m.group(1) if m else None


def otp_email_search_hints(*, requested_after_unix: int | None = None) -> list[str]:
    """Example search queries an agent can run in Gmail/Outlook/etc."""
    hints = [f"from:{OTP_EMAIL_FROM}"]
    if requested_after_unix is not None:
        hints.append(f"from:{OTP_EMAIL_FROM} after:{requested_after_unix}")
    return hints


def trigger_otp(
    id_number: str,
    email: str,
    *,
    timeout: float = 30.0,
) -> int:
    """Ask Swiftness to email a one-time code. Returns Unix epoch (seconds)."""
    client = SwiftnessReadOnlyClient(timeout=timeout)
    before = int(time.time())
    client.request_otp(id_number, email)
    return before


def authenticate(
    client: SwiftnessReadOnlyClient,
    *,
    id_number: str,
    email: str,
    otp: str,
    user_label: str = "",
) -> None:
    """Exchange OTP for a JWT and bootstrap the desktop session key."""
    client.login_with_otp(id_number, otp, email)
    desktop = client.get_desktop_items()
    if not client.swiftness_key:
        who = user_label or id_number
        raise SwiftnessError(
            f"getDesktopItems for {who} returned no swiftnessKey: "
            f"keys={list(desktop)}"
        )


# ============================================================ Swiftness client


class SwiftnessReadOnlyClient:
    """Swiftness client that can only read.

    Each instance holds one auth session. JWT lifetime is ~30 min, so
    for batch jobs prefer a fresh client per pull.
    """

    def __init__(self, *, timeout: float = 30.0):
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(_BROWSER_HEADERS)
        self._token: str | None = None
        self._swiftness_key: str | None = None

    # -------------------------------------------------- low-level guards

    def _post(self, path: str, body: dict | None = None) -> Any:
        if path not in _ALLOWED_POST_PATHS:
            raise SwiftnessSecurityError(
                f"refusing to POST {path!r}: not in allowlist "
                f"({sorted(_ALLOWED_POST_PATHS)})"
            )
        url = f"{PORTAL_API}/{path}"
        headers = {"Content-Type": "application/json"}
        if self._token and path not in {_AUTH_OTP_PATH, _AUTH_LOGIN_PATH}:
            headers["Authorization"] = f"BEARER {self._token}"
        r = self._session.post(
            url, json=body or {}, headers=headers, timeout=self._timeout
        )
        if r.status_code >= 400:
            raise SwiftnessError(f"{path} failed: {r.status_code} {r.text[:300]}")
        if not r.text:
            return None
        try:
            return r.json()
        except ValueError:
            return r.text

    def _get(self, path: str, params: dict | None = None) -> requests.Response:
        if path not in _ALLOWED_GET_PATHS:
            raise SwiftnessSecurityError(
                f"refusing to GET {path!r}: not in allowlist "
                f"({sorted(_ALLOWED_GET_PATHS)})"
            )
        url = f"{PORTAL_API}/{path}"
        headers = {}
        if self._token:
            headers["Authorization"] = f"BEARER {self._token}"
        r = self._session.get(
            url, params=params or {}, headers=headers, timeout=self._timeout
        )
        if r.status_code >= 400:
            raise SwiftnessError(f"{path} failed: {r.status_code} {r.text[:300]}")
        return r

    # -------------------------------------------------- auth

    def request_otp(self, id_number: str, email: str) -> None:
        """Trigger an OTP email. Doesn't return anything useful - the
        OTP itself arrives by email."""
        self._post(
            _AUTH_OTP_PATH,
            {
                "IdNumber": id_number,
                "PhoneNumber": "",
                "Email": email,
                "Token": "",
                "IsNewSaverOtp": False,
                "AuthType": 2,  # 2 = email; 1 would be SMS
            },
        )

    def login_with_otp(self, id_number: str, otp: str, email: str) -> str:
        """Exchange (id, otp, email) for a JWT. Stores it on the client
        and also returns it so callers can persist if desired."""
        body = self._post(
            _AUTH_LOGIN_PATH,
            {
                "IdentificationNumber": id_number,
                "OtpNumber": otp,
                "MobilePhone": "",
                "EmailAddress": email,
                "AuthenticationTypeCode": 2,
            },
        )
        token = _extract_jwt_from_login(body)
        if not token:
            raise SwiftnessError(
                f"loginwithotp succeeded but couldn't find JWT in response: {body!r}"
            )
        self._token = token
        return token

    # -------------------------------------------------- session bootstrap

    def get_desktop_items(self) -> dict:
        """First call after auth. Returns a dict that includes the
        ``swiftnessKey`` we'll need for every later call."""
        body = self._post("desktop/getDesktopItems", {})
        if not isinstance(body, dict):
            raise SwiftnessError(f"getDesktopItems: unexpected shape {type(body).__name__}")
        # Field name varies a bit across Swiftness API versions - try
        # the obvious ones, then fall back to scanning for any UUID.
        key = (
            body.get("SwiftnessKey")
            or body.get("swiftnessKey")
            or body.get("SwiftNessHandlerId")
            or body.get("swiftNessHandlerId")
            or _scan_for_uuid(body)
        )
        if key:
            self._swiftness_key = key
        return body

    @property
    def swiftness_key(self) -> str | None:
        return self._swiftness_key

    def get_event_status(self) -> dict:
        if not self._swiftness_key:
            raise SwiftnessError("call get_desktop_items() first")
        body = self._post(
            "desktop/getDesktopEventStatus",
            {"swiftNessHandlerId": self._swiftness_key},
        )
        return body if isinstance(body, dict) else {"raw": body}

    # -------------------------------------------------- data

    def get_management_companies_responses(self) -> dict:
        if not self._swiftness_key:
            raise SwiftnessError("call get_desktop_items() first")
        body = self._post(
            "holdings/getManagementCompaniesResponses",
            {"swiftNessHandlerId": self._swiftness_key},
        )
        return body if isinstance(body, dict) else {"raw": body}

    def get_saving_concentrations(self) -> dict:
        if not self._swiftness_key:
            raise SwiftnessError("call get_desktop_items() first")
        body = self._post(
            "holdings/getSavingConcentrations",
            {"SwiftnessKey": self._swiftness_key},
        )
        return body if isinstance(body, dict) else {"raw": body}

    def get_document_xml(self, *, additional_language_code: int = 0) -> str:
        """Download the consolidated portfolio XML (fileType=3)."""
        if not self._swiftness_key:
            raise SwiftnessError("call get_desktop_items() first")
        r = self._get(
            "helpers/getDocument",
            {
                "swiftnessKey": self._swiftness_key,
                "fileType": 3,
                "additionalLanguageCode": additional_language_code,
            },
        )
        return r.text


# ============================================================ helpers


_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _scan_for_uuid(obj: Any) -> str | None:
    """Best-effort: walk a JSON-ish object and return the first value
    that looks like a UUID. Used as a fallback when Swiftness renames
    the swiftnessKey field on us."""
    if isinstance(obj, str):
        return obj if _UUID_RE.match(obj) else None
    if isinstance(obj, dict):
        for v in obj.values():
            r = _scan_for_uuid(v)
            if r:
                return r
    if isinstance(obj, list):
        for v in obj:
            r = _scan_for_uuid(v)
            if r:
                return r
    return None


def _extract_jwt_from_login(body: Any) -> str | None:
    """Pull the JWT out of a ``loginwithotp`` response. The shape isn't
    100% stable - try the common field names, then fall back to
    scanning any string for the JWT regex."""
    if not body:
        return None
    if isinstance(body, str):
        return _find_jwt_in_str(body)
    if isinstance(body, dict):
        for k in ("Token", "token", "JwtToken", "AccessToken", "Url", "RedirectUrl"):
            v = body.get(k)
            if isinstance(v, str):
                hit = _find_jwt_in_str(v)
                if hit:
                    return hit
        # Last resort: scan all string values.
        for v in body.values():
            if isinstance(v, str):
                hit = _find_jwt_in_str(v)
                if hit:
                    return hit
    return None


_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def _find_jwt_in_str(s: str) -> str | None:
    m = _JWT_RE.search(s)
    return m.group(0) if m else None


# ============================================================ parsing


# Mapping from Swiftness product-type codes to high-level buckets.
# Codes verified against live API responses; unknown codes land in "other".
_BUCKETS = {
    "pension": {
        "codes": {6, 11, 22, 23},        # 22 confirmed
        "name_hints": ("פנסיה",),
    },
    "keren_hishtalmut": {
        "codes": {4, 7},                  # 4 confirmed
        "name_hints": ("השתלמות",),
    },
    "gemel": {
        "codes": {3, 5, 13, 14, 19, 20},  # not yet seen on a live account
        "name_hints": ("גמל",),
    },
    "life_insurance": {
        "codes": {1, 2, 8},               # 1 confirmed (קצת שמור)
        "name_hints": ("ביטוח חיים", "פוליסה"),
    },
}


def _bucket_for(code: int | None, name: str | None) -> str:
    if code is not None:
        for bucket, spec in _BUCKETS.items():
            if code in spec["codes"]:
                return bucket
    if name:
        for bucket, spec in _BUCKETS.items():
            if any(h in name for h in spec["name_hints"]):
                return bucket
    return "other"


def _maybe_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _coerce_float(v: Any) -> float:
    return _maybe_float(v) or 0.0


def _unwrap_concentration_body(body: dict | None) -> dict | None:
    """Find the dict that holds ``savingConcentrations`` / camel variants.

    Swiftness sometimes wraps the response (``{"savingConcentration":
    {...}}``) and sometimes returns the inner dict directly. Be tolerant.
    """
    if not isinstance(body, dict):
        return None
    for key in ("savingConcentration", "SavingConcentration"):
        v = body.get(key)
        if isinstance(v, dict):
            return v
    return body


def parse_saving_concentrations(body: dict) -> list[SavingConcentration]:
    """Flatten ``getSavingConcentrations`` into a list of
    ``SavingConcentration`` rows (one per product-type-code).

    Tolerates either the wrapped or unwrapped shape of the response.
    """
    inner = _unwrap_concentration_body(body) or {}
    rows: list[dict] = []
    for key in (
        "savingConcentrations",
        "SavingConcentrations",
        "Concentrations",
        "Items",
    ):
        v = inner.get(key) if isinstance(inner, dict) else None
        if isinstance(v, list):
            rows = v
            break
    if not rows and isinstance(body, list):
        rows = body  # type: ignore[assignment]

    out: list[SavingConcentration] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(SavingConcentration(
            product_type_code=_int_or_none(
                row.get("productTypeCode") or row.get("ProductTypeCode")
            ),
            product_type_name=_str_or_none(
                row.get("productTypeName") or row.get("ProductTypeName")
            ),
            current_saving_ils=_coerce_float(
                row.get("currentSaving") or row.get("CurrentSaving")
            ),
            accumulated_balance_forecast_ils=_coerce_float(
                row.get("accumulatedBalanceForecast")
                or row.get("AccumulatedBalanceForecast")
            ),
            accumulated_old_age_pension_ils=_coerce_float(
                row.get("accumulatedOldAgePension")
                or row.get("AccumulatedOldAgePension")
            ),
            monthly_pension_partner_ils=_coerce_float(
                row.get("deathAmountMonthlyPartner")
                or row.get("DeathAmountMonthlyPartner")
            ),
            monthly_pension_child_ils=_coerce_float(
                row.get("deathAmountMonthlyChild")
                or row.get("DeathAmountMonthlyChild")
            ),
            work_disability_monthly_ils=_coerce_float(
                row.get("workDisabilityAmountMonthly")
                or row.get("WorkDisabilityAmountMonthly")
            ),
            life_insurance_one_time_ils=_coerce_float(
                row.get("lifeInsuranceOnetimePayment")
                or row.get("LifeInsuranceOnetimePayment")
            ),
            raw=row,
        ))
    return out


def parse_saving_products(body: dict) -> list[Policy]:
    """Flatten ``productsDetails.savingProductsdetailsList`` into per-
    policy ``Policy`` rows. Returns ``[]`` if the section is absent."""
    if not isinstance(body, dict):
        return []
    pd = body.get("productsDetails") or body.get("ProductsDetails") or {}
    rows: list[dict] = []
    if isinstance(pd, dict):
        for key in (
            "savingProductsdetailsList",
            "savingProductsDetailsList",
            "SavingProductsdetailsList",
            "SavingProductsDetailsList",
        ):
            v = pd.get(key)
            if isinstance(v, list):
                rows = v
                break

    out: list[Policy] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append(Policy(
            policy_key=_int_or_none(row.get("policy_Key") or row.get("policyKey")),
            product_type_code=_int_or_none(row.get("productTypeCode")),
            product_type_name=_str_or_none(row.get("productTypeName")),
            manufacturer_id=_str_or_none(row.get("manufacturerCorporationId")),
            manufacturer_name=_strip_str(row.get("manufacturerName")),
            account_short_name=_strip_str(row.get("accountShortName")),
            policy_name=_strip_str(row.get("policyName")),
            last_deposit_amount_ils=_maybe_float(row.get("lastDepositAmount")),
            last_deposit_at_iso=_str_or_none(row.get("lastReferDate")),
            last_deposit_employer_name=_strip_str(row.get("lastDepositEmployerName")),
            actual_management_fee_pct=_maybe_float(row.get("actualManagementFeeAmount")),
            net_yield_pct=_maybe_float(row.get("netYieldPercent")),
            retirement_age=_maybe_float(row.get("retirementAge")),
            raw=row,
        ))
    return out


def total_current_saving(body: dict) -> float | None:
    """Pull the pre-computed grand total from ``savingConcentration.
    total_CurrentSavings`` if present. Useful as a sanity check against
    summing the per-row ``current_saving_ils``."""
    inner = _unwrap_concentration_body(body)
    if not isinstance(inner, dict):
        return None
    return _maybe_float(
        inner.get("total_CurrentSavings")
        or inner.get("totalCurrentSavings")
        or inner.get("Total_CurrentSavings")
    )


def _str_or_none(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return str(v)


def _strip_str(v: Any) -> str | None:
    """Trim and return None for empty/whitespace strings. Hebrew labels
    in Swiftness's responses sometimes have trailing tabs."""
    if v is None:
        return None
    s = str(v).strip()
    return s or None


def _int_or_none(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        try:
            return int(float(v))
        except (TypeError, ValueError):
            return None


# ============================================================ orchestration


def load_credentials(path: Path | None = None) -> dict:
    """Read the Swiftness credentials file. Schema:

    .. code-block:: json

        {
          "users": [
            {
              "label": "primary",
              "id_number": "123456789",
              "email": "you@example.com"
            }
          ]
        }
    """
    p = path or DEFAULT_CRED_PATH
    cfg = json.loads(p.read_text(encoding="utf-8"))
    users = cfg.get("users") or []
    if not users:
        raise SwiftnessError("credentials: no users listed")
    for u in users:
        if not u.get("id_number") or not u.get("email"):
            raise SwiftnessError(
                f"credentials: user {u.get('label')!r} missing id_number / email"
            )
    return cfg


def pull_savings(
    *,
    user_label: str,
    id_number: str,
    email: str,
    otp: str | None = None,
    client: SwiftnessReadOnlyClient | None = None,
    fetch_xml: bool = False,
    timeout: float = 30.0,
) -> SavingsSnapshot:
    """End-to-end pull for one user.

    Pass ``otp`` to authenticate (or an already-authenticated ``client``).
    This module does not read email; the caller supplies the OTP after
    fetching it via their own email integration.
    """
    from datetime import datetime, timezone

    if client is None:
        if not otp:
            raise SwiftnessOtpRequired(
                f"OTP required for {user_label!r}. Call request_otp first, "
                "read the 6-digit code from your email (from "
                f"{OTP_EMAIL_FROM}), then retry with otp=..."
            )
        client = SwiftnessReadOnlyClient(timeout=timeout)
        authenticate(
            client,
            id_number=id_number,
            email=email,
            otp=otp,
            user_label=user_label,
        )
    elif not client.swiftness_key:
        raise SwiftnessError("provided client is not authenticated")

    return _pull_savings_with_client(
        client,
        user_label=user_label,
        id_number=id_number,
        fetch_xml=fetch_xml,
    )


def _pull_savings_with_client(
    client: SwiftnessReadOnlyClient,
    *,
    user_label: str,
    id_number: str,
    fetch_xml: bool,
) -> SavingsSnapshot:
    from datetime import datetime, timezone

    sc_body = client.get_saving_concentrations()
    rows = parse_saving_concentrations(sc_body)
    policies = parse_saving_products(sc_body)

    # Stitch product_type_name from policies onto concentration rows
    # (concentrations themselves don't carry the HE label).
    name_by_code: dict[int, str] = {}
    for p in policies:
        if p.product_type_code is not None and p.product_type_name and p.product_type_code not in name_by_code:
            name_by_code[p.product_type_code] = p.product_type_name
    enriched_rows: list[SavingConcentration] = []
    for r in rows:
        if r.product_type_name is None and r.product_type_code in name_by_code:
            enriched_rows.append(replace(r, product_type_name=name_by_code[r.product_type_code]))
        else:
            enriched_rows.append(r)
    rows = enriched_rows

    by_bucket: dict[str, float] = {
        "pension": 0.0,
        "gemel": 0.0,
        "keren_hishtalmut": 0.0,
        "life_insurance": 0.0,
        "other": 0.0,
    }
    for r in rows:
        b = _bucket_for(r.product_type_code, r.product_type_name)
        by_bucket[b] += r.current_saving_ils

    grand = sum(by_bucket.values())
    api_total = total_current_saving(sc_body)
    if api_total is not None and abs(api_total - grand) > 1.0:
        log.warning(
            "swiftness sum mismatch for %s: bucketed=%.2f vs API total=%.2f",
            user_label, grand, api_total,
        )

    calc_date = None
    inner = _unwrap_concentration_body(sc_body) or {}
    if isinstance(inner, dict):
        ev = inner.get("eventInfo") or {}
        if isinstance(ev, dict):
            calc_date = _str_or_none(ev.get("calcDate") or ev.get("CalcDate"))

    snap = SavingsSnapshot(
        user_label=user_label,
        user_id_masked="***" + id_number[-3:],
        pulled_at_iso=datetime.now(timezone.utc).isoformat(),
        swiftness_key=client.swiftness_key,
        calc_date_iso=calc_date,
        pension_total_ils=by_bucket["pension"],
        gemel_total_ils=by_bucket["gemel"],
        keren_hishtalmut_total_ils=by_bucket["keren_hishtalmut"],
        life_insurance_total_ils=by_bucket["life_insurance"],
        other_total_ils=by_bucket["other"],
        grand_total_ils=grand,
        concentrations=rows,
        policies=policies,
    )

    # Step 5: optional XML.
    if fetch_xml:
        try:
            snap.xml = client.get_document_xml()
        except SwiftnessError as e:
            log.warning("swiftness xml download failed for %s: %s", user_label, e)

    return snap
