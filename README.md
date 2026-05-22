# swiftness-mcp

Read-only [Model Context Protocol](https://modelcontextprotocol.io/) server for **Swiftness** (המסלקה הפנסיונית) — Israel's pension clearing house that aggregates savings data from pension funds, keren hishtalmut, and gemel providers.

**Author:** [Uri Harduf](https://github.com/urh)

## What is it good for?

Let an AI assistant pull your consolidated pension and savings picture without manual copy-paste:

- *"What is my total pension and savings balance according to Swiftness?"*
- *"Break down my savings by product type — pension, keren hishtalmut, gemel."*
- *"Which management companies hold my policies and what are the fees?"*

Useful for retirement planning dashboards, monthly net-worth updates, or simply asking natural-language questions about your Israeli long-term savings.

The server is **read-only**: it authenticates and reads aggregated data. It cannot switch funds, change beneficiaries, or submit withdrawals.

## Tools

| Tool | Description |
|------|-------------|
| `request_otp` | Ask Swiftness to email a one-time login code |
| `submit_otp` | Complete login with the 6-digit code (caches session ~25 min) |
| `get_savings_summary` | Bucketed totals (pension, gemel, keren hishtalmut, life insurance) |
| `get_saving_concentrations` | Per-product-type breakdown with retirement forecasts |
| `get_policies` | Individual policies with manufacturer, fees, and yields |

Data tools accept optional `otp`. If omitted and no cached session exists, they trigger an OTP email and return `otp_required` instructions for the agent.

## Agent-driven OTP (no mailbox credentials here)

Swiftness sends a 6-digit code by email from `doNotReply@swiftness.co.il`. **This MCP never reads your inbox** — the calling agent should use a separate email MCP (Gmail, Outlook, etc.).

Typical flow:

1. **Swiftness MCP** — `request_otp(user_label="primary")` (or call a data tool, which auto-requests on first use)
2. **Email MCP** — search for the code, e.g. Gmail: `from:doNotReply@swiftness.co.il`
3. **Swiftness MCP** — `submit_otp(user_label="primary", otp="123456")` *or* `get_savings_summary(..., otp="123456")`
4. Further data calls reuse the cached session until it expires (~25 minutes)

Swiftness sometimes sends **two** OTP emails 20–30 seconds apart with different codes; always use the **newest** message.

## Setup

### 1. Credentials

```bash
mkdir -p ~/.config/swiftness
cp credentials.example.json ~/.config/swiftness/credentials.json
chmod 600 ~/.config/swiftness/credentials.json
```

Each user entry needs a national ID number and the email registered with Swiftness.

### 2. Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 3. MCP configuration

```json
{
  "mcpServers": {
    "swiftness": {
      "command": "/path/to/swiftness-mcp/.venv/bin/python",
      "args": ["-m", "swiftness_mcp"],
      "env": {
        "SWIFTNESS_CREDENTIALS_PATH": "/Users/you/.config/swiftness/credentials.json"
      }
    }
  }
}
```

Pair with your email MCP in the same agent (e.g. `gmail-personal`, `gmail-work`, or any provider).

## CLI

The CLI requires an OTP on the command line (read it from your mail client first):

```bash
python scripts/pull.py --user primary --otp 123456
python scripts/pull.py --user primary --otp 123456 --xml-out /tmp/portfolio.xml
```

## Authentication flow

1. Request OTP email from Swiftness (`createOtp`)
2. Agent reads the 6-digit code via its **own** email integration
3. Exchange OTP for a short-lived JWT (`loginwithotp`)
4. Fetch desktop session key and savings data

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
