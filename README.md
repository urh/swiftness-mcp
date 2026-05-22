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
| `get_savings_summary` | Bucketed totals (pension, gemel, keren hishtalmut, life insurance) |
| `get_saving_concentrations` | Per-product-type breakdown with retirement forecasts |
| `get_policies` | Individual policies with manufacturer, fees, and yields |

All tools accept optional `user_label` and `otp`. If `otp` is omitted, the server triggers email OTP and can read it automatically from Gmail when OAuth tokens are configured.

## Setup

### 1. Credentials

```bash
mkdir -p ~/.config/swiftness
cp credentials.example.json ~/.config/swiftness/credentials.json
chmod 600 ~/.config/swiftness/credentials.json
```

Each user entry needs a national ID number and the email registered with Swiftness.

### 2. Gmail OTP (optional)

For unattended pulls, configure Gmail OAuth token paths (same tokens used by the Gmail MCP server work):

```json
{
  "users": [
    {
      "label": "primary",
      "id_number": "123456789",
      "email": "you@example.com",
      "gmail_token_path": "~/.config/gmail-mcp/credentials.json",
      "gmail_oauth_path": "~/.config/gmail-mcp/gcp-oauth.keys.json"
    }
  ]
}
```

Alternatively, pass a 6-digit `otp` argument if you triggered authentication manually on the Swiftness website.

### 3. Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. MCP configuration

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

## CLI

```bash
python scripts/pull.py
python scripts/pull.py --user primary --otp 123456
python scripts/pull.py --xml-out /tmp/portfolio.xml
```

## Authentication flow

1. Request OTP email from Swiftness (`createOtp`)
2. Read the 6-digit code from email (manual or Gmail helper)
3. Exchange OTP for a short-lived JWT (`loginwithotp`)
4. Fetch desktop session key and savings data

Swiftness sometimes sends two OTP emails; the client waits and uses the most recent code.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT — see [LICENSE](LICENSE).
