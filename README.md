# R2 Log Analyzer MCP Server

A remote MCP server that lets you analyze HTTP request logs and WAF/Firewall event logs stored in Cloudflare R2 using natural language via MCP clients such as Claude Desktop.

Runs on Cloudflare Workers with Cloudflare Access OAuth authentication, automatic gzip log decompression, and WAF Payload Logging (`encrypted_matched_data`) decryption.

## Features

- **Natural language log analysis** — Simply ask your MCP client something like "Analyze today's WAF blocks"
- **Cloudflare Access OAuth** — Secure access control via OAuth 2.1 with PKCE
- **Automatic gzip decompression** — Transparently decompresses `.log.gz` files output by Logpush
- **WAF payload decryption** — Automatically decrypts Cloudflare WAF Payload Logging encrypted payloads (HPKE: X25519 + ChaCha20-Poly1305)
- **Durable Objects** — Uses Cloudflare Durable Objects for MCP protocol state management

## Architecture

```
┌──────────────┐     OAuth 2.1 + PKCE     ┌─────────────────────────┐
│ MCP Client   │◄────────────────────────►│ Cloudflare Access       │
│ (Claude etc) │                          │ (OIDC IdP)              │
└──────┬───────┘                          └─────────────────────────┘
       │ MCP Protocol (SSE)
       ▼
┌──────────────────────────────┐
│ R2 Log Analyzer MCP Server   │
│ (Cloudflare Worker)          │
│                              │
│  ┌─────────────────────────┐ │
│  │ Durable Object          │ │     ┌──────────────────┐
│  │ (McpAgent)              │ │────►│ R2: HTTP Logs    │
│  │                         │ │     └──────────────────┘
│  │  - Log query/analysis   │ │     ┌──────────────────┐
│  │  - Payload decryption   │ │────►│ R2: WAF Logs     │
│  │  - gzip decompression   │ │     └──────────────────┘
│  └─────────────────────────┘ │
│                              │     ┌──────────────────┐
│  OAuth state & PKCE ─────────│────►│ KV: OAUTH_KV     │
└──────────────────────────────┘     └──────────────────┘
```

## Available Tools

| Tool | Description |
|---|---|
| `list_log_files` | List log files in an R2 bucket |
| `query_http_logs` | Search and filter HTTP request logs |
| `query_firewall_logs` | Search and filter WAF firewall event logs (with automatic payload decryption) |
| `analyze_http_traffic` | Top-N analysis of HTTP traffic (by IP, country, path, status code, etc.) |
| `analyze_waf_events` | Top-N analysis of WAF events (by action, rule, source, attacker IP, etc.) |
| `get_log_entry` | Retrieve details of a specific log entry by RayID |
| `read_raw_log_file` | Read a raw log file directly from R2 |
| `decrypt_waf_payload` | Decrypt an individual WAF encrypted payload (`encrypted_matched_data`) |

## Prerequisites

- A Cloudflare account (Workers, R2, KV, Durable Objects, Access)
- [Logpush](https://developers.cloudflare.com/logs/logpush/) configured to output logs to R2 buckets
  - [HTTP requests](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/) dataset
  - [Firewall events](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/) dataset
- A [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/) OIDC application

## Setup

### 1. Clone the Repository and Install Dependencies

```bash
git clone https://github.com/takaakisuzuki/r2-log-analyzer-mcp.git
cd r2-log-analyzer-mcp
npm install
```

### 2. Create a KV Namespace

```bash
npx wrangler kv:namespace create "OAUTH_KV"
```

Set the output ID in `kv_namespaces[0].id` in `wrangler.jsonc`.

### 3. Configure R2 Bucket Names

Set your Logpush destination R2 bucket names in the `r2_buckets` section of `wrangler.jsonc`.

```jsonc
"r2_buckets": [
  {
    "binding": "HTTP_LOG_BUCKET",
    "bucket_name": "<your-http-logs-bucket>"
  },
  {
    "binding": "WAF_LOG_BUCKET",
    "bucket_name": "<your-waf-logs-bucket>"
  }
]
```

> **Note**: Separate buckets may be created for each Logpush dataset. Verify in Cloudflare Dashboard > Analytics & Logs > Logpush.

### 4. Create a Cloudflare Access OIDC Application

Go to [Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) > Access > Applications and create a **SaaS Application**.

1. Application type: **OIDC**
2. **Scopes**: `openid`, `email`, `profile`
3. **Redirect URLs**:
   - Production: `https://r2-log-analyzer-mcp.<your-subdomain>.workers.dev/callback`
   - Local development: `http://localhost:8788/callback`

Note the following values after creation:
- Client ID
- Client Secret
- Authorization URL
- Token URL
- JWKS URL (Certificate URL)

### 5. Set Secrets

```bash
npx wrangler secret put ACCESS_CLIENT_ID
npx wrangler secret put ACCESS_CLIENT_SECRET
npx wrangler secret put ACCESS_TOKEN_URL
npx wrangler secret put ACCESS_AUTHORIZATION_URL
npx wrangler secret put ACCESS_JWKS_URL
npx wrangler secret put COOKIE_ENCRYPTION_KEY  # Generate with: openssl rand -hex 32
```

### 6. Deploy

```bash
npm run deploy
```

### 7. Configure WAF Payload Decryption (Optional)

Enable [WAF Payload Logging](https://developers.cloudflare.com/waf/managed-rules/payload-logging/) to encrypt and log the content of request bodies that match WAF rules.

#### Generate a Key Pair

Generate a key pair via Cloudflare Dashboard > Security > WAF > Managed rules > target ruleset > **Configure payload logging**, or use [matched-data-cli](https://github.com/cloudflare/matched-data-cli):

```bash
cargo install matched-data-cli
matched-data-cli generate-key-pair
```

#### Set the Private Key

```bash
npx wrangler secret put MATCHED_PAYLOAD_PRIVATE_KEY
# Enter the generated private key (base64-encoded)
```

Register the public key in the Managed Ruleset payload logging settings in the Cloudflare Dashboard.

Once configured, `Metadata.encrypted_matched_data` will be recorded in logs when a WAF rule matches request body content, and this MCP server will automatically decrypt it.

## Local Development

```bash
# Set secrets in .dev.vars
cat > .dev.vars << 'EOF'
ACCESS_CLIENT_ID=<your-client-id>
ACCESS_CLIENT_SECRET=<your-client-secret>
ACCESS_TOKEN_URL=<your-token-url>
ACCESS_AUTHORIZATION_URL=<your-authorization-url>
ACCESS_JWKS_URL=<your-jwks-url>
COOKIE_ENCRYPTION_KEY=<random-hex-string>
MATCHED_PAYLOAD_PRIVATE_KEY=<optional-private-key>
EOF

# Start the development server
npm run dev
```

Test the connection with [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector):

```bash
npx @modelcontextprotocol/inspector@latest
# URL: http://localhost:8788/sse
```

## Connecting from MCP Clients

### Claude Desktop

Go to `Settings > Developer > Edit Config` and add the following:

```json
{
  "mcpServers": {
    "r2-log-analyzer": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://r2-log-analyzer-mcp.<your-subdomain>.workers.dev/sse"
      ]
    }
  }
}
```

On the first connection, a browser window will open showing the Cloudflare Access authentication screen.

### Windsurf / Cursor

Type: `command`, Command:

```
npx mcp-remote https://r2-log-analyzer-mcp.<your-subdomain>.workers.dev/sse
```

## Usage Examples

You can query your MCP client (e.g., Claude Desktop) like this:

```
Analyze today's WAF firewall event logs
```

```
Show me the IPs with the most 403 status codes in yesterday's HTTP traffic
```

```
Show details for RayID 9dd222669c879d35
```

```
What are the most common attack patterns in this week's WAF blocks?
```

## Project Structure

```
src/
├── index.ts              # Main entry point, MCP tool definitions
├── access-handler.ts     # Cloudflare Access OAuth handler
├── matched-data.ts       # WAF payload decryption (HPKE)
└── workers-oauth-utils.ts # OAuth/CSRF/PKCE utilities
```

## Logpush Configuration Tips

When configuring Logpush to R2, using separate prefixes makes management easier:

- HTTP requests: `http_requests/{DATE}/`
- Firewall events: `firewall_events/{DATE}/`

If you use WAF payload decryption, make sure to include the **Metadata** field in your Logpush job data fields.

## Log Schema

### HTTP Requests — Key Fields

| Field | Description |
|---|---|
| `EdgeStartTimestamp` | Request received timestamp |
| `ClientIP` / `ClientCountry` | Client information |
| `ClientRequestHost` / `ClientRequestMethod` / `ClientRequestPath` | Request details |
| `EdgeResponseStatus` / `OriginResponseStatus` | Response status |
| `CacheCacheStatus` | Cache status |
| `SecurityAction` / `SecurityRuleID` | Security action |
| `BotScore` / `BotScoreSrc` | Bot detection score |
| `WAFAttackScore` / `WAFSQLiAttackScore` / `WAFXSSAttackScore` | WAF attack scores |
| `RayID` | Request ID |

### Firewall Events — Key Fields

| Field | Description |
|---|---|
| `Datetime` | Event timestamp |
| `Action` | Action taken (block, challenge, log, etc.) |
| `ClientIP` / `ClientCountry` | Client information |
| `ClientRequestHost` / `ClientRequestMethod` / `ClientRequestPath` | Request details |
| `Description` | Rule description |
| `RuleID` | Rule ID |
| `Source` | Security product (firewallManaged, firewallCustom, etc.) |
| `Metadata` | Metadata (`encrypted_matched_data`, `ruleset_version`, etc.) |
| `LeakedCredentialCheckResult` | Leaked credential check result |
| `RayID` | Request ID |

## Tech Stack

- [Cloudflare Workers](https://developers.cloudflare.com/workers/) — Serverless runtime
- [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/) — MCP session management
- [Cloudflare R2](https://developers.cloudflare.com/r2/) — Log storage
- [Cloudflare KV](https://developers.cloudflare.com/kv/) — OAuth state management
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/) — Authentication
- [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) — Model Context Protocol
- [agents](https://github.com/cloudflare/agents) — Cloudflare Agents framework
- [@hpke/core](https://github.com/dajiaji/hpke-js) — WAF payload decryption (HPKE)

## License

MIT
