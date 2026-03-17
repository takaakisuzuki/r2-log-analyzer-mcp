# R2 Log Analyzer MCP Server

Cloudflare R2に保存されたHTTPリクエストログおよびWAF/ファイアウォールイベントログを、Claude DesktopなどのMCPクライアントから自然言語で分析できるリモートMCPサーバーです。

Cloudflare Workers上で動作し、Cloudflare Access OAuthによる認証、gzip圧縮ログの自動展開、WAFペイロードロギング（`encrypted_matched_data`）の復号化に対応しています。

## 特徴

- **自然言語でのログ分析** — 「昨日のWAFブロックを分析して」のようにMCPクライアントに問い合わせるだけ
- **Cloudflare Access OAuth認証** — PKCE対応のOAuth 2.1フローでセキュアなアクセス制御
- **gzip自動展開** — Logpushが出力する `.log.gz` ファイルを透過的に展開
- **WAFペイロード復号化** — Cloudflare WAF Payload Loggingの暗号化ペイロード（HPKE: X25519 + ChaCha20-Poly1305）を自動復号
- **Durable Objects** — MCPプロトコルのステート管理にCloudflare Durable Objectsを使用

## アーキテクチャ

```
┌──────────────┐     OAuth 2.1 + PKCE     ┌─────────────────────────┐
│ MCP Client   │◄────────────────────────►│ Cloudflare Access       │
│ (Claude等)   │                          │ (OIDC IdP)              │
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

## 提供ツール

| ツール名 | 説明 |
|---|---|
| `list_log_files` | R2バケット内のログファイル一覧を取得 |
| `query_http_logs` | HTTPリクエストログの検索・フィルタリング |
| `query_firewall_logs` | WAFファイアウォールイベントログの検索・フィルタリング（ペイロード自動復号付き） |
| `analyze_http_traffic` | HTTPトラフィックのTop-N分析（IP、国、パス、ステータスコード等） |
| `analyze_waf_events` | WAFイベントのTop-N分析（アクション、ルール、ソース、攻撃元IP等） |
| `get_log_entry` | RayIDによる特定ログエントリの詳細取得 |
| `read_raw_log_file` | R2上の生ログファイルの直接読み取り |
| `decrypt_waf_payload` | WAF暗号化ペイロード（`encrypted_matched_data`）の個別復号化 |

## 前提条件

- Cloudflareアカウント（Workers, R2, KV, Durable Objects, Access）
- [Logpush](https://developers.cloudflare.com/logs/logpush/) でR2バケットへのログ出力が設定済みであること
  - [HTTP requests](https://developers.cloudflare.com/logs/reference/log-fields/zone/http_requests/) データセット
  - [Firewall events](https://developers.cloudflare.com/logs/reference/log-fields/zone/firewall_events/) データセット
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/) のOIDCアプリケーション設定

## セットアップ

### 1. リポジトリのクローンと依存関係のインストール

```bash
git clone https://github.com/<your-org>/r2-log-analyzer-mcp.git
cd r2-log-analyzer-mcp
npm install
```

### 2. KVネームスペースの作成

```bash
npx wrangler kv:namespace create "OAUTH_KV"
```

出力されたIDを `wrangler.jsonc` の `kv_namespaces[0].id` に設定してください。

### 3. R2バケット名の設定

`wrangler.jsonc` の `r2_buckets` に、Logpushの出力先R2バケット名を設定してください。

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

> **Note**: Logpushのデータセットごとに別バケットが作成される場合があります。Cloudflare Dashboard > Analytics & Logs > Logpush で確認してください。

### 4. Cloudflare Access OIDCアプリの作成

[Cloudflare Zero Trust Dashboard](https://one.dash.cloudflare.com/) > Access > Applications から **SaaS Application** を作成します。

1. Application type: **OIDC**
2. **Scopes**: `openid`, `email`, `profile`
3. **Redirect URLs**:
   - 本番: `https://r2-log-analyzer-mcp.<your-subdomain>.workers.dev/callback`
   - ローカル開発: `http://localhost:8788/callback`

作成後に表示される以下の情報を控えてください:
- Client ID
- Client Secret
- Authorization URL
- Token URL
- JWKS URL (Certificate URL)

### 5. シークレットの設定

```bash
npx wrangler secret put ACCESS_CLIENT_ID
npx wrangler secret put ACCESS_CLIENT_SECRET
npx wrangler secret put ACCESS_TOKEN_URL
npx wrangler secret put ACCESS_AUTHORIZATION_URL
npx wrangler secret put ACCESS_JWKS_URL
npx wrangler secret put COOKIE_ENCRYPTION_KEY  # openssl rand -hex 32 で生成
```

### 6. デプロイ

```bash
npm run deploy
```

### 7. WAFペイロード復号化の設定（オプション）

[WAF Payload Logging](https://developers.cloudflare.com/waf/managed-rules/payload-logging/) を有効化すると、WAFルールにマッチしたリクエストボディの内容を暗号化してログに記録できます。

#### 鍵ペアの生成

Cloudflare Dashboard > Security > WAF > Managed rules > 該当ルールセット > **Configure payload logging** で鍵ペアを生成するか、[matched-data-cli](https://github.com/cloudflare/matched-data-cli) を使用します。

```bash
cargo install matched-data-cli
matched-data-cli generate-key-pair
```

#### 秘密鍵の設定

```bash
npx wrangler secret put MATCHED_PAYLOAD_PRIVATE_KEY
# 生成された秘密鍵（base64エンコード）を入力
```

公開鍵はCloudflare Dashboard の Managed Ruleset のペイロードロギング設定に登録してください。

設定後、WAFルールがリクエストボディの内容にマッチした際に `Metadata.encrypted_matched_data` がログに記録され、本MCPサーバーが自動的に復号化します。

## ローカル開発

```bash
# .dev.vars にシークレットを設定
cat > .dev.vars << 'EOF'
ACCESS_CLIENT_ID=<your-client-id>
ACCESS_CLIENT_SECRET=<your-client-secret>
ACCESS_TOKEN_URL=<your-token-url>
ACCESS_AUTHORIZATION_URL=<your-authorization-url>
ACCESS_JWKS_URL=<your-jwks-url>
COOKIE_ENCRYPTION_KEY=<random-hex-string>
MATCHED_PAYLOAD_PRIVATE_KEY=<optional-private-key>
EOF

# 開発サーバーの起動
npm run dev
```

[MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) で接続テスト:

```bash
npx @modelcontextprotocol/inspector@latest
# URL: http://localhost:8788/sse
```

## MCPクライアントからの接続

### Claude Desktop

`Settings > Developer > Edit Config` で以下を設定:

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

初回接続時にブラウザが開き、Cloudflare Accessの認証画面が表示されます。

### Windsurf / Cursor

Type: `command`、Command:

```
npx mcp-remote https://r2-log-analyzer-mcp.<your-subdomain>.workers.dev/sse
```

## 使用例

MCPクライアント（Claude Desktop等）で以下のように問い合わせられます:

```
WAFファイアウォールイベントの今日のログを分析して
```

```
昨日のHTTPトラフィックでステータス403が多いIPを教えて
```

```
RayID 9dd222669c879d35 の詳細を見せて
```

```
今週のWAFブロックで最も多い攻撃パターンは？
```

## プロジェクト構成

```
src/
├── index.ts              # メインエントリポイント、MCPツール定義
├── access-handler.ts     # Cloudflare Access OAuth認証ハンドラー
├── matched-data.ts       # WAFペイロード復号化（HPKE）
└── workers-oauth-utils.ts # OAuth/CSRF/PKCEユーティリティ
```

## Logpush設定のヒント

R2へのLogpush設定時、プレフィックスを分けると管理しやすくなります:

- HTTPリクエスト: `http_requests/{DATE}/`
- ファイアウォールイベント: `firewall_events/{DATE}/`

WAFペイロード復号化を利用する場合は、Logpushジョブのデータフィールドに **Metadata** を含めてください。

## ログスキーマ

### HTTP Requests 主要フィールド

| フィールド | 説明 |
|---|---|
| `EdgeStartTimestamp` | リクエスト受信タイムスタンプ |
| `ClientIP` / `ClientCountry` | クライアント情報 |
| `ClientRequestHost` / `ClientRequestMethod` / `ClientRequestPath` | リクエスト情報 |
| `EdgeResponseStatus` / `OriginResponseStatus` | レスポンスステータス |
| `CacheCacheStatus` | キャッシュ状態 |
| `SecurityAction` / `SecurityRuleID` | セキュリティアクション |
| `BotScore` / `BotScoreSrc` | Bot検出スコア |
| `WAFAttackScore` / `WAFSQLiAttackScore` / `WAFXSSAttackScore` | WAF攻撃スコア |
| `RayID` | リクエストID |

### Firewall Events 主要フィールド

| フィールド | 説明 |
|---|---|
| `Datetime` | イベント発生日時 |
| `Action` | アクション（block, challenge, log 等） |
| `ClientIP` / `ClientCountry` | クライアント情報 |
| `ClientRequestHost` / `ClientRequestMethod` / `ClientRequestPath` | リクエスト情報 |
| `Description` | ルール説明 |
| `RuleID` | ルールID |
| `Source` | セキュリティプロダクト（firewallManaged, firewallCustom 等） |
| `Metadata` | メタデータ（`encrypted_matched_data`, `ruleset_version` 等） |
| `LeakedCredentialCheckResult` | 漏洩認証情報チェック結果 |
| `RayID` | リクエストID |

## 技術スタック

- [Cloudflare Workers](https://developers.cloudflare.com/workers/) — サーバーレス実行環境
- [Cloudflare Durable Objects](https://developers.cloudflare.com/durable-objects/) — MCPセッション管理
- [Cloudflare R2](https://developers.cloudflare.com/r2/) — ログストレージ
- [Cloudflare KV](https://developers.cloudflare.com/kv/) — OAuth状態管理
- [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/) — 認証
- [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) — Model Context Protocol
- [agents](https://github.com/cloudflare/agents) — Cloudflare Agents framework
- [@hpke/core](https://github.com/dajiaji/hpke-js) — WAFペイロード復号化（HPKE）

## ライセンス

MIT
