import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import { decryptLogEntries, decryptMatchedData } from "./matched-data";
import type { Props } from "./workers-oauth-utils";

// Maximum number of log lines to process per request to avoid OOM
const MAX_LOG_LINES = 5000;
// Maximum number of R2 objects to read per query
const MAX_OBJECTS_PER_QUERY = 10;

/**
 * Decompress gzip content using DecompressionStream.
 */
async function decompressGzip(body: ReadableStream): Promise<string> {
	const ds = new DecompressionStream("gzip");
	const decompressed = body.pipeThrough(ds);
	const reader = decompressed.getReader();
	const chunks: Uint8Array[] = [];
	while (true) {
		const { done, value } = await reader.read();
		if (done) break;
		chunks.push(value);
	}
	const decoder = new TextDecoder();
	return chunks.map((c) => decoder.decode(c, { stream: true })).join("") + decoder.decode();
}

/**
 * Read text from an R2 object, auto-detecting gzip by key extension.
 */
async function readR2ObjectText(obj: R2ObjectBody, key: string): Promise<string> {
	if (key.endsWith(".gz")) {
		return decompressGzip(obj.body);
	}
	return obj.text();
}

/**
 * Parse newline-delimited JSON (ndjson) log content.
 * Logpush writes logs as gzipped ndjson.
 */
function parseLogLines(text: string): Record<string, any>[] {
	const lines = text.split("\n").filter((line) => line.trim().length > 0);
	const results: Record<string, any>[] = [];
	for (const line of lines) {
		if (results.length >= MAX_LOG_LINES) break;
		try {
			const parsed = JSON.parse(line);
			// If the entire content is a JSON array, flatten it
			if (Array.isArray(parsed)) {
				for (const item of parsed) {
					if (results.length >= MAX_LOG_LINES) break;
					results.push(item);
				}
			} else {
				results.push(parsed);
			}
		} catch {
			// Skip unparseable lines
		}
	}
	return results;
}

/**
 * Read and parse log objects from R2 matching a given prefix.
 */
async function readLogsFromR2(
	bucket: R2Bucket,
	prefix: string,
	maxObjects: number = MAX_OBJECTS_PER_QUERY,
): Promise<Record<string, any>[]> {
	const listed = await bucket.list({ prefix, limit: maxObjects });
	const allLogs: Record<string, any>[] = [];

	for (const obj of listed.objects) {
		if (allLogs.length >= MAX_LOG_LINES) break;
		const r2Obj = await bucket.get(obj.key);
		if (!r2Obj) continue;

		const text = await readR2ObjectText(r2Obj, obj.key);
		const parsed = parseLogLines(text);
		allLogs.push(...parsed);
	}

	return allLogs.slice(0, MAX_LOG_LINES);
}

/**
 * Filter logs by field values. Supports simple equality matching.
 */
function filterLogs(
	logs: Record<string, any>[],
	filters: Record<string, string | number | boolean>,
): Record<string, any>[] {
	return logs.filter((log) => {
		for (const [key, value] of Object.entries(filters)) {
			const logValue = log[key];
			if (logValue === undefined) return false;
			// Case-insensitive string comparison
			if (typeof logValue === "string" && typeof value === "string") {
				if (logValue.toLowerCase() !== value.toLowerCase()) return false;
			} else if (logValue !== value) {
				return false;
			}
		}
		return true;
	});
}

/**
 * Count occurrences of a field value and return top N.
 */
function topN(
	logs: Record<string, any>[],
	field: string,
	n: number,
): { value: string; count: number }[] {
	const counts = new Map<string, number>();
	for (const log of logs) {
		const val = log[field];
		if (val !== undefined && val !== null) {
			const key = String(val);
			counts.set(key, (counts.get(key) || 0) + 1);
		}
	}
	return Array.from(counts.entries())
		.map(([value, count]) => ({ value, count }))
		.sort((a, b) => b.count - a.count)
		.slice(0, n);
}

/**
 * Format a summary table as readable text.
 */
function formatTopN(items: { value: string; count: number }[], label: string): string {
	if (items.length === 0) return `No data found for ${label}.`;
	const lines = items.map((item, i) => `  ${i + 1}. ${item.value}: ${item.count}`);
	return `Top ${label}:\n${lines.join("\n")}`;
}

export class R2LogAnalyzerMCP extends McpAgent<Env, Record<string, never>, Props> {
	server = new McpServer({
		name: "R2 Log Analyzer",
		version: "1.0.0",
	});

	async init() {
		// ---------------------------------------------------------------
		// Tool: list_log_files
		// ---------------------------------------------------------------
		this.server.tool(
			"list_log_files",
			"List log files stored in R2 under a given prefix. Use this to discover available log files before querying them. Logpush typically stores files with date-based prefixes like 'http_requests/20250315/' or 'firewall_events/20250315/'.",
			{
				bucket: z
					.enum(["http", "waf"])
					.describe("Which log bucket to list: 'http' for HTTP request logs, 'waf' for WAF firewall event logs."),
				prefix: z
					.string()
					.default("")
					.describe(
						"R2 key prefix to list. Leave empty to list root.",
					),
				limit: z
					.number()
					.min(1)
					.max(100)
					.default(20)
					.describe("Maximum number of files to list (1-100)."),
			},
			async ({ bucket, prefix, limit }) => {
				const r2Bucket = bucket === "http" ? this.env.HTTP_LOG_BUCKET : this.env.WAF_LOG_BUCKET;
				const bucketLabel = bucket === "http" ? "HTTP requests" : "WAF firewall events";
				const listed = await r2Bucket.list({
					prefix: prefix || undefined,
					limit,
				});

				if (listed.objects.length === 0) {
					// Also try listing prefixes (directories)
					const delimited = await r2Bucket.list({
						prefix: prefix || undefined,
						delimiter: "/",
						limit,
					});
					const prefixes = delimited.delimitedPrefixes || [];
					if (prefixes.length > 0) {
						return {
							content: [
								{
									type: "text" as const,
									text: "[" + bucketLabel + "] Found " + prefixes.length + " prefixes (directories):\n" + prefixes.join("\n"),
								},
							],
						};
					}
					const displayPrefix = prefix || "(root)";
					return {
						content: [
							{
								type: "text" as const,
								text: "[" + bucketLabel + "] No files found under prefix \"" + displayPrefix + "\".",
							},
						],
					};
				}

				const displayPrefix2 = prefix || "(root)";
				const fileList = listed.objects.map((obj) => {
					const sizeKB = (obj.size / 1024).toFixed(1);
					const uploaded = obj.uploaded.toISOString();
					return "  " + obj.key + " (" + sizeKB + " KB, " + uploaded + ")";
				});

				const truncatedMsg = listed.truncated ? "\n  ... (truncated, more files available)" : "";
				return {
					content: [
						{
							type: "text" as const,
							text: "[" + bucketLabel + "] Found " + listed.objects.length + " files under \"" + displayPrefix2 + "\":\n" + fileList.join("\n") + truncatedMsg,
						},
					],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: query_http_logs
		// ---------------------------------------------------------------
		this.server.tool(
			"query_http_logs",
			"Query and filter HTTP request logs stored in R2. Returns matching log entries from Cloudflare Logpush http_requests dataset. Key fields include: ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestURI, ClientRequestUserAgent, EdgeResponseStatus, EdgeColoCode, OriginResponseStatus, RayID, SecurityAction, BotScore, CacheCacheStatus, EdgeStartTimestamp, etc.",
			{
				prefix: z
					.string()
					.describe(
						"R2 key prefix for the HTTP log files, e.g. 'http_requests/2025-03-15' or 'http_requests/'.",
					),
				filters: z
					.record(z.union([z.string(), z.number(), z.boolean()]))
					.optional()
					.describe(
						'Optional filters as key-value pairs to match log fields, e.g. {"ClientCountry":"JP","EdgeResponseStatus":403}.',
					),
				fields: z
					.array(z.string())
					.optional()
					.describe(
						"Optional list of fields to include in the output. If omitted, returns key summary fields.",
					),
				max_results: z
					.number()
					.min(1)
					.max(100)
					.default(50)
					.describe("Maximum number of matching log entries to return."),
			},
			async ({ prefix, filters, fields, max_results }) => {
				const logs = await readLogsFromR2(this.env.HTTP_LOG_BUCKET, prefix);

				if (logs.length === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found under prefix "${prefix}".` }],
					};
				}

				let filtered = filters ? filterLogs(logs, filters) : logs;
				const totalMatched = filtered.length;
				filtered = filtered.slice(0, max_results);

				const defaultFields = [
					"EdgeStartTimestamp",
					"ClientIP",
					"ClientCountry",
					"ClientRequestMethod",
					"ClientRequestHost",
					"ClientRequestPath",
					"EdgeResponseStatus",
					"OriginResponseStatus",
					"CacheCacheStatus",
					"SecurityAction",
					"RayID",
				];

				const outputFields = fields || defaultFields;
				const entries = filtered.map((log) => {
					const entry: Record<string, any> = {};
					for (const f of outputFields) {
						if (log[f] !== undefined) {
							entry[f] = log[f];
						}
					}
					return entry;
				});

				const summary = [
					`HTTP Logs Query Results (prefix: "${prefix}")`,
					`Total logs read: ${logs.length}`,
					`Matched: ${totalMatched}`,
					`Returned: ${entries.length}`,
					filters ? `Filters: ${JSON.stringify(filters)}` : "No filters applied",
					"---",
				].join("\n");

				return {
					content: [
						{
							type: "text" as const,
							text: summary + "\n" + JSON.stringify(entries, null, 2),
						},
					],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: query_firewall_logs
		// ---------------------------------------------------------------
		this.server.tool(
			"query_firewall_logs",
			"Query and filter WAF/firewall event logs stored in R2. Returns matching log entries from Cloudflare Logpush firewall_events dataset. Key fields include: Action, ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestUserAgent, Datetime, Description, EdgeColoCode, EdgeResponseStatus, RayID, RuleID, Source, Kind, MatchIndex, Metadata, etc.",
			{
				prefix: z
					.string()
					.describe(
						"R2 key prefix for the firewall log files, e.g. 'firewall_events/2025-03-15' or 'firewall_events/'.",
					),
				filters: z
					.record(z.union([z.string(), z.number(), z.boolean()]))
					.optional()
					.describe(
						'Optional filters as key-value pairs, e.g. {"Action":"block","Source":"firewallManaged"}.',
					),
				fields: z
					.array(z.string())
					.optional()
					.describe(
						"Optional list of fields to include in the output. If omitted, returns key summary fields.",
					),
				max_results: z
					.number()
					.min(1)
					.max(100)
					.default(50)
					.describe("Maximum number of matching log entries to return."),
			},
			async ({ prefix, filters, fields, max_results }) => {
				let logs = await readLogsFromR2(this.env.WAF_LOG_BUCKET, prefix);

				if (logs.length === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found under prefix "${prefix}".` },
						],
					};
				}

				// Auto-decrypt matched payloads if private key is configured
				logs = await decryptLogEntries(logs, this.env.MATCHED_PAYLOAD_PRIVATE_KEY);

				let filtered = filters ? filterLogs(logs, filters) : logs;
				const totalMatched = filtered.length;
				filtered = filtered.slice(0, max_results);

				const defaultFields = [
					"Datetime",
					"Action",
					"ClientIP",
					"ClientCountry",
					"ClientRequestHost",
					"ClientRequestMethod",
					"ClientRequestPath",
					"ClientRequestUserAgent",
					"Description",
					"RuleID",
					"Source",
					"EdgeResponseStatus",
					"RayID",
					"Metadata",
				];

				const outputFields = fields || defaultFields;
				const entries = filtered.map((log) => {
					const entry: Record<string, any> = {};
					for (const f of outputFields) {
						if (log[f] !== undefined) {
							entry[f] = log[f];
						}
					}
					return entry;
				});

				const summary = [
					`Firewall Events Query Results (prefix: "${prefix}")`,
					`Total logs read: ${logs.length}`,
					`Matched: ${totalMatched}`,
					`Returned: ${entries.length}`,
					filters ? `Filters: ${JSON.stringify(filters)}` : "No filters applied",
					"---",
				].join("\n");

				return {
					content: [
						{
							type: "text" as const,
							text: summary + "\n" + JSON.stringify(entries, null, 2),
						},
					],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: analyze_http_traffic
		// ---------------------------------------------------------------
		this.server.tool(
			"analyze_http_traffic",
			"Analyze HTTP request logs to generate traffic summaries. Provides top-N rankings for IPs, countries, paths, status codes, user agents, cache status, and more.",
			{
				prefix: z
					.string()
					.describe("R2 key prefix for the HTTP log files, e.g. 'http_requests/2025-03-15'."),
				top_n: z
					.number()
					.min(1)
					.max(50)
					.default(10)
					.describe("Number of top entries to show per category."),
				filters: z
					.record(z.union([z.string(), z.number(), z.boolean()]))
					.optional()
					.describe("Optional pre-filters to apply before analysis."),
			},
			async ({ prefix, top_n, filters }) => {
				const logs = await readLogsFromR2(this.env.HTTP_LOG_BUCKET, prefix);

				if (logs.length === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found under prefix "${prefix}".` }],
					};
				}

				const filtered = filters ? filterLogs(logs, filters) : logs;

				const analyses = [
					`HTTP Traffic Analysis (prefix: "${prefix}")`,
					`Total logs analyzed: ${filtered.length}`,
					filters ? `Pre-filters: ${JSON.stringify(filters)}` : "",
					"===",
					"",
					formatTopN(topN(filtered, "ClientIP", top_n), "Client IPs"),
					"",
					formatTopN(topN(filtered, "ClientCountry", top_n), "Countries"),
					"",
					formatTopN(topN(filtered, "ClientRequestHost", top_n), "Request Hosts"),
					"",
					formatTopN(topN(filtered, "ClientRequestPath", top_n), "Request Paths"),
					"",
					formatTopN(topN(filtered, "ClientRequestMethod", top_n), "HTTP Methods"),
					"",
					formatTopN(topN(filtered, "EdgeResponseStatus", top_n), "Edge Response Status Codes"),
					"",
					formatTopN(topN(filtered, "OriginResponseStatus", top_n), "Origin Response Status Codes"),
					"",
					formatTopN(topN(filtered, "CacheCacheStatus", top_n), "Cache Status"),
					"",
					formatTopN(topN(filtered, "ClientRequestUserAgent", top_n), "User Agents"),
					"",
					formatTopN(topN(filtered, "EdgeColoCode", top_n), "Edge Colo Codes (Data Centers)"),
					"",
					formatTopN(topN(filtered, "SecurityAction", top_n), "Security Actions"),
					"",
					formatTopN(topN(filtered, "ClientDeviceType", top_n), "Device Types"),
				].filter(Boolean);

				return {
					content: [{ type: "text" as const, text: analyses.join("\n") }],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: analyze_waf_events
		// ---------------------------------------------------------------
		this.server.tool(
			"analyze_waf_events",
			"Analyze WAF/firewall event logs to generate security summaries. Provides top-N rankings for blocked IPs, actions, rules, sources, countries, and targeted paths.",
			{
				prefix: z
					.string()
					.describe("R2 key prefix for the firewall log files, e.g. 'firewall_events/2025-03-15'."),
				top_n: z
					.number()
					.min(1)
					.max(50)
					.default(10)
					.describe("Number of top entries to show per category."),
				filters: z
					.record(z.union([z.string(), z.number(), z.boolean()]))
					.optional()
					.describe("Optional pre-filters to apply before analysis."),
			},
			async ({ prefix, top_n, filters }) => {
				const logs = await readLogsFromR2(this.env.WAF_LOG_BUCKET, prefix);

				if (logs.length === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found under prefix "${prefix}".` },
						],
					};
				}

				const filtered = filters ? filterLogs(logs, filters) : logs;

				const analyses = [
					`WAF/Firewall Events Analysis (prefix: "${prefix}")`,
					`Total events analyzed: ${filtered.length}`,
					filters ? `Pre-filters: ${JSON.stringify(filters)}` : "",
					"===",
					"",
					formatTopN(topN(filtered, "Action", top_n), "Actions"),
					"",
					formatTopN(topN(filtered, "Source", top_n), "Security Sources"),
					"",
					formatTopN(topN(filtered, "ClientIP", top_n), "Client IPs"),
					"",
					formatTopN(topN(filtered, "ClientCountry", top_n), "Countries"),
					"",
					formatTopN(topN(filtered, "ClientRequestHost", top_n), "Targeted Hosts"),
					"",
					formatTopN(topN(filtered, "ClientRequestPath", top_n), "Targeted Paths"),
					"",
					formatTopN(topN(filtered, "ClientRequestMethod", top_n), "HTTP Methods"),
					"",
					formatTopN(topN(filtered, "RuleID", top_n), "Rule IDs"),
					"",
					formatTopN(topN(filtered, "Description", top_n), "Rule Descriptions"),
					"",
					formatTopN(topN(filtered, "EdgeColoCode", top_n), "Edge Colo Codes"),
					"",
					formatTopN(topN(filtered, "ClientRequestUserAgent", top_n), "User Agents"),
				].filter(Boolean);

				return {
					content: [{ type: "text" as const, text: analyses.join("\n") }],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: get_log_entry
		// ---------------------------------------------------------------
		this.server.tool(
			"get_log_entry",
			"Get the full details of a specific log entry by RayID. Searches through log files in the specified bucket to find the matching entry.",
			{
				bucket: z
					.enum(["http", "waf"])
					.describe("Which log bucket to search: 'http' for HTTP request logs, 'waf' for WAF firewall event logs."),
				prefix: z
					.string()
					.default("")
					.describe(
						"R2 key prefix to search within.",
					),
				ray_id: z.string().describe("The RayID of the log entry to find."),
			},
			async ({ bucket, prefix, ray_id }) => {
				const r2Bucket = bucket === "http" ? this.env.HTTP_LOG_BUCKET : this.env.WAF_LOG_BUCKET;
				let logs = await readLogsFromR2(r2Bucket, prefix);

				let entry = logs.find((log) => log.RayID === ray_id);

				if (!entry) {
					return {
						content: [
							{
								type: "text" as const,
								text: `No log entry found with RayID "${ray_id}" under prefix "${prefix}". Searched ${logs.length} entries.`,
							},
						],
					};
				}

				// Auto-decrypt matched payload for WAF entries
				if (bucket === "waf" && this.env.MATCHED_PAYLOAD_PRIVATE_KEY) {
					const decrypted = await decryptLogEntries([entry], this.env.MATCHED_PAYLOAD_PRIVATE_KEY);
					entry = decrypted[0];
				}

				return {
					content: [
						{
							type: "text" as const,
							text: `Log entry for RayID ${ray_id}:\n${JSON.stringify(entry, null, 2)}`,
						},
					],
				};
			},
		);

		// ---------------------------------------------------------------
		// Tool: read_raw_log_file
		// ---------------------------------------------------------------
		this.server.tool(
			"read_raw_log_file",
			"Read the raw contents of a specific log file from R2. Useful for inspecting file format or reading small files directly.",
			{
				bucket: z
					.enum(["http", "waf"])
					.describe("Which log bucket to read from: 'http' for HTTP request logs, 'waf' for WAF firewall event logs."),
				key: z.string().describe("The full R2 object key to read."),
				max_lines: z
					.number()
					.min(1)
					.max(500)
					.default(100)
					.describe("Maximum number of lines to return."),
			},
			async ({ bucket, key, max_lines }) => {
				const r2Bucket = bucket === "http" ? this.env.HTTP_LOG_BUCKET : this.env.WAF_LOG_BUCKET;
				const obj = await r2Bucket.get(key);
				if (!obj) {
					return {
						content: [{ type: "text" as const, text: `File not found: "${key}".` }],
					};
				}

				const text = await readR2ObjectText(obj, key);
				const lines = text.split("\n").slice(0, max_lines);

				return {
					content: [
						{
							type: "text" as const,
							text: `File: ${key} (${(obj.size / 1024).toFixed(1)} KB)\nShowing ${lines.length} lines:\n---\n${lines.join("\n")}`,
						},
					],
				};
			},
		);
		// ---------------------------------------------------------------
		// Tool: decrypt_waf_payload
		// ---------------------------------------------------------------
		this.server.tool(
			"decrypt_waf_payload",
			"Decrypt an encrypted WAF matched payload. Cloudflare WAF payload logging encrypts the matched request data that triggered a rule. This tool decrypts the encrypted_matched_data field from the Metadata of a WAF log entry. The decrypted data shows the exact string that triggered the rule, along with surrounding context (before/after text). Requires MATCHED_PAYLOAD_PRIVATE_KEY to be configured.",
			{
				encrypted_data: z
					.string()
					.describe("The base64-encoded encrypted_matched_data value from the Metadata field of a WAF log entry."),
			},
			async ({ encrypted_data }) => {
				if (!this.env.MATCHED_PAYLOAD_PRIVATE_KEY) {
					return {
						content: [
							{
								type: "text" as const,
								text: "MATCHED_PAYLOAD_PRIVATE_KEY is not configured. Please set this secret to enable payload decryption.",
							},
						],
					};
				}

				const decrypted = await decryptMatchedData(
					encrypted_data,
					this.env.MATCHED_PAYLOAD_PRIVATE_KEY,
				);

				if (!decrypted) {
					return {
						content: [
							{
								type: "text" as const,
								text: "Failed to decrypt the payload. The data may be corrupted or the private key may be incorrect.",
							},
						],
					};
				}

				let formatted: string;
				try {
					const parsed = JSON.parse(decrypted);
					formatted = JSON.stringify(parsed, null, 2);
				} catch {
					formatted = decrypted;
				}

				return {
					content: [
						{
							type: "text" as const,
							text: "Decrypted WAF matched payload:\n" + formatted,
						},
					],
				};
			},
		);
	}
}

export default new OAuthProvider({
	apiHandler: R2LogAnalyzerMCP.serve("/mcp"),
	apiRoute: "/mcp",
	authorizeEndpoint: "/authorize",
	clientRegistrationEndpoint: "/register",
	defaultHandler: { fetch: handleAccessRequest as any },
	tokenEndpoint: "/token",
});
