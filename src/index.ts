import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpAgent } from "agents/mcp";
import { z } from "zod";
import { handleAccessRequest } from "./access-handler";
import { decryptLogEntries, decryptMatchedData } from "./matched-data";
import type { Props } from "./workers-oauth-utils";

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
		try {
			const parsed = JSON.parse(line);
			// If the entire content is a JSON array, flatten it
			if (Array.isArray(parsed)) {
				for (const item of parsed) {
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
 * Check if a single log entry matches all filters (case-insensitive string comparison).
 */
function matchesFilters(
	log: Record<string, any>,
	filters: Record<string, string | number | boolean>,
): boolean {
	for (const [key, value] of Object.entries(filters)) {
		const logValue = log[key];
		if (logValue === undefined) return false;
		if (typeof logValue === "string" && typeof value === "string") {
			if (logValue.toLowerCase() !== value.toLowerCase()) return false;
		} else if (logValue !== value) {
			return false;
		}
	}
	return true;
}

/**
 * Iterate ALL R2 objects under a prefix with cursor-based pagination.
 * Processes each file one at a time to avoid holding all logs in memory.
 * Return `false` from callback to stop early (e.g. when a specific entry is found).
 */
async function forEachLogInR2(
	bucket: R2Bucket,
	prefix: string,
	callback: (log: Record<string, any>) => boolean | void,
): Promise<{ totalEntries: number; filesProcessed: number }> {
	let cursor: string | undefined;
	let filesProcessed = 0;
	let totalEntries = 0;
	let stopped = false;

	do {
		const listed = await bucket.list({
			prefix,
			limit: 100,
			cursor,
		});

		for (const obj of listed.objects) {
			if (stopped) break;
			const r2Obj = await bucket.get(obj.key);
			if (!r2Obj) continue;

			const text = await readR2ObjectText(r2Obj, obj.key);
			const logs = parseLogLines(text);
			filesProcessed++;

			for (const log of logs) {
				totalEntries++;
				const result = callback(log);
				if (result === false) {
					stopped = true;
					break;
				}
			}
		}

		cursor = listed.truncated ? listed.cursor : undefined;
	} while (cursor && !stopped);

	return { totalEntries, filesProcessed };
}

/**
 * Streaming aggregator that counts field values without storing raw logs in memory.
 * Only keeps Map<field, Map<value, count>> — O(unique values) memory instead of O(total logs).
 */
class StreamingAggregator {
	private counters = new Map<string, Map<string, number>>();
	private _total = 0;

	get total() {
		return this._total;
	}

	add(log: Record<string, any>, fields: string[]) {
		this._total++;
		for (const field of fields) {
			const val = log[field];
			if (val !== undefined && val !== null) {
				const key = String(val);
				if (!this.counters.has(field)) {
					this.counters.set(field, new Map());
				}
				const fieldMap = this.counters.get(field)!;
				fieldMap.set(key, (fieldMap.get(key) || 0) + 1);
			}
		}
	}

	topN(field: string, n: number): { value: string; count: number }[] {
		const fieldMap = this.counters.get(field);
		if (!fieldMap) return [];
		return Array.from(fieldMap.entries())
			.map(([value, count]) => ({ value, count }))
			.sort((a, b) => b.count - a.count)
			.slice(0, n);
	}
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
			"Query and filter HTTP request logs stored in R2. Scans ALL log files under the prefix (no sampling). Returns matching log entries from Cloudflare Logpush http_requests dataset. Key fields include: ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestURI, ClientRequestUserAgent, EdgeResponseStatus, EdgeColoCode, OriginResponseStatus, RayID, SecurityAction, BotScore, CacheCacheStatus, EdgeStartTimestamp, etc.",
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
				const results: Record<string, any>[] = [];
				let totalMatched = 0;

				const { totalEntries, filesProcessed } = await forEachLogInR2(
					this.env.HTTP_LOG_BUCKET,
					prefix,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							totalMatched++;
							if (results.length < max_results) {
								const entry: Record<string, any> = {};
								for (const f of outputFields) {
									if (log[f] !== undefined) entry[f] = log[f];
								}
								results.push(entry);
							}
						}
					},
				);

				if (totalEntries === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found under prefix "${prefix}".` }],
					};
				}

				const summary = [
					`HTTP Logs Query Results (prefix: "${prefix}")`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
					`Matched: ${totalMatched}`,
					`Returned: ${results.length}`,
					filters ? `Filters: ${JSON.stringify(filters)}` : "No filters applied",
					"---",
				].join("\n");

				return {
					content: [
						{
							type: "text" as const,
							text: summary + "\n" + JSON.stringify(results, null, 2),
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
			"Query and filter WAF/firewall event logs stored in R2. Scans ALL log files under the prefix (no sampling). Returns matching log entries from Cloudflare Logpush firewall_events dataset. Key fields include: Action, ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestUserAgent, Datetime, Description, EdgeColoCode, EdgeResponseStatus, RayID, RuleID, Source, Kind, MatchIndex, Metadata, etc.",
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
				const results: Record<string, any>[] = [];
				let totalMatched = 0;
				const privateKey = this.env.MATCHED_PAYLOAD_PRIVATE_KEY;

				const { totalEntries, filesProcessed } = await forEachLogInR2(
					this.env.WAF_LOG_BUCKET,
					prefix,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							totalMatched++;
							if (results.length < max_results) {
								results.push(log);
							}
						}
					},
				);

				if (totalEntries === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found under prefix "${prefix}".` },
						],
					};
				}

				// Auto-decrypt matched payloads for collected results only
				const decryptedResults = await decryptLogEntries(results, privateKey);

				const entries = decryptedResults.map((log: Record<string, any>) => {
					const entry: Record<string, any> = {};
					for (const f of outputFields) {
						if (log[f] !== undefined) entry[f] = log[f];
					}
					return entry;
				});

				const summary = [
					`Firewall Events Query Results (prefix: "${prefix}")`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
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
			"Analyze HTTP request logs to generate traffic summaries. Scans ALL log files under the prefix (no sampling). Provides top-N rankings for IPs, countries, paths, status codes, user agents, cache status, and more.",
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
				const analysisFields = [
					"ClientIP", "ClientCountry", "ClientRequestHost",
					"ClientRequestPath", "ClientRequestMethod",
					"EdgeResponseStatus", "OriginResponseStatus",
					"CacheCacheStatus", "ClientRequestUserAgent",
					"EdgeColoCode", "SecurityAction", "ClientDeviceType",
				];
				const agg = new StreamingAggregator();

				const { totalEntries, filesProcessed } = await forEachLogInR2(
					this.env.HTTP_LOG_BUCKET,
					prefix,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							agg.add(log, analysisFields);
						}
					},
				);

				if (totalEntries === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found under prefix "${prefix}".` }],
					};
				}

				const analyses = [
					`HTTP Traffic Analysis (prefix: "${prefix}")`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
					`Total logs analyzed (after filters): ${agg.total}`,
					filters ? `Pre-filters: ${JSON.stringify(filters)}` : "",
					"===",
					"",
					formatTopN(agg.topN("ClientIP", top_n), "Client IPs"),
					"",
					formatTopN(agg.topN("ClientCountry", top_n), "Countries"),
					"",
					formatTopN(agg.topN("ClientRequestHost", top_n), "Request Hosts"),
					"",
					formatTopN(agg.topN("ClientRequestPath", top_n), "Request Paths"),
					"",
					formatTopN(agg.topN("ClientRequestMethod", top_n), "HTTP Methods"),
					"",
					formatTopN(agg.topN("EdgeResponseStatus", top_n), "Edge Response Status Codes"),
					"",
					formatTopN(agg.topN("OriginResponseStatus", top_n), "Origin Response Status Codes"),
					"",
					formatTopN(agg.topN("CacheCacheStatus", top_n), "Cache Status"),
					"",
					formatTopN(agg.topN("ClientRequestUserAgent", top_n), "User Agents"),
					"",
					formatTopN(agg.topN("EdgeColoCode", top_n), "Edge Colo Codes (Data Centers)"),
					"",
					formatTopN(agg.topN("SecurityAction", top_n), "Security Actions"),
					"",
					formatTopN(agg.topN("ClientDeviceType", top_n), "Device Types"),
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
			"Analyze WAF/firewall event logs to generate security summaries. Scans ALL log files under the prefix (no sampling). Provides top-N rankings for blocked IPs, actions, rules, sources, countries, and targeted paths.",
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
				const analysisFields = [
					"Action", "Source", "ClientIP", "ClientCountry",
					"ClientRequestHost", "ClientRequestPath",
					"ClientRequestMethod", "RuleID", "Description",
					"EdgeColoCode", "ClientRequestUserAgent",
				];
				const agg = new StreamingAggregator();

				const { totalEntries, filesProcessed } = await forEachLogInR2(
					this.env.WAF_LOG_BUCKET,
					prefix,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							agg.add(log, analysisFields);
						}
					},
				);

				if (totalEntries === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found under prefix "${prefix}".` },
						],
					};
				}

				const analyses = [
					`WAF/Firewall Events Analysis (prefix: "${prefix}")`,
					`Files processed: ${filesProcessed}`,
					`Total events scanned: ${totalEntries}`,
					`Total events analyzed (after filters): ${agg.total}`,
					filters ? `Pre-filters: ${JSON.stringify(filters)}` : "",
					"===",
					"",
					formatTopN(agg.topN("Action", top_n), "Actions"),
					"",
					formatTopN(agg.topN("Source", top_n), "Security Sources"),
					"",
					formatTopN(agg.topN("ClientIP", top_n), "Client IPs"),
					"",
					formatTopN(agg.topN("ClientCountry", top_n), "Countries"),
					"",
					formatTopN(agg.topN("ClientRequestHost", top_n), "Targeted Hosts"),
					"",
					formatTopN(agg.topN("ClientRequestPath", top_n), "Targeted Paths"),
					"",
					formatTopN(agg.topN("ClientRequestMethod", top_n), "HTTP Methods"),
					"",
					formatTopN(agg.topN("RuleID", top_n), "Rule IDs"),
					"",
					formatTopN(agg.topN("Description", top_n), "Rule Descriptions"),
					"",
					formatTopN(agg.topN("EdgeColoCode", top_n), "Edge Colo Codes"),
					"",
					formatTopN(agg.topN("ClientRequestUserAgent", top_n), "User Agents"),
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
			"Get the full details of a specific log entry by RayID. Searches through ALL log files in the specified bucket to find the matching entry (stops as soon as found).",
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
				let entry: Record<string, any> | undefined;

				const { totalEntries, filesProcessed } = await forEachLogInR2(
					r2Bucket,
					prefix,
					(log) => {
						if (log.RayID === ray_id) {
							entry = log;
							return false; // stop iteration
						}
					},
				);

				if (!entry) {
					return {
						content: [
							{
								type: "text" as const,
								text: `No log entry found with RayID "${ray_id}" under prefix "${prefix}". Searched ${totalEntries} entries across ${filesProcessed} files.`,
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
							text: `Log entry for RayID ${ray_id} (found after scanning ${filesProcessed} files):\n${JSON.stringify(entry, null, 2)}`,
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
