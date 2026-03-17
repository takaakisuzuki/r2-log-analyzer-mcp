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
 * Convert a local date (YYYY-MM-DD) + timezone offset (hours) to a UTC time range
 * and the UTC date directory prefixes needed to cover that range.
 *
 * Example: date="2026-03-15", tzOffset=9 (JST)
 *   → UTC range: 2026-03-14T15:00:00Z ~ 2026-03-15T15:00:00Z
 *   → UTC date dirs: ["20260314/", "20260315/"]
 */
function localDateToUTCRange(
	date: string,
	tzOffset: number,
	basePrefix: string = "",
): { utcStart: string; utcEnd: string; prefixes: string[] } {
	const [year, month, day] = date.split("-").map(Number);
	// Local midnight → UTC
	const utcStart = new Date(Date.UTC(year, month - 1, day, -tzOffset, 0, 0));
	const utcEnd = new Date(utcStart.getTime() + 24 * 60 * 60 * 1000);

	// Collect all UTC dates that fall within the range
	const utcDates = new Set<string>();
	const cursor = new Date(utcStart);
	while (cursor < utcEnd) {
		const y = cursor.getUTCFullYear();
		const m = String(cursor.getUTCMonth() + 1).padStart(2, "0");
		const d = String(cursor.getUTCDate()).padStart(2, "0");
		utcDates.add(`${y}${m}${d}`);
		cursor.setUTCDate(cursor.getUTCDate() + 1);
	}

	const prefixes = Array.from(utcDates).map(
		(d) => (basePrefix ? `${basePrefix}${d}/` : `${d}/`),
	);

	return {
		utcStart: utcStart.toISOString(),
		utcEnd: utcEnd.toISOString(),
		prefixes,
	};
}

/**
 * Iterate ALL R2 objects under one or more prefixes with cursor-based pagination.
 * Processes each file one at a time to avoid holding all logs in memory.
 * Return `false` from callback to stop early (e.g. when a specific entry is found).
 * When timeRange is specified, only entries whose Datetime/EdgeStartTimestamp falls
 * within [start, end) are passed to the callback.
 */
async function forEachLogInR2(
	bucket: R2Bucket,
	prefixes: string | string[],
	callback: (log: Record<string, any>) => boolean | void,
	timeRange?: { start: string; end: string },
): Promise<{ totalEntries: number; filesProcessed: number; filteredEntries: number }> {
	const prefixList = Array.isArray(prefixes) ? prefixes : [prefixes];
	let filesProcessed = 0;
	let totalEntries = 0;
	let filteredEntries = 0;
	let stopped = false;

	for (const prefix of prefixList) {
		if (stopped) break;
		let cursor: string | undefined;

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
					// Apply time range filter if specified
					if (timeRange) {
						const dt = log.Datetime || log.EdgeStartTimestamp;
						if (dt && (dt < timeRange.start || dt >= timeRange.end)) continue;
					}
					filteredEntries++;
					const result = callback(log);
					if (result === false) {
						stopped = true;
						break;
					}
				}
			}

			cursor = listed.truncated ? listed.cursor : undefined;
		} while (cursor && !stopped);
	}

	return { totalEntries, filesProcessed, filteredEntries };
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
			"Query and filter HTTP request logs stored in R2. Scans ALL log files (no sampling). Supports timezone-aware date queries: specify 'date' + 'timezone_offset' to auto-generate correct UTC prefixes and filter by exact time range. Key fields: ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestURI, ClientRequestUserAgent, EdgeResponseStatus, EdgeColoCode, OriginResponseStatus, RayID, SecurityAction, BotScore, CacheCacheStatus, EdgeStartTimestamp, etc.",
			{
				prefix: z
					.string()
					.optional()
					.describe(
						"R2 key prefix for the HTTP log files, e.g. 'http_requests/20250315/'. Required unless 'date' is specified.",
					),
				date: z
					.string()
					.optional()
					.describe(
						"Local date to query (YYYY-MM-DD). Auto-generates UTC prefixes and filters by exact time range. Use with timezone_offset.",
					),
				timezone_offset: z
					.number()
					.optional()
					.default(0)
					.describe(
						"UTC offset in hours for the 'date' parameter (e.g. 9 for JST, -5 for EST). Defaults to 0 (UTC).",
					),
				base_prefix: z
					.string()
					.optional()
					.default("")
					.describe(
						"Base R2 prefix prepended to auto-generated date prefixes when using 'date' mode (e.g. 'http_requests/').",
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
			async ({ prefix, date, timezone_offset, base_prefix, filters, fields, max_results }) => {
				// Resolve prefixes and optional time range
				let scanPrefixes: string | string[];
				let timeRange: { start: string; end: string } | undefined;
				let dateInfo = "";

				if (date) {
					const resolved = localDateToUTCRange(date, timezone_offset ?? 0, base_prefix ?? "");
					scanPrefixes = resolved.prefixes;
					timeRange = { start: resolved.utcStart, end: resolved.utcEnd };
					dateInfo = `Local date: ${date} (UTC${timezone_offset && timezone_offset >= 0 ? "+" : ""}${timezone_offset ?? 0}) → UTC range: ${resolved.utcStart} ~ ${resolved.utcEnd}\nScanning prefixes: ${resolved.prefixes.join(", ")}`;
				} else if (prefix) {
					scanPrefixes = prefix;
				} else {
					return {
						content: [{ type: "text" as const, text: "Either 'prefix' or 'date' must be specified." }],
					};
				}

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

				const { totalEntries, filesProcessed, filteredEntries } = await forEachLogInR2(
					this.env.HTTP_LOG_BUCKET,
					scanPrefixes,
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
					timeRange,
				);

				if (totalEntries === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found.${dateInfo ? "\n" + dateInfo : ""}` }],
					};
				}

				const summary = [
					`HTTP Logs Query Results`,
					dateInfo || `Prefix: "${prefix}"`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
					timeRange ? `In time range: ${filteredEntries}` : "",
					`Matched (after filters): ${totalMatched}`,
					`Returned: ${results.length}`,
					filters ? `Filters: ${JSON.stringify(filters)}` : "No filters applied",
					"---",
				].filter(Boolean).join("\n");

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
			"Query and filter WAF/firewall event logs stored in R2. Scans ALL log files (no sampling). Supports timezone-aware date queries: specify 'date' + 'timezone_offset' to auto-generate correct UTC prefixes and filter by exact time range. Key fields: Action, ClientIP, ClientCountry, ClientRequestHost, ClientRequestMethod, ClientRequestPath, ClientRequestUserAgent, Datetime, Description, EdgeColoCode, EdgeResponseStatus, RayID, RuleID, Source, Kind, MatchIndex, Metadata, etc.",
			{
				prefix: z
					.string()
					.optional()
					.describe(
						"R2 key prefix for the firewall log files, e.g. 'firewall_events/20250315/'. Required unless 'date' is specified.",
					),
				date: z
					.string()
					.optional()
					.describe(
						"Local date to query (YYYY-MM-DD). Auto-generates UTC prefixes and filters by exact time range. Use with timezone_offset.",
					),
				timezone_offset: z
					.number()
					.optional()
					.default(0)
					.describe(
						"UTC offset in hours for the 'date' parameter (e.g. 9 for JST, -5 for EST). Defaults to 0 (UTC).",
					),
				base_prefix: z
					.string()
					.optional()
					.default("")
					.describe(
						"Base R2 prefix prepended to auto-generated date prefixes when using 'date' mode (e.g. 'firewall_events/').",
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
			async ({ prefix, date, timezone_offset, base_prefix, filters, fields, max_results }) => {
				let scanPrefixes: string | string[];
				let timeRange: { start: string; end: string } | undefined;
				let dateInfo = "";

				if (date) {
					const resolved = localDateToUTCRange(date, timezone_offset ?? 0, base_prefix ?? "");
					scanPrefixes = resolved.prefixes;
					timeRange = { start: resolved.utcStart, end: resolved.utcEnd };
					dateInfo = `Local date: ${date} (UTC${timezone_offset && timezone_offset >= 0 ? "+" : ""}${timezone_offset ?? 0}) → UTC range: ${resolved.utcStart} ~ ${resolved.utcEnd}\nScanning prefixes: ${resolved.prefixes.join(", ")}`;
				} else if (prefix) {
					scanPrefixes = prefix;
				} else {
					return {
						content: [{ type: "text" as const, text: "Either 'prefix' or 'date' must be specified." }],
					};
				}

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

				const { totalEntries, filesProcessed, filteredEntries } = await forEachLogInR2(
					this.env.WAF_LOG_BUCKET,
					scanPrefixes,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							totalMatched++;
							if (results.length < max_results) {
								results.push(log);
							}
						}
					},
					timeRange,
				);

				if (totalEntries === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found.${dateInfo ? "\n" + dateInfo : ""}` },
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
					`Firewall Events Query Results`,
					dateInfo || `Prefix: "${prefix}"`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
					timeRange ? `In time range: ${filteredEntries}` : "",
					`Matched (after filters): ${totalMatched}`,
					`Returned: ${entries.length}`,
					filters ? `Filters: ${JSON.stringify(filters)}` : "No filters applied",
					"---",
				].filter(Boolean).join("\n");

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
			"Analyze HTTP request logs to generate traffic summaries. Scans ALL log files (no sampling). Supports timezone-aware date queries: specify 'date' + 'timezone_offset' to auto-generate correct UTC prefixes and filter by exact time range. Provides top-N rankings for IPs, countries, paths, status codes, user agents, cache status, and more.",
			{
				prefix: z
					.string()
					.optional()
					.describe("R2 key prefix for the HTTP log files, e.g. 'http_requests/20250315/'. Required unless 'date' is specified."),
				date: z
					.string()
					.optional()
					.describe("Local date to analyze (YYYY-MM-DD). Auto-generates UTC prefixes and filters by exact time range."),
				timezone_offset: z
					.number()
					.optional()
					.default(0)
					.describe("UTC offset in hours (e.g. 9 for JST, -5 for EST). Defaults to 0 (UTC)."),
				base_prefix: z
					.string()
					.optional()
					.default("")
					.describe("Base R2 prefix prepended to auto-generated date prefixes when using 'date' mode."),
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
			async ({ prefix, date, timezone_offset, base_prefix, top_n, filters }) => {
				let scanPrefixes: string | string[];
				let timeRange: { start: string; end: string } | undefined;
				let dateInfo = "";

				if (date) {
					const resolved = localDateToUTCRange(date, timezone_offset ?? 0, base_prefix ?? "");
					scanPrefixes = resolved.prefixes;
					timeRange = { start: resolved.utcStart, end: resolved.utcEnd };
					dateInfo = `Local date: ${date} (UTC${timezone_offset && timezone_offset >= 0 ? "+" : ""}${timezone_offset ?? 0}) → UTC range: ${resolved.utcStart} ~ ${resolved.utcEnd}\nScanning prefixes: ${resolved.prefixes.join(", ")}`;
				} else if (prefix) {
					scanPrefixes = prefix;
				} else {
					return {
						content: [{ type: "text" as const, text: "Either 'prefix' or 'date' must be specified." }],
					};
				}

				const analysisFields = [
					"ClientIP", "ClientCountry", "ClientRequestHost",
					"ClientRequestPath", "ClientRequestMethod",
					"EdgeResponseStatus", "OriginResponseStatus",
					"CacheCacheStatus", "ClientRequestUserAgent",
					"EdgeColoCode", "SecurityAction", "ClientDeviceType",
				];
				const agg = new StreamingAggregator();

				const { totalEntries, filesProcessed, filteredEntries } = await forEachLogInR2(
					this.env.HTTP_LOG_BUCKET,
					scanPrefixes,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							agg.add(log, analysisFields);
						}
					},
					timeRange,
				);

				if (totalEntries === 0) {
					return {
						content: [{ type: "text" as const, text: `No HTTP logs found.${dateInfo ? "\n" + dateInfo : ""}` }],
					};
				}

				const analyses = [
					`HTTP Traffic Analysis`,
					dateInfo || `Prefix: "${prefix}"`,
					`Files processed: ${filesProcessed}`,
					`Total logs scanned: ${totalEntries}`,
					timeRange ? `In time range: ${filteredEntries}` : "",
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
			"Analyze WAF/firewall event logs to generate security summaries. Scans ALL log files (no sampling). Supports timezone-aware date queries: specify 'date' + 'timezone_offset' to auto-generate correct UTC prefixes and filter by exact time range. Provides top-N rankings for blocked IPs, actions, rules, sources, countries, and targeted paths.",
			{
				prefix: z
					.string()
					.optional()
					.describe("R2 key prefix for the firewall log files, e.g. 'firewall_events/20250315/'. Required unless 'date' is specified."),
				date: z
					.string()
					.optional()
					.describe("Local date to analyze (YYYY-MM-DD). Auto-generates UTC prefixes and filters by exact time range."),
				timezone_offset: z
					.number()
					.optional()
					.default(0)
					.describe("UTC offset in hours (e.g. 9 for JST, -5 for EST). Defaults to 0 (UTC)."),
				base_prefix: z
					.string()
					.optional()
					.default("")
					.describe("Base R2 prefix prepended to auto-generated date prefixes when using 'date' mode."),
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
			async ({ prefix, date, timezone_offset, base_prefix, top_n, filters }) => {
				let scanPrefixes: string | string[];
				let timeRange: { start: string; end: string } | undefined;
				let dateInfo = "";

				if (date) {
					const resolved = localDateToUTCRange(date, timezone_offset ?? 0, base_prefix ?? "");
					scanPrefixes = resolved.prefixes;
					timeRange = { start: resolved.utcStart, end: resolved.utcEnd };
					dateInfo = `Local date: ${date} (UTC${timezone_offset && timezone_offset >= 0 ? "+" : ""}${timezone_offset ?? 0}) → UTC range: ${resolved.utcStart} ~ ${resolved.utcEnd}\nScanning prefixes: ${resolved.prefixes.join(", ")}`;
				} else if (prefix) {
					scanPrefixes = prefix;
				} else {
					return {
						content: [{ type: "text" as const, text: "Either 'prefix' or 'date' must be specified." }],
					};
				}

				const analysisFields = [
					"Action", "Source", "ClientIP", "ClientCountry",
					"ClientRequestHost", "ClientRequestPath",
					"ClientRequestMethod", "RuleID", "Description",
					"EdgeColoCode", "ClientRequestUserAgent",
				];
				const agg = new StreamingAggregator();

				const { totalEntries, filesProcessed, filteredEntries } = await forEachLogInR2(
					this.env.WAF_LOG_BUCKET,
					scanPrefixes,
					(log) => {
						if (!filters || matchesFilters(log, filters)) {
							agg.add(log, analysisFields);
						}
					},
					timeRange,
				);

				if (totalEntries === 0) {
					return {
						content: [
							{ type: "text" as const, text: `No firewall logs found.${dateInfo ? "\n" + dateInfo : ""}` },
						],
					};
				}

				const analyses = [
					`WAF/Firewall Events Analysis`,
					dateInfo || `Prefix: "${prefix}"`,
					`Files processed: ${filesProcessed}`,
					`Total events scanned: ${totalEntries}`,
					timeRange ? `In time range: ${filteredEntries}` : "",
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
