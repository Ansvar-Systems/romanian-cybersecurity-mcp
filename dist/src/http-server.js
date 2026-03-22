#!/usr/bin/env node
/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { CallToolRequestSchema, ListToolsRequestSchema, } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { searchGuidance, getGuidance, searchAdvisories, getAdvisory, listFrameworks, } from "./db.js";
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "romanian-cybersecurity-mcp";
let pkgVersion = "0.1.0";
try {
    const pkg = JSON.parse(readFileSync(join(__dirname, "..", "package.json"), "utf8"));
    pkgVersion = pkg.version;
}
catch {
    // fallback
}
// --- Tool definitions (shared with index.ts) ---------------------------------
const TOOLS = [
    {
        name: "ro_cyber_search_guidance",
        description: "Full-text search across BSI guidelines and technical reports. Covers Technical Guidelines (TR series), IT-Grundschutz building blocks, BSI Standards, and recommendations.",
        inputSchema: {
            type: "object",
            properties: {
                query: { type: "string", description: "Search query (e.g., 'TLS Kryptographie', 'IT-Grundschutz Server')" },
                type: {
                    type: "string",
                    enum: ["guideline", "standard", "recommendation", "regulation"],
                    description: "Filter by document type. Optional.",
                },
                series: {
                    type: "string",
                    enum: ["DNSC", "NIS2", "ISMS"],
                    description: "Filter by BSI series. Optional.",
                },
                status: {
                    type: "string",
                    enum: ["current", "superseded", "draft"],
                    description: "Filter by document status. Optional.",
                },
                limit: { type: "number", description: "Max results (default 20)." },
            },
            required: ["query"],
        },
    },
    {
        name: "ro_cyber_get_guidance",
        description: "Get a specific BSI guidance document by reference (e.g., 'BSI TR-03116', 'BSI-Standard 200-1', 'SYS.1.1').",
        inputSchema: {
            type: "object",
            properties: {
                reference: { type: "string", description: "BSI document reference" },
            },
            required: ["reference"],
        },
    },
    {
        name: "ro_cyber_search_advisories",
        description: "Search BSI security advisories and alerts. Returns advisories with severity, affected products, and CVE references.",
        inputSchema: {
            type: "object",
            properties: {
                query: { type: "string", description: "Search query (e.g., 'kritische Schwachstelle', 'Ransomware')" },
                severity: {
                    type: "string",
                    enum: ["critical", "high", "medium", "low"],
                    description: "Filter by severity level. Optional.",
                },
                limit: { type: "number", description: "Max results (default 20)." },
            },
            required: ["query"],
        },
    },
    {
        name: "ro_cyber_get_advisory",
        description: "Get a specific BSI security advisory by reference (e.g., 'BSI-CB-K24-0001').",
        inputSchema: {
            type: "object",
            properties: {
                reference: { type: "string", description: "BSI advisory reference" },
            },
            required: ["reference"],
        },
    },
    {
        name: "ro_cyber_list_frameworks",
        description: "List all BSI frameworks and standard series covered in this MCP.",
        inputSchema: { type: "object", properties: {}, required: [] },
    },
    {
        name: "ro_cyber_about",
        description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
        inputSchema: { type: "object", properties: {}, required: [] },
    },
];
// --- Zod schemas -------------------------------------------------------------
const SearchGuidanceArgs = z.object({
    query: z.string().min(1),
    type: z.enum(["technical_guideline", "it_grundschutz", "standard", "recommendation"]).optional(),
    series: z.enum(["TR", "IT-Grundschutz", "BSI-Standard"]).optional(),
    status: z.enum(["current", "superseded", "draft"]).optional(),
    limit: z.number().int().positive().max(100).optional(),
});
const GetGuidanceArgs = z.object({
    reference: z.string().min(1),
});
const SearchAdvisoriesArgs = z.object({
    query: z.string().min(1),
    severity: z.enum(["critical", "high", "medium", "low"]).optional(),
    limit: z.number().int().positive().max(100).optional(),
});
const GetAdvisoryArgs = z.object({
    reference: z.string().min(1),
});
// --- MCP server factory ------------------------------------------------------
function createMcpServer() {
    const server = new Server({ name: SERVER_NAME, version: pkgVersion }, { capabilities: { tools: {} } });
    server.setRequestHandler(ListToolsRequestSchema, async () => ({
        tools: TOOLS,
    }));
    server.setRequestHandler(CallToolRequestSchema, async (request) => {
        const { name, arguments: args = {} } = request.params;
        function textContent(data) {
            return {
                content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
            };
        }
        function errorContent(message) {
            return {
                content: [{ type: "text", text: message }],
                isError: true,
            };
        }
        try {
            switch (name) {
                case "ro_cyber_search_guidance": {
                    const parsed = SearchGuidanceArgs.parse(args);
                    const results = searchGuidance({
                        query: parsed.query,
                        type: parsed.type,
                        series: parsed.series,
                        status: parsed.status,
                        limit: parsed.limit,
                    });
                    return textContent({ results, count: results.length });
                }
                case "ro_cyber_get_guidance": {
                    const parsed = GetGuidanceArgs.parse(args);
                    const doc = getGuidance(parsed.reference);
                    if (!doc) {
                        return errorContent(`Guidance document not found: ${parsed.reference}`);
                    }
                    return textContent(doc);
                }
                case "ro_cyber_search_advisories": {
                    const parsed = SearchAdvisoriesArgs.parse(args);
                    const results = searchAdvisories({
                        query: parsed.query,
                        severity: parsed.severity,
                        limit: parsed.limit,
                    });
                    return textContent({ results, count: results.length });
                }
                case "ro_cyber_get_advisory": {
                    const parsed = GetAdvisoryArgs.parse(args);
                    const advisory = getAdvisory(parsed.reference);
                    if (!advisory) {
                        return errorContent(`Advisory not found: ${parsed.reference}`);
                    }
                    return textContent(advisory);
                }
                case "ro_cyber_list_frameworks": {
                    const frameworks = listFrameworks();
                    return textContent({ frameworks, count: frameworks.length });
                }
                case "ro_cyber_about": {
                    return textContent({
                        name: SERVER_NAME,
                        version: pkgVersion,
                        description: "BSI (DNSC (Directoratul Național de Securitate Cibernetică)) MCP server. Provides access to BSI technical guidelines, IT-Grundschutz building blocks, BSI Standards, and security advisories.",
                        data_source: "BSI (https://www.bsi.bund.de/)",
                        tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
                    });
                }
                default:
                    return errorContent(`Unknown tool: ${name}`);
            }
        }
        catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            return errorContent(`Error executing ${name}: ${message}`);
        }
    });
    return server;
}
// --- HTTP server -------------------------------------------------------------
async function main() {
    const sessions = new Map();
    const httpServer = createServer((req, res) => {
        handleRequest(req, res, sessions).catch((err) => {
            console.error(`[${SERVER_NAME}] Unhandled error:`, err);
            if (!res.headersSent) {
                res.writeHead(500, { "Content-Type": "application/json" });
                res.end(JSON.stringify({ error: "Internal server error" }));
            }
        });
    });
    async function handleRequest(req, res, activeSessions) {
        const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
        if (url.pathname === "/health") {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
            return;
        }
        if (url.pathname === "/mcp") {
            const sessionId = req.headers["mcp-session-id"];
            if (sessionId && activeSessions.has(sessionId)) {
                const session = activeSessions.get(sessionId);
                await session.transport.handleRequest(req, res);
                return;
            }
            const mcpServer = createMcpServer();
            const transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
            });
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
            await mcpServer.connect(transport);
            transport.onclose = () => {
                if (transport.sessionId) {
                    activeSessions.delete(transport.sessionId);
                }
                mcpServer.close().catch(() => { });
            };
            await transport.handleRequest(req, res);
            if (transport.sessionId) {
                activeSessions.set(transport.sessionId, { transport, server: mcpServer });
            }
            return;
        }
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Not found" }));
    }
    httpServer.listen(PORT, () => {
        console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
        console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
        console.error(`Health check:  http://localhost:${PORT}/health`);
    });
    process.on("SIGTERM", () => {
        console.error("Received SIGTERM, shutting down...");
        httpServer.close(() => process.exit(0));
    });
}
main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
