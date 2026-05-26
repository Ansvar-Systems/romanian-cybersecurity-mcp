#!/usr/bin/env node

/**
 * Romanian Cybersecurity MCP — stdio entry point.
 *
 * Provides MCP tools for querying DNSC (Directoratul Național de Securitate
 * Cibernetică) guidelines, technical standards, security advisories, and
 * cybersecurity frameworks.
 *
 * Tool prefix: ro_cyber_
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
} from "./db.js";
import { buildCitation, buildItemCitation } from "./utils/citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback to default
}

const SERVER_NAME = "romanian-cybersecurity-mcp";

// --- Tool definitions ---------------------------------------------------------

const TOOLS = [
  {
    name: "ro_cyber_search_guidance",
    description:
      "Full-text search across DNSC guidelines and technical standards. Covers national cybersecurity recommendations, NIS2 implementation guidance, ISMS standards, and critical infrastructure protection requirements for Romania. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'securitate cibernetică', 'NIS2', 'ISMS', 'criptografie')",
        },
        type: {
          type: "string",
          enum: ["guideline", "standard", "recommendation", "regulation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["DNSC", "NIS2", "ISMS"],
          description: "Filter by framework series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Defaults to returning all statuses.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "ro_cyber_get_guidance",
    description:
      "Get a specific DNSC guidance document by reference (e.g., 'DNSC-GHID-2024-01', 'DNSC-REC-2023-02').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "DNSC document reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "ro_cyber_search_advisories",
    description:
      "Search DNSC security advisories and alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: {
          type: "string",
          description: "Search query (e.g., 'vulnerabilitate critică', 'ransomware', 'VPN')",
        },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return. Defaults to 20.",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "ro_cyber_get_advisory",
    description:
      "Get a specific DNSC security advisory by reference (e.g., 'DNSC-ALERT-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: {
          type: "string",
          description: "DNSC advisory reference",
        },
      },
      required: ["reference"],
    },
  },
  {
    name: "ro_cyber_list_frameworks",
    description:
      "List all DNSC frameworks and standard series covered in this MCP, including National Cybersecurity Strategy, NIS2 implementation, and ISMS guidance for Romania.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ro_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
];

// --- Zod schemas for argument validation --------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["guideline", "standard", "recommendation", "regulation"]).optional(),
  series: z.enum(["DNSC", "NIS2", "ISMS"]).optional(),
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

// --- Helper ------------------------------------------------------------------

function textContent(data: unknown) {
  return {
    content: [
      { type: "text" as const, text: JSON.stringify(data, null, 2) },
    ],
  };
}

function errorContent(message: string) {
  return {
    content: [{ type: "text" as const, text: message }],
    isError: true as const,
  };
}

// --- Server setup ------------------------------------------------------------

const server = new Server(
  { name: SERVER_NAME, version: pkgVersion },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

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
        const annotated = results.map((r) => ({
          ...(r as unknown as Record<string, unknown>),
          _citation: buildItemCitation(r, "ro_cyber_search_guidance"),
        }));
        return textContent({ results: annotated, count: annotated.length });
      }

      case "ro_cyber_get_guidance": {
        const parsed = GetGuidanceArgs.parse(args);
        const doc = getGuidance(parsed.reference);
        if (!doc) {
          return errorContent(`Guidance document not found: ${parsed.reference}`);
        }
        const _citation = buildCitation(
          parsed.reference,
          (doc as unknown as Record<string, unknown>).title as string || parsed.reference,
          "ro_cyber_get_guidance",
          { reference: parsed.reference },
        );
        return textContent({ ...doc as unknown as Record<string, unknown>, _citation });
      }

      case "ro_cyber_search_advisories": {
        const parsed = SearchAdvisoriesArgs.parse(args);
        const results = searchAdvisories({
          query: parsed.query,
          severity: parsed.severity,
          limit: parsed.limit,
        });
        const annotated = results.map((r) => ({
          ...(r as unknown as Record<string, unknown>),
          _citation: buildItemCitation(r, "ro_cyber_search_advisories"),
        }));
        return textContent({ results: annotated, count: annotated.length });
      }

      case "ro_cyber_get_advisory": {
        const parsed = GetAdvisoryArgs.parse(args);
        const advisory = getAdvisory(parsed.reference);
        if (!advisory) {
          return errorContent(`Advisory not found: ${parsed.reference}`);
        }
        const _citation = buildCitation(
          parsed.reference,
          (advisory as unknown as Record<string, unknown>).title as string || parsed.reference,
          "ro_cyber_get_advisory",
          { reference: parsed.reference },
        );
        return textContent({ ...advisory as unknown as Record<string, unknown>, _citation });
      }

      case "ro_cyber_list_frameworks": {
        const frameworks = listFrameworks();
        return textContent({ frameworks, count: frameworks.length });
      }

      case "ro_cyber_about": {
        return textContent({
          name: SERVER_NAME,
          version: pkgVersion,
          description:
            "DNSC (Directoratul Național de Securitate Cibernetică — Romanian National Directorate of Cyber Security) MCP server. Provides access to DNSC guidelines, technical standards, NIS2 implementation guidance, and security advisories for Romania.",
          data_source: "DNSC (https://www.dnsc.ro/)",
          coverage: {
            guidance: "DNSC technical guidelines, recommendations, NIS2 implementation standards",
            advisories: "DNSC security advisories and vulnerability alerts",
            frameworks: "National Cybersecurity Strategy, NIS2 implementation, ISMS guidance",
          },
          tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
        });
      }

      default:
        return errorContent(`Unknown tool: ${name}`);
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorContent(`Error executing ${name}: ${message}`);
  }
});

// --- Main --------------------------------------------------------------------

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`${SERVER_NAME} v${pkgVersion} running on stdio\n`);
}

main().catch((err) => {
  process.stderr.write(`Fatal error: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
