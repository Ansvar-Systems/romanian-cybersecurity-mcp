/**
 * Handler-level integration tests for ro_cyber_search_* citation invariant.
 *
 * These tests call the exported handler functions directly — bypassing the MCP
 * wire protocol — so they exercise the full dispatch path including the
 * .map(_citation) annotation step.  A pure unit test of buildItemCitation
 * (like citation.test.ts) would NOT catch a regression where the switch case
 * in index.ts forgets to call .map() at all, because the handler functions
 * would be skipped.
 *
 * The DB layer is mocked so tests run cleanly on a fresh checkout (data/dnsc.db
 * is gitignored; fileMustExist: true would crash otherwise). Fixture data uses
 * realistic reference patterns so the dnscReferenceToSourceUrl branches are
 * exercised in the same way as the real corpus.
 */

import { describe, it, expect, vi } from "vitest";
import type { Guidance, Advisory } from "../src/db.js";

vi.mock("../src/db.js", async () => {
  const actual = await vi.importActual<typeof import("../src/db.js")>("../src/db.js");

  const guidanceFixtures: Guidance[] = [
    {
      id: 1,
      reference: "DNSC-G-01/2023",
      title: "Ghid pentru securitatea serviciilor cloud",
      title_en: "Cloud Services Security Guide",
      date: "2023-04-10",
      type: "guideline",
      series: "DNSC",
      summary: "Cerinte minime de securitate pentru serviciile cloud.",
      full_text: "...",
      topics: "cloud,securitate",
      status: "current",
    },
    {
      id: 2,
      reference: "DNSC-ALERT-VULNERABILITATE-CRITICA-IN-NGINX-UI",
      title: "ALERTA: Vulnerabilitate critica in Nginx UI",
      title_en: null,
      date: "2024-03-09",
      type: "guideline",
      series: "DNSC",
      summary: null,
      full_text: "...",
      topics: null,
      status: "current",
    },
  ];

  const advisoryFixtures: Advisory[] = [
    {
      id: 1,
      reference: "DNSC-ALERT-2024-001",
      title: "Vulnerabilitate critica Microsoft Exchange Server",
      date: "2024-02-15",
      severity: "critical",
      affected_products: "Microsoft Exchange Server 2016, 2019",
      summary: "Exploatare activa CVE-2024-21410.",
      full_text: "...",
      cve_references: "CVE-2024-21410",
    },
    {
      id: 2,
      reference: "DNSC-ALERT-2024-002",
      title: "Campanie phishing",
      date: "2024-06-10",
      severity: "high",
      affected_products: null,
      summary: null,
      full_text: "...",
      cve_references: null,
    },
  ];

  return {
    ...actual,
    getDb: () => { throw new Error("getDb must not be called in tests — DB layer is mocked"); },
    searchGuidance: (opts: { query: string; limit?: number }): Guidance[] => {
      // Simulate no-hits for the sentinel query used in "returns empty" tests.
      if (opts.query.includes("zzzzz_no_hits")) return [];
      return guidanceFixtures.slice(0, opts.limit ?? guidanceFixtures.length);
    },
    searchAdvisories: (opts: { query: string; limit?: number }): Advisory[] => {
      if (opts.query.includes("zzzzz_no_hits")) return [];
      return advisoryFixtures.slice(0, opts.limit ?? advisoryFixtures.length);
    },
  };
});
import {
  handleSearchGuidance,
  handleSearchAdvisories,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// ro_cyber_search_guidance handler
// ---------------------------------------------------------------------------

describe("handleSearchGuidance", () => {
  it("attaches _citation to every result row", () => {
    const out = handleSearchGuidance({ query: "securitate", limit: 5 });
    expect(out.results.length).toBeGreaterThan(0);
    for (const item of out.results) {
      expect(item["_citation"]).toBeDefined();
      expect((item["_citation"] as Record<string, unknown>)["publisher"]).toBe(
        "Directoratul Național de Securitate Cibernetică (DNSC)",
      );
      expect((item["_citation"] as Record<string, unknown>)["license"]).toBe(
        "Romanian-Legea-8-1996-Art-9",
      );
      expect(
        (item["_citation"] as Record<string, unknown>)["source"],
      ).toBeTruthy();
      expect(
        String((item["_citation"] as Record<string, unknown>)["source_url"]),
      ).toMatch(/^https?:\/\/.+/);
      expect((item["_citation"] as Record<string, unknown>)["mcp_tool"]).toBe(
        "ro_cyber_search_guidance",
      );
    }
  });

  it("count matches results array length", () => {
    const out = handleSearchGuidance({ query: "securitate", limit: 5 });
    expect(out.count).toBe(out.results.length);
  });

  it("returns empty results array (not error) when query has no hits", () => {
    const out = handleSearchGuidance({
      query: "zzzzz_no_hits_zzzzz_xqk7",
      limit: 3,
    });
    expect(Array.isArray(out.results)).toBe(true);
    expect(out.results).toEqual([]);
    expect(out.count).toBe(0);
  });

  it("respects the limit parameter", () => {
    const out = handleSearchGuidance({ query: "securitate", limit: 1 });
    expect(out.results.length).toBeLessThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// ro_cyber_search_advisories handler
// ---------------------------------------------------------------------------

describe("handleSearchAdvisories", () => {
  it("attaches _citation to every result row with correct mcp_tool", () => {
    const out = handleSearchAdvisories({ query: "vulnerabilitate", limit: 5 });
    expect(out.results.length).toBeGreaterThan(0);
    for (const item of out.results) {
      expect(item["_citation"]).toBeDefined();
      expect((item["_citation"] as Record<string, unknown>)["mcp_tool"]).toBe(
        "ro_cyber_search_advisories",
      );
      expect(
        (item["_citation"] as Record<string, unknown>)["publisher"],
      ).toBe("Directoratul Național de Securitate Cibernetică (DNSC)");
      expect(
        String((item["_citation"] as Record<string, unknown>)["source_url"]),
      ).toMatch(/^https?:\/\/.+/);
    }
  });

  it("count matches results array length", () => {
    const out = handleSearchAdvisories({ query: "vulnerabilitate", limit: 5 });
    expect(out.count).toBe(out.results.length);
  });

  it("returns empty results array (not error) when query has no hits", () => {
    const out = handleSearchAdvisories({
      query: "zzzzz_no_hits_zzzzz_xqk7",
      limit: 3,
    });
    expect(Array.isArray(out.results)).toBe(true);
    expect(out.results).toEqual([]);
    expect(out.count).toBe(0);
  });
});
