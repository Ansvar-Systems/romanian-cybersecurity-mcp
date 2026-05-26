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
 * Tests run against the real data/dnsc.db included in the repo.
 */

import { describe, it, expect } from "vitest";
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
