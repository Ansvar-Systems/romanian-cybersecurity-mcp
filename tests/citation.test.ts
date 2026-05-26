/**
 * Tests for citation fields on ro_cyber_search_* results.
 *
 * Verifies that the Source Attribution Standard is satisfied:
 * every search result row carries a _citation block with non-empty
 * source_url, publisher, and license.
 *
 * PR: fix/2026-05-26-populate-citation-on-search-results
 */

import { describe, it, expect } from "vitest";
import {
  buildItemCitation,
  dnscReferenceToSourceUrl,
} from "../src/utils/citation.js";

// ---------------------------------------------------------------------------
// dnscReferenceToSourceUrl — URL pattern reconstruction
// ---------------------------------------------------------------------------

describe("dnscReferenceToSourceUrl", () => {
  it("maps DNSC-DOC-* to /vezi/document/ path", () => {
    const url = dnscReferenceToSourceUrl("DNSC-DOC-GHID-SECURITATE-CIBERNETICA-2021");
    expect(url).toBe(
      "https://www.dnsc.ro/vezi/document/ghid-securitate-cibernetica-2021",
    );
  });

  it("maps DNSC-ALERT-* to /citeste/alerta- path", () => {
    const url = dnscReferenceToSourceUrl(
      "DNSC-ALERT-VULNERABILITATE-CRITICA-IN-NGINX-UI",
    );
    expect(url).toBe(
      "https://www.dnsc.ro/citeste/alerta-vulnerabilitate-critica-in-nginx-ui",
    );
  });

  it("maps DNSC-ALERT-CVE-* to /citeste/alerta-cve- path", () => {
    const url = dnscReferenceToSourceUrl("DNSC-ALERT-CVE-2024-12345");
    expect(url).toBe("https://www.dnsc.ro/citeste/alerta-cve-2024-12345");
  });

  it("maps DNSC-WEEKLY-YYYY-MM-DD to weekly cybersecurity news path", () => {
    const url = dnscReferenceToSourceUrl("DNSC-WEEKLY-2026-03-19");
    expect(url).toBe(
      "https://www.dnsc.ro/citeste/stirile-saptamanii-din-cybersecurity-19-03-2026",
    );
  });

  it("maps DNSC-COMM-* to /citeste/comunicat- path", () => {
    const url = dnscReferenceToSourceUrl("DNSC-COMM-8-MARTIE-SIGURANTA-ONLINE");
    expect(url).toBe(
      "https://www.dnsc.ro/citeste/comunicat-8-martie-siguranta-online",
    );
  });

  it("maps DNSC-ART-* to /citeste/ path", () => {
    const url = dnscReferenceToSourceUrl(
      "DNSC-ART-ANUNT-DNSC-NU-MAI-ELIBEREAZA-CERTIFICATE",
    );
    expect(url).toBe(
      "https://www.dnsc.ro/citeste/anunt-dnsc-nu-mai-elibereaza-certificate",
    );
  });

  it("falls back to DNSC homepage for unknown reference patterns", () => {
    const url = dnscReferenceToSourceUrl("UNKNOWN-REFERENCE");
    expect(url).toBe("https://www.dnsc.ro/");
  });
});

// ---------------------------------------------------------------------------
// buildItemCitation — citation field shape for search results
// ---------------------------------------------------------------------------

describe("buildItemCitation", () => {
  const sampleGuidance = {
    reference: "DNSC-DOC-GHID-SECURITATE-CIBERNETICA-2021",
    title: "Ghid securitate cibernetică 2021",
    date: "2021-04-15",
  };

  const sampleAdvisory = {
    reference: "DNSC-ALERT-VULNERABILITATE-CRITICA-IN-NGINX-UI",
    title: "ALERTĂ: Vulnerabilitate critică în Nginx UI",
    date: "2026-03-09",
  };

  it("returns non-empty source_url for a guidance item", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.source_url).toBeTruthy();
    expect(citation.source_url.length).toBeGreaterThan(0);
  });

  it("returns non-empty source_url for an advisory item", () => {
    const citation = buildItemCitation(sampleAdvisory, "ro_cyber_search_advisories");
    expect(citation.source_url).toBeTruthy();
    expect(citation.source_url.length).toBeGreaterThan(0);
  });

  it("sets publisher to DNSC full name in Romanian", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.publisher).toBe(
      "Directoratul Național de Securitate Cibernetică (DNSC)",
    );
  });

  it("sets license to Romanian-Legea-8-1996-Art-9 (sole Romanian entry in catalog)", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.license).toBe("Romanian-Legea-8-1996-Art-9");
  });

  it("sets source to the reference string", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.source).toBe(sampleGuidance.reference);
  });

  it("sets source_full_name to the title when present", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.source_full_name).toBe(sampleGuidance.title);
  });

  it("falls back to reference as source_full_name when title is absent", () => {
    const citation = buildItemCitation(
      { reference: "DNSC-ART-SOMETHING" },
      "ro_cyber_search_guidance",
    );
    expect(citation.source_full_name).toBe("DNSC-ART-SOMETHING");
  });

  it("sets effective_date from item.date", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.effective_date).toBe("2021-04-15");
  });

  it("sets effective_date to empty string when date is null", () => {
    const citation = buildItemCitation(
      { reference: "DNSC-ART-NODATEARTICLE", date: null },
      "ro_cyber_search_guidance",
    );
    expect(citation.effective_date).toBe("");
  });

  it("sets mcp_tool to the tool name passed in", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.mcp_tool).toBe("ro_cyber_search_guidance");

    const citation2 = buildItemCitation(sampleAdvisory, "ro_cyber_search_advisories");
    expect(citation2.mcp_tool).toBe("ro_cyber_search_advisories");
  });

  it("source_url starts with https://www.dnsc.ro/", () => {
    const citation = buildItemCitation(sampleGuidance, "ro_cyber_search_guidance");
    expect(citation.source_url.startsWith("https://www.dnsc.ro/")).toBe(true);
  });

  // Key assertion from the remediation plan: all required gateway-overlay fields are present
  it("carries all fields the gateway citation overlay requires", () => {
    const citation = buildItemCitation(sampleAdvisory, "ro_cyber_search_advisories");
    const requiredFields = [
      "source",
      "source_full_name",
      "source_url",
      "publisher",
      "license",
      "effective_date",
      "mcp_tool",
    ] as const;
    for (const field of requiredFields) {
      expect(citation[field]).toBeDefined();
    }
  });
});
