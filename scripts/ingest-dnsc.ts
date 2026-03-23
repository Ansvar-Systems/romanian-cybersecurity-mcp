#!/usr/bin/env npx tsx
/**
 * Ingestion crawler for DNSC (Directoratul National de Securitate Cibernetica)
 * and CERT-RO content.
 *
 * Crawls four content streams from dnsc.ro:
 *   1. RSS feed           — latest alerts, news, and guidance (https://dnsc.ro/feed)
 *   2. Alert tag pages     — paginated alert listings (/tag/alerta?page=N)
 *   3. Guidance documents  — published guides and recommendations (/vezi/document/*)
 *   4. Guidance articles   — published articles with recommendations (/citeste/*)
 *
 * Populates the advisories, guidance, and frameworks tables defined in src/db.ts.
 *
 * Prerequisites:
 *   npm install cheerio        # if not already in devDependencies
 *   npm install @types/cheerio  # for TS types
 *
 * Usage:
 *   npx tsx scripts/ingest-dnsc.ts
 *   npx tsx scripts/ingest-dnsc.ts --dry-run       # fetch & parse, don't write DB
 *   npx tsx scripts/ingest-dnsc.ts --resume         # skip already-ingested references
 *   npx tsx scripts/ingest-dnsc.ts --force          # drop existing data and re-ingest
 *   npx tsx scripts/ingest-dnsc.ts --feed=rss       # only RSS feed
 *   npx tsx scripts/ingest-dnsc.ts --feed=alerts    # only alert tag pages
 *   npx tsx scripts/ingest-dnsc.ts --feed=guides    # only guidance document pages
 *   npx tsx scripts/ingest-dnsc.ts --feed=articles  # only guidance article pages
 *   npx tsx scripts/ingest-dnsc.ts --max-pages 10   # limit paginated listing pages
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import type { Element } from "domhandler";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const DB_PATH = process.env["DNSC_DB_PATH"] ?? "data/dnsc.db";
const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_BASE_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_PAGES = 50;

const BASE_URL = "https://dnsc.ro";
const WWW_BASE_URL = "https://www.dnsc.ro";
const RSS_FEED_URL = `${BASE_URL}/feed`;

const USER_AGENT =
  "AnsvarDNSCCrawler/1.0 (+https://github.com/Ansvar-Systems/romanian-cybersecurity-mcp)";

/**
 * Tag listing pages for alerts. DNSC uses /tag/{tag}?page=N pagination.
 * The "alerta" tag captures vulnerability alerts and security warnings.
 */
const ALERT_TAG_PAGES = [
  `${WWW_BASE_URL}/tag/alerta`,
] as const;

/**
 * Known guidance document URLs on DNSC.
 * These are direct links to published guides, standards, and recommendations
 * under the /vezi/document/ path.
 */
const GUIDANCE_DOCUMENT_URLS = [
  `${BASE_URL}/vezi/document/ghid-securitate-cibernetica-2021`,
  `${WWW_BASE_URL}/vezi/document/principii-strategice-de-securitate-cibernetica-pentru-managementul-organizatiei`,
  `${WWW_BASE_URL}/vezi/document/ghid-protectie-functionari-publici`,
  `${BASE_URL}/vezi/document/q-east-indrumarul-de-planificare-a-securitatii-cibernetice`,
  `${WWW_BASE_URL}/vezi/document/ghid-securizare-aplicatii-web`,
  `${WWW_BASE_URL}/vezi/document/amenintari-generice-securitate-cibernetica`,
  `${WWW_BASE_URL}/vezi/document/ghid-elaborare-daicms`,
  `${WWW_BASE_URL}/vezi/document/dnsc-ghid-prevenire-si-gestionare-amenintari-interne`,
  `${BASE_URL}/vezi/document/ghid-pentru-asigurarea-securitatii-cibernetice-pentru-imm-uri`,
  `${BASE_URL}/vezi/document/cert-ro-ghid-identificare-ose`,
  `${BASE_URL}/vezi/document/ghid-practic-identificare-fsd`,
  `${BASE_URL}/vezi/document/scam-phishing-vishing`,
  `${WWW_BASE_URL}/vezi/document/dnsc-decalex-ghid-practic-privind-gestionarea-datelor-cu-caracter-personal-de-catre-companii`,
] as const;

/**
 * Known guidance article URLs on DNSC — articles with recommendations,
 * NIS2 guidance, awareness content. Under the /citeste/ path.
 */
const GUIDANCE_ARTICLE_URLS = [
  `${WWW_BASE_URL}/citeste/directiva-nis-2-0-UE`,
  `${BASE_URL}/citeste/recomandari-gestionarea-atacurilor-ddos`,
  `${BASE_URL}/citeste/12-pasi-securizarea-afacerii-cyber-IMM-ENISA`,
  `${WWW_BASE_URL}/citeste/comunicat-ghid-gdpr-data-protection-dnsc-decalex-companii`,
  `${BASE_URL}/citeste/alerta-atacuri-de-tip-spoofing-phishing-vishing-asupra-utilizatorilor-din-romania`,
  `${BASE_URL}/citeste/comunicat-campanie-prevenire-fraude-online`,
] as const;

/**
 * Tag listing pages for guidance/recommendations content.
 */
const GUIDANCE_TAG_PAGES = [
  `${WWW_BASE_URL}/tag/comunicat`,
  `${WWW_BASE_URL}/tag/CERT-RO`,
] as const;

// ---------------------------------------------------------------------------
// URL classification patterns
// ---------------------------------------------------------------------------

/** URL or title patterns identifying vulnerability alerts / security warnings. */
const ALERT_PATTERNS = [
  /\balerta\b/i,
  /\balert[aă]\b/i,
  /\bvulnerabilitate\b/i,
  /\bvulnerabilit[aă][tț]i\b/i,
  /\bexploatat[aă]\b/i,
  /\bzero-day\b/i,
  /\b0-day\b/i,
  /\b0-click\b/i,
  /\bcve-\d{4}/i,
  /\bcvss\b/i,
  /\bransomware\b/i,
  /\bmalware\b/i,
  /\bexploit\b/i,
];

/** Weekly news digest pattern. */
const WEEKLY_NEWS_PATTERN = /stirile[_-]saptamanii|stiri-saptamana/i;

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const DRY_RUN = args.includes("--dry-run");
const RESUME = args.includes("--resume");
const FORCE = args.includes("--force");

function flagValue(name: string): string | undefined {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return undefined;
  return args[idx + 1];
}

function getFeedFilter(): string | null {
  const feedArg = args.find((a) => a.startsWith("--feed="));
  return feedArg ? feedArg.split("=")[1]! : null;
}

const FEED_FILTER = getFeedFilter();
const MAX_PAGES = Number(flagValue("--max-pages") || DEFAULT_MAX_PAGES);

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function log(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.log(`[${ts}] ${msg}`);
}

function warn(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.warn(`[${ts}] WARN: ${msg}`);
}

function logError(msg: string): void {
  const ts = new Date().toISOString().slice(0, 19);
  console.error(`[${ts}] ERROR: ${msg}`);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

let lastRequestTime = 0;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function rateLimit(): Promise<void> {
  const elapsed = Date.now() - lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestTime = Date.now();
}

async function fetchWithRetry(url: string, attempt = 0): Promise<string> {
  await rateLimit();

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    const res = await fetch(url, {
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ro-RO,ro;q=0.9,en;q=0.5",
      },
      signal: controller.signal,
      redirect: "follow",
    });

    clearTimeout(timer);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
    }

    return await res.text();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (attempt < MAX_RETRIES) {
      const backoff = RETRY_BACKOFF_BASE_MS * Math.pow(2, attempt);
      warn(`Request failed (${msg}), retrying in ${backoff}ms (attempt ${attempt + 1}/${MAX_RETRIES})`);
      await sleep(backoff);
      return fetchWithRetry(url, attempt + 1);
    }
    throw new Error(`Failed to fetch ${url} after ${MAX_RETRIES} retries: ${msg}`);
  }
}

// ---------------------------------------------------------------------------
// RSS parsing
// ---------------------------------------------------------------------------

interface RssItem {
  title: string;
  link: string;
  pubDate: string | null;
  description: string;
}

function parseRssFeed(xml: string): RssItem[] {
  const $ = cheerio.load(xml, { xmlMode: true });
  const items: RssItem[] = [];

  $("item").each((_, el) => {
    const title = $(el).find("title").text().trim();
    const link = $(el).find("link").text().trim();
    const pubDate = $(el).find("pubDate").text().trim() || null;
    const description = $(el).find("description").text().trim();

    if (title && link) {
      items.push({ title, link, pubDate, description });
    }
  });

  return items;
}

// ---------------------------------------------------------------------------
// Date parsing
// ---------------------------------------------------------------------------

function parseDateString(raw: string | null): string | null {
  if (!raw) return null;

  // RSS pubDate: "Fri, 20 Mar 2026 14:58:23 +0200"
  const rssMatch = raw.match(/\w+,\s+(\d{1,2})\s+(\w+)\s+(\d{4})/);
  if (rssMatch) {
    const months: Record<string, string> = {
      Jan: "01", Feb: "02", Mar: "03", Apr: "04", May: "05", Jun: "06",
      Jul: "07", Aug: "08", Sep: "09", Oct: "10", Nov: "11", Dec: "12",
    };
    const mon = months[rssMatch[2]!];
    if (mon) {
      return `${rssMatch[3]}-${mon}-${rssMatch[1]!.padStart(2, "0")}`;
    }
  }

  // Romanian date: "20.03.2026" or "20.3.2026 14:58"
  const roMatch = raw.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
  if (roMatch) {
    return `${roMatch[3]}-${roMatch[2]!.padStart(2, "0")}-${roMatch[1]!.padStart(2, "0")}`;
  }

  // ISO format: "2026-03-20"
  const isoMatch = raw.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (isoMatch) {
    return isoMatch[0]!;
  }

  // Romanian month names: "20 martie 2026"
  const roMonthMatch = raw.match(
    /(\d{1,2})\s+(ianuarie|februarie|martie|aprilie|mai|iunie|iulie|august|septembrie|octombrie|noiembrie|decembrie)\s+(\d{4})/i,
  );
  if (roMonthMatch) {
    const roMonths: Record<string, string> = {
      ianuarie: "01", februarie: "02", martie: "03", aprilie: "04",
      mai: "05", iunie: "06", iulie: "07", august: "08",
      septembrie: "09", octombrie: "10", noiembrie: "11", decembrie: "12",
    };
    const mon = roMonths[roMonthMatch[2]!.toLowerCase()];
    if (mon) {
      return `${roMonthMatch[3]}-${mon}-${roMonthMatch[1]!.padStart(2, "0")}`;
    }
  }

  return null;
}

/**
 * Extract a date from the slug of a DNSC URL.
 * E.g. "stirile-saptamanii-din-cybersecurity-19-03-2026" => "2026-03-19"
 */
function extractDateFromSlug(url: string): string | null {
  // Pattern: DD-MM-YYYY at end of slug
  const match = url.match(/(\d{2})-(\d{2})-(\d{4})$/);
  if (match) {
    return `${match[3]}-${match[2]}-${match[1]}`;
  }
  // Pattern: DD.MM.YYYY in slug
  const dotMatch = url.match(/(\d{2})\.(\d{2})\.(\d{4})/);
  if (dotMatch) {
    return `${dotMatch[3]}-${dotMatch[2]}-${dotMatch[1]}`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// CVE / severity / product extraction
// ---------------------------------------------------------------------------

function extractCves(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d{4,}/g);
  return matches ? [...new Set(matches)] : [];
}

function extractSeverity(text: string): string | null {
  const lower = text.toLowerCase();

  // CVSS score-based severity
  const cvssMatch = text.match(/CVSS[^:]*?[:\s]+(\d+\.?\d*)/i);
  if (cvssMatch) {
    const score = parseFloat(cvssMatch[1]!);
    if (score >= 9.0) return "critical";
    if (score >= 7.0) return "high";
    if (score >= 4.0) return "medium";
    return "low";
  }

  // Romanian severity keywords
  if (lower.includes("critic") || lower.includes("critical")) return "critical";
  if (lower.includes("ridicat") || lower.includes("grav") || lower.includes("high") || lower.includes("sever")) return "high";
  if (lower.includes("mediu") || lower.includes("moderate") || lower.includes("medium")) return "medium";
  if (lower.includes("scazut") || lower.includes("redus") || lower.includes("low")) return "low";

  return null;
}

function extractProducts(text: string): string[] {
  const products: string[] = [];

  const productPatterns = [
    /(?:Fortinet|FortiOS|FortiProxy|FortiManager|FortiAnalyzer|FortiWeb|FortiMail|FortiVoice|FortiNDR|FortiSIEM|FortiGate)\s*[\d.x-]*/gi,
    /(?:Cisco)\s+(?:ASA|FTD|IOS|IOS XE|ISE|Catalyst|SD-WAN|AsyncOS|Secure Email)[^,.\n]*/gi,
    /(?:Microsoft)\s+(?:Exchange|365|Windows|Office|Edge|Outlook|Teams|SharePoint|Azure)[^,.\n]*/gi,
    /(?:Ivanti)\s+(?:Connect Secure|Policy Secure|EPMM|Endpoint Manager)[^,.\n]*/gi,
    /(?:Palo Alto)\s+(?:GlobalProtect|PAN-OS|Networks)[^,.\n]*/gi,
    /(?:SonicWall)\s+(?:Gen \d+|SMA|SSLVPN)[^,.\n]*/gi,
    /(?:Citrix|NetScaler)\s+(?:ADC|Gateway|NetScaler)[^,.\n]*/gi,
    /(?:Apache)\s+(?:Log4j|Struts|Tomcat|HTTP Server|ActiveMQ)[^,.\n]*/gi,
    /(?:VMware)\s+(?:vCenter|ESXi|Workspace ONE|vSphere|NSX)[^,.\n]*/gi,
    /(?:Honeywell)\s+(?:CCTV|Pro-Watch|Experion)[^,.\n]*/gi,
    /(?:Zoom)\s+(?:Client|Node|MMR|Workplace)[^,.\n]*/gi,
    /(?:Google)\s+(?:Chrome|Chromium|Android)[^,.\n]*/gi,
    /(?:Apple)\s+(?:iOS|macOS|Safari|iPadOS|watchOS|tvOS|visionOS)[^,.\n]*/gi,
    /(?:WhatsApp|Telegram|Signal|WinRAR|OpenSSH|WordPress|Plesk|pgAdmin|n8n|UniFi|QNAP|Synology|Dell|HP|Lenovo)\s*[\d.x-]*/gi,
  ];

  for (const pattern of productPatterns) {
    const matches = text.match(pattern);
    if (matches) {
      for (const m of matches) {
        const cleaned = m.trim().replace(/\s+/g, " ");
        if (cleaned.length > 2 && !products.includes(cleaned)) {
          products.push(cleaned);
        }
      }
    }
  }

  return [...new Set(products)].slice(0, 20);
}

// ---------------------------------------------------------------------------
// Detail page parsing
// ---------------------------------------------------------------------------

interface ParsedPage {
  title: string;
  body: string;
  date: string | null;
  summary: string | null;
  cves: string[];
  products: string[];
  severity: string | null;
}

function parseDetailPage(
  html: string,
  fallbackTitle: string,
  fallbackDate: string | null,
): ParsedPage {
  const $ = cheerio.load(html);

  // Remove non-content elements
  $("nav, footer, .cookie-banner, .cookie-consent, [role='navigation'], script, style, noscript, header, .menu, .sidebar, .social-share").remove();

  // Title — h1 first, then og:title, then fallback
  let title =
    $("h1").first().text().trim() ||
    $('meta[property="og:title"]').attr("content")?.trim() ||
    $("title").text().trim() ||
    fallbackTitle;

  // Date — look for time elements, meta dates, inline text patterns
  let dateRaw: string | null = null;

  const timeEl = $("time").first();
  if (timeEl.length) {
    dateRaw = timeEl.attr("datetime") || timeEl.text().trim();
  }

  if (!dateRaw) {
    const metaDate =
      $('meta[property="article:published_time"]').attr("content") ||
      $('meta[name="date"]').attr("content") ||
      $('meta[name="DC.date"]').attr("content");
    if (metaDate) dateRaw = metaDate;
  }

  if (!dateRaw) {
    // Look for Romanian date pattern in the first few paragraphs
    const leadText = $("p").slice(0, 5).text();
    const dateMatch = leadText.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
    if (dateMatch) {
      dateRaw = dateMatch[0]!;
    }
  }

  if (!dateRaw) {
    // Look for date pattern in page header area or breadcrumb
    const headerText = $(".article-date, .post-date, .date, .meta, .breadcrumb").text();
    const dateMatch = headerText.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
    if (dateMatch) {
      dateRaw = dateMatch[0]!;
    }
  }

  const date = parseDateString(dateRaw) ?? fallbackDate;

  // Main body extraction — try main content areas
  const mainContent =
    ($("article").first().length ? $("article").first() : null) ||
    ($("main").first().length ? $("main").first() : null) ||
    ($(".content, .article-content, .post-content, .entry-content").first().length
      ? $(".content, .article-content, .post-content, .entry-content").first()
      : null) ||
    $("body");

  // Build structured text
  const bodyParts: string[] = [];
  mainContent.find("h2, h3, h4, p, li, td, blockquote").each((_, el) => {
    const tag = (el as unknown as Element).tagName?.toLowerCase() ?? "";
    const text = $(el).text().trim();
    if (!text) return;

    if (tag.startsWith("h")) {
      bodyParts.push(`\n## ${text}\n`);
    } else if (tag === "li") {
      bodyParts.push(`- ${text}`);
    } else if (tag === "blockquote") {
      bodyParts.push(`> ${text}`);
    } else {
      bodyParts.push(text);
    }
  });

  let body = bodyParts.join("\n").trim();

  // Fallback: all paragraph text
  if (body.length < 100) {
    body = $("p")
      .map((_, el) => $(el).text().trim())
      .get()
      .filter(Boolean)
      .join("\n\n");
  }

  // Last resort: entire text content
  if (body.length < 50) {
    body = mainContent.text().replace(/\s+/g, " ").trim();
  }

  const fullText = `${title}\n\n${body}`;
  const cves = extractCves(fullText);
  const severity = extractSeverity(fullText);
  const products = extractProducts(fullText);

  // Summary — first meaningful paragraph (>40 chars, not a heading)
  let summary: string | null = null;
  for (const part of bodyParts) {
    const cleaned = part.replace(/^[-#>\s]+/, "").trim();
    if (cleaned.length > 40 && !cleaned.startsWith("##")) {
      summary = cleaned.slice(0, 500);
      break;
    }
  }

  return { title, body, date, summary, cves, products, severity };
}

// ---------------------------------------------------------------------------
// Tag listing page parsing
// ---------------------------------------------------------------------------

interface TagListItem {
  title: string;
  url: string;
  snippet: string;
}

/**
 * Parse a DNSC /tag/{name}?page=N listing page.
 * Extracts article links from the tag listing.
 */
function parseTagListingPage(html: string): TagListItem[] {
  const $ = cheerio.load(html);
  const items: TagListItem[] = [];

  // DNSC tag pages list articles as links. Look for anchors pointing to /citeste/
  $("a[href*='/citeste/']").each((_, el) => {
    const href = $(el).attr("href");
    const text = $(el).text().trim();

    if (!href || !text || text.length < 10) return;

    // Skip navigation, menu, and header links
    const parent = $(el).closest("nav, header, footer, .menu, .breadcrumb");
    if (parent.length) return;

    // Build full URL
    const fullUrl = href.startsWith("http")
      ? href
      : href.startsWith("/")
        ? `${BASE_URL}${href}`
        : `${BASE_URL}/${href}`;

    // Get snippet from nearby text
    const snippet = $(el).parent().text().trim().slice(0, 300);

    // Avoid duplicates in this page
    if (!items.some((i) => i.url === fullUrl)) {
      items.push({ title: text, url: fullUrl, snippet });
    }
  });

  return items;
}

/**
 * Check if a tag listing page has a next page.
 * DNSC uses ?page=N query parameter pagination.
 */
function hasNextPage(html: string, currentPage: number): boolean {
  const $ = cheerio.load(html);
  const nextPage = currentPage + 1;

  // Check for a link to ?page=nextPage
  const nextLink = $(`a[href*="page=${nextPage}"]`).length > 0;

  // Also check for pagination nav with "next" or "urmatoarea" (Romanian for "next")
  const nextNav =
    $("a:contains('»')").length > 0 ||
    $("a:contains('Urm')").length > 0 ||
    $(".pagination .next").length > 0;

  return nextLink || nextNav;
}

// ---------------------------------------------------------------------------
// Reference generation
// ---------------------------------------------------------------------------

function generateReference(url: string, fallbackIndex: number): string {
  // Extract the slug from the URL
  const slug = url
    .replace(/^https?:\/\/(?:www\.)?dnsc\.ro\//, "")
    .replace(/^citeste\//, "")
    .replace(/^vezi\/document\//, "doc-");

  // Alert: /citeste/alerta-* => DNSC-ALERT-{slug}
  if (slug.startsWith("alerta-")) {
    // Try to extract CVE for a tighter reference
    const cveMatch = slug.match(/cve-(\d{4})-(\d+)/i);
    if (cveMatch) {
      return `DNSC-ALERT-CVE-${cveMatch[1]}-${cveMatch[2]}`;
    }
    const shortSlug = slug
      .replace(/^alerta-/, "")
      .replace(/[^a-z0-9-]/gi, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);
    return `DNSC-ALERT-${shortSlug}`.toUpperCase();
  }

  // Weekly news: /citeste/stirile-saptamanii-din-cybersecurity-DD-MM-YYYY
  const weeklyMatch = slug.match(/stirile[_-]saptamanii.*?(\d{2})-(\d{2})-(\d{4})$/);
  if (weeklyMatch) {
    return `DNSC-WEEKLY-${weeklyMatch[3]}-${weeklyMatch[2]}-${weeklyMatch[1]}`;
  }
  if (WEEKLY_NEWS_PATTERN.test(slug)) {
    const shortSlug = slug
      .replace(/^stirile[_-]saptamanii[_-]din[_-]cybersecurity[_-]?/, "")
      .replace(/[^a-z0-9-]/gi, "-")
      .slice(0, 30);
    return `DNSC-WEEKLY-${shortSlug || fallbackIndex}`.toUpperCase();
  }

  // Document: /vezi/document/* => DNSC-DOC-{slug}
  if (slug.startsWith("doc-")) {
    const docSlug = slug
      .replace(/^doc-/, "")
      .replace(/[^a-z0-9-]/gi, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);
    return `DNSC-DOC-${docSlug}`.toUpperCase();
  }

  // Press release / comunicat
  if (slug.startsWith("comunicat")) {
    const commSlug = slug
      .replace(/^comunicat-de-presa-?/, "")
      .replace(/^comunicat-?/, "")
      .replace(/[^a-z0-9-]/gi, "-")
      .replace(/-+/g, "-")
      .slice(0, 60);
    return `DNSC-COMM-${commSlug}`.toUpperCase();
  }

  // Generic article
  const genericSlug = slug
    .replace(/[^a-z0-9-]/gi, "-")
    .replace(/-+/g, "-")
    .slice(0, 60);
  return `DNSC-ART-${genericSlug || fallbackIndex}`.toUpperCase();
}

// ---------------------------------------------------------------------------
// Content classification
// ---------------------------------------------------------------------------

type ContentType = "advisory" | "guidance";

interface Classification {
  type: ContentType;
  guidanceType: string | null;
  series: string | null;
}

function classifyContent(url: string, title: string): Classification {
  const combined = `${url} ${title}`.toLowerCase();

  // Alerts and vulnerability advisories
  if (ALERT_PATTERNS.some((p) => p.test(combined))) {
    return { type: "advisory", guidanceType: null, series: null };
  }

  // Weekly cybersecurity news digests => guidance (situational awareness)
  if (WEEKLY_NEWS_PATTERN.test(url) || WEEKLY_NEWS_PATTERN.test(title)) {
    return { type: "guidance", guidanceType: "weekly_digest", series: "DNSC-Weekly" };
  }

  // Document pages (guides, standards)
  if (url.includes("/vezi/document/")) {
    if (combined.includes("ghid")) {
      return { type: "guidance", guidanceType: "guideline", series: "DNSC" };
    }
    if (combined.includes("indrumar") || combined.includes("planificare")) {
      return { type: "guidance", guidanceType: "planning_guide", series: "DNSC" };
    }
    if (combined.includes("standard") || combined.includes("principii")) {
      return { type: "guidance", guidanceType: "standard", series: "DNSC" };
    }
    return { type: "guidance", guidanceType: "publication", series: "DNSC" };
  }

  // NIS2 content
  if (combined.includes("nis2") || combined.includes("nis 2") || combined.includes("directiva nis")) {
    return { type: "guidance", guidanceType: "regulation_guide", series: "NIS2" };
  }

  // GDPR content
  if (combined.includes("gdpr") || combined.includes("date cu caracter personal")) {
    return { type: "guidance", guidanceType: "regulation_guide", series: "GDPR" };
  }

  // Press releases
  if (combined.includes("comunicat")) {
    return { type: "guidance", guidanceType: "press_release", series: "DNSC" };
  }

  // Recommendations
  if (combined.includes("recomandari") || combined.includes("recomandare")) {
    return { type: "guidance", guidanceType: "recommendation", series: "DNSC" };
  }

  // Default: general guidance
  return { type: "guidance", guidanceType: "article", series: "DNSC" };
}

// ---------------------------------------------------------------------------
// Topic derivation
// ---------------------------------------------------------------------------

function deriveTopics(page: ParsedPage, classification: Classification): string[] {
  const topics: string[] = [];
  const text = `${page.title} ${page.body}`.toLowerCase();

  const topicMap: Array<[RegExp, string]> = [
    [/\bnis2?\b|nis\s*2/i, "NIS2"],
    [/\bgdpr\b|date cu caracter personal/i, "GDPR"],
    [/\bransomware\b|ransom/i, "ransomware"],
    [/\bphishing\b|inselaciune|frauda/i, "phishing"],
    [/\bddos\b|denial.of.service|palvelunesto/i, "DDoS"],
    [/\bmalware\b|program malitios|troian/i, "malware"],
    [/\bcloud\b|servicii cloud/i, "cloud"],
    [/\binfrastructur[aă] critic[aă]\b|servicii esentiale/i, "infrastructura_critica"],
    [/\bscada\b|\bics\b|sisteme de control industrial/i, "ICS/SCADA"],
    [/\biot\b|internet of things|dispozitive conectate/i, "IoT"],
    [/\bai\b|inteligent[aă] artificial[aă]|machine learning/i, "AI"],
    [/\b5g\b|retele mobile/i, "5G"],
    [/\bcriptare\b|criptografie|tls|ssl|encryption/i, "criptografie"],
    [/\bmfa\b|autentificare multifactor|two.factor/i, "MFA"],
    [/\bvpn\b/i, "VPN"],
    [/\bbackup\b|copie de siguranta/i, "backup"],
    [/\bsanatate\b|spital|medical/i, "sanatate"],
    [/\benergetic\b|energie|electric/i, "energie"],
    [/\bfinanciar\b|banc[aă]|plati/i, "financiar"],
    [/\btransport\b/i, "transport"],
    [/\beducatie\b|scoal[aă]|universit/i, "educatie"],
    [/\bimm\b|intreprinderi mici/i, "IMM"],
    [/\biso\s*27001\b|isms/i, "ISMS"],
    [/\baudit\b|auditor/i, "audit"],
    [/\bincident\b|raspuns la incident/i, "incident_response"],
    [/\bspam\b/i, "spam"],
    [/\bspoofing\b|vishing\b/i, "spoofing"],
    [/\bwordpress\b/i, "WordPress"],
    [/\bwindows\b/i, "Windows"],
    [/\blinux\b/i, "Linux"],
    [/\bandroid\b/i, "Android"],
    [/\bapple\b|ios\b|macos\b/i, "Apple"],
  ];

  for (const [pattern, topic] of topicMap) {
    if (pattern.test(text)) {
      topics.push(topic);
    }
  }

  if (classification.series && classification.series !== "DNSC") {
    topics.push(classification.series);
  }

  return topics.length > 0 ? topics : ["securitate_cibernetica"];
}

// ---------------------------------------------------------------------------
// Database operations
// ---------------------------------------------------------------------------

function openDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  if (FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    log("Deleted existing database (--force)");
  }

  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

function getExistingReferences(db: Database.Database): Set<string> {
  const refs = new Set<string>();
  const gRows = db.prepare("SELECT reference FROM guidance").all() as Array<{ reference: string }>;
  for (const r of gRows) refs.add(r.reference);
  const aRows = db.prepare("SELECT reference FROM advisories").all() as Array<{ reference: string }>;
  for (const r of aRows) refs.add(r.reference);
  return refs;
}

// ---------------------------------------------------------------------------
// Ingestion stats
// ---------------------------------------------------------------------------

interface IngestStats {
  fetched: number;
  inserted: number;
  skipped: number;
  errors: number;
}

function emptyStats(): IngestStats {
  return { fetched: 0, inserted: 0, skipped: 0, errors: 0 };
}

// ---------------------------------------------------------------------------
// Insert helpers
// ---------------------------------------------------------------------------

function insertAdvisory(
  db: Database.Database,
  reference: string,
  page: ParsedPage,
  existingRefs: Set<string>,
): boolean {
  try {
    db.prepare(`
      INSERT OR REPLACE INTO advisories
        (reference, title, date, severity, affected_products, summary, full_text, cve_references)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      reference,
      page.title,
      page.date,
      page.severity,
      page.products.length > 0 ? page.products.join(", ") : null,
      page.summary,
      page.body,
      page.cves.length > 0 ? page.cves.join(", ") : null,
    );
    existingRefs.add(reference);
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`DB insert failed for advisory ${reference}: ${msg}`);
    return false;
  }
}

function insertGuidance(
  db: Database.Database,
  reference: string,
  page: ParsedPage,
  classification: Classification,
  existingRefs: Set<string>,
): boolean {
  try {
    const topics = deriveTopics(page, classification);
    db.prepare(`
      INSERT OR REPLACE INTO guidance
        (reference, title, title_en, date, type, series, summary, full_text, topics, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      reference,
      page.title,
      null, // title_en — no automatic translation
      page.date,
      classification.guidanceType,
      classification.series,
      page.summary,
      page.body,
      topics.join(", "),
      "current",
    );
    existingRefs.add(reference);
    return true;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    warn(`DB insert failed for guidance ${reference}: ${msg}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// Ingestion: RSS feed
// ---------------------------------------------------------------------------

async function ingestRssFeed(
  db: Database.Database,
  existingRefs: Set<string>,
): Promise<IngestStats> {
  const stats = emptyStats();

  log(`Fetching RSS feed: ${RSS_FEED_URL}`);
  let xml: string;
  try {
    xml = await fetchWithRetry(RSS_FEED_URL);
  } catch {
    logError("Failed to fetch RSS feed");
    stats.errors++;
    return stats;
  }

  const items = parseRssFeed(xml);
  log(`Parsed ${items.length} items from RSS feed`);

  for (let i = 0; i < items.length; i++) {
    const item = items[i]!;

    // Only follow dnsc.ro links
    if (!item.link.includes("dnsc.ro")) {
      stats.skipped++;
      continue;
    }

    const reference = generateReference(item.link, i);

    if (RESUME && existingRefs.has(reference)) {
      stats.skipped++;
      continue;
    }

    stats.fetched++;
    const progress = `[${stats.fetched}/${items.length}]`;
    log(`${progress} Fetching: ${item.title.slice(0, 80)}`);

    let page: ParsedPage;
    try {
      const html = await fetchWithRetry(item.link);
      const fallbackDate = parseDateString(item.pubDate) ?? extractDateFromSlug(item.link);
      page = parseDetailPage(html, item.title, fallbackDate);
    } catch {
      warn(`Failed to fetch detail page: ${item.link}`);
      page = {
        title: item.title,
        body: item.description || item.title,
        date: parseDateString(item.pubDate) ?? extractDateFromSlug(item.link),
        summary: item.description?.slice(0, 500) || null,
        cves: extractCves(item.description || ""),
        products: extractProducts(item.description || ""),
        severity: extractSeverity(item.description || ""),
      };
      stats.errors++;
    }

    const classification = classifyContent(item.link, item.title);

    if (!DRY_RUN) {
      let ok: boolean;
      if (classification.type === "advisory") {
        ok = insertAdvisory(db, reference, page, existingRefs);
      } else {
        ok = insertGuidance(db, reference, page, classification, existingRefs);
      }
      if (ok) {
        stats.inserted++;
      } else {
        stats.errors++;
      }
    } else {
      log(`  [dry-run] Would insert ${classification.type}: ${reference}`);
      stats.inserted++;
    }

    if (i < items.length - 1) {
      await sleep(RATE_LIMIT_MS);
    }
  }

  return stats;
}

// ---------------------------------------------------------------------------
// Ingestion: tag listing pages (paginated)
// ---------------------------------------------------------------------------

async function ingestTagPages(
  db: Database.Database,
  tagUrls: readonly string[],
  defaultClassification: Classification,
  existingRefs: Set<string>,
  label: string,
): Promise<IngestStats> {
  const stats = emptyStats();
  const seenUrls = new Set<string>();

  for (const tagBaseUrl of tagUrls) {
    log(`Crawling tag listing: ${tagBaseUrl}`);

    for (let pageNum = 1; pageNum <= MAX_PAGES; pageNum++) {
      const pageUrl = pageNum === 1 ? tagBaseUrl : `${tagBaseUrl}?page=${pageNum}`;
      log(`  Page ${pageNum}: ${pageUrl}`);

      let html: string;
      try {
        html = await fetchWithRetry(pageUrl);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.includes("403") || msg.includes("404")) {
          log(`  Stopped at page ${pageNum} (${msg})`);
          break;
        }
        warn(`Failed to fetch listing page ${pageUrl}: ${msg}`);
        stats.errors++;
        break;
      }

      const listItems = parseTagListingPage(html);

      if (listItems.length === 0) {
        log(`  No items found on page ${pageNum}, stopping pagination`);
        break;
      }

      log(`  Found ${listItems.length} items on page ${pageNum}`);

      for (const item of listItems) {
        if (seenUrls.has(item.url)) continue;
        seenUrls.add(item.url);

        const reference = generateReference(item.url, stats.fetched);

        if (RESUME && existingRefs.has(reference)) {
          stats.skipped++;
          continue;
        }

        stats.fetched++;
        log(`  [${label}][${stats.fetched}] ${item.title.slice(0, 70)}`);

        let page: ParsedPage;
        try {
          const detailHtml = await fetchWithRetry(item.url);
          const fallbackDate = extractDateFromSlug(item.url);
          page = parseDetailPage(detailHtml, item.title, fallbackDate);
        } catch {
          warn(`Failed to fetch detail: ${item.url}`);
          page = {
            title: item.title,
            body: item.snippet || item.title,
            date: extractDateFromSlug(item.url),
            summary: item.snippet?.slice(0, 500) || null,
            cves: extractCves(item.snippet || ""),
            products: extractProducts(item.snippet || ""),
            severity: extractSeverity(item.snippet || ""),
          };
          stats.errors++;
        }

        // Re-classify each item individually (tag pages can mix content types)
        const classification = classifyContent(item.url, item.title);
        const effectiveClassification =
          classification.type !== defaultClassification.type
            ? classification
            : defaultClassification.type === "advisory"
              ? classification
              : classification;

        if (!DRY_RUN) {
          let ok: boolean;
          if (effectiveClassification.type === "advisory") {
            ok = insertAdvisory(db, reference, page, existingRefs);
          } else {
            ok = insertGuidance(db, reference, page, effectiveClassification, existingRefs);
          }
          if (ok) {
            stats.inserted++;
          } else {
            stats.errors++;
          }
        } else {
          log(`  [dry-run] Would insert ${effectiveClassification.type}: ${reference}`);
          stats.inserted++;
        }

        await sleep(RATE_LIMIT_MS);
      }

      // Check pagination
      if (!hasNextPage(html, pageNum)) {
        log(`  No more pages after page ${pageNum}`);
        break;
      }

      await sleep(RATE_LIMIT_MS);
    }
  }

  return stats;
}

// ---------------------------------------------------------------------------
// Ingestion: direct URL lists (guidance documents + articles)
// ---------------------------------------------------------------------------

async function ingestDirectUrls(
  db: Database.Database,
  urls: readonly string[],
  existingRefs: Set<string>,
  label: string,
): Promise<IngestStats> {
  const stats = emptyStats();

  for (let i = 0; i < urls.length; i++) {
    const url = urls[i]!;
    const reference = generateReference(url, i);

    if (RESUME && existingRefs.has(reference)) {
      stats.skipped++;
      continue;
    }

    // Skip PDF links — we only parse HTML
    if (url.endsWith(".pdf")) {
      log(`  [${label}] Skipping PDF: ${url}`);
      stats.skipped++;
      continue;
    }

    stats.fetched++;
    log(`  [${label}][${stats.fetched}/${urls.length}] Fetching: ${url}`);

    let page: ParsedPage;
    try {
      const html = await fetchWithRetry(url);
      const fallbackDate = extractDateFromSlug(url);
      page = parseDetailPage(html, url.split("/").pop() || label, fallbackDate);
    } catch {
      warn(`Failed to fetch: ${url}`);
      page = {
        title: url.split("/").pop()?.replace(/-/g, " ") || label,
        body: `[Content unavailable — failed to fetch ${url}]`,
        date: null,
        summary: null,
        cves: [],
        products: [],
        severity: null,
      };
      stats.errors++;
    }

    const classification = classifyContent(url, page.title);

    if (!DRY_RUN) {
      let ok: boolean;
      if (classification.type === "advisory") {
        ok = insertAdvisory(db, reference, page, existingRefs);
      } else {
        ok = insertGuidance(db, reference, page, classification, existingRefs);
      }
      if (ok) {
        stats.inserted++;
      } else {
        stats.errors++;
      }
    } else {
      log(`  [dry-run] Would insert ${classification.type}: ${reference}`);
      stats.inserted++;
    }

    if (i < urls.length - 1) {
      await sleep(RATE_LIMIT_MS);
    }
  }

  return stats;
}

// ---------------------------------------------------------------------------
// Framework updates
// ---------------------------------------------------------------------------

function updateFrameworks(db: Database.Database): void {
  if (DRY_RUN) {
    log("[dry-run] Would update framework document counts");
    return;
  }

  const upsertFramework = db.prepare(`
    INSERT INTO frameworks (id, name, name_en, description, document_count)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET document_count = excluded.document_count
  `);

  // Count guidance by series
  const seriesCounts = db
    .prepare("SELECT series, COUNT(*) as cnt FROM guidance WHERE series IS NOT NULL GROUP BY series")
    .all() as Array<{ series: string; cnt: number }>;

  const frameworkDefs: Array<{
    id: string;
    name: string;
    name_en: string;
    description: string;
    seriesMatch: string;
  }> = [
    {
      id: "dnsc-guidelines",
      name: "Ghiduri si recomandari DNSC",
      name_en: "DNSC Guidelines and Recommendations",
      description:
        "Ghiduri, standarde tehnice si recomandari publicate de Directoratul National de Securitate Cibernetica pentru protectia sistemelor informatice si a infrastructurii critice din Romania.",
      seriesMatch: "DNSC",
    },
    {
      id: "nis2-ro",
      name: "Implementarea NIS2 in Romania",
      name_en: "NIS2 Directive Implementation in Romania",
      description:
        "Cerinte si ghiduri pentru implementarea Directivei NIS2 (UE 2022/2555) in Romania, conform OUG nr. 155/2024 si Legii nr. 362/2018.",
      seriesMatch: "NIS2",
    },
    {
      id: "gdpr-ro",
      name: "Protectia datelor cu caracter personal (GDPR)",
      name_en: "Personal Data Protection (GDPR)",
      description:
        "Ghiduri practice pentru conformitatea cu Regulamentul General privind Protectia Datelor (GDPR) in Romania.",
      seriesMatch: "GDPR",
    },
    {
      id: "dnsc-weekly",
      name: "Stirile saptamanii din cybersecurity",
      name_en: "Weekly Cybersecurity News",
      description:
        "Rezumate saptamanale ale celor mai importante evenimente, vulnerabilitati si amenintari de securitate cibernetica publicate de DNSC.",
      seriesMatch: "DNSC-Weekly",
    },
  ];

  for (const fw of frameworkDefs) {
    const count = seriesCounts.find((s) => s.series === fw.seriesMatch)?.cnt ?? 0;
    upsertFramework.run(fw.id, fw.name, fw.name_en, fw.description, count);
  }

  // Advisory count as pseudo-framework
  const advisoryCount = (
    db.prepare("SELECT COUNT(*) as cnt FROM advisories").get() as { cnt: number }
  ).cnt;
  upsertFramework.run(
    "dnsc-advisories",
    "Alerte si avertizari de securitate DNSC",
    "DNSC Security Alerts and Advisories",
    "Alerte de securitate cibernetica, avertizari privind vulnerabilitati critice si avize de securitate publicate de DNSC/CERT-RO.",
    advisoryCount,
  );

  log(`Updated ${frameworkDefs.length + 1} framework document counts`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  log("=== DNSC / CERT-RO Ingestion Crawler ===");
  log(`Database: ${DB_PATH}`);
  log(`Mode: ${DRY_RUN ? "DRY RUN" : FORCE ? "FORCE (re-ingest)" : RESUME ? "RESUME" : "FULL"}`);
  log(`Max pages per tag: ${MAX_PAGES}`);
  if (FEED_FILTER) log(`Feed filter: ${FEED_FILTER}`);
  log("");

  const db = openDb();
  const existingRefs = RESUME ? getExistingReferences(db) : new Set<string>();
  if (RESUME) {
    log(`Found ${existingRefs.size} existing references (will skip)`);
  }

  const allStats: Record<string, IngestStats> = {};

  // 1. RSS feed — latest alerts and news
  if (!FEED_FILTER || FEED_FILTER === "rss") {
    log("--- Phase 1: RSS feed ---");
    allStats["rss"] = await ingestRssFeed(db, existingRefs);
    log("");
  }

  // 2. Alert tag pages — paginated alert listings
  if (!FEED_FILTER || FEED_FILTER === "alerts") {
    log("--- Phase 2: Alert tag pages ---");
    allStats["alerts"] = await ingestTagPages(
      db,
      ALERT_TAG_PAGES,
      { type: "advisory", guidanceType: null, series: null },
      existingRefs,
      "alerts",
    );
    log("");
  }

  // 3. Guidance tag pages — press releases, CERT-RO articles
  if (!FEED_FILTER || FEED_FILTER === "articles") {
    log("--- Phase 3: Guidance tag pages ---");
    allStats["tag-articles"] = await ingestTagPages(
      db,
      GUIDANCE_TAG_PAGES,
      { type: "guidance", guidanceType: "article", series: "DNSC" },
      existingRefs,
      "articles",
    );
    log("");
  }

  // 4. Direct guidance document URLs
  if (!FEED_FILTER || FEED_FILTER === "guides") {
    log("--- Phase 4: Guidance documents ---");
    allStats["documents"] = await ingestDirectUrls(db, GUIDANCE_DOCUMENT_URLS, existingRefs, "docs");
    log("");

    log("--- Phase 4b: Guidance articles ---");
    allStats["articles"] = await ingestDirectUrls(db, GUIDANCE_ARTICLE_URLS, existingRefs, "articles");
    log("");
  }

  // 5. Update framework document counts
  updateFrameworks(db);

  // Summary
  log("=== Ingestion Summary ===");
  let totalFetched = 0;
  let totalInserted = 0;
  let totalSkipped = 0;
  let totalErrors = 0;

  for (const [name, stats] of Object.entries(allStats)) {
    log(
      `  ${name.padEnd(14)} — fetched: ${stats.fetched}, inserted: ${stats.inserted}, skipped: ${stats.skipped}, errors: ${stats.errors}`,
    );
    totalFetched += stats.fetched;
    totalInserted += stats.inserted;
    totalSkipped += stats.skipped;
    totalErrors += stats.errors;
  }

  log("");
  log(
    `  TOTAL          — fetched: ${totalFetched}, inserted: ${totalInserted}, skipped: ${totalSkipped}, errors: ${totalErrors}`,
  );

  // DB totals
  if (!DRY_RUN) {
    const guidanceCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM guidance").get() as { cnt: number }
    ).cnt;
    const advisoryCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM advisories").get() as { cnt: number }
    ).cnt;
    const frameworkCount = (
      db.prepare("SELECT COUNT(*) as cnt FROM frameworks").get() as { cnt: number }
    ).cnt;
    log("");
    log("Database totals:");
    log(`  Frameworks:  ${frameworkCount}`);
    log(`  Guidance:    ${guidanceCount}`);
    log(`  Advisories:  ${advisoryCount}`);
  }

  db.close();
  log("");
  log("Done.");
}

main().catch((err) => {
  logError(`Fatal: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
