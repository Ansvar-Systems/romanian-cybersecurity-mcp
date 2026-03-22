import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["DNSC_DB_PATH"] ?? "data/dnsc.db";
const force = process.argv.includes("--force");
const dir = dirname(DB_PATH);
if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log("Deleted " + DB_PATH); }

const db = new Database(DB_PATH);
db.exec(SCHEMA_SQL);

const frameworks = [
  { id: "dnsc-framework", name: "Cadrul national de securitate cibernetica", name_en: "National Cybersecurity Framework", description: "Cadrul DNSC pentru protectia sistemelor informatice si a infrastructurii critice din Romania.", document_count: 5 },
  { id: "nis2-ro", name: "Implementarea NIS2 in Romania", name_en: "NIS2 Directive Implementation in Romania", description: "Cerinte pentru implementarea Directivei NIS2 in Romania.", document_count: 1 },
  { id: "isms-dnsc", name: "Managementul securitatii informatiei (ISMS)", name_en: "Information Security Management System", description: "Seria DNSC pentru implementarea ISMS conform ISO/IEC 27001.", document_count: 2 },
];

const guidance = [
  { reference: "DNSC-G-01/2023", title: "Ghid pentru securitatea serviciilor cloud", title_en: "Cloud Services Security Guide", date: "2023-04-10", type: "guideline", series: "DNSC", summary: "Cerinte minime de securitate pentru serviciile cloud utilizate de institutiile publice.", full_text: "Ghid DNSC-G-01/2023\n\nCerinte cloud\n1. Evaluarea riscurilor inainte de migrare.\n2. Garantii contractuale.\n3. Sisteme de backup.\n4. Auditabilitate.\n5. Criptare date.", topics: "cloud,securitate", status: "current" },
  { reference: "DNSC-G-02/2023", title: "Securitatea sistemelor ICS/SCADA", title_en: "ICS/SCADA Security Guide", date: "2023-07-15", type: "standard", series: "DNSC", summary: "Protectia sistemelor de control industrial in sectoarele energetic si al apei.", full_text: "Ghid DNSC-G-02/2023\n\nSecuritate ICS/SCADA\n1. Segmentarea retelei OT/IT.\n2. Acces privilegiat in OT.\n3. Actualizare componente.\n4. Detectia anomaliilor.\n5. Planuri de raspuns la incidente.", topics: "ICS,SCADA,OT", status: "current" },
  { reference: "DNSC-R-01/2024", title: "Recomandari pentru autentificarea multifactor", title_en: "Multi-Factor Authentication Recommendations", date: "2024-02-01", type: "recommendation", series: "DNSC", summary: "Implementarea autentificarii multifactor in sistemele institutiilor publice.", full_text: "Recomandare DNSC-R-01/2024\n\nMFA este esential contra accesului neautorizat.\nMetode: FIDO2, TOTP, hardver token.\nObligatoriu pentru administratori si acces la distanta.", topics: "MFA,autentificare", status: "current" },
  { reference: "DNSC-G-03/2024", title: "Ghid NIS2 pentru operatorii de servicii esentiale", title_en: "NIS2 Guide for Essential Service Operators", date: "2024-05-01", type: "regulation", series: "NIS2", summary: "Ghid de implementare pentru entitatile obligate conform Legii nr. 362/2018 modificata pentru NIS2.", full_text: "Ghid DNSC-G-03/2024\n\nObligatii NIS2\n1. Inregistrarea la DNSC.\n2. Sistem de management al securitatii.\n3. Notificarea incidentelor in 24/72 ore.\n4. Riscurile lantului de aprovizionare.\n5. Penetration tests.", topics: "NIS2,inregistrare,incident", status: "current" },
  { reference: "DNSC-R-02/2024", title: "Recomandari privind securitatea AI", title_en: "AI Security Recommendations", date: "2024-10-01", type: "recommendation", series: "DNSC", summary: "Implementarea securizata a sistemelor AI in institutii publice si infrastructura critica.", full_text: "Recomandare DNSC-R-02/2024\n\nAI si securitate\n1. Evaluarea riscurilor AI.\n2. Protectia datelor de antrenament.\n3. Monitorizarea iesirilor.\n4. Conformitate AI Act.\n5. Interzicerea AI din surse nedemne in infrastructura critica.", topics: "AI,inteligenta artificiala", status: "current" },
];

const advisories = [
  { reference: "DNSC-ALERT-2024-001", title: "Vulnerabilitate critica Microsoft Exchange Server", date: "2024-02-15", severity: "critical", affected_products: "Microsoft Exchange Server 2016, 2019", summary: "Exploatare activa CVE-2024-21410 in Microsoft Exchange Server permitand NTLM Relay.", full_text: "DNSC-ALERT-2024-001\n\nExploatare activa CVE-2024-21410.\nMasuri: Patch KB5035106, activare EPA, monitorizare NTLM.", cve_references: "CVE-2024-21410" },
  { reference: "DNSC-ALERT-2024-002", title: "Campanie phishing vizand bancile romanesti", date: "2024-06-10", severity: "high", affected_products: "Internet banking, aplicatii mobile bancare", summary: "Campanie sofisticata de phishing vizand clientii bancilor romanesti.", full_text: "DNSC-ALERT-2024-002\n\nCampanie de phishing cu site-uri clonate ale bancilor romanesti.\nTehnici: SMS fals, domenii frauduloase, redirectionare.\nIOC disponibili entitatilor inregistrate.", cve_references: null },
  { reference: "DNSC-ALERT-2024-003", title: "Ransomware in sectorul sanatatii din Romania", date: "2024-09-05", severity: "critical", affected_products: "Sisteme informatice spitalicesti, Windows Server", summary: "Atacuri ransomware vizand spitalele si institutiile medicale din Romania.", full_text: "DNSC-ALERT-2024-003\n\nRansomware in sistemul sanitar romanesc.\nVectori: RDP/VPN, phishing, lanturi de aprovizionare.\nMasuri: backup offline, segmentare, EDR, raportare 24h.", cve_references: null },
];

const iF = db.prepare("INSERT OR REPLACE INTO frameworks (id, name, name_en, description, document_count) VALUES (@id, @name, @name_en, @description, @document_count)");
const iG = db.prepare("INSERT OR REPLACE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (@reference, @title, @title_en, @date, @type, @series, @summary, @full_text, @topics, @status)");
const iA = db.prepare("INSERT OR REPLACE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (@reference, @title, @date, @severity, @affected_products, @summary, @full_text, @cve_references)");

for (const f of frameworks) iF.run(f);
for (const g of guidance) iG.run(g);
for (const a of advisories) iA.run(a);

console.log("Seeded " + frameworks.length + " frameworks, " + guidance.length + " guidance, " + advisories.length + " advisories into " + DB_PATH);
db.close();
