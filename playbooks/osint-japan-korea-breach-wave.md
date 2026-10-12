# OSINT Hunting Playbook — Exposed Data Platforms Behind the Japan–Korea Breach Wave

**Date:** 2026-10-12
**Write-up:** https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-12-2026.html
**MITRE ATT&CK:** T1595 (Active Scanning), T1596 (Search Open Technical Databases), T1190 (Exploit Public-Facing Application), T1133 (External Remote Services)

## Situation

October 2026 brought a breach wave across Japan and South Korea past 10.8M confirmed leaked records (Monogatari/Yakiniku King 10.78M, Park24/Times Car 6.6M incl. identity documents, plus Asahi Kasei, MrMax, GMO, Citizen Watch, Daiwa, and seven South Korean financial institutions). Per Macnica, 119 similar web data-leak incidents hit Japan in 2026 — driven by **mobile API abuse and Metabase attacks** — with 99 lookalike cases across 13 other regions. Separately, Warlock ransomware keeps breaching critical infrastructure through **unpatched on-premises SharePoint** (ToolShell chain, 15 months since first exploitation). Both stories share one root cause visible from the outside: **data platforms exposed to the internet**. This playbook hunts that exposure with purely passive OSINT — no scanning of your own, no touching target systems beyond reading public banners.

**OPSEC rule for every module below:** use third-party indexes (Shodan, Censys, certificate transparency). Never port-scan or probe a host you do not own. Banner data from an index is OSINT; a SYN packet from your machine is not.

---

## Module 1 — Exposed Metabase instances

**Goal:** find internet-facing Metabase deployments (analytics/BI layer) that match the attack surface behind Japan's 2026 web data-leak wave, so you can check whether any belong to your organization or supply chain before attackers do.

**OSINT sources:** Shodan, Censys Search.

**Queries:**
- Shodan: `http.title:"Metabase"` — baseline population of indexed Metabase login pages.
- Shodan: `http.title:"Metabase" country:"JP"` / `country:"KR"` — scope to the breach-wave geography; compare counts against your own country's footprint.
- Censys: `services.http.response.html_title = "Metabase"` — second index to cross-check and catch hosts Shodan missed.
- Refine by version: Metabase exposes its build in the page/API banner indexed by both engines. Filter to builds older than your minimum supported version.

**Triage:**
1. Deduplicate Shodan vs. Censys results by IP:port.
2. For each hit, resolve the ASN/org — flag anything in your company's, subsidiaries', or key vendors' netblocks.
3. Check whether authentication is even required: indexed screenshots/banners sometimes reveal setup-wizard or open instances (no login gate). Those are critical.
4. Record version strings; anything more than two minor versions behind current is a patch candidate.

**Escalate:** confirmed instance in your estate → verify with the asset owner, enforce SSO/MFA, restrict to VPN/private link, patch. Vendor instance → notify the vendor's security contact with the indexed URL and timestamp.

## Module 2 — Unpatched SharePoint (ToolShell / CVE-2026-45659 exposure)

**Goal:** enumerate internet-facing on-premises SharePoint servers — the exact foothold Warlock is still riding 15 months after ToolShell first burned.

**OSINT sources:** Shodan, Censys, certificate transparency (crt.sh).

**Queries:**
- Shodan: `http.title:"SharePoint"` — baseline.
- Shodan: `http.html:"16.0.0."` combined with SharePoint titles — surfaces build numbers in indexed banners; anything on a 16.0.0.xxxx build predating the ToolShell patches is suspect.
- Censys: `services.http.response.html_title : "SharePoint"` with `services.software` version filters where available.
- crt.sh: search `%sharepoint%` / `%sp%.<target-domain>` — find forgotten SharePoint hostnames in your own domains via certificate issuance you may not know about.

**Triage:**
1. Separate SharePoint Online (Microsoft 365, `*.sharepoint.com` — not your problem) from on-premises (self-hosted, custom domains — your problem).
2. For on-prem hits in your netblocks: confirm patch level against the ToolShell chain (CVE-2025-49704, CVE-2025-49706, CVE-2025-53770, CVE-2025-53771) and CISA KEV-listed CVE-2026-45659.
3. Remember the recovery step most shops skip: **ASP.NET machine-key rotation after patching** (flagged mandatory by the EU joint technical assessment). An indexed "patched" build with a never-rotated key is still exposed.

**Escalate:** unpatched or key-never-rotated on-prem SharePoint → emergency patch + key rotation per Microsoft's ToolShell guidance; treat any internet-facing instance you cannot account for as a potential foothold and hunt it (EDR: VS Code tunnel processes, SYSVOL writes — see the brief's Warlock notes).

## Module 3 — VS Code tunnel / remote-access infrastructure

**Goal:** Warlock used Visual Studio Code tunnels for C2. Tunnel endpoints are discoverable in passive OSINT and make good watchlist material.

**OSINT sources:** certificate transparency, passive DNS (community data, VirusTotal).

**Queries:**
- crt.sh / CT logs: subdomains matching remote-access patterns under your domains (`*remote*`, `*tunnel*`, `*vscode*`, `*devtunnel*`) that you did not provision.
- VirusTotal / passive DNS: resolve those names historically — a tunnel endpoint that appeared days before an incident window and vanished after is worth pulling into the timeline.

**Triage:**
1. Any tunnel-pattern hostname on your domains that IT did not create → treat as suspicious until proven otherwise.
2. Correlate first-seen dates against your EDR timeline for the same window.

**Escalate:** unrecognized tunnel endpoint → block at the edge, hunt the endpoint that created it (EDR process-creation for tunnel binaries), rotate credentials on the box.

## Module 4 — Ransomware leak-site monitoring (Q3 record context)

**Goal:** Q3 2026 set the record at 2,627 claimed attacks with <10% victim confirmation — the incidents you hear about are a fraction. Maintain a standing OSINT watch for your sector.

**OSINT sources:** ransomware leak-site trackers (e.g. Ransomware.live), Tor-accessible leak blogs via a dedicated research VM.

**Queries:**
- Trackers: filter by your sector + region weekly; watch for Warlock, Qilin, Rhysida, and Majinahanashi posts naming organizations adjacent to yours (peers, vendors, customers).
- For each relevant claim: capture the alleged data categories and the proof pack (sample files) — they tell you what the crew actually had, which informs your own exposure review.

**Triage:**
1. Claims are leads, not breaches — require victim/regulator confirmation before treating as fact (per the brief: Rhysida's and Majinahanashi's Oct 12 claims are unverified).
2. A claim against a direct vendor → trigger your third-party incident process; ask the vendor for a statement and scope.

**Escalate:** confirmed claim against your organization → invoke the IR plan; confirmed claim against a critical vendor → assess shared data exposure.

---

## Appendix — Sample hunt queries (copy-paste)

All queries below are starting patterns — tune the country, ASN, and version filters to your estate. Replace `yourdomain.tld` with your own domains.

**Shodan**
```
http.title:"Metabase"
http.title:"Metabase" country:"CA"
http.title:"Metabase" country:"JP"
http.title:"SharePoint"
http.title:"SharePoint" http.html:"16.0.0."
http.title:"SharePoint" country:"CA"
```
`http.title:"Metabase"` is the baseline population; the `country:` variants scope it to home turf (CA) vs. the breach-wave geography (JP). The `http.html:"16.0.0."` pattern surfaces SharePoint build strings in indexed banners — compare hits against patched builds for the ToolShell chain and CVE-2026-45659.

**Censys Search**
```
services.http.response.html_title="Metabase"
services.http.response.html_title="SharePoint"
```
Second index to cross-check Shodan — deduplicate by IP:port and keep the union.

**urlscan.io**
```
page.title:"Metabase"
page.title:"SharePoint"
```
Catches exposed instances that scanners indexed via page crawls rather than banners; sort by scan date descending to spot newly exposed hosts first.

**Certificate transparency (crt.sh)**
```
q=%.yourdomain.tld   → filter results for: sharepoint, sp, metabase, bi, analytics, tunnel, remote, vscode
```
Finds forgotten SharePoint/Metabase hostnames and unrecognized tunnel-pattern subdomains on your own domains via certificates you may not know were issued.

**Triage order for every hit:** (1) dedupe across indexes, (2) resolve ASN/org — flag your netblocks, subsidiaries, and top vendors, (3) check for missing auth gates (setup wizard / open instance = critical), (4) record version strings and compare against current patched builds.

---

## False positives to expect

- **Honeypots and researchers** run intentionally exposed Metabase/SharePoint — check ASN and banner quirks before alerting.
- **Version strings lie**: banners can be masked by WAFs; treat OSINT version data as a prioritization signal, then confirm from inside.
- **Title collisions**: `http.title:"Metabase"` occasionally catches unrelated pages embedding the word — eyeball the Censys/Shodan screenshot before logging.

## What "done" looks like

A weekly run of Modules 1–2 against your netblocks and top-10 vendors, Module 3 as a standing CT watch, Module 4 as a weekly sector review — each producing either "no new exposure" or a ticket with an indexed URL, timestamp, ASN, and version string. OSINT hunting does not replace EDR/SIEM detection; it finds the doors before the EDR has to catch someone walking through them.
