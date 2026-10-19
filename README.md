# KQL Threat Hunting

Hunting queries from my research, written for Microsoft Defender (`Device*` tables, KQL) with Splunk SPL equivalents in [`queries/splunk/`](./queries/splunk/). Every query links back to the full write-up on my blog.

## Queries

| File | Technique | MITRE ATT&CK | Write-up |
|---|---|---|---|
| [powershell-obfuscation-amsi.kql](./queries/powershell-obfuscation-amsi.kql) | Obfuscated PowerShell + AMSI bypass | T1059.001, T1562.001 | [Hunting obfuscated PowerShell](https://amitvijayan.com/journal/articles/hunting-obfuscated-powershell-and-amsi.html) |
| [registry-runkey-persistence.kql](./queries/registry-runkey-persistence.kql) | Registry Run-key persistence | T1547.001 | [Hunting registry Run-key persistence](https://amitvijayan.com/journal/articles/hunting-registry-run-key-persistence.html) |
| [scheduled-task-persistence.kql](./queries/scheduled-task-persistence.kql) | Scheduled task persistence | T1053.005 | [Hunting scheduled task persistence](https://amitvijayan.com/journal/articles/hunting-scheduled-task-persistence.html) |
| [rdp-logon-anomalies.kql](./queries/rdp-logon-anomalies.kql) | RDP logon anomalies | T1021.001 | [Investigating unexpected RDP logons](https://amitvijayan.com/journal/articles/investigating-unexpected-rdp-logons.html) |
| [dns-tunneling.kql](./queries/dns-tunneling.kql) | DNS tunneling | T1048.003 | [Hunting DNS tunneling](https://amitvijayan.com/journal/articles/hunting-dns-tunneling-and-data.html) |
| [kerberoasting-rc4.kql](./queries/kerberoasting-rc4.kql) | Kerberoasting (RC4 tickets) | T1558.003 | [Hunting Kerberoasting](https://amitvijayan.com/journal/articles/hunting-kerberoasting-when-rc4-ticket.html) |
| [compromised-mailbox-phishing.kql](./queries/compromised-mailbox-phishing.kql) | Compromised mailbox phishing | T1078, T1534 | [Daily Cyber Threat Brief — October 6, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-6-2026.html) |
| [fortibleed-fortigate-admin-lockout.kql](./queries/fortibleed-fortigate-admin-lockout.kql) · [fortibleed-fortigate-admin-lockout.spl](./queries/splunk/fortibleed-fortigate-admin-lockout.spl) | FortiGate admin-account deletions and lockouts (FortiBleed) | T1190, T1078, T1562.001 | [Daily Cyber Threat Brief — October 9, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-9-2026.html) |
| [flax-typhoon-web-shells.kql](./queries/flax-typhoon-web-shells.kql) · [flax-typhoon-web-shells.spl](./queries/splunk/flax-typhoon-web-shells.spl) | Web-shell footholds on internet-facing servers (Flax Typhoon KEV wave) | T1190, T1505.003, T1059 | [Daily Cyber Threat Brief — October 10, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-10-2026.html) |
| [cve-2026-35273-oracle-peoplesoft.kql](./queries/cve-2026-35273-oracle-peoplesoft.kql) · [cve-2026-35273-oracle-peoplesoft.spl](./queries/splunk/cve-2026-35273-oracle-peoplesoft.spl) | Oracle PeopleSoft web-shell hunting (ShinyHunters CVE-2026-35273) | T1190, T1505.003, T1059 | [Daily Cyber Threat Brief — October 11, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-11-2026.html) |
| [warlock-ransomware-toolshell.kql](./queries/warlock-ransomware-toolshell.kql) · [warlock-ransomware-toolshell.spl](./queries/splunk/warlock-ransomware-toolshell.spl) | Warlock ransomware TTPs: BYOVD K7RKScan driver, VS Code tunnel C2, SYSVOL staging (SharePoint ToolShell chain) | T1190, T1562.001, T1572, T1486 | [Daily Cyber Threat Brief — October 12, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-12-2026.html) |
| [third-party-account-query-anomaly.kql](./queries/third-party-account-query-anomaly.kql) · [third-party-account-query-anomaly.spl](./queries/splunk/third-party-account-query-anomaly.spl) | Abused third-party account query-volume anomaly (Danish CPR registry breach) | T1078, T1530 | [Daily Cyber Threat Brief — October 13, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-13-2026.html) |
| [cve-2026-104935-ivanti-connect-secure.kql](./queries/cve-2026-104935-ivanti-connect-secure.kql) · [cve-2026-104935-ivanti-connect-secure.spl](./queries/splunk/cve-2026-104935-ivanti-connect-secure.spl) | Ivanti Connect Secure zero-day chain (UTA0576): auth bypass + upload file-write race to root, log-tamper + password-spray follow-on | T1190, T1070, T1110.001 | [Daily Cyber Threat Brief — October 14, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-14-2026.html) |
| [kev-security-appliance-exploitation.kql](./queries/kev-security-appliance-exploitation.kql) · [kev-security-appliance-exploitation.spl](./queries/splunk/kev-security-appliance-exploitation.spl) | CISA KEV Oct 14 wave (CVE-2026-0322, CVE-2026-76519, CVE-2026-105133, CVE-2026-105134): hunt exposed PAN-OS / Cisco SEG / AhsayCBS instances + AhsayCBS command-injection post-exploitation | T1190, T1059, T1070 | [Daily Cyber Threat Brief — October 15, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-15-2026.html) |
| [ai-agent-credential-reuse.kql](./queries/ai-agent-credential-reuse.kql) · [ai-agent-credential-reuse.spl](./queries/splunk/ai-agent-credential-reuse.spl) | Rogue AI agents: exposed-credential reuse + burst bulk reads (CERT-In CIAD-2026-0049) | T1552, T1078 | [Daily Cyber Threat Brief — October 16, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-16-2026.html) |
| [adfection-zero-click-spyware.kql](./queries/adfection-zero-click-spyware.kql) · [adfection-zero-click-spyware.spl](./queries/splunk/adfection-zero-click-spyware.spl) | Zero-click spyware via targeted ads (Candiru "AdFection"): hunt the mtrtb[.]com validator + browser-to-exploit-server handoff | T1189 | [Daily Cyber Threat Brief — October 17, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-17-2026.html) |
| [connectwise-service-principal-hijack.kql](./queries/connectwise-service-principal-hijack.kql) · [connectwise-service-principal-hijack.spl](./queries/splunk/connectwise-service-principal-hijack.spl) | Hijacked backup-vendor service principals (ConnectWise/SkyKick, 162 M365 tenants): scripted sign-ins + directory role self-grants + credential adds | T1078.004, T1550.001, T1098 | [Hunting Hijacked Vendor Service Principals](https://amitvijayan.com/journal/articles/hunting-hijacked-vendor-service-principals.html) |

## Playbooks

Step-by-step hunting playbooks using passive OSINT (Shodan, Censys, certificate transparency) — no scanning, index data only.

| File | Technique | MITRE ATT&CK | Write-up |
|---|---|---|---|
| [osint-japan-korea-breach-wave.md](./playbooks/osint-japan-korea-breach-wave.md) | OSINT hunt for exposed Metabase/SharePoint behind the Japan-Korea breach wave | T1595, T1596, T1190 | [Daily Cyber Threat Brief — October 12, 2026](https://amitvijayan.com/journal/articles/daily-cyber-threat-brief-october-12-2026.html) |

## Notes

- Time windows (`ago(14d)` etc.) are starting points — tighten them to your environment.
- Thresholds (scores, counts) are tuned for signal over noise; expect to baseline them.
- All queries are my own work, published under MIT. No employer data, ever.
