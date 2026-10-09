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

## Notes

- Time windows (`ago(14d)` etc.) are starting points — tighten them to your environment.
- Thresholds (scores, counts) are tuned for signal over noise; expect to baseline them.
- All queries are my own work, published under MIT. No employer data, ever.
