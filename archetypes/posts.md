---
title: "Campaign Name: Short Descriptive Subtitle"
date: {{ .Date }}
author: "ThreatProphet"
description: "One sentence summary for search engines and social sharing."
tags:
  - lazarus-group
  - contagious-interview
  - javascript
  - rat
  - linkedin-lure
  - blockchain
  - node-js
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.002
  - T1059.007
  - T1071.001
report_id: "TP-2026-001"
showToc: true
---

> *"[ Insert a short atmospheric or biblical opener relevant to the campaign — one sentence. ]"*

## Executive Summary

One to three paragraphs. Written for a technical audience but accessible to a non-specialist. Cover:
- What the attack was
- Who it targeted and how
- What made it technically notable
- Confidence level on attribution (if any)

---

## Attack Overview

### Initial Contact

How the victim was approached. Platform, lure type, social engineering pretext. Include screenshots or reconstructed timeline where available.

### Kill Chain

Step-by-step execution flow from initial contact to full compromise. Keep it tight — this should be scannable.

1. Step one
2. Step two
3. Step three

---

## Technical Analysis

### [Component 1 — e.g. Stage 1: Delivery Mechanism]

Detailed technical breakdown. Include code blocks where relevant.

```javascript
// Annotated code sample
```

### [Component 2 — e.g. Stage 2: Payload Staging]

Continue for each distinct technical component.

### [Component 3 — e.g. C2 Communication]

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | LinkedIn recruitment lure |
| T1059.007 | JavaScript | Execution | Node.js Function constructor |
| T1071.001 | Web Protocols | C2 | Plain HTTP beacon every 5s |

Full mapping: [ATT&CK Navigator Layer](#) *(optional)*

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| 163.245.194.216 | IP | C2 server, TCP/3000 |
| vscodesettingtask.vercel.app | Domain | Stage 1 delivery, inactive |

### Blockchain Infrastructure

| Address | Chain | Role |
|---|---|---|
| 0xE251b37B... | BSC | Payload staging contract |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| 163.245.194.216 | IPv4 | High |

### File Indicators

| Hash (SHA256) | Filename | Notes |
|---|---|---|
| `abc123...` | server.js | Malicious server component |

### Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| github.com/LuckyKat1001 | GitHub Account | Confirmed operator |

---

## Attribution Assessment

Assessed confidence: **Low / Medium / High**

Summary of attribution indicators. Always caveat: TTP similarity is not confirmed attribution.

Relevant prior reporting:
- [Unit42 — Contagious Interview](#)
- [CISA Advisory](#)

---

## Remediation

### If You Ran the Code

Brief prioritized action list for victims.

### Network-Level Detection

Specific detection rules, signatures, or queries.

### Host-Level Hardening

Preventive configuration changes.

---

## Appendix: Evidence Artifacts

| Artifact ID | Description | SHA256 |
|---|---|---|
| EX-001 | LinkedIn screenshot | `abc123...` |
| EX-002 | Malicious tasks.json | `def456...` |

---

*TLP:CLEAR — This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-001 | Published: {{ .Date }} | Author: ThreatProphet*
