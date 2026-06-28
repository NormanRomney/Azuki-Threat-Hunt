<p align="center">
  <img src="https://github.com/user-attachments/assets/337bb215-8833-4653-b570-93c443bd9c11" width="1200" alt="Threat Hunt Cover Image"/>
</p>

# 🛡️ Threat Hunt Report – Azuki Import/Export Trading Co.
### 梓貿易株式会社 | Corporate Espionage & Data Exfiltration

---

## 📌 Executive Summary

On 19 November 2025, Azuki Import/Export Trading Co. suffered a targeted cyber intrusion resulting in the theft of confidential shipping contracts and supplier pricing data. An attacker gained initial access via Remote Desktop Protocol using compromised credentials belonging to IT administrator **kenji.sato**, originating from external IP **88.97.178.12**.

The attacker deployed a fully automated PowerShell attack chain (`wupdate.ps1`) that established persistence, disabled Windows Defender, downloaded credential theft tools, exfiltrated data to Discord, and pivoted laterally to a secondary internal host. The intrusion explains how a competitor was able to undercut Azuki's 6-year shipping contract by exactly 3% — the stolen pricing data provided precise intelligence for the bid.

A total of **20 threat hunting flags** were identified across process, network, registry, and file telemetry from Microsoft Defender for Endpoint. The attack demonstrates sophisticated Living off the Land (LOLBin) techniques with minimal custom tooling.

---

## 🎯 Hunt Objectives

- Identify malicious activity across endpoints and network telemetry
- Correlate attacker behaviour to MITRE ATT&CK techniques
- Document evidence, detection gaps, and response opportunities

---

## 🧭 Scope & Environment

| Field | Detail |
|-------|--------|
| **Organisation** | Azuki Import/Export Trading Co. – 梓貿易株式会社 |
| **Compromised Host** | AZUKI-SL (IT Admin Workstation) |
| **Lateral Movement Target** | 10.1.0.188 |
| **Compromised Account** | kenji.sato |
| **Attacker IP** | 88.97.178.12 |
| **C2 Server** | 78.141.196.6:443 |
| **Timeframe** | 2025-11-19 00:00 UTC → 2025-11-20 00:00 UTC |
| **Data Sources** | Microsoft Defender for Endpoint (DeviceProcessEvents, DeviceNetworkEvents, DeviceRegistryEvents, DeviceFileEvents, DeviceLogonEvents) |
| **Total Flags** | 20 |

---

## 🧠 Hunt Overview & Attack Narrative

The attacker gained access using stolen credentials for `kenji.sato` via RDP from IP `88.97.178.12`. Upon establishing a session on AZUKI-SL, a batch file (`WindowsUpdate.bat`) was executed from the Downloads folder, triggering the download of `wupdate.bat` and subsequently `wupdate.ps1` from the C2 server at `78.141.196.6`.

The PowerShell script automated the entire attack lifecycle: it created a hidden staging directory (`C:\ProgramData\WindowsCache`), added Windows Defender exclusions for key file types and paths, downloaded a malware beacon (disguised as `svchost.exe`) and Mimikatz (disguised as `AdobeGC.exe`, saved as `mm.exe`) via the LOLBin `certutil.exe`, and created a scheduled task for daily persistence.

Credential theft was performed using Mimikatz's `sekurlsa::logonpasswords` module against LSASS memory. The dumped credentials enabled lateral movement to `10.1.0.188` as the `fileadmin` account using the native `mstsc.exe` RDP client. A backdoor account named `support` was created with local administrator rights for redundant persistence.

Stolen data was archived to `export-data.zip` and exfiltrated via `curl.exe` to a Discord webhook — abusing a trusted platform to evade network controls. Finally, the attacker cleared the Security, System, and Application event logs using `wevtutil.exe` in an attempt to destroy forensic evidence.

---

## ⏱️ Attack Timeline

| Time (UTC ~) | Event |
|-------------|-------|
| 18:30 | Initial RDP access from `88.97.178.12` using `kenji.sato` credentials |
| 18:32 | `WindowsUpdate.bat` downloaded and executed from Downloads folder |
| 18:33 | `wupdate.bat` downloaded to Temp via `Invoke-WebRequest` |
| 18:34 | `wupdate.ps1` downloaded to Temp; Windows Defender exclusions set |
| 18:35 | `C:\ProgramData\WindowsCache` staging directory created (hidden + system) |
| 18:36 | `svchost.exe` malware beacon downloaded via `certutil.exe` |
| 18:37 | `AdobeGC.exe` (Mimikatz) downloaded as `mm.exe` via `certutil.exe` |
| 18:38 | Scheduled task `Windows Update Check` created for daily persistence |
| 18:40 | System reconnaissance: `ipconfig`, `whoami`, `systeminfo`, `ARP -a`, `hostname` |
| 18:45 | `mm.exe` executed: `privilege::debug` + `sekurlsa::logonpasswords` |
| 18:47 | Backdoor account `support` created and added to Administrators |
| 18:50 | Data collected and archived to `export-data.zip` |
| 18:52 | `export-data.zip` exfiltrated to Discord webhook via `curl.exe` |
| 18:54 | Lateral movement: `cmdkey` + `mstsc.exe` → `10.1.0.188` as `fileadmin` |
| 18:58 | Event logs cleared: Security, System, Application (`wevtutil cl`) |

---

## 🧬 MITRE ATT&CK Summary

| # | Category | Technique | MITRE ID | Priority |
|--:|----------|-----------|----------|----------|
| 1 | Initial Access | Remote Access Source | T1078 | 🔴 Critical |
| 2 | Initial Access | Compromised User Account | T1078 | 🔴 Critical |
| 3 | Discovery | Network Reconnaissance | T1018 | 🟠 High |
| 4 | Defence Evasion | Malware Staging Directory | T1074.001 | 🟠 High |
| 5 | Defence Evasion | File Extension Exclusions | T1562.001 | 🟠 High |
| 6 | Defence Evasion | Temporary Folder Exclusion | T1562.001 | 🟠 High |
| 7 | Defence Evasion | Download Utility Abuse (LOLBin) | T1218 | 🟠 High |
| 8 | Persistence | Scheduled Task Name | T1053.005 | 🔴 Critical |
| 9 | Persistence | Scheduled Task Target | T1053.005 | 🔴 Critical |
| 10 | Command & Control | C2 Server IP Address | T1071.001 | 🔴 Critical |
| 11 | Command & Control | C2 Communication Port | T1571 | 🟠 High |
| 12 | Credential Access | Credential Dumping Tool | T1003.001 | 🔴 Critical |
| 13 | Credential Access | Memory Extraction Module | T1003.001 | 🔴 Critical |
| 14 | Collection | Data Staging Archive | T1560.001 | 🟠 High |
| 15 | Exfiltration | Exfiltration Channel | T1567.002 | 🔴 Critical |
| 16 | Anti-Forensics | Event Log Tampering | T1070.001 | 🟠 High |
| 17 | Persistence | Backdoor Account Creation | T1136.001 | 🔴 Critical |
| 18 | Execution | Malicious Automation Script | T1059.001 | 🔴 Critical |
| 19 | Lateral Movement | Secondary Target | T1021.001 | 🔴 Critical |
| 20 | Lateral Movement | Remote Access Tool | T1021.001 | 🟠 High |

---

## 🔍 Flag Analysis

---

<details>
<summary>🚩 <strong>Flag 1 – INITIAL ACCESS: Remote Access Source</strong></summary>

### 🎯 Objective
Identify the source IP of the unauthorised RDP connection to attribute the intrusion.

### 📌 Finding
An external IP address successfully authenticated via RDP to the AZUKI-SL workstation outside business hours.

### ✅ Answer
```
88.97.178.12
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Account | kenji.sato |
| Action | LogonSuccess |
| Remote IP | 88.97.178.12 |
| Protocol | RDP |

### 💡 Why It Matters
This is the initial foothold. The external IP represents the attacker's origin and should be blocked at the firewall immediately. Attribution may be possible through threat intelligence correlation.

### 🔧 KQL Query

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```

</details>

---

<details>
<summary>🚩 <strong>Flag 2 – INITIAL ACCESS: Compromised User Account</strong></summary>

### 🎯 Objective
Identify which credentials were used for unauthorised access to determine scope of compromise.

### 📌 Finding
The account `kenji.sato` was used to authenticate via RDP from the external attacker IP.

### ✅ Answer
```
kenji.sato
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Account | kenji.sato |
| Remote IP | 88.97.178.12 |
| Action | LogonSuccess |

### 💡 Why It Matters
Compromised credentials are the entry vector. The account must be disabled immediately, the password reset, and all active sessions terminated.

### 🔧 KQL Query

```kql
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType
```

</details>

---

<details>
<summary>🚩 <strong>Flag 3 – DISCOVERY: Network Reconnaissance</strong></summary>

### 🎯 Objective
Identify network enumeration commands run to discover lateral movement targets.

### 📌 Finding
`ARP.EXE` was executed with the `-a` flag to enumerate network neighbours and map active hosts on the subnet.

### ✅ Answer
```
ARP.EXE -a
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Process | ARP.EXE |
| Arguments | -a |
| Account | kenji.sato |
| Parent Process | wupdate.ps1 (PowerShell) |

### 💡 Why It Matters
ARP enumeration maps active hosts on the subnet, providing the attacker with lateral movement targets. This was part of broader reconnaissance including `ipconfig`, `whoami`, `systeminfo`, and `hostname`.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 4 – DEFENCE EVASION: Malware Staging Directory</strong></summary>

### 🎯 Objective
Locate the primary directory used to store and organise attack tools and stolen data.

### 📌 Finding
The attacker created a hidden directory `C:\ProgramData\WindowsCache` to stage all malware, setting hidden and system attributes to conceal it.

### ✅ Answer
```
C:\ProgramData\WindowsCache
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Directory | C:\ProgramData\WindowsCache |
| Files Staged | svchost.exe, mm.exe, export-data.zip |
| Attributes Set | +h +s (hidden, system) |

### 💡 Why It Matters
The directory name mimics legitimate Windows system paths. `C:\ProgramData` is writable without UAC, making it a common attacker staging location. All subsequent attack activity originated from here.

### 🔧 KQL Query

```kql
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, FileName, FolderPath
```

</details>

---

<details>
<summary>🚩 <strong>Flag 5 – DEFENCE EVASION: File Extension Exclusions</strong></summary>

### 🎯 Objective
Determine how many file types were excluded from Windows Defender scanning.

### 📌 Finding
Three file extensions were added to Windows Defender exclusions via registry: `.exe`, `.ps1`, and `.bat`.

### ✅ Answer
```
3
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Registry Key | HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions |
| Extension 1 | .exe |
| Extension 2 | .ps1 |
| Extension 3 | .bat |
| Action | RegistryValueSet |

### 💡 Why It Matters
Excluding the exact file types used in the attack ensured Defender would not scan or quarantine malicious tools, effectively blinding the AV engine across all attack vectors.

### 🔧 KQL Query

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Windows Defender\\Exclusions\\Extensions"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 6 – DEFENCE EVASION: Temporary Folder Exclusion</strong></summary>

### 🎯 Objective
Identify which folder paths were excluded from Defender scanning to allow malicious scripts to run.

### 📌 Finding
The user Temp directory was excluded from Defender so scripts downloaded there would not be scanned on arrival or execution.

### ✅ Answer
```
C:\Users\KENJI~1.SAT\AppData\Local\Temp
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Registry Key | HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths |
| Path 1 Excluded | C:\Users\KENJI~1.SAT\AppData\Local\Temp |
| Path 2 Excluded | C:\ProgramData\WindowsCache |
| Action | RegistryValueSet |

### 💡 Why It Matters
Both `wupdate.bat` and `wupdate.ps1` were downloaded to this Temp folder. Excluding it prevented Defender from flagging the malicious scripts on arrival, enabling their execution without AV interference.

### 🔧 KQL Query

```kql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Windows Defender\\Exclusions\\Paths"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 7 – DEFENCE EVASION: Download Utility Abuse (LOLBin)</strong></summary>

### 🎯 Objective
Identify the native Windows binary weaponised to download malware from the C2 server.

### 📌 Finding
`certutil.exe` was used with `-urlcache -f` to download two malware payloads from the C2 server.

### ✅ Answer
```
certutil.exe
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Binary | certutil.exe |
| C2 Server | http://78.141.196.6:8080 |
| Download 1 | svchost.exe → C:\ProgramData\WindowsCache\svchost.exe |
| Download 2 | AdobeGC.exe → C:\ProgramData\WindowsCache\mm.exe |

### 💡 Why It Matters
`certutil.exe` is a trusted, signed Microsoft binary that can bypass application whitelisting. The `-urlcache -f` flag was designed for certificate revocation lists but works equally well for downloading arbitrary files — a well-known LOLBin technique.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "certutil.exe"
| where ProcessCommandLine contains "-urlcache"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```

</details>

---

<details>
<summary>🚩 <strong>Flag 8 – PERSISTENCE: Scheduled Task Name</strong></summary>

### 🎯 Objective
Identify the scheduled task created to maintain persistence across system reboots.

### 📌 Finding
A scheduled task named `Windows Update Check` was created to execute the malware beacon daily at 02:00 AM as SYSTEM.

### ✅ Answer
```
Windows Update Check
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Task Name | Windows Update Check |
| Schedule | Daily at 02:00 AM |
| Run As | SYSTEM |
| Created Via | schtasks.exe /create |

### 💡 Why It Matters
The task name is designed to blend with legitimate Windows maintenance. Running as SYSTEM with daily execution ensures the malware beacon survives reboots with maximum privilege.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```

</details>

---

<details>
<summary>🚩 <strong>Flag 9 – PERSISTENCE: Scheduled Task Target Executable</strong></summary>

### 🎯 Objective
Identify the malware path configured in the scheduled task to understand the persistence mechanism.

### 📌 Finding
The task is configured to run `C:\ProgramData\WindowsCache\svchost.exe` — the malware beacon disguised as a legitimate Windows process name.

### ✅ Answer
```
C:\ProgramData\WindowsCache\svchost.exe
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Task Run Path | C:\ProgramData\WindowsCache\svchost.exe |
| Disguised As | svchost.exe (legitimate Windows process name) |
| Schedule | /sc daily /st 02:00 |
| Privilege | /ru SYSTEM |

### 💡 Why It Matters
The malware is named `svchost.exe` to masquerade as a legitimate Windows Service Host. Located in the hidden staging directory, it executes nightly as SYSTEM — a privileged, stealthy persistence mechanism.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
```

</details>

---

<details>
<summary>🚩 <strong>Flag 10 – COMMAND & CONTROL: C2 Server IP Address</strong></summary>

### 🎯 Objective
Identify the attacker's C2 server for immediate blocking and threat intelligence correlation.

### 📌 Finding
All malicious downloads and C2 communications originated from a single server at `78.141.196.6`.

### ✅ Answer
```
78.141.196.6
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| C2 IP | 78.141.196.6 |
| Payload 1 | wupdate.bat |
| Payload 2 | wupdate.ps1 |
| Payload 3 | svchost.exe (beacon) |
| Payload 4 | AdobeGC.exe (Mimikatz) |

### 💡 Why It Matters
This single server hosted all malicious payloads and received C2 beacon check-ins. Blocking this IP at the perimeter and in EDR is an immediate containment action.

### 🔧 KQL Query

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6"
| where RemotePort == 443
| project TimeGenerated, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 11 – COMMAND & CONTROL: C2 Communication Port</strong></summary>

### 🎯 Objective
Identify the actual network port used for C2 communications per endpoint network telemetry.

### 📌 Finding
Network telemetry shows C2 communications occurred over **port 443 (HTTPS)**, not port 8080 as seen in process command lines. The C2 server likely proxied 8080 internally to 443 externally.

### ✅ Answer
```
443
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| C2 IP | 78.141.196.6 |
| Actual Port (Network Logs) | 443 (HTTPS) |
| Port Seen in Commands | 8080 (server-side proxy) |
| Data Source | DeviceNetworkEvents |

### 💡 Why It Matters
Port 443 allows C2 traffic to blend seamlessly with normal HTTPS traffic, evading port-based firewall rules. Always corroborate process command-line evidence with actual network telemetry — they can tell different parts of the story.

### 🔧 KQL Query

```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6"
| where RemotePort == 443
| project TimeGenerated, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 12 – CREDENTIAL ACCESS: Credential Dumping Tool</strong></summary>

### 🎯 Objective
Identify the renamed credential theft tool used to extract passwords and hashes from memory.

### 📌 Finding
Mimikatz was downloaded disguised as `AdobeGC.exe` and saved as `mm.exe` to evade filename-based AV detection.

### ✅ Answer
```
mm.exe
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Filename | mm.exe |
| Downloaded As | AdobeGC.exe |
| True Tool | Mimikatz |
| Location | C:\ProgramData\WindowsCache\mm.exe |

### 💡 Why It Matters
Renaming Mimikatz bypasses signature-based AV detection. The tool extracts plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS memory, enabling lateral movement.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "mm.exe"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath
```

</details>

---

<details>
<summary>🚩 <strong>Flag 13 – CREDENTIAL ACCESS: Memory Extraction Module</strong></summary>

### 🎯 Objective
Identify the specific Mimikatz module used to extract credentials from LSASS memory.

### 📌 Finding
The `sekurlsa::logonpasswords` module was executed against LSASS to dump plaintext passwords and NTLM hashes.

### ✅ Answer
```
sekurlsa::logonpasswords
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Tool | mm.exe (Mimikatz) |
| Module 1 | privilege::debug (acquire debug rights) |
| Module 2 | sekurlsa::logonpasswords (dump credentials) |
| Target | LSASS process memory |

### 💡 Why It Matters
This module extracts plaintext passwords, NTLM hashes, and Kerberos tickets from LSASS. The dumped credentials for `fileadmin` were subsequently used to RDP into `10.1.0.188`.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "sekurlsa::logonpasswords"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 14 – COLLECTION: Data Staging Archive</strong></summary>

### 🎯 Objective
Identify the archive file created to package stolen data for exfiltration.

### 📌 Finding
A ZIP archive named `export-data.zip` was created in the staging directory by `wupdate.ps1`, containing the stolen company data.

### ✅ Answer
```
export-data.zip
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Archive Name | export-data.zip |
| Full Path | C:\ProgramData\WindowsCache\export-data.zip |
| Created By | wupdate.ps1 |
| Contents | Stolen shipping contracts and pricing data |

### 💡 Why It Matters
Compression reduces transfer size and packages all stolen files into a single payload. The filename `export-data` suggests the attacker had specific knowledge of the data they were targeting.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "export-data.zip"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 15 – EXFILTRATION: Exfiltration Channel</strong></summary>

### 🎯 Objective
Identify the cloud platform abused to exfiltrate stolen data outside the network.

### 📌 Finding
`curl.exe` was used to POST `export-data.zip` to a Discord webhook URL, abusing the platform as an exfiltration channel.

### ✅ Answer
```
Discord
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Tool | curl.exe |
| Platform | Discord (discord.com/api/webhooks/...) |
| Method | HTTP POST via webhook |
| File Sent | C:\ProgramData\WindowsCache\export-data.zip |

### 💡 Why It Matters
Discord is a trusted platform rarely blocked by enterprise firewalls. Webhook-based exfiltration blends with normal HTTPS traffic on port 443 and requires no dedicated attacker infrastructure — a Living off Trusted Sites (LoTS) technique.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "discord.com"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
```

</details>

---

<details>
<summary>🚩 <strong>Flag 16 – ANTI-FORENSICS: Event Log Tampering</strong></summary>

### 🎯 Objective
Identify the sequence and first Windows event log cleared by the attacker to destroy evidence.

### 📌 Finding
`wevtutil.exe` was used to clear three logs in sequence: **Security** first, then System, then Application.

### ✅ Answer
```
Security
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Tool | wevtutil.exe |
| 1st Log Cleared | Security |
| 2nd Log Cleared | System |
| 3rd Log Cleared | Application |

### 💡 Why It Matters
The Security log was cleared first as it contains logon events, privilege use, and access records — the most incriminating evidence. Without SIEM log forwarding, this action successfully destroyed local forensic evidence.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine contains "cl"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

</details>

---

<details>
<summary>🚩 <strong>Flag 17 – PERSISTENCE: Backdoor Account Creation</strong></summary>

### 🎯 Objective
Identify the hidden administrator account created to maintain privileged persistent access.

### 📌 Finding
A local account named `support` was created via `net.exe` and immediately added to the Administrators group.

### ✅ Answer
```
support
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Username | support |
| Group | Administrators |
| Tool | net.exe |
| Commands | net user support /add → net localgroup Administrators support /add |

### 💡 Why It Matters
The `support` name mimics a legitimate IT helpdesk account. With local admin rights, the attacker retains privileged persistent access even if `kenji.sato` is disabled or the primary foothold is removed.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "net.exe"
| where ProcessCommandLine contains "support"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

</details>

---

<details>
<summary>🚩 <strong>Flag 18 – EXECUTION: Malicious Automation Script</strong></summary>

### 🎯 Objective
Identify the PowerShell script that automated the full attack chain post-access.

### 📌 Finding
`wupdate.ps1` was downloaded from the C2 server and executed with `-ExecutionPolicy Bypass` to automate all attack activities.

### ✅ Answer
```
wupdate.ps1
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Script | wupdate.ps1 |
| Path | C:\Users\kenji.sato\AppData\Local\Temp\wupdate.ps1 |
| Downloaded From | http://78.141.196.6:8080/wupdate.ps1 |
| Execution Flag | -ExecutionPolicy Bypass |

### 💡 Why It Matters
This single script automated reconnaissance, AV evasion, malware staging, credential dumping, persistence, backdoor creation, exfiltration, lateral movement, and log clearing — the complete attack chain from one orchestrated payload.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "wupdate.ps1"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

</details>

---

<details>
<summary>🚩 <strong>Flag 19 – LATERAL MOVEMENT: Secondary Target</strong></summary>

### 🎯 Objective
Identify the internal system the attacker pivoted to after credential dumping.

### 📌 Finding
`cmdkey.exe` was used to store `fileadmin` credentials for `10.1.0.188`, followed immediately by an `mstsc.exe` RDP connection to that host.

### ✅ Answer
```
10.1.0.188
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Target IP | 10.1.0.188 |
| Credential Used | fileadmin (obtained via Mimikatz) |
| Tool 1 | cmdkey.exe (credential pre-storage) |
| Tool 2 | mstsc.exe (RDP connection) |

### 💡 Why It Matters
The `fileadmin` account name strongly suggests this target is a file server — the likely source of the stolen shipping contracts and pricing data. This was a targeted, intelligence-driven pivot.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("mstsc.exe", "cmdkey.exe")
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

</details>

---

<details>
<summary>🚩 <strong>Flag 20 – LATERAL MOVEMENT: Remote Access Tool</strong></summary>

### 🎯 Objective
Identify the built-in Windows tool used to move laterally to the secondary target.

### 📌 Finding
`mstsc.exe` (Microsoft Terminal Services Client) was used to establish an RDP connection to `10.1.0.188` using pre-stored `fileadmin` credentials.

### ✅ Answer
```
mstsc.exe
```

### 🔍 Evidence

| Field | Value |
|-------|-------|
| Host | azuki-sl |
| Tool | mstsc.exe |
| Full Name | Microsoft Terminal Services Client |
| Target | 10.1.0.188 |
| Argument | /v:10.1.0.188 |

### 💡 Why It Matters
`mstsc.exe` is a signed Windows binary that generates legitimate-looking RDP traffic on port 3389. Using it for lateral movement is a classic Living off the Land technique that blends with normal administrative activity and is harder to detect than third-party remote access tools.

### 🔧 KQL Query

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("mstsc.exe", "cmdkey.exe")
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

</details>

---

## 🚨 Detection Gaps & Recommendations

### Observed Gaps

1. No alerting on RDP logons from external/unknown IPs outside business hours
2. Windows Defender exclusions were added without triggering any alert or review workflow
3. `certutil.exe` network activity (`-urlcache`) was not flagged despite being a known LOLBin
4. Discord webhook exfiltration was not blocked or detected at the network layer
5. Event log clearing (`wevtutil cl`) did not trigger a high-priority alert
6. Local account creation (`net user /add`) outside provisioning systems was not flagged

### Recommendations

1. Implement Conditional Access policies to restrict RDP to known IP ranges and require MFA
2. Alert in real time on any changes to Windows Defender exclusion registry keys
3. Deploy process execution rules to alert on `certutil.exe -urlcache` and `schtasks /create`
4. Block outbound connections to `discord.com/api/webhooks` at the proxy/firewall level
5. Enable SIEM log forwarding so local event log clearing cannot destroy evidence
6. Enable LSASS protection (RunAsPPL) and Credential Guard to prevent memory dumping
7. Alert immediately on local Administrator group membership changes

---

## 🧾 Final Assessment

This intrusion represents a sophisticated, targeted corporate espionage operation. The attacker demonstrated advanced operational security awareness — using LOLBins throughout, renaming tools to evade detection, abusing trusted cloud services for exfiltration, and clearing forensic evidence on exit.

The attack was motivated by competitive intelligence. The precision of the competitor's contract underbid (exactly 3%) strongly corroborates that the stolen pricing data was directly operationalised. The attacker's familiarity with the environment — targeting the `fileadmin` account and pivoting to what is likely a file server — suggests either prior reconnaissance or an insider element.

**Immediate remediation actions:**
- Disable `kenji.sato` and `support` accounts
- Remove the `Windows Update Check` scheduled task
- Delete `C:\ProgramData\WindowsCache` and all contents
- Block `88.97.178.12` and `78.141.196.6` at the perimeter firewall and EDR
- Initiate a full compromise assessment on `10.1.0.188`
- Reset credentials for `fileadmin` and any accounts with access to pricing/contract data

---

## 📎 Analyst Notes

- Report structured for threat hunt portfolio and incident response review
- All 20 flags are reproducible via the KQL queries provided in each section
- MITRE ATT&CK techniques mapped directly to observed evidence
- Timeline reconstructed from process event timestamps across multiple MDE data sources
- KQL queries tested against `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceFileEvents`, and `DeviceLogonEvents`

---

*Classification: CONFIDENTIAL | Azuki Import/Export Trading Co. Threat Hunt | 2025-11-19*
