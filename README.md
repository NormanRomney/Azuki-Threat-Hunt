# Azuki-Threat-Hunt
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/ab77ae49-5a12-4766-8624-e7471a86846e" />

🛡 Threat Hunt Project: Azuki Import/Export Compromise
📌 Project Overview

This project documents a simulated threat hunt investigation involving Azuki Import/Export Trading Co. (梓貿易株式会社), a 23-employee shipping logistics company operating between Japan and Southeast Asia.

The organization experienced a competitive breach after confidential supplier contracts and pricing data appeared on underground forums. Investigation was conducted using Microsoft Defender for Endpoint telemetry.

🎯 Investigation Objectives

The hunt aimed to answer the following:

How did the attacker gain initial access?

Which accounts were compromised?

What data was stolen?

How was the data exfiltrated?

Did persistence remain on the system?

🖥 Environment

EDR Platform: Microsoft Defender for Endpoint

Primary Compromised System: AZUKI-SL (IT Admin Workstation)

Log Source Tables Used:

DeviceProcessEvents

DeviceLogonEvents

DeviceRegistryEvents

DeviceNetworkEvents

DeviceFileEvents

🔍 Attack Timeline & Findings
1️⃣ Initial Access

Technique: Remote Desktop Protocol (RDP)
Source IP: 88.97.178.12
Compromised Account: kenji.sato

An external RDP login was identified in DeviceLogonEvents. The attacker authenticated using valid credentials, indicating credential compromise rather than exploitation.

MITRE ATT&CK: T1021.001 – Remote Services (RDP)

2️⃣ Discovery

Command Executed:

ARP.EXE -a

The attacker enumerated local network neighbors to identify internal pivot targets.

MITRE ATT&CK: T1016 – System Network Configuration Discovery

3️⃣ Defense Evasion
Malware Staging Directory
C:\ProgramData\WindowsCache

The directory was created and hidden to store malicious payloads.

Windows Defender Exclusions

3 file extensions excluded

Temp folder excluded:

C:\Users\KENJI~1.SAT\AppData\Local\Temp
Living-off-the-Land Download Utility
certutil.exe

Used to download malicious payloads.

MITRE ATT&CK:

T1562 – Impair Defenses

T1218 – Signed Binary Proxy Execution

4️⃣ Persistence
Scheduled Task Created

Task Name:

Windows Update Check

Execution Target:

C:\ProgramData\WindowsCache\svchost.exe
Backdoor Local Administrator Account
support

The attacker ensured long-term access via both scheduled task and hidden admin account.

MITRE ATT&CK:

T1053.005 – Scheduled Task

T1136 – Create Account

5️⃣ Command & Control

C2 Server: 78.141.196.6
Port: 443

Outbound HTTPS communications were established from the staged malware.

MITRE ATT&CK: T1071.001 – Web Protocols

6️⃣ Credential Access

Credential Dumping Tool: mm.exe
Module Used:

sekurlsa::logonpasswords

The attacker used a renamed instance of Mimikatz to extract credentials from LSASS memory.

MITRE ATT&CK: T1003.001 – OS Credential Dumping (LSASS)

7️⃣ Collection & Staging

Archive Created:

export-data.zip

Sensitive pricing and supplier contract data were compressed for exfiltration.

MITRE ATT&CK: T1560 – Archive Collected Data

8️⃣ Exfiltration

Cloud Service Used: Discord

The attacker abused Discord’s upload functionality to exfiltrate stolen data over HTTPS.

MITRE ATT&CK: T1567.002 – Exfiltration Over Web Service

9️⃣ Anti-Forensics

First Log Cleared:

Security

The attacker used wevtutil.exe to clear Windows event logs.

MITRE ATT&CK: T1070.001 – Clear Windows Event Logs

🔟 Lateral Movement

Target IP: 10.1.0.188
Tool Used: mstsc.exe

The attacker pivoted internally using built-in RDP tools.

MITRE ATT&CK: T1021.001 – Remote Services

📊 Full Attack Chain Mapping (MITRE ATT&CK)
Phase	Technique	ID
Initial Access	Remote Services (RDP)	T1021.001
Discovery	Network Enumeration	T1016
Defense Evasion	Modify Defender	T1562
Execution	Living-off-the-Land Binary	T1218
Persistence	Scheduled Task	T1053.005
Credential Access	LSASS Dumping	T1003.001
Collection	Archive Data	T1560
Exfiltration	Web Service	T1567.002
Impact	Account Creation	T1136
Anti-Forensics	Clear Event Logs	T1070.001
🚨 Impact Assessment
Confirmed Data Exposure

Supplier contracts

Pricing agreements

Potential credential compromise

Business Impact

Competitive undercutting (3% contract loss)

Reputation risk

Potential regulatory implications

🛠 Remediation Actions Recommended

Disable external RDP access

Enforce MFA for all administrative accounts

Remove scheduled task and backdoor account

Remove Defender exclusions

Block C2 IP at firewall

Conduct full credential reset across privileged users

Review outbound web traffic policies

🧠 Detection Engineering Opportunities

Detections should be implemented for:

certutil.exe with external URL

schtasks.exe /create

LSASS memory access

wevtutil.exe cl

RDP logins from external IPs

Defender exclusion registry changes

Outbound traffic to non-approved cloud services (e.g., Discord)

🧾 Skills Demonstrated

Endpoint telemetry analysis (MDE)

KQL investigation

MITRE ATT&CK mapping

Credential compromise analysis

Persistence mechanism identification

Cloud exfiltration detection

Incident reporting & documentation
