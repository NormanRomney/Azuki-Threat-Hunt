# Azuki-Threat-Hunt
<img width="740" height="1110" alt="image" src="https://github.com/user-attachments/assets/ab77ae49-5a12-4766-8624-e7471a86846e" />

INCIDENT BRIEF - Azuki Import/Export - 梓貿易株式会社
SITUATION:
Competitor undercut our 6-year shipping contract by exactly 3%. Our supplier contracts and pricing data appeared on underground forums.
COMPANY:
Azuki Import/Export Trading Co. - 23 employees, shipping logistics Japan/SE Asia
COMPROMISED SYSTEMS:

AZUKI-SL (IT admin workstation)
EVIDENCE AVAILABLE:
Microsoft Defender for Endpoint logs

INVESTIGATION QUESTIONS:
Initial access method?
Compromised accounts?
Data stolen?
Exfiltration method?
Persistent access remaining?

DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))

🚩 Flag 1: INITIAL ACCESS - Remote Access Source
Remote Desktop Protocol connections leave network traces that identify the source of unauthorised access. Determining the origin helps with threat actor attribution and blocking ongoing attacks.
Question: Identify the source IP address of the Remote Desktop Protocol connection?
Answer: 88.97.178.12

Query:

DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated  between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType

Screen Shot of Results:



🚩 Flag 2: INITIAL ACCESS - Compromised User Account

Identifying which credentials were compromised determines the scope of unauthorised access and guides remediation efforts including password resets and privilege reviews.

Question: Identify the user account that was compromised for initial access?
Answer: kenji.sato

Query:

DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated  between (datetime(2025-11-19) .. datetime(2025-11-20))
| where isnotempty(RemoteIP)
| where ActionType == "LogonSuccess"
| project TimeGenerated, AccountName, DeviceName, ActionType, RemoteIP, RemoteIPType

Screen Shot of Results:

🚩 Flag 3: DISCOVERY - Network Reconnaissance

Attackers enumerate network topology to identify lateral movement opportunities and high-value targets. This reconnaissance activity is a key indicator of advanced persistent threats.

Question: Identify the command and argument used to enumerate network neighbours?
Answer: ARP.EXE -a

Query:
DeviceProcessEvents
| where TimeGenerated  between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where AccountName == "kenji.sato"
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine, InitiatingProcessCommandLine

Screen Shot of Results:


🚩Flag 4: DEFENCE EVASION - Malware Staging Directory

Attackers establish staging locations to organise tools and stolen data. Identifying these directories reveals the scope of compromise and helps locate additional malicious artefacts.

Question: Identify the PRIMARY staging directory where malware was stored?
Answer: C:\ProgramData\WindowsCache

Query:
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "kenji.sato"
| where TimeGenerated  between (datetime(2025-11-19) .. datetime(2025-11-20))
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, FileName, FolderPath

Screen Shot of Results:


🚩 Flag 5: DEFENCE EVASION - File Extension Exclusions
Attackers add file extension exclusions to Windows Defender to prevent scanning of malicious files. Counting these exclusions reveals the scope of the attacker's defense evasion strategy.

Question: How many file extensions were excluded from Windows Defender scanning?
Answer: 3

Query:
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Windows Defender\\Exclusions\\Extensions"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 6: DEFENCE EVASION - Temporary Folder Exclusion
Attackers add folder path exclusions to Windows Defender to prevent scanning of directories used for downloading and executing malicious tools. These exclusions allow malware to run undetected.

Question: What temporary folder path was excluded from Windows Defender scanning?
Answer: C:\Users\KENJI~1.SAT\AppData\Local\Temp

Query:
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RegistryKey contains "Windows Defender\\Exclusions\\Extensions"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 7: DEFENCE EVASION - Download Utility Abuse
Legitimate system utilities are often weaponized to download malware while evading detection. Identifying these techniques helps improve defensive controls.

Question: Identify the Windows-native binary the attacker abused to download files?
Answer: certutil.exe

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "certutil.exe"
| where ProcessCommandLine contains "-urlcache"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName

Screen Shot of Results:


🚩 Flag 8: PERSISTENCE - Scheduled Task Name
Scheduled tasks provide reliable persistence across system reboots. The task name often attempts to blend with legitimate Windows maintenance routines.
Question: Identify the name of the scheduled task created for persistence?
Answer: Windows Update Check
Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
Screen Shot of Results:

🚩 Flag 9: PERSISTENCE - Scheduled Task Target
The scheduled task action defines what executes at runtime. This reveals the exact persistence mechanism and the malware location.
Question: Identify the executable path configured in the scheduled task?
Answer: C:\ProgramData\WindowsCache\svchost.exe
Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "schtasks.exe"
| where ProcessCommandLine contains "/create"
| project TimeGenerated, InitiatingProcessAccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFileName
Screen Shot of Results:

🚩 Flag 10: COMMAND & CONTROL - C2 Server Address
Command and control infrastructure allows attackers to remotely control compromised systems. Identifying C2 servers enables network blocking and infrastructure tracking.

Question: Identify the IP address of the command and control server?
Answer: 78.141.196.6

Query:
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6"
| where RemotePort == 8080
| project TimeGenerated, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 11: COMMAND & CONTROL - C2 Communication Port
C2 communication ports can indicate the framework or protocol used. This information supports network detection rules and threat intelligence correlation.

Question: Identify the destination port used for command and control communications?
Answer: 443

Query:
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where RemoteIP == "78.141.196.6"
| where RemotePort == 443
| project TimeGenerated, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 12: CREDENTIAL ACCESS - Credential Theft Tool
Credential dumping tools extract authentication secrets from system memory. These tools are typically renamed to avoid signature-based detection.

Question: Identify the filename of the credential dumping tool?
Answer: mm.exe
Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "mm.exe"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, FolderPath

Screen Shot of Results:


🚩 Flag 13: CREDENTIAL ACCESS - Memory Extraction Module
Credential dumping tools use specific modules to extract passwords from security subsystems. Documenting the exact technique used aids in detection engineering.

Question: Identify the module used to extract logon passwords from memory?
Answer: sekurlsa::logonpasswords

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "sekurlsa::logonpasswords"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 14: COLLECTION - Data Staging Archive
Attackers compress stolen data for efficient exfiltration. The archive filename often includes dates or descriptive names for the attacker's organisation.

Question: Identify the compressed archive filename used for data exfiltration?
Answer: export-data.zip

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "export-data.zip"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 15: EXFILTRATION - Exfiltration Channel
Cloud services with upload capabilities are frequently abused for data theft. Identifying the service helps with incident scope determination and potential data recovery.

Question: Identify the cloud service used to exfiltrate stolen data?
Answer: Discord

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where ProcessCommandLine contains "discord.com"
| project TimeGenerated, AccountName, FileName, FolderPath, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine

Screen Shot of Results:


🚩 Flag 16: ANTI-FORENSICS - Log Tampering
Clearing event logs destroys forensic evidence and impedes investigation efforts. The order of log clearing can indicate attacker priorities and sophistication.

Question: Identify the first Windows event log cleared by the attacker?
Answer: Security

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "wevtutil.exe"
| where ProcessCommandLine contains "cl"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

Screen Shot of Results:


🚩 Flag 17: IMPACT - Persistence Account
Hidden administrator accounts provide alternative access for future operations. These accounts are often configured to avoid appearing in normal user interfaces.

Question: Identify the backdoor account username created by the attacker?

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "net.exe"
| where ProcessCommandLine contains "support"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

Screen Shot of Results:


🚩 Flag 18: EXECUTION - Malicious Script
Attackers often use scripting languages to automate their attack chain. Identifying the initial attack script reveals the entry point and automation method used in the compromise.

Question: Identify the PowerShell script file used to automate the attack chain?
Answer: wupdate.ps1

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "wupdate.ps1"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

Screen Shot of Results:


🚩 Flag 19: LATERAL MOVEMENT - Secondary Target
Lateral movement targets are selected based on their access to sensitive data or network privileges. Identifying these targets reveals attacker objectives.

Question: What IP address was targeted for lateral movement?
Answer: 10.1.0.188

Query:DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("mstsc.exe", "cmdkey.exe")
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

Screen Shot of Result:


Flag 20: LATERAL MOVEMENT - Remote Access Tool
Built-in remote access tools are preferred for lateral movement as they blend with legitimate administrative activity. This technique is harder to detect than custom tools.

Question: Identify the remote access tool used for lateral movement?
Answer: mstsc.exe

Query:
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where DeviceName == "azuki-sl"
| where FileName in ("mstsc.exe", "cmdkey.exe")
| where ProcessCommandLine contains "10.1.0.188"
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc

Screen Shot of Results:






