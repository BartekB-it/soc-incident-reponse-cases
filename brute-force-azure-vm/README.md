# Incident Response Mini-Case: Azure VM Brute Force Attempts (Microsoft Sentinel + Defender)

## Executive Summary

On **2025-11-18 at 17:07 UTC** the custom analytics rule **“Brute Force Attempt Detection”** in Microsoft Sentinel fired. Over the last 5 hours, **17 public IP addresses** attempted to log in to **21 Azure VMs**, generating roughly **550 failed logon attempts**. 

No logon successes from those IPs were found.
Affected VMs were isolated, antivirus scans were run, NSG rules were restricted, and follow-up detection and hardening actions were proposed.

The incident was closed as **True Positive - suspicious activity**, with **no confirmed compromise**.

---

## Scenario / Context

The SOC received a Sentinel incident based on the rule:

> Same remote IP address has failed to log in to the same local host (Azure VM) 10 times or more withing the last 5 hours.

Goal of the investigation:

- confirm whether brute force attempts were real,
- check if any attempts succeeded,
- contain exposed assets,
- propose improvements to detections, NSG defaults and runbooks.

---

## Tools & Platforms

- **Microsoft Sentinel** - analytics rule, incidents, investigation graph, KQL
- **Microsoft Defender for Endpoint** - device isolation, AV scans, recommendations
- **Microsoft Azure** - NSG inbound rules for exposed VMs
- **Kusto Query Language (KQL)** - log analysis in `DeviceLogonEvents`

---

## Detection & Inital Triage

1. **Sentinel incident overview**

   - Rule: `Bartek - Brute Force Attempt Detection`
   - Severity: `Medium`
   - Evidence: 21 related events, 1 alert
   - Tactic / Technique: `Credential Access (T1110.001 - Password Guessing)`
  
     _Screenshot:_ incident list + incident details
     `![Sentinel incident](screenshots/sentinel-incident-overview.png)`

2. **KQL - confirm brute-force pattern**

```kql
DeviceLogonEvents
| where ActionType == “LogonFailed” and TimeGenerated > ago(5h)
| summarize EventCount=count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

This query showed:
- **21 VMs** targeted,
- **17 unique RemoteIP values**,
- up to **137 failed logons** per IP/VM pair,
- **~550 failed logons** in total.

  _Screenshot:_ KQL results table
  ![KQL failed logons](screenshots/kql-failed-logons.png)

---

## Investigation Steps

### 1. Claim and activate the incident

- Assigned the incident to myself and changed status from `New` to `Active`.
- Opened the **Investigation graph** to visualise all affected VMs and relationships.

  _Screenshot:_ investigation graph with multiple VMs tied to one incident
  ![Investigation graph](screenshots/investigation-graph.png)

### 2. Containment - devices & network

For each affected VM:
1. Opened the device page in **Microsoft Defender for Endpoint** to validate risk level recommendations.

  _Screenshots:_ device overview (risk level High, exposure Medium, discovered vulns)
  ![Defender device overview](screenshots/defender-device-overview.png)

2. Ran an **antivirus scan* from Defender portal (no malware found).
3. In **Azure NSG**, restricted inbound access:
   - replaced "open to Internet" rules with a rule allowing RDP/SSH only from a specific admin IP.
   - goal: stop random Internet brute-force attempts while keeping controlled admin access.
  
   _Screenshots:_ NSG inbound rule (RDP, single IP, TCP)
   ![NSG rule](screenshots/nsg-rdp-rule.png)

### 3. Check for successful logons

I searched in DeviceLogonEvents with the exact KQL query that our detection for Brute Force Attempts used:

```kql
DeviceLogonEvents
| where ActionType == “LogonFailed” and TimeGenerated > ago(5h)
| summarize EventCount=count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```

The findings were matching the results of our alert: 21 VMs attacked by 17 different public IPs, with a combined sum of 550 tries.

Then I went with our runbook and isolated every device that was affected by the attack and ran an AV scan for every device.

I restricted inbound NSG rules on the attacked VMs to allow only internal/management traffic.

After that I checked with every target device if the suspected public IP attacker had any successful attempt with this KQL query:

```kql
let TargetDevice = “TargetDeviceName”;
let SuspectIP = “IpOfTheSuspect”
DeviceLogonEvents
| where ActionType == “LogonSuccess”
| where DeviceName == TargetDevice and RemoteIP == SuspectIP
| order by TimeGenerated desc
```

I did the query for every device with its attacker. Every query gave no results.

The incident was closed as a True Positive - brute force attempts occurred but none of them were successful.

---

## Condensed timeline
	
Start of the brute force: 11/18/25 01:32 PM
Alert triggered: 11/18/25 05:07 PM
Incident changed status to active: 11/18/25 05:16 PM
Isolating VMs, AV scanning and setting NSG rules: 11/18/25 05:23 PM - 05:30 PM
Checking if any of the BF attempts were successful: 11/18/25 05:33 PM
Closing the incident: 11/18/25 05:40 PM

---

## Findings & Impact

All new VMs are having all inbound ports opened by default - very dangerous, the devices can be scanned by potential attackers, bots, etc.
There was no dedicated analytics rule to detect successful logons following brute-force activity - very dangerous, this can give a potential attacker, who would break in, a valuable time to leave persistence or some kind of backdoor, even if detected afterwards.
The runbook triggers heavy containment (isolation, scans) before confirming compromise, which wastes analyst time on low-impact activity - time and resource wasting, we don’t have to act as if there is a break in if we are not sure of one. This way analysts cannot take care of different, more serious alerts.
There is no structured brute force rule that would add severity when a certain number of attempts would be crossed - missed opportunity, can be dangerous, so that 100 attempts in the last 5 hours would get higher severity (e.g. High instead of Medium), so that 100 are treated as more serious than 10 attempts.

---

## Response & Remediations

	What was done as a response:
All the attacked VMs were isolated.
All the attacked VMs were scanned with AV - no results.
NSG rules for attacked VMs were changed to only allow inside connection.

	What can be improved:
Basic NSG rules for new VMs should be allowing only traffic from the inside.
A new rule can be applied for detecting successful brute forces.
Runbooks for brute force attempts should be changed accordingly with the new rule, so we act only on successful brute force attempts.
A new brute force attempt rules should be added with severity higher than the last one (e.g. High) - so we can take care of more dangerous brute force attempts first.

---

## MITRE ATT&CK

T1110.001 - Brute Force: Password Guessing: the attackers were persistent with using only “administrator” as a login.
T1580 - Cloud Infrastructure Discovery: the attack could be treated as a discovery scan as well, since the VMs were visible to everyone on the internet.
