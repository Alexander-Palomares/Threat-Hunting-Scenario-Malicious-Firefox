![Mozilla-Firefox-Logo-2009-500x281-min](https://github.com/user-attachments/assets/20834dc3-68e1-4641-a0fd-9dcd7967ec9e)

# Threat Hunt Report: Unauthorized FirefoxPortable.exe Usage
- [Scenario Creation](https://github.com/Alexander-Palomares/Threat-Hunting-Scenario-Malicious-Firefox/edit/main/threat-hunting-scenario-creation.md)
  
## 🔧 Platforms and Tools Used
- **Operating System:** Windows 10 (Azure-hosted Virtual Machines)
- **EDR Platform:** Microsoft Defender for Endpoint
- **Query Language:** Kusto Query Language (KQL)
- **Software in Focus:** Firefox Portable

## Scenario

A manager reported possible policy violations after noticing large file uploads from a monitored device. This led to an investigation to identify any unauthorized software that may have been used to bypass security controls or anonymize traffic. During initial triage, analysts discovered that the employee had been using a portable browser that didn’t require installation, raising suspicions of evasion techniques.

---

## 📌 Objective
To determine whether FirefoxPortable.exe—a portable, policy-evading version of the Firefox browser—was executed from a non-standard directory, possibly to evade detection or bypass software restrictions.
  ### Plan:
1. Identify abnormal process executions of `FirefoxPortable.exe`.
2. Filter out legitimate installations (i.e., from `Program Files`).
3. Correlate findings with device and user activity.

---

## 🕵️‍♂️ Steps Taken

### Step 1: Query the `DeviceProcessEvents` Table
I started by identifying executions of FirefoxPortable.exe from non-standard paths:

```kql
DeviceProcessEvents
| where FileName == "FirefoxPortable.exe"
| where FolderPath !contains "Program Files"
```
![image](https://github.com/user-attachments/assets/fb74b619-89d0-493c-9704-0977d3891dc9)

This revealed that a user (39a0c7e391c3f837b2cfb890fdaab1804eb39cfd) executed FirefoxPortable from a location outside `Program Files`, indicating a likely portable use case bypassing install restrictions. I now know the DeviceId and can investigate the logs more precisely.

---

### Step 2: Network Activity Analysis
The next step after identifying the malicious actor is to check whether this browser was used to access cloud services or external file-sharing domains—anything that might indicate data exfiltration.

```kql
DeviceNetworkEvents
| where DeviceId == @"39a0c7e391c3f837b2cfb890fdaab1804eb39cfd"
| where InitiatingProcessFileName contains "firefox"
| where RemoteUrl has_any ("mega.nz", "wetransfer.com", "dropbox.com", "gofile.io")
```

![image](https://github.com/user-attachments/assets/5512168a-5afa-4ae3-8b0d-0247a3849b95)

The results show clear evidence of attempts to access cloud services through Firefox. This raises further concern and suggests it was less likely an accident and more likely a deliberate attack.

---

### Step 3: File Activity Search
Now that we're confident this was not an accidental attack, we can further investigate for any clues the attacker may have left on the machine. I searched through the 'DeviceFileEvents' table for suspicious files around the time Firefox Portable was launched and checked if any were deleted to cover their tracks.

```kql
DeviceFileEvents
| where DeviceId == @"39a0c7e391c3f837b2cfb890fdaab1804eb39cfd"
| where FileName has_any ("private-notes.txt", "project-docs.zip")
| project Timestamp, DeviceId, FileName, ActionType, InitiatingProcessCommandLine
```
![image](https://github.com/user-attachments/assets/b3105b2f-410d-49fa-9297-99ac474bab2c)

The results show the creation of a text file named 'private-notes,' which raises obvious concern, as it was created during the time of the attack.

---
# Sequence of Events: Firefox Portable – Suspicious Activity

## 🔸 Event 1: Alert Triggered by Management

A manager reported unusually **large outbound data transfers** from a monitored device.  
Concerned about potential **policy violations or data exfiltration**, a cybersecurity analyst was tasked with investigating the endpoint.

## 🔸 Event 2: Detection of Portable Browser Execution

The analyst queried `DeviceProcessEvents` for instances of `FirefoxPortable.exe` running from **non-standard directories**.

**Discovery:**
- `FirefoxPortable.exe` was executed from **outside the `Program Files` directory**.
- This indicates the use of a **portable browser**, possibly to bypass installation restrictions or endpoint monitoring.
- **Device ID:** `39a0c7e391c3f837b2cfb890fdaab1804eb39cfd`.

## 🔸 Event 3: Cloud Service Access via Portable Firefox

A focused network analysis (`DeviceNetworkEvents`) was performed to detect potential data exfiltration.

**Discovery:**
- Firefox initiated connections to known **cloud storage and file-sharing platforms**:
  - `mega.nz`
  - `wetransfer.com`
  - `dropbox.com`
- These domains are frequently used for **external file uploads**, strengthening the case for potential data exfiltration.

## 🔸 Event 4: Suspicious File Creation on Endpoint

The analyst queried `DeviceFileEvents` for any file creation or modification activity on the same device.

**Discovery:**
- A file named **`private-notes.txt`** was created shortly after the browser execution.
- The timing and file name suggest potential **intent to document or organize stolen data**.

## 🔸 Event 5: Correlation and Confirmation of Malicious Intent

By correlating:
- The **execution** of FirefoxPortable,
- **Cloud service access**, and
- The **creation of suspicious local files**,

---

## Summary
The investigation confirmed the use of `FirefoxPortable.exe` from a non-standard folder by user `alexanderp`. While Firefox is not inherently malicious, the use of a portable version outside policy-approved directories raises concerns about intent and data exfiltration potential. The original alert about large data uploads further supports this concern.

---

## 📌 Response Taken
- The endpoint was isolated.
- The user’s manager was notified.
- Forensic images were preserved for further analysis.
- HR was consulted to determine next steps regarding Acceptable Use Policy violations.

---

## Created By Alexander Palomares 
- Date: 2025-05-05  
- [Github](https://github.com/Alexander-Palomares)
- [LinkedIn](https://www.linkedin.com/in/alexander-palomares-a867202b1/)
  
---
