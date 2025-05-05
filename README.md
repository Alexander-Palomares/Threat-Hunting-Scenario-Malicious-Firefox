![Firefox Logo with Crosshair](https://upload.wikimedia.org/wikipedia/commons/8/80/Firefox_logo%2C_2019.svg)

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
We started by identifying executions of FirefoxPortable.exe from non-standard paths:

```kql
DeviceProcessEvents
| where FileName == "FirefoxPortable.exe"
| where FolderPath !contains "Program Files"
```

This revealed that a user executed FirefoxPortable from a location outside `Program Files`, indicating a likely portable use case bypassing install restrictions.

### Step 2: Analyze Contextual Details
After identifying the suspicious process execution, we examined fields like `InitiatingProcessAccountName`, `ProcessCommandLine`, and `FolderPath` to determine who ran the software and from where. This gives insight into user intent and method of delivery (USB, browser download, etc.).

### Step 3: Timeline Reconstruction
Using `Timestamp`, we correlated the activity to specific hours of the workday. This helped contextualize the timing and potential motive (e.g., after hours, during peak work time).

---

## 📅 Example Timeline
- **2025-04-14 22:58 UTC** — `FirefoxPortable.exe` executed from `C:\Users\alexanderp\Desktop\FirefoxPortable`.
- **2025-04-14 22:59 UTC** — Network connections initiated by `firefox.exe`.

---

## 🧾 Summary
The investigation confirmed the use of `FirefoxPortable.exe` from a non-standard folder by user `alexanderp`. While Firefox is not inherently malicious, the use of a portable version outside policy-approved directories raises concerns about intent and data exfiltration potential. The original alert about large data uploads further supports this concern.

---

## 📌 Response Taken
- The endpoint was isolated.
- The user’s manager was notified.
- Forensic images were preserved for further analysis.
- HR was consulted to determine next steps regarding Acceptable Use Policy violations.

---

## ✍️ Created By
**Author:** [Your Name Here]  
**GitHub:** [YourGitHub](https://github.com/yourgithub)  
**LinkedIn:** [YourLinkedIn](https://linkedin.com/in/yourlinkedin)  
**Date:** 2025-05-05  

---

## 📘 Notes
- Portable applications are commonly used to bypass restrictions in enterprise environments.
- Defender for Endpoint is capable of catching these if tuned appropriately.
- Consider blocking execution from user directories in Group Policy or via AppLocker.

---

## 🔁 Revision History
| Version | Description                    | Date         | Author        |
|---------|--------------------------------|--------------|---------------|
| 1.0     | Initial Report Creation        | 2025-05-05   | Your Name     |
