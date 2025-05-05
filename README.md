# 🕵️‍♂️ Threat Hunting Scenario – Firefox Portable Abuse

## 🔍 Overview

**Threat Name:** Unauthorized Use of Portable Firefox with Suspicious Download Activity  
**Objective:** Identify the use of Firefox Portable to bypass monitoring tools and transfer data using cloud-based services.

> 🚨 **Reason for the Hunt:**  
A cybersecurity news alert detailed a rise in employees using portable browsers to bypass network monitoring and content filtering. Internal logs also flagged abnormal download behavior on a few endpoints. Management requested an internal threat hunt to detect unauthorized usage and assess risk exposure.

---

## 🧪 Simulation Steps (What the "Bad Actor" Did)

1. Downloaded Firefox Portable from:  
   `https://portableapps.com/apps/internet/firefox_portable`

2. Extracted the package to a custom folder:  
   `C:\Users\<username>\Downloads\ff-portable`

3. Launched the browser:  
   `firefoxportable.exe`

4. Visited cloud services and uploaded/downloaded files:  
   - `mega.nz`  
   - `dropbox.com`  
   - `wetransfer.com`

5. Created a text file:  
   `private-notes.txt` — containing sensitive notes or info

6. Later deleted the file to hide activity

---

## 📊 Detection Tables (Microsoft Defender XDR)

| Table Name           | Description                                                                 |
|----------------------|-----------------------------------------------------------------------------|
| `DeviceFileEvents`   | Detects creation/deletion of files like `firefoxportable.exe`, `*.txt`, etc.|
| `DeviceProcessEvents`| Detects execution of processes like `firefoxportable.exe` from odd paths     |
| `DeviceNetworkEvents`| Identifies access to external cloud services from Firefox Portable           |

---

## 📌 KQL Queries

### 1. Detect Firefox Portable Placed on Disk
```kql
DeviceFileEvents
| where FileName has "firefoxportable"
| project Timestamp, DeviceName, FolderPath, FileName, ActionType, InitiatingProcessCommandLine
