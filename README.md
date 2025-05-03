# Threat Hunt Scenario: Malicious Firefox Extension

## Threat Event: Suspicious Firefox Extension Installation and Data Exfiltration

### Reason for Hunt
Unusual network traffic patterns were detected by the SOC, specifically encrypted outbound traffic to unknown external domains during non-business hours. Multiple alerts referenced `firefox.exe` as the initiating process. A recent cybersecurity news article also highlighted malicious extensions affecting Firefox browsers with capabilities for credential theft and surveillance.

---

## Steps the "Bad Actor" Took to Create Logs and IoCs

1. User receives a phishing email encouraging them to install a "Productivity Boost" Firefox extension from a non-Mozilla domain.
2. Victim opens Firefox and manually installs the `.xpi` extension file.
3. Extension runs in the background, logging keystrokes and capturing form data (e.g., credentials).
4. Extension establishes C2 (Command and Control) communication with a remote server via HTTPS.
5. Periodic exfiltration of stolen data (logins, cookies) to the attacker’s server.
6. Attacker uses stolen credentials to attempt unauthorized logins into internal systems.
7. User closes and reopens Firefox over several days as the extension remains persistent.

---

## Tables Used to Detect IoCs

| **Table Name**         | **Description**                                                                                              |
|------------------------|--------------------------------------------------------------------------------------------------------------|
| `DeviceProcessEvents`  | Detects Firefox process launch and execution context for identifying suspicious launches.                   |
| `DeviceFileEvents`     | Detects installation of `.xpi` files, which are Firefox extension files.                                     |
| `DeviceNetworkEvents`  | Tracks network traffic initiated by Firefox, including suspicious external connections.                      |

- Microsoft Docs:
  - [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/deviceprocessevents-table)
  - [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/devicefileevents-table)
  - [DeviceNetworkEvents](https://learn.microsoft.com/en-us/defender-xdr/devicenetworkevents-table)

---

## Related Queries

```kql
// Detect Firefox process launches
DeviceProcessEvents
| where FileName =~ "firefox.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Detect installation of suspicious Firefox extensions (.xpi)
DeviceFileEvents
| where FileName endswith ".xpi"
| where FolderPath contains "Mozilla\\Firefox"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Detect Firefox making outbound HTTPS connections to unknown or suspicious domains
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "firefox.exe"
| where RemoteUrl !contains "mozilla" and RemotePort == 443
| project Timestamp, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine

// Look for repeated Firefox connections outside business hours (example: 8 PM to 6 AM)
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "firefox.exe"
| where hourofday(Timestamp) < 6 or hourofday(Timestamp) > 20
| project Timestamp, DeviceName, RemoteUrl, RemoteIP
