# 🌐 Network Hunt: SMB Lateral Movement Detection

---

## 🎯 Objective
Identify suspicious SMB traffic patterns that may indicate lateral movement, credential theft, brute force attempts, or remote command execution within the network.

---

## 🔍 Key Indicators
- Excessive SMB authentication failures  
- SMB connections between unusual host pairs  
- Lateral movement tools such as PsExec, SMBExec, Impacket  
- Creation of remote services over SMB (Service Control Manager abuse)  
- High-frequency connections to ADMIN$, IPC$, or C$ shares  
- Anonymous SMB logins or NTLMv1 authentication use  

---

## 🕵️ Hunt Queries (KQL)

### **1. Excessive SMB Authentication Failures**

kql
DeviceNetworkEvents
| where Protocol == "SMB"
| where ActionType in ("FailedLogon", "FailedCredentialAuthentication")
| summarize Failures = count() by DeviceName, RemoteIP, AccountName
| where Failures > 20
| sort by Failures desc


### **2. Lateral Movement via PsExec / Remote Service Creation**

kql
DeviceProcessEvents
| where ProcessCommandLine contains "psexec" 
    or ProcessCommandLine contains "remcom" 
    or ProcessCommandLine contains "svcctl"
| project Timestamp, DeviceName, FileName, ProcessCommandLine


### **3. Suspicious Access to ADMIN$ / IPC$ Shares**

kql
DeviceNetworkEvents
| where Protocol == "SMB"
| where RemotePort in (445)
| where RemoteUrl contains "ADMIN$" 
    or RemoteUrl contains "IPC$"
    or RemoteUrl contains "C$"
| project Timestamp, DeviceName, RemoteIP, RemoteUrl, ActionType


### **4. High-Frequency SMB Connections Between Hosts**

kql
DeviceNetworkEvents
| where Protocol == "SMB"
| summarize Count = count() by DeviceName, RemoteIP
| where Count > 200
| sort by Count desc


### **5. Impacket / SMBExec Behavior**

kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("impacket", "secretsdump", "wmiexec", "smbexec", "dcomexec")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

---

## 🧑‍💻 Analyst Workflow

1. Determine if SMB authentication failures indicate brute force or password spraying  
2. Examine whether lateral movement tools (PsExec, Impacket) were executed  
3. Correlate remote service creation with suspicious SMB traffic  
4. Identify abnormal host-to-host SMB communication paths  
5. Check whether privileged shares (ADMIN$, IPC$) were accessed improperly  
6. Validate if compromised credentials or pass-the-hash techniques were used  
7. Escalate if unauthorized access or lateral movement is confirmed  

---

## 🧩 MITRE ATT&CK Mapping

- **T1021.002 – SMB/Windows Admin Shares**  
- **T1075 – Pass the Hash**  
- **T1021 – Remote Services**  
- **T1035 – Service Execution**  
- **T1047 – WMI Execution**  

---
