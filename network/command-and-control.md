# 🌐 Network Hunt: Command & Control (C2) Detection

---

## 🎯 Objective
Identify beaconing, long-running callbacks, encrypted traffic anomalies, or suspicious outbound connections that may indicate active command-and-control channels.

---

## 🔍 Key Indicators
- Periodic beaconing at fixed intervals  
- Long-duration outbound sessions  
- Connections to rare or low-reputation domains  
- Uncommon ports for outbound traffic  
- JA3/JA3S signatures linked to malware  
- Encrypted payload patterns over HTTP/S  
- DNS-based C2 (high-frequency queries, algorithmic domains)  

---

## 🕵️ Hunt Queries (KQL)

### **1. Periodic Beaconing (Consistent Intervals)**

kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| summarize FirstSeen=min(Timestamp), LastSeen=max(Timestamp), Count=count() 
        by DeviceName, RemoteIP, RemotePort
| extend Interval = (LastSeen - FirstSeen) / Count
| where Count > 10 and Interval between (1min .. 5min)
| sort by Interval asc


### **2. Rare External Connections (Low-Frequency Destination)**

kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| summarize Count=count() by RemoteIP, RemotePort
| where Count < 5
| sort by Count asc


### **3. Suspicious JA3 / JA3S Fingerprints**

kql
DeviceNetworkEvents
| where Protocol == "TLS"
| where JA3 in ("51c64c77e60f3980ee88d3e0b1d3f6a3",
               "6734f37431670b3ab4292b8f60f29984")
| project Timestamp, DeviceName, RemoteIP, RemotePort, JA3


### **4. Long-Lived Outbound Sessions**

kql
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| extend Duration = iff(isnull(NetworkDuration), 0, NetworkDuration)
| where Duration > 600  // >10 minutes
| project Timestamp, DeviceName, RemoteIP, Duration, RemotePort


### **5. HTTP/S C2 with Encrypted Payloads**

kql
DeviceNetworkEvents
| where Protocol in ("HTTP", "HTTPS")
| where Url has_any ("update", "sync", "payload", "tasks", "cmd")
| where ResponseBodySize > 50000 or RequestBodySize > 50000
| project Timestamp, DeviceName, Url, ResponseBodySize, RequestBodySize


---

## 🧑‍💻 Analyst Workflow

1. Validate if beaconing intervals match known malware families  
2. Inspect rare outbound destinations for threat intelligence hits  
3. Review JA3/JA3S fingerprint matches for C2 frameworks  
4. Analyze session length for abnormal long-running connections  
5. Check if HTTP/S payload size indicates encrypted or staged data  
6. Correlate with DNS tunneling or SMB movement indicators  
7. Escalate if the connection shows signs of persistent C2 activity  

---

## 🧩 MITRE ATT&CK Mapping

- **T1071 – Application Layer Protocol**  
- **T1071.001 – Web Protocols (HTTP/S C2)**  
- **T1571 – Non-Standard Port C2**  
- **T1095 – Non-Application Layer Protocol**  
- **T1568 – Dynamic Resolution (C2 infrastructure)**  
- **T1041 – Exfiltration Over C2 Channel**  

---
