# 🪟 Windows Hunt: RDP Brute Force Attack

## 🎯 Objective  
Detect repeated failed logins that indicate brute-force attempts over RDP.

---

## 🔎 Key Indicators  
- High volume failed RDP logons  
- Successful logon after many failures  
- Authentication from unusual IPs  

---

## 🧪 Hunt Query (KQL)
kql
DeviceLogonEvents
| where LogonType == 10  // RDP
| summarize Failures = countif(ActionType == "FailedLogon"),
            Successes = countif(ActionType == "LogonSuccess")
            by DeviceName, AccountName, RemoteIP
| where Failures > 10

---

## 👨‍💻 Analyst Workflow  
1. Validate geolocation of RemoteIP  
2. Check if account is service or user  
3. Look for credential stuffing patterns  
4. Escalate if successful login follows brute force  

---

## 🧩 MITRE ATT&CK  
- **T1110 – Brute Force**  
