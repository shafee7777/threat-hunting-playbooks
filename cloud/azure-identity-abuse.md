# ☁️ Cloud Hunt: Azure Identity Abuse

---

## 🎯 Objective
Detect suspicious activity targeting Azure AD identities, tokens, and authentication flows that may indicate account takeover or privilege escalation.

---

## 🔍 Key Indicators
- Impossible travel sign-ins  
- MFA fatigue attacks  
- Authentication from anonymizers (TOR, VPNs)  
- Token replay or refresh token theft  
- OAuth consent grant abuse  
- Excessive failed login attempts  
- Privilege escalation via role assignment changes  

---

## 🕵️ Hunt Queries (KQL)

### **1. Impossible Travel Logins**
kql
SigninLogs
| extend Location = tostring(LocationDetails.countryOrRegion)
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) 
        by UserPrincipalName, IPAddress, Location
| extend TimeDiff = datetime_diff("hour", LastSeen, FirstSeen)
| where TimeDiff < 1 and Location != prev(Location)
| project UserPrincipalName, Location, FirstSeen, LastSeen, TimeDiff


### **2. MFA Fatigue – Multiple MFA Prompts**
kql
SigninLogs
| where ResultType == "50140"
| summarize Attempts=count() by UserPrincipalName, IPAddress
| where Attempts > 5


### **3. OAuth Consent Grant Abuse**
kql
AuditLogs
| where OperationName =~ "Add service principal"
      or OperationName =~ "Consent to application"
| project TimeGenerated, InitiatedBy, TargetResources, OperationName


### **4. Suspicious Privilege Escalation**
kql
AuditLogs
| where OperationName == "Add role assignment"
| project TimeGenerated, InitiatedBy, Role=TargetResources[0].displayName


---

## 🧑‍💻 Analyst Workflow

1. Validate impossible travel using known user locations  
2. Review elevated privileges granted unexpectedly  
3. Check MFA fatigue patterns and verify with user  
4. Inspect OAuth app grants for malicious third-party apps  
5. Evaluate login origins (TOR, VPN, anomalies)  
6. Correlate with Azure AD risk detections  

---

## 🧩 MITRE ATT&CK Mapping

- **T1078 – Valid Accounts**  
- **T1556 – Authentication Manipulation**  
- **T1528 – Steal Application Access Token**  
- **T1098 – Account Manipulation**  
- **T1110 – Credential Stuffing / Brute Force**  

---
