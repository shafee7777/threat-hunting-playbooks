# ☁️ Cloud Hunt: M365 OAuth Abuse

---

## 🎯 Objective
Detect malicious OAuth application grants, token abuse, and privilege escalation inside Microsoft 365 environments.

---

## 🔍 Key Indicators
- New OAuth apps created  
- High-permission consent granted unexpectedly  
- Token replay or suspicious refresh tokens  
- Impossible travel associated with OAuth app usage  
- OAuth apps accessing high-value mailboxes  
- Consent granting by compromised users  

---

## 🕵️ Hunt Queries (KQL)

### **1. New OAuth Application Consent**
kql
AuditLogs
| where OperationName == "Consent to application"
| project TimeGenerated, InitiatedBy, AppId=TargetResources[0].id, Details=TargetResources


### **2. OAuth App Access to Mailboxes**
kql
OfficeActivity
| where Operation == "Add-MailboxPermission"
| where UserType == "Application"
| project TimeGenerated, Mailbox, ApplicationId, AccessRights


### **3. Suspicious Token Replay**
kql
SigninLogs
| where TokenIssuerName != "Azure AD"
| where ResultType == "0"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress


---

## 🧑‍💻 Analyst Workflow

1. Validate new OAuth app creation with admin teams  
2. Review API permission scope  
3. Detect mailbox access attempts by OAuth apps  
4. Investigate possible token theft or replay attacks  
5. Disable suspicious applications immediately  
6. Rotate credentials + enforce Conditional Access  

---

## 🧩 MITRE ATT&CK Mapping

- **T1528 – Steal Application Access Token**  
- **T1552 – Unsecured Credentials**  
- **T1098 – Account Manipulation**  
- **T1114 – Email Collection**  
- **T1134 – Access Token Manipulation**  

---
