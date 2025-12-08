# ☁️ Cloud Hunt: AWS IAM Anomalies

---

## 🎯 Objective
Detect abnormal AWS IAM activity involving permissions, credential usage, MFA bypass, and suspicious API calls.

---

## 🔍 Key Indicators
- Creation of new IAM users unexpectedly  
- AccessKey creation without MFA  
- IAM role assumption spikes  
- Policy changes granting admin privileges  
- API calls from unusual IPs  
- Root account authentication  
- Long-unused keys suddenly used  

---

## 🕵️ Hunt Queries (CloudTrail)

### **1. Suspicious IAM User Creation**
sql
CloudTrail
| where eventName == "CreateUser"
| project eventTime, userIdentity.arn, requestParameters.userName


### **2. Access Keys Created Without MFA**
sql
CloudTrail
| where eventName == "CreateAccessKey"
| where userIdentity.sessionContext.attributes.mfaAuthenticated == "false"
| project eventTime, userIdentity.userName, sourceIPAddress


### **3. Privilege Escalation via Policy Attachment**
sql
CloudTrail
| where eventName in ("AttachUserPolicy","PutUserPolicy","AttachRolePolicy")
| project eventTime, userIdentity.userName, requestParameters.policyArn


### **4. Root Account Usage**
sql
CloudTrail
| where userIdentity.type == "Root"
| project eventTime, eventSource, eventName, sourceIPAddress


---

## 🧑‍💻 Analyst Workflow

1. Validate IAM changes with change-control logs  
2. Review locations/IPs for unusual behavior  
3. Disable newly created AccessKeys until verified  
4. Analyze policy attachment for privilege escalation  
5. Force-rotate keys if suspicious access observed  
6. Determine whether root activity is legitimate  

---

## 🧩 MITRE ATT&CK Mapping

- **T1078 – Valid Accounts**  
- **T1098 – Account Manipulation**  
- **T1068 – Permission Abuse**  
- **T1550 – Use of Stolen Cloud Credentials**  
- **T1580 – Cloud Infrastructure Manipulation**  

---
