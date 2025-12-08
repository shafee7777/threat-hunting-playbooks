# 🪟 Windows Hunt: Scheduled Task Persistence

## 🎯 Objective  
Detect persistence via malicious scheduled tasks.

---

## 🔎 Key Indicators  
- Repeated task creation  
- Task names resembling system tasks  
- Tasks running encoded PowerShell  

---

## 🧪 Hunt Query (KQL)
kql
DeviceRegistryEvents
| where RegistryKey contains "Schedule\\TaskCache"
| where RegistryValueData contains_any ("powershell", "cmd.exe", "encodedcommand", ".vbs")

---

## 👨‍💻 Analyst Workflow  
1. Review task name + action  
2. Determine user who created task  
3. Check execution frequency  
4. Inspect referenced script or binary  
5. Escalate if used for persistence or C2  

---

## 🧩 MITRE ATT&CK  
- **T1053 – Scheduled Task/Job**  
