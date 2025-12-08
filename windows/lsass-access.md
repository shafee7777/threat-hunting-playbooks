# 🪟 Windows Hunt: LSASS Access Attempt

## 🎯 Objective  
Detect attempts to dump LSASS memory for credential theft.

---

## 🔎 Key Indicators  
- Tools: ProcDump, Mimikatz, comsvcs.dll  
- Access to LSASS process handle  
- Memory dump file creation  

---

## 🧪 Hunt Query (KQL)
kql
DeviceProcessEvents
| where FileName in ("procdump.exe", "mimikatz.exe", "taskmgr.exe", "lsass.exe")
    or ProcessCommandLine has_any ("lsass", "-ma", "-mm", "procdump", "sekurlsa")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName

---

## 👨‍💻 Analyst Workflow  
1. Check for dump file creation  
2. Validate accounts involved  
3. Inspect parent process chain  
4. Check for lateral movement before/after dump  
5. Escalate if unauthorized memory access is confirmed  

---

## 🧩 MITRE ATT&CK  
- **T1003 – Credential Dumping**  
- **T1003.001 – LSASS Memory**  
