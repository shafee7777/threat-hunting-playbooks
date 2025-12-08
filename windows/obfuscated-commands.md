# 🪟 Windows Hunt: Obfuscated Command Execution

## 🎯 Objective  
Detect adversaries hiding malicious intent through obfuscated command lines.

---

## 🔎 Key Indicators  
- Concatenated strings  
- Special characters used for evasion  
- Encoded payloads  
- Long or dynamic command strings  

---

## 🧪 Hunt Query (KQL)
kql
DeviceProcessEvents
| where ProcessCommandLine has_any ("^", "+", "&", "%", "$(", "FromBase64String", "Invoke-Expression")
| where FileName in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")

---

## 👨‍💻 Analyst Workflow  
1. Extract suspicious characters and reconstruct command  
2. Decode hidden payloads  
3. Look for staging or download behavior  
4. Confirm execution context (user, device)  
5. Escalate if ANY credential tool / payload is embedded  

---

## 🧩 MITRE ATT&CK  
- **T1027 – Obfuscated Files or Information**  
- **T1059 – Command and Scripting Interpreter**  
