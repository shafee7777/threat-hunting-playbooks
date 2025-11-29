# 🔎 Threat Hunting Playbooks

A collection of practical, repeatable threat-hunting playbooks for **Windows**, **network**, and **cloud** environments.

Each playbook includes:

- 🎯 Hypothesis & objective  
- 📊 Required data sources  
- 🧪 Hunt queries (primarily KQL for M365 Defender & Microsoft Sentinel)  
- 🧠 Analyst workflow & triage guidance  
- 🧱 MITRE ATT&CK mapping  

This repo is structured like a real-world detection engineering & threat-hunting portfolio.

---

## 📁 Repository Structure

```text
windows/     -> Host-based hunts (EDR, PowerShell, persistence)
network/     -> Network-based threats (DNS tunneling, SMB lateral movement)
cloud/       -> Azure/AWS identity and cloud hunting playbooks
queries/     -> Reusable KQL & Sigma rule examples
