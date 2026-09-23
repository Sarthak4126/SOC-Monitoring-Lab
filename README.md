# Project 2: SOC Monitoring & Intrusion Detection Lab

A fully functional mini Security Operations Center (SOC) built in Python — simulating real enterprise SIEM, IDS, log collection, attack scenarios, and incident investigation.  
Aligned with **MITRE ATT&CK®** · **NIST SP 800-61** · **PTES**

---

## Project Structure

SOC-Monitoring-Lab/
│
├── soc_core/ # Core SOC engine
│ ├── detection_engine.py # SIEM correlation engine & IDS rule processor
│ ├── telemetry_generator.py # Realistic log telemetry generator (318 events)
│ ├── models.py # SecurityEvent & Alert data models
│ └── logs/
│ ├── soc_events.json # Generated event log (machine-readable)
│ └── soc_alerts.json # Triggered alerts with MITRE mappings
│
├── soc_dashboard/ # Flask SOC web interface
│ ├── app.py # Main dashboard app
│ ├── templates/
│ │ ├── base.html # Kibana-style layout
│ │ ├── dashboard.html # SOC Overview — metrics, severity, top IPs
│ │ ├── alerts.html # Alert Manager — full alert queue
│ │ ├── log_explorer.html # Log Explorer with search & filters
│ │ ├── incident_detail.html # Incident Investigation Workbench
│ │ └── simulator.html # Attack Simulator controls
│ └── static/ # Static assets
│
├── configs/ # Configuration files
├── guides/ # Setup and usage guides
├── reports/
│ └── SOC_Monitoring_Report.pdf # Full incident report with MITRE mapping
└── requirements.txt # Python dependencies


---

## Quick Start

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/SOC-Monitoring-Lab.git
cd SOC-Monitoring-Lab
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Launch the SOC dashboard
```bash
python soc_dashboard/app.py
```

Dashboard runs at: **`http://127.0.0.1:5500`**

On startup the SOC engine automatically:
- Generates 318 realistic security events across 4 log sources
- Runs the detection engine and fires alerts
- Populates the dashboard with live metrics

---

## SOC Capabilities

| Component | Description |
| :--- | :--- |
| **Telemetry Generator** | Simulates auth, web, process, and network logs — baseline + attack traffic |
| **Detection Engine (SIEM)** | Correlation rules engine with MITRE ATT&CK tagging and severity scoring |
| **Alert Manager** | Centralized alert queue sorted by severity score |
| **Log Explorer** | Searchable, filterable event log across all sources |
| **Incident Workbench** | Full timeline reconstruction — up to 30 correlated events per alert |
| **Attack Simulator** | On-demand triggering of 5 attack scenarios via web UI |

---

## Attack Scenarios & Detection

| Scenario | MITRE Technique | Severity | Events | Detection Source |
| :--- | :--- | :---: | :---: | :--- |
| SSH Brute Force | T1110 — Brute Force | High | 25 | auth_log |
| SQL Injection | T1190 — Exploit Public App | Critical | 5 | network_ids, web_log |
| Port Scanning | T1046 — Network Discovery | High | 15 | network_ids (Suricata) |
| Privilege Escalation | T1548 — Abuse Elevation | Critical | 8 | sysmon (EventID=1) |
| Web Shell Upload | T1505.003 — Web Shell | Critical | 5 | web_log |

---

## SOC Dashboard Pages

- **SOC Overview** — 318 events ingested, 9 active alerts, severity distribution, top source IPs with SUSPECT/INTERNAL tagging, MITRE tactic mapping, live alert stream
- **Alert Manager** — Full alert queue with rule ID, MITRE tag, source IP, event count, status
- **Log Explorer** — Search and filter across all 318 events by keyword, category, or severity
- **Incident Workbench** — Per-alert timeline with 30 related events correlated by source IP and username
- **Attack Simulator** — Trigger brute force, SQLi, port scan, privilege escalation, or web shell attacks on demand

---

## Results Summary

- **318** total security events ingested
- **9** alerts fired — 3 Critical, 6 High
- **5/5** attack scenarios detected successfully
- **1** threat actor identified: `185.220.101.47` (flagged SUSPECT)
- **1** compromised internal account: `sarah.chen` (NOVAVAULT-DC01)

---

## 🛠️ Tools & Stack
Python · Flask · SQLite · Sysmon (simulated) · Suricata (simulated) · MITRE ATT&CK

## 📋 Standards
MITRE ATT&CK® · NIST SP 800-61 · PTES
