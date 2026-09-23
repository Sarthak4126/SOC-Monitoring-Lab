"""
SOC Core: IDS Engine & SIEM Correlation Rule Engine
Implements Suricata-style network IDS rules and Wazuh-style behavioral correlation rules.
Processes SecurityEvent objects and generates Alert objects when threat signatures match.
"""
import os
import json
from datetime import datetime, timedelta
from collections import defaultdict
from soc_core.models import SecurityEvent, Alert

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALERTS_FILE = os.path.join(BASE_DIR, "soc_core", "logs", "soc_alerts.json")
os.makedirs(os.path.dirname(ALERTS_FILE), exist_ok=True)

# =====================================================================
# IDS NETWORK SIGNATURE RULES (Suricata-style)
# =====================================================================
IDS_RULES = [
    {
        "rule_id": "IDS-NET-001",
        "rule_name": "Rapid Sequential Port Scan Detected",
        "description": "Multiple distinct destination ports probed from same source IP within 60 seconds.",
        "severity": "High",
        "severity_score": 78,
        "mitre_tactic": "Discovery",
        "mitre_technique": "Network Service Discovery",
        "mitre_technique_id": "T1046",
        "match": {"event_type": "port_scan"},
        "threshold": 5,
        "window_seconds": 60,
    },
    {
        "rule_id": "IDS-AUTH-001",
        "rule_name": "SSH / Admin Brute Force Attack",
        "description": "More than 5 failed authentication attempts from the same source IP within 120 seconds.",
        "severity": "High",
        "severity_score": 85,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "match": {"event_type": "brute_force_attempt"},
        "threshold": 5,
        "window_seconds": 120,
    },
    {
        "rule_id": "IDS-WEB-002",
        "rule_name": "SQL Injection Attempt Detected",
        "description": "SQL injection pattern detected in HTTP request URI or body.",
        "severity": "Critical",
        "severity_score": 95,
        "mitre_tactic": "Initial Access",
        "mitre_technique": "Exploit Public-Facing Application",
        "mitre_technique_id": "T1190",
        "match": {"event_type": "sqli_attempt"},
        "threshold": 1,
        "window_seconds": 60,
    },
    {
        "rule_id": "IDS-WEB-005",
        "rule_name": "Malicious File Upload / Web Shell",
        "description": "Upload of dangerous file extension (.php, .aspx, .jsp, .py) via avatar or file endpoint.",
        "severity": "Critical",
        "severity_score": 98,
        "mitre_tactic": "Persistence",
        "mitre_technique": "Server Software Component: Web Shell",
        "mitre_technique_id": "T1505.003",
        "match": {"event_type": "webshell_upload_attempt"},
        "threshold": 1,
        "window_seconds": 60,
    },
    {
        "rule_id": "SIEM-PROC-005",
        "rule_name": "Suspicious Administrative Command Execution",
        "description": "Process execution matching known attacker tooling: Mimikatz, privilege escalation commands, or remote download.",
        "severity": "Critical",
        "severity_score": 92,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "Abuse Elevation Control Mechanism",
        "mitre_technique_id": "T1548",
        "match": {"event_type": "suspicious_process"},
        "threshold": 1,
        "window_seconds": 300,
    },
    {
        "rule_id": "SIEM-AUTH-003",
        "rule_name": "Successful Login After Multiple Failures (Possible Brute Force Success)",
        "description": "Account successfully authenticated after 3+ consecutive failures - potential successful brute force.",
        "severity": "High",
        "severity_score": 82,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "Brute Force",
        "mitre_technique_id": "T1110",
        "match": {"event_type": "successful_login"},
        "threshold": 1,
        "window_seconds": 120,
    },
]


class DetectionEngine:
    """
    Main IDS/SIEM detection engine.
    Processes events through signature rules and behavioral correlation rules.
    """

    def __init__(self):
        self.alerts: list[Alert] = []
        self._event_buckets: dict = defaultdict(list)  # key: (rule_id, source_ip) -> [events]
        self._fail_tracker: dict = defaultdict(list)   # src_ip -> [timestamps of failures]

    def process_events(self, events: list[SecurityEvent]) -> list[Alert]:
        """Process a batch of events through all detection rules."""
        for event in events:
            self._run_ids_rules(event)
            self._run_behavioral_correlation(event)
        return self.alerts

    def _run_ids_rules(self, event: SecurityEvent):
        """Match event against IDS signature rules."""
        for rule in IDS_RULES:
            match_field = rule["match"]
            matched = all(getattr(event, k, None) == v for k, v in match_field.items())
            if not matched:
                continue

            bucket_key = (rule["rule_id"], event.source_ip)
            now = event.timestamp
            window = timedelta(seconds=rule["window_seconds"])

            # Keep only events within the time window
            self._event_buckets[bucket_key] = [
                e for e in self._event_buckets[bucket_key]
                if abs(now - e.timestamp) <= window
            ]
            self._event_buckets[bucket_key].append(event)

            if len(self._event_buckets[bucket_key]) >= rule["threshold"]:
                # Check if we already raised this exact alert recently
                existing = [a for a in self.alerts if a.rule_id == rule["rule_id"] and a.source_ip == event.source_ip]
                if existing:
                    existing[-1].event_count += 1
                else:
                    alert = Alert(
                        rule_id=rule["rule_id"],
                        rule_name=rule["rule_name"],
                        severity=rule["severity"],
                        severity_score=rule["severity_score"],
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        username=event.username,
                        hostname=event.hostname,
                        description=rule["description"],
                        mitre_tactic=rule["mitre_tactic"],
                        mitre_technique=rule["mitre_technique"],
                        mitre_technique_id=rule["mitre_technique_id"],
                        event_count=len(self._event_buckets[bucket_key]),
                        timestamp=now,
                    )
                    self.alerts.append(alert)

    def _run_behavioral_correlation(self, event: SecurityEvent):
        """Wazuh-style behavioral correlation rules."""
        # Rule: Successful login after multiple failures = possible brute success
        if event.event_type == "failed_login":
            self._fail_tracker[event.source_ip].append(event.timestamp)

        if event.event_type == "successful_login":
            recent_fails = [
                t for t in self._fail_tracker.get(event.source_ip, [])
                if abs(event.timestamp - t) < timedelta(seconds=300)
            ]
            if len(recent_fails) >= 3:
                existing = [a for a in self.alerts if a.rule_id == "SIEM-AUTH-003" and a.source_ip == event.source_ip]
                if not existing:
                    alert = Alert(
                        rule_id="SIEM-AUTH-003",
                        rule_name="Successful Login After Multiple Failures (Brute Force Success)",
                        severity="High",
                        severity_score=82,
                        source_ip=event.source_ip,
                        destination_ip=event.destination_ip,
                        username=event.username,
                        hostname=event.hostname,
                        description=f"Account '{event.username}' authenticated successfully after {len(recent_fails)} failures from {event.source_ip}. Possible successful brute-force attack.",
                        mitre_tactic="Credential Access",
                        mitre_technique="Brute Force",
                        mitre_technique_id="T1110",
                        event_count=len(recent_fails) + 1,
                        timestamp=event.timestamp,
                    )
                    self.alerts.append(alert)

    def save_alerts(self, path: str = None) -> str:
        out_path = path or ALERTS_FILE
        with open(out_path, "w") as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)
        return out_path

    def get_summary(self) -> dict:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for a in self.alerts:
            severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": severity_counts,
            "alerts": [a.to_dict() for a in self.alerts]
        }


def run_detection(events: list[SecurityEvent]) -> tuple[list[Alert], dict]:
    """Convenience function: run detection on a list of events."""
    engine = DetectionEngine()
    alerts = engine.process_events(events)
    engine.save_alerts()
    summary = engine.get_summary()
    print(f"\n[+] Detection complete: {summary['total_alerts']} alerts generated")
    for sev, count in summary["by_severity"].items():
        if count > 0:
            print(f"    [{sev}] {count}")
    return alerts, summary


if __name__ == "__main__":
    from soc_core.telemetry_generator import generate_all_telemetry
    events = generate_all_telemetry()
    run_detection(events)
