"""
SOC Core: Unified Security Event Data Model (Elastic Common Schema - ECS aligned)
Defines the standardized event format used throughout the SOC Monitoring Lab.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import uuid


@dataclass
class SecurityEvent:
    """Normalized security event following ECS (Elastic Common Schema)."""
    # Core identifiers
    event_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8].upper())
    timestamp: datetime = field(default_factory=datetime.now)

    # Event classification
    event_category: str = ""       # authentication, network, process, web, file, intrusion
    event_type: str = ""           # failed_login, port_scan, sqli_attempt, bruteforce, etc.
    event_action: str = ""         # raw action description

    # Source & Destination
    source_ip: str = ""
    source_port: int = 0
    destination_ip: str = ""
    destination_port: int = 0
    hostname: str = ""
    username: str = ""

    # Log source
    log_source: str = ""           # sysmon, auth_log, web_log, network_ids, windows_event
    raw_log: str = ""

    # Detection & Alerting
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "Low"          # Critical, High, Medium, Low, Info
    severity_score: int = 0        # 0-100
    alert_triggered: bool = False

    # MITRE ATT&CK
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""

    # Process (Sysmon)
    process_name: str = ""
    process_command: str = ""
    process_pid: int = 0
    parent_process: str = ""

    # Network / Web
    http_method: str = ""
    http_url: str = ""
    http_status: int = 0
    user_agent: str = ""
    protocol: str = ""

    # Outcome
    outcome: str = ""              # success, failure, unknown

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "event_category": self.event_category,
            "event_type": self.event_type,
            "event_action": self.event_action,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "hostname": self.hostname,
            "username": self.username,
            "log_source": self.log_source,
            "raw_log": self.raw_log,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "alert_triggered": self.alert_triggered,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "process_name": self.process_name,
            "process_command": self.process_command,
            "process_pid": self.process_pid,
            "parent_process": self.parent_process,
            "http_method": self.http_method,
            "http_url": self.http_url,
            "http_status": self.http_status,
            "user_agent": self.user_agent,
            "protocol": self.protocol,
            "outcome": self.outcome,
        }


@dataclass
class Alert:
    """Represents a triggered SOC alert from the detection engine."""
    alert_id: str = field(default_factory=lambda: "ALT-" + str(uuid.uuid4())[:6].upper())
    timestamp: datetime = field(default_factory=datetime.now)
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "Medium"
    severity_score: int = 50
    source_ip: str = ""
    destination_ip: str = ""
    username: str = ""
    hostname: str = ""
    description: str = ""
    mitre_tactic: str = ""
    mitre_technique: str = ""
    mitre_technique_id: str = ""
    event_count: int = 1
    status: str = "Open"          # Open, Investigating, Resolved, False Positive
    raw_events: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "severity_score": self.severity_score,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "username": self.username,
            "hostname": self.hostname,
            "description": self.description,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "event_count": self.event_count,
            "status": self.status,
        }
