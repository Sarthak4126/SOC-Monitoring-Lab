"""
SOC Dashboard: Flask Web Application
Interactive Kibana/Wazuh-style SOC dashboard with:
- Live metrics & severity distribution
- Real-time alert stream
- Log explorer with filters
- Interactive attack simulation controls
- Incident investigation workbench
"""
import os
import sys
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request, session

# Add parent dir to path for soc_core imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from soc_core.telemetry_generator import generate_all_telemetry, simulate_brute_force, simulate_sqli_attack, simulate_port_scan, simulate_privilege_escalation, simulate_webshell_upload, all_events as global_events, ATTACKER_IPS
from soc_core.detection_engine import DetectionEngine

app = Flask(__name__)
app.secret_key = "soc_dashboard_lab_2026"


@app.context_processor
def inject_globals():
    return {"now_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")}

# In-memory SOC state
SOC_STATE = {
    "events": [],
    "alerts": [],
    "engine": DetectionEngine(),
    "initialized": False,
}


def initialize_soc():
    """Generate initial telemetry and run detection on startup."""
    if not SOC_STATE["initialized"]:
        events = generate_all_telemetry(save_to_file=True)
        SOC_STATE["events"] = events
        SOC_STATE["engine"] = DetectionEngine()
        alerts, _ = _run_detection(events)
        SOC_STATE["alerts"] = alerts
        SOC_STATE["initialized"] = True
    return SOC_STATE["events"], SOC_STATE["alerts"]


def _run_detection(events):
    engine = SOC_STATE["engine"]
    alerts = engine.process_events(events)
    engine.save_alerts()
    return alerts, engine.get_summary()


def get_metrics():
    events = SOC_STATE["events"]
    alerts = SOC_STATE["alerts"]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for a in alerts:
        sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1

    # Top source IPs
    ip_counter = {}
    for e in events:
        if e.source_ip:
            ip_counter[e.source_ip] = ip_counter.get(e.source_ip, 0) + 1
    top_ips = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)[:10]

    # Event categories
    cat_counter = {}
    for e in events:
        cat = e.event_category or "unknown"
        cat_counter[cat] = cat_counter.get(cat, 0) + 1

    # Events over time (hourly buckets for last 4 hours)
    hourly = {}
    for e in events:
        hour_key = e.timestamp.strftime("%H:00")
        hourly[hour_key] = hourly.get(hour_key, 0) + 1
    hourly_sorted = dict(sorted(hourly.items()))

    # MITRE ATT&CK tactic distribution
    mitre_counter = {}
    for a in alerts:
        tactic = a.mitre_tactic or "Unknown"
        mitre_counter[tactic] = mitre_counter.get(tactic, 0) + 1

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "severity_distribution": sev_counts,
        "top_source_ips": top_ips,
        "event_categories": cat_counter,
        "events_over_time": hourly_sorted,
        "mitre_tactics": mitre_counter,
    }


# --------------------
# ROUTES
# --------------------

@app.route("/")
def dashboard():
    initialize_soc()
    metrics = get_metrics()
    return render_template("dashboard.html", metrics=metrics)


@app.route("/alerts")
def alerts_view():
    initialize_soc()
    alerts_data = [a.to_dict() for a in SOC_STATE["alerts"]]
    alerts_data.sort(key=lambda x: x["severity_score"], reverse=True)
    return render_template("alerts.html", alerts=alerts_data)


@app.route("/log_explorer")
def log_explorer():
    initialize_soc()
    search_q = request.args.get("q", "").lower()
    category = request.args.get("category", "")
    severity = request.args.get("severity", "")

    events = SOC_STATE["events"]
    filtered = []
    for e in events:
        d = e.to_dict()
        if search_q and search_q not in (d.get("raw_log", "") + d.get("event_action", "")).lower():
            continue
        if category and d.get("event_category") != category:
            continue
        if severity and d.get("severity") != severity:
            continue
        filtered.append(d)

    filtered.sort(key=lambda x: x["timestamp"], reverse=True)
    return render_template("log_explorer.html", events=filtered[:200], search_q=search_q, category=category, severity=severity)


@app.route("/incident/<alert_id>")
def incident_detail(alert_id):
    initialize_soc()
    alert = next((a for a in SOC_STATE["alerts"] if a.alert_id == alert_id), None)
    if not alert:
        return "Alert not found", 404

    # Find related events
    related = [
        e.to_dict() for e in SOC_STATE["events"]
        if e.source_ip == alert.source_ip or e.username == alert.username
    ]
    related.sort(key=lambda x: x["timestamp"])
    return render_template("incident_detail.html", alert=alert.to_dict(), related_events=related[:30])


@app.route("/simulator")
def simulator():
    initialize_soc()
    return render_template("simulator.html")


# --------------------
# API ENDPOINTS
# --------------------

@app.route("/api/metrics")
def api_metrics():
    initialize_soc()
    return jsonify(get_metrics())


@app.route("/api/alerts")
def api_alerts():
    initialize_soc()
    alerts_data = [a.to_dict() for a in SOC_STATE["alerts"]]
    alerts_data.sort(key=lambda x: x["timestamp"], reverse=True)
    return jsonify({"total": len(alerts_data), "alerts": alerts_data[:50]})


@app.route("/api/simulate/<scenario>", methods=["POST"])
def api_simulate(scenario):
    """Trigger specific attack scenarios on demand."""
    initialize_soc()
    attacker = ATTACKER_IPS[0]
    new_events = []

    if scenario == "brute_force":
        from soc_core import telemetry_generator as tg
        tg.all_events = []
        simulate_brute_force(attacker_ip=attacker, count=20)
        new_events = list(tg.all_events)
    elif scenario == "sqli":
        from soc_core import telemetry_generator as tg
        tg.all_events = []
        simulate_sqli_attack(attacker_ip=attacker)
        new_events = list(tg.all_events)
    elif scenario == "port_scan":
        from soc_core import telemetry_generator as tg
        tg.all_events = []
        simulate_port_scan(attacker_ip=attacker, count=15)
        new_events = list(tg.all_events)
    elif scenario == "privesc":
        from soc_core import telemetry_generator as tg
        tg.all_events = []
        simulate_privilege_escalation(count=6)
        new_events = list(tg.all_events)
    elif scenario == "webshell":
        from soc_core import telemetry_generator as tg
        tg.all_events = []
        simulate_webshell_upload(attacker_ip=attacker)
        new_events = list(tg.all_events)
    else:
        return jsonify({"error": "Unknown scenario"}), 400

    SOC_STATE["events"].extend(new_events)
    new_alerts, summary = _run_detection(new_events)
    SOC_STATE["alerts"] = SOC_STATE["engine"].alerts

    return jsonify({
        "success": True,
        "scenario": scenario,
        "new_events_generated": len(new_events),
        "new_alerts_triggered": len(new_alerts),
        "total_alerts": summary["total_alerts"],
        "severity_summary": summary["by_severity"]
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset SOC state and regenerate fresh telemetry."""
    SOC_STATE["events"] = []
    SOC_STATE["alerts"] = []
    SOC_STATE["engine"] = DetectionEngine()
    SOC_STATE["initialized"] = False
    initialize_soc()
    return jsonify({"success": True, "message": "SOC state reset and telemetry regenerated."})


if __name__ == "__main__":
    print("[*] Initializing NovaVault SOC Monitoring Dashboard...")
    initialize_soc()
    print("[*] Dashboard starting at http://127.0.0.1:5500")
    app.run(host="127.0.0.1", port=5500, debug=True, use_reloader=False)
