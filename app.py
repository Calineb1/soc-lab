"""
SOC Fortress Custom Dashboard
Backend: Flask + Graylog + Ollama
"""

import os
import json
import re
import subprocess
import ipaddress
from collections import Counter
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify
)
import requests

# Optional .env support
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ===========================================================================
# Config
# ===========================================================================
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(APP_DIR, "data")
CONFIG_FILE = os.path.join(APP_DIR, "config.json")
EXEC_LOG = os.path.join(DATA_DIR, "execution_log.jsonl")
APPROVAL_LOG = os.path.join(DATA_DIR, "approvals.jsonl")

os.makedirs(DATA_DIR, exist_ok=True)

# Defaults — overridden by config.json if present, then by env vars
CONFIG = {
    "ollama_model": "llama3.1",
    "ollama_url": "http://127.0.0.1:11434",
    "ollama_timeout": 120,
    "graylog_url": "http://ingest.socfortress.local:9000/api/search/universal/relative",
    "graylog_user": "admin",
    "graylog_pass": "Kaline1",
    "execute_enabled": False,  # Dangerous: enable only after testing
    "default_alert_range": 300,  # seconds
}


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                CONFIG.update(json.load(f))
        except Exception as e:
            print(f"[config] failed to load: {e}")

    # Env vars take precedence
    for k in list(CONFIG.keys()):
        env_key = "SOC_" + k.upper()
        if env_key in os.environ:
            v = os.environ[env_key]
            if isinstance(CONFIG[k], bool):
                CONFIG[k] = v.lower() in ("1", "true", "yes")
            elif isinstance(CONFIG[k], int):
                CONFIG[k] = int(v)
            else:
                CONFIG[k] = v


def save_config():
    # Don't persist secrets to config.json
    safe = {k: v for k, v in CONFIG.items() if "pass" not in k}
    with open(CONFIG_FILE, "w") as f:
        json.dump(safe, f, indent=2)


load_config()


# ===========================================================================
# Flask app
# ===========================================================================
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-only-change-me-before-prod")

USERS = {
    "admin": os.environ.get("ADMIN_PASSWORD", "ChangeMe123!")
}


# ===========================================================================
# Auth
# ===========================================================================
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "GET" and session.get("user"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if u in USERS and USERS[u] == p:
            session.clear()
            session["user"] = u
            return redirect(request.args.get("next") or url_for("dashboard"))
        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ===========================================================================
# Graylog
# ===========================================================================
def get_alerts(seconds=None):
    seconds = seconds or CONFIG["default_alert_range"]
    params = {"query": "*", "range": seconds, "limit": 30}
    headers = {"Accept": "application/json", "X-Requested-By": "siem-dashboard"}

    try:
        r = requests.get(
            CONFIG["graylog_url"],
            params=params,
            auth=(CONFIG["graylog_user"], CONFIG["graylog_pass"]),
            headers=headers,
            timeout=10
        )
        data = r.json()
    except Exception as e:
        print(f"[graylog] error: {e}")
        return []

    out = []
    for msg in data.get("messages", []):
        m = msg["message"]
        out.append({
            "timestamp": m.get("timestamp"),
            "host": m.get("agent_name"),
            "agent_ip": m.get("agent_ip"),
            "event": m.get("rule_description"),
            "severity": m.get("rule_level"),
            "rule_id": m.get("rule_id") or "",
            "rule_groups": m.get("rule_groups") or "",
            "process": (
                m.get("data_win_eventdata_image")
                or m.get("data_win_eventdata_sourceImage")
                or m.get("data_win_eventdata_targetImage")
                or "N/A"
            ),
            "user": (
                m.get("data_win_eventdata_user")
                or m.get("data_win_eventdata_User")
                or "N/A"
            ),
            "command_line": m.get("data_win_eventdata_commandLine") or "",
            "src_ip": m.get("data_win_eventdata_sourceIp") or "",
            "dst_ip": m.get("data_win_eventdata_destinationIp") or "",
            "dst_port": m.get("data_win_eventdata_destinationPort") or "",
            "event_id": m.get("data_win_system_eventID") or "",
            "mitre_rule": m.get("data_win_eventdata_ruleName") or "",
            "target_filename": m.get("data_win_eventdata_targetFilename") or "",
        })
    return out


def graylog_status():
    try:
        r = requests.get(
            CONFIG["graylog_url"].replace("/search/universal/relative", "/system"),
            auth=(CONFIG["graylog_user"], CONFIG["graylog_pass"]),
            timeout=4
        )
        return r.status_code == 200
    except Exception:
        return False


# ===========================================================================
# Aggregations for dashboard
# ===========================================================================
def safe_int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def parse_ts(ts):
    if not ts:
        return None
    try:
        # Graylog: "2024-01-01T12:00:00.000Z"
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def compute_dashboard_metrics(alerts):
    total = len(alerts)

    sev_critical = sum(1 for a in alerts if safe_int(a.get("severity")) >= 12)
    sev_high     = sum(1 for a in alerts if 10 <= safe_int(a.get("severity")) < 12)
    sev_medium   = sum(1 for a in alerts if 5 <= safe_int(a.get("severity")) < 10)
    sev_low      = sum(1 for a in alerts if safe_int(a.get("severity")) < 5)

    hosts = Counter(a.get("host") for a in alerts if a.get("host"))
    events = Counter(a.get("event") for a in alerts if a.get("event"))


    # MITRE tactic — heuristic from rule_groups string
    # MITRE tactic extraction
    tactics = Counter()

    for a in alerts:
        rule_name = a.get("mitre_rule") or ""

        match = re.search(r"technique_name=([^,]+)", rule_name)

        if match:
            technique = match.group(1).strip()
            tactics[technique] += 1



    sevs = [safe_int(a.get("severity")) for a in alerts if a.get("severity") is not None]
    avg_sev = round(sum(sevs) / len(sevs), 1) if sevs else 0




    # Trend: bucket by 5-minute window
    buckets = {}
    for a in alerts:
        dt = parse_ts(a.get("timestamp"))
        if not dt:
            continue
        dt = dt.replace(minute=dt.minute - dt.minute % 5, second=0, microsecond=0)
        key = dt.strftime("%H:%M")
        buckets[key] = buckets.get(key, 0) + 1
    trend = sorted(buckets.items())

    return {
        "total": total,
        "sev_critical": sev_critical,
        "sev_high": sev_high,
        "sev_medium": sev_medium,
        "sev_low": sev_low,
        "endpoints": len(hosts),
        "agents_online": len(hosts),
        "avg_severity": avg_sev,
        "top_hosts": hosts.most_common(5),
        "top_events": [(e[:60], c) for e, c in events.most_common(5)],
        "top_tactic": tactics.most_common(1)[0][0] if tactics else "N/A",
        "tactics": tactics.most_common(8),
        "trend_labels": [k for k, _ in trend],
        "trend_values": [v for _, v in trend],
    }


# ===========================================================================
# Ollama
# ===========================================================================
def ollama_status():
    try:
        r = requests.get(f"{CONFIG['ollama_url']}/api/tags", timeout=3)
        if r.status_code == 200:
            data = r.json()
            models = [m.get("name", "?") for m in data.get("models", [])]
            return {
                "online": True,
                "models": models,
                "active_model": CONFIG["ollama_model"],
                "model_loaded": CONFIG["ollama_model"] in models
            }
    except Exception as e:
        print(f"[ollama] status: {e}")
    return {"online": False, "models": [],
            "active_model": CONFIG["ollama_model"], "model_loaded": False}


def call_ollama(prompt, system=None, force_json=False, model=None):
    payload = {
        "model": model or CONFIG["ollama_model"],
        "prompt": prompt,
        "stream": False,
    }
    if system:
        payload["system"] = system
    if force_json:
        payload["format"] = "json"

    r = requests.post(
        f"{CONFIG['ollama_url']}/api/generate",
        json=payload,
        timeout=CONFIG["ollama_timeout"]
    )
    r.raise_for_status()
    return r.json().get("response", "").strip()


def extract_json(text):
    text = text.strip()
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
    return None


# ===========================================================================
# Prompts
# ===========================================================================
SOC_SYSTEM_PROMPT = (
    "You are an experienced Security Operations Center (SOC) analyst with deep "
    "expertise in Windows security, Sysmon event IDs, MITRE ATT&CK framework, "
    "and incident response. You analyze security events with precision and "
    "technical clarity. Be concise, accurate, and avoid speculation."
)


def fmt_incident(i):
    return (
        f"- Timestamp: {i.get('timestamp')}\n"
        f"- Host: {i.get('host')}\n"
        f"- User: {i.get('user')}\n"
        f"- Rule: {i.get('event')}\n"
        f"- Severity (raw): {i.get('severity')}\n"
        f"- Process: {i.get('process')}\n"
        f"- Command line: {i.get('command_line') or 'N/A'}\n"
        f"- Source IP: {i.get('src_ip') or 'N/A'}\n"
        f"- Destination IP: {i.get('dst_ip') or 'N/A'}\n"
        f"- Destination port: {i.get('dst_port') or 'N/A'}\n"
        f"- Sysmon event ID: {i.get('event_id') or 'N/A'}\n"
        f"- Target filename: {i.get('target_filename') or 'N/A'}"
    )


def build_analysis_prompt(i):
    return f"""Analyze this security incident using ONLY the provided fields.
Do not assume compromise. Do not label activity as Command and Control unless the event clearly shows external suspicious beaconing, malware, or known bad infrastructure.
If the event could be benign, say so clearly.

Respond with valid JSON ONLY matching this schema:

{{
  "incident_title": "short descriptive title",
  "severity": "Critical | High | Medium | Low",
  "summary": "1-2 sentence plain-language summary",
  "why_it_matters": "why this is or isn't a security concern",
  "possible_attack_type": "Unclear / Needs Investigation | Suspicious PowerShell Activity | Possible Process Injection | Suspicious File Creation | Network Connection | Other",
  "mitre_tactic": "Relevant MITRE tactic if supported by the event, otherwise Unclear / Not enough evidence",
  "recommended_steps": ["step 1", "step 2", "step 3"],
  "suggested_active_response": ["safe action 1", "safe action 2"],
  "suggested_command": "safe read-only PowerShell/netsh command for investigation, or empty string",
  "confidence": "High | Medium | Low"
}}

Incident:
{fmt_incident(i)}

Important calibration rules:
- Localhost/127.0.0.1 traffic is usually local application activity, not C2 by default.
- User AppData file creation can be benign; recommend hash/checking context before escalation.
- PowerShell network connections are suspicious only when unexpected; recommend correlation first.
- Process injection alerts can be false positives; mention analyst validation.
- Do not recommend host isolation unless severity is Critical or there is clear malicious evidence.
- Prefer read-only commands such as Get-FileHash, Get-Process, Get-NetTCPConnection, Get-AuthenticodeSignature.

JSON only. No prose, no markdown.
- Sysmon Event ID mappings are STRICT:
  - Event ID 1 = Process Creation
  - Event ID 3 = Network Connection
  - Event ID 11 = File Creation
- Never describe Sysmon Event ID 11 as Process Creation."""

def build_remediation_prompt(i):
    return f"""Generate a SAFE Windows PowerShell investigation/remediation script.

Incident:
{fmt_incident(i)}

Rules:
- Output only one PowerShell code block.
- Maximum 6 commands.
- Add a short comment before each command.
- Prefer simple, reliable Windows commands.
- Use ONLY values present in the incident fields.
- Do NOT invent placeholder IPs, ports, hashes, usernames, filenames, or PIDs.
- If Destination IP is N/A, empty, or unknown, do NOT use Test-NetConnection or New-NetFirewallRule.
- If Sysmon Event ID is 11, treat it as File Creation, not Process Creation.
- Sysmon Event ID mappings are STRICT:
  - Event ID 1 = Process Creation
  - Event ID 3 = Network Connection
  - Event ID 11 = File Creation
- For file creation alerts, prioritize Test-Path, Get-FileHash, Get-Content, and Get-WinEvent.
- For suspicious IPs only when a real dst_ip is present: check connection, block IP using New-NetFirewallRule, then verify with Get-NetFirewallRule.
- For New-NetFirewallRule, use RemoteAddress and RemotePort, not DestinationIP or DestinationPort.
- For Test-NetConnection, use ComputerName and Port, not RemoteAddress and RemotePort.
- For Sysmon logs: use Get-WinEvent -FilterHashtable with LogName='Microsoft-Windows-Sysmon/Operational' and ID when available, with -MaxEvents 50.
- Do not disable security tools, logging, Sysmon, Wazuh, Defender, firewall, or monitoring rules.
- Do not delete files, clear logs, modify detection rules, or kill processes unless a specific PID is provided.
Respond with the script only."""
def classify_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return "internal/private" if addr.is_private else "external/public"
    except Exception:
        return "unknown"
def fmt_incident(i):
    src_ip = i.get("src_ip") or "N/A"
    dst_ip = i.get("dst_ip") or "N/A"

    src_type = classify_ip(src_ip) if src_ip != "N/A" else "unknown"
    dst_type = classify_ip(dst_ip) if dst_ip != "N/A" else "unknown"

    return (
        f"- Timestamp: {i.get('timestamp')}\n"
        f"- Host: {i.get('host')}\n"
        f"- User: {i.get('user')}\n"
        f"- Rule: {i.get('event')}\n"
        f"- Severity (raw): {i.get('severity')}\n"
        f"- Process: {i.get('process')}\n"
        f"- Command line: {i.get('command_line') or 'N/A'}\n"
        f"- Source IP: {src_ip} ({src_type})\n"
        f"- Destination IP: {dst_ip} ({dst_type})\n"
        f"- Destination port: {i.get('dst_port') or 'N/A'}\n"
        f"- Sysmon event ID: {i.get('event_id') or 'N/A'}\n"
        f"- Target filename: {i.get('target_filename') or 'N/A'}"
    )



def build_report_prompt(i):
    return f"""Generate a concise SOC incident report in markdown.

Sections:
- Summary
- Affected Asset
- Indicators
- Timeline
- Recommended Actions
- Analyst Notes

Rules:
- Keep it concise and professional.
- Focus only on the provided incident fields.
- Do not assume compromise unless evidence strongly supports it.
- If evidence is inconclusive, clearly state that further investigation is required.
- Use bullet points where appropriate.
- If source or destination IP fields are empty, missing, or N/A, state:
  "No source or destination IP information was present in the event."
- Keep the report SOC-oriented and operational.
- Distinguish clearly between internal/private IPs and external/public IPs.
- Do not describe a destination IP as internal unless it belongs to a private RFC1918 range.
- Treat severity levels 0-4 as Low, 5-9 as Medium, 10-14 as High, and 15+ as Critical unless otherwise specified.
Incident:
- Sysmon Event ID mappings are STRICT:
  - Event ID 1 = Process Creation
  - Event ID 3 = Network Connection
  - Event ID 11 = File Creation
- Never describe Sysmon Event ID 11 as Process Creation.
{fmt_incident(i)}
"""


def build_threat_intel_prompt(i):
    indicators = []
    if i.get("dst_ip"): indicators.append(f"IP: {i['dst_ip']}")
    if i.get("src_ip"): indicators.append(f"Source IP: {i['src_ip']}")
    if i.get("process"): indicators.append(f"Process: {i['process']}")
    if i.get("target_filename"): indicators.append(f"File: {i['target_filename']}")
    if i.get("command_line"): indicators.append(f"Cmdline: {i['command_line']}")

    ind_block = "\n".join(f"- {x}" for x in indicators) or "- (none extracted)"

    return f"""Provide threat intelligence context for the indicators below.
For each indicator, assess:
1. Is this likely benign, suspicious, or malicious based on patterns?
2. What threat actor groups, malware families, or attack techniques are
   commonly associated with this kind of indicator?
3. What enrichment sources should the analyst check (VirusTotal, AbuseIPDB,
   AlienVault OTX, etc.)?
4. Any quick reasoning-based reputation assessment?
5. Do not speculate about specific threat actors or malware families unless there is strong evidence.
6. If an IP belongs to a cloud provider (AWS, Azure, Cloudflare, Google Cloud), state that cloud infrastructure can be used for both legitimate and malicious purposes.
7. Keep assessments evidence-based and probabilistic.
8. Do not change or rewrite IP addresses from the incident.


Indicators extracted from incident on host {i.get('host', '?')}:
{ind_block}

Respond in markdown with one section per indicator. Be concrete. If you don't
have enough info, say so — don't make up specifics."""


def build_correlation_prompt(base, related):
    rel_block = "\n".join(
        f"{idx}. [{a.get('timestamp')}] host={a.get('host')} user={a.get('user')} "
        f"sev={a.get('severity')} event=\"{a.get('event')}\" proc={a.get('process')}"
        for idx, a in enumerate(related[:10], 1)
    ) or "(no related events found)"

    return f"""You are looking for an attack chain. Below is a BASE event followed by
candidate RELATED events from the same time window. Determine:

1. Which related events are part of the same attack chain as the base event?
2. What's the likely sequence and technique progression (use MITRE ATT&CK)?
3. Is this an active intrusion, a single anomaly, or noise?
4. Recommended next investigation steps.

BASE EVENT:
{fmt_incident(base)}

CANDIDATE RELATED EVENTS:
{rel_block}

Respond in markdown. Be direct."""


def build_rule_prompt(i, rule_format):
    return f"""Generate a {rule_format} detection rule based on this incident.

Incident:
{fmt_incident(i)}

Requirements:
- Make the rule generic enough to detect similar behavior.
- Keep it specific enough to avoid obvious false positives.
- Use only fields present in the incident.
- Do not invent missing fields, hashes, parent processes, usernames, or MITRE techniques.
- If MITRE mapping is uncertain, use "Unclear" or omit the tactic.
- Prefer suspicious behavior patterns over exact one-time values when possible.
- Avoid hardcoding local/private IPs unless they are central to the detection.
- Include a short rationale before the rule.
- Then output only one valid {rule_format} YAML code block.
- Sysmon Event ID 1 means Process Creation.
- Sysmon Event ID 3 means Network Connection.
- Sysmon Event ID 11 means File Creation.
- If Sysmon Event ID is 11, describe it as File Creation, not Process Creation.
- Preserve file extensions exactly as provided. Do not change .ps1 to .ps3.

Respond in this format:
Short rationale paragraph.

```yaml
# rule here
```"""


def build_triage_prompt(alerts):
    if not alerts:
        return "Respond with: 'No active alerts to triage.'"

    alerts = sorted(
        alerts,
        key=lambda a: int(a.get("severity") or 0),
        reverse=True
    )

    lines = [
        f"{i}. [{a.get('timestamp')}] host={a.get('host')} user={a.get('user')} "
        f"sev={a.get('severity')} event=\"{a.get('event')}\" proc={a.get('process')} "
        f"cmd=\"{a.get('command_line') or 'N/A'}\" dst={a.get('dst_ip') or 'N/A'}:{a.get('dst_port') or 'N/A'}"
        for i, a in enumerate(alerts[:15], 1)
    ]

    return f"""You are a SOC lead triaging current alerts.

Alerts:
{chr(10).join(lines)}

Provide a concise triage briefing in markdown with:
1. **Top priorities** — the 3 alerts or alert groups to investigate first
2. **Patterns / correlations** — repeated hosts, processes, users, destinations, or event types
3. **Recommended investigation order** — practical next steps
4. **Quick wins** — likely false positives or checks that can reduce noise

Rules:
- Do not assume compromise based only on repeated alerts.
- Repeated alerts may indicate noise, false positives, or normal repetitive activity.
- Do not claim privilege escalation, persistence, lateral movement, malware, or C2 unless explicitly supported by the alert fields.
- Treat legitimate Microsoft processes cautiously and mention validation before escalation.
- Avoid speculative threat actor or malware names.
- Focus on prioritization, correlation, and investigation guidance.
- If evidence is inconclusive, say further validation is required.

Be direct. No filler."""


def build_chat_system_prompt(alerts):
    if not alerts:
        return SOC_SYSTEM_PROMPT + "\n\nNo current active alerts."
    lines = [
        f"{i}. [{a.get('timestamp')}] {a.get('host')} / {a.get('user')} — "
        f"{a.get('event')} (sev {a.get('severity')}) proc={a.get('process')}"
        for i, a in enumerate(alerts[:10], 1)
    ]
    return SOC_SYSTEM_PROMPT + "\n\nCurrent alerts:\n" + "\n".join(lines)


# ===========================================================================
# Pages
# ===========================================================================
@app.route("/")
@login_required
def home():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Wider window for richer dashboard trend data
    alerts = get_alerts(seconds=86400)
    metrics = compute_dashboard_metrics(alerts)
    recent = sorted(alerts, key=lambda a: a.get("timestamp") or "", reverse=True)[:10]
    return render_template(
        "dashboard.html",
        metrics=metrics,
        recent=recent,
        ollama=ollama_status(),
        graylog_ok=graylog_status(),
        current_user=session.get("user"),
    )


@app.route("/incidents")
@login_required
def incidents():
    alerts = get_alerts()
    return render_template(
        "incidents.html",
        alerts=alerts,
        current_user=session.get("user")
    )


@app.route("/ai-analyst", methods=["GET", "POST"])
@login_required
def ai_analyst():
    alerts = get_alerts()
    status = ollama_status()
    preselected = None
    if request.method == "POST":
        preselected = {k: request.form.get(k, "") for k in [
            "timestamp", "host", "user", "event", "severity", "process",
            "command_line", "src_ip", "dst_ip", "dst_port", "event_id",
            "target_filename"
        ]}
    return render_template(
        "ai_analyst.html",
        alerts=alerts,
        status=status,
        config=CONFIG,
        preselected=preselected,
        current_user=session.get("user")
    )


# ===========================================================================
# AI API endpoints
# ===========================================================================
@app.route("/api/ollama-status")
@login_required
def api_ollama_status():
    return jsonify(ollama_status())


@app.route("/api/analyze", methods=["POST"])
@login_required
def api_analyze():
    incident = request.get_json() or {}
    try:
        raw = call_ollama(
            build_analysis_prompt(incident),
            system=SOC_SYSTEM_PROMPT,
            force_json=True
        )
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500

    parsed = extract_json(raw)
    if parsed is None:
        return jsonify({"error": "AI returned invalid JSON", "raw": raw}), 502
    return jsonify({"analysis": parsed, "raw": raw})


@app.route("/api/remediation", methods=["POST"])
@login_required
def api_remediation():
    incident = request.get_json() or {}
    try:
        raw = call_ollama(build_remediation_prompt(incident), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"script": raw})


@app.route("/api/report", methods=["POST"])
@login_required
def api_report():
    incident = request.get_json() or {}
    try:
        raw = call_ollama(build_report_prompt(incident), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"report": raw})


@app.route("/api/threat-intel", methods=["POST"])
@login_required
def api_threat_intel():
    incident = request.get_json() or {}
    try:
        raw = call_ollama(build_threat_intel_prompt(incident), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"intel": raw})


@app.route("/api/correlate", methods=["POST"])
@login_required
def api_correlate():
    base = request.get_json() or {}
    all_alerts = get_alerts()
    # Find candidate related events: same host, same user, or same dst_ip
    related = []
    for a in all_alerts:
        if a is base: continue
        if a.get("timestamp") == base.get("timestamp") and a.get("event") == base.get("event"):
            continue
        score = 0
        if a.get("host") and a.get("host") == base.get("host"): score += 2
        if a.get("user") and a.get("user") == base.get("user"): score += 1
        if a.get("dst_ip") and a.get("dst_ip") == base.get("dst_ip"): score += 3
        if a.get("process") and a.get("process") == base.get("process"): score += 1
        if score >= 1:
            related.append(a)
    related = related[:10]

    try:
        raw = call_ollama(build_correlation_prompt(base, related), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"correlation": raw, "related_count": len(related)})


@app.route("/api/rule-generator", methods=["POST"])
@login_required
def api_rule_generator():
    body = request.get_json() or {}
    incident = body.get("incident", {})
    rule_format = body.get("format", "Sigma")
    if rule_format not in ("Sigma", "Wazuh"):
        rule_format = "Sigma"
    try:
        raw = call_ollama(build_rule_prompt(incident, rule_format), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"rule": raw, "format": rule_format})


@app.route("/api/auto-triage", methods=["POST"])
@login_required
def api_auto_triage():
    alerts = get_alerts()
    try:
        raw = call_ollama(build_triage_prompt(alerts), system=SOC_SYSTEM_PROMPT)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"triage": raw, "alert_count": len(alerts)})


@app.route("/api/chat", methods=["POST"])
@login_required
def api_chat():
    body = request.get_json() or {}
    message = body.get("message", "").strip()
    history = body.get("history", [])
    if not message:
        return jsonify({"error": "Empty message"}), 400

    alerts = get_alerts()
    system = build_chat_system_prompt(alerts)
    convo = []
    for turn in history[-10:]:
        convo.append(f"{turn.get('role','user').upper()}: {turn.get('content','')}")
    convo.append(f"USER: {message}")
    convo.append("ASSISTANT:")
    try:
        reply = call_ollama("\n".join(convo), system=system)
    except Exception as e:
        return jsonify({"error": f"Ollama call failed: {e}"}), 500
    return jsonify({"reply": reply})


# ===========================================================================
# Setup / Config API
# ===========================================================================
@app.route("/api/config", methods=["GET", "POST"])
@login_required
def api_config():
    if request.method == "GET":
        # Hide secrets
        safe = {k: v for k, v in CONFIG.items() if "pass" not in k}
        return jsonify(safe)

    body = request.get_json() or {}
    allowed = {"ollama_model", "ollama_url", "ollama_timeout",
               "execute_enabled", "default_alert_range"}
    for k, v in body.items():
        if k in allowed:
            CONFIG[k] = v
    save_config()
    return jsonify({"ok": True, "config": {k: v for k, v in CONFIG.items() if "pass" not in k}})


@app.route("/api/test-connections")
@login_required
def api_test_connections():
    return jsonify({
        "graylog": graylog_status(),
        "ollama": ollama_status(),
    })


# ===========================================================================
# Active Response Execution (DISABLED BY DEFAULT)
# ===========================================================================
# Only commands matching these patterns can run when execute_enabled is True.
# Conservative by design — extend with care.
EXECUTE_ALLOWLIST = [
    r"^netsh\s+advfirewall\s+firewall\s+(add|delete|show)\s+rule\s+.+$",
    r"^taskkill\s+/PID\s+\d+\s+/F$",
    r"^taskkill\s+/IM\s+[\w.\-]+\s+/F$",
    r"^powershell(\.exe)?\s+-Command\s+[\"']Stop-Process\s+-Id\s+\d+\s+-Force[\"']$",
    r"^powershell(\.exe)?\s+-Command\s+[\"']Get-Process[\"']$",
]

EXECUTE_FORBIDDEN = [
    r"\b(format|del\s+/[fsq]|rm\s+-rf|rmdir\s+/s|shutdown|reg\s+delete)\b",
    r"\b(Remove-Item\s+-Recurse|Format-Volume|Clear-Disk)\b",
]


def append_jsonl(path, obj):
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def is_command_allowed(cmd):
    if not cmd or len(cmd) > 1000:
        return False, "Command empty or too long"
    for forbidden in EXECUTE_FORBIDDEN:
        if re.search(forbidden, cmd, re.IGNORECASE):
            return False, f"Matches forbidden pattern: {forbidden}"
    for allowed in EXECUTE_ALLOWLIST:
        if re.match(allowed, cmd, re.IGNORECASE):
            return True, "ok"
    return False, "Command does not match any allowlist pattern"


@app.route("/api/approve", methods=["POST"])
@login_required
def api_approve():
    """
    Logs an approved response action. Executes if execute_enabled is True
    AND the command passes the allowlist. Otherwise log-only.
    """
    body = request.get_json() or {}
    command = body.get("command", "").strip()
    incident = body.get("incident", {})
    user = session.get("user")

    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user": user,
        "command": command,
        "incident_host": incident.get("host"),
        "incident_event": incident.get("event"),
        "executed": False,
        "result": None,
    }

    if not CONFIG.get("execute_enabled"):
        record["result"] = "Execution disabled in config; logged only."
        append_jsonl(APPROVAL_LOG, record)
        return jsonify({"executed": False, "logged": True,
                        "message": "Approval logged. Execution is disabled in config."})

    ok, reason = is_command_allowed(command)
    if not ok:
        record["result"] = f"Blocked by allowlist: {reason}"
        append_jsonl(APPROVAL_LOG, record)
        return jsonify({"executed": False, "blocked": True, "reason": reason}), 400

    # Execute (timeout 30s, capture output)
    try:
        proc = subprocess.run(
            command, shell=True, capture_output=True, text=True, timeout=30
        )
        record["executed"] = True
        record["result"] = {
            "returncode": proc.returncode,
            "stdout": proc.stdout[-2000:],
            "stderr": proc.stderr[-2000:],
        }
        append_jsonl(EXEC_LOG, record)
        return jsonify({"executed": True, "result": record["result"]})
    except subprocess.TimeoutExpired:
        record["result"] = "Timed out after 30s"
        append_jsonl(EXEC_LOG, record)
        return jsonify({"executed": False, "error": "Command timed out"}), 500
    except Exception as e:
        record["result"] = f"Error: {e}"
        append_jsonl(EXEC_LOG, record)
        return jsonify({"executed": False, "error": str(e)}), 500


@app.route("/api/reject", methods=["POST"])
@login_required
def api_reject():
    body = request.get_json() or {}
    record = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "user": session.get("user"),
        "command": body.get("command", ""),
        "incident_host": body.get("incident", {}).get("host"),
        "incident_event": body.get("incident", {}).get("event"),
        "rejected": True,
        "reason": body.get("reason", "user rejected"),
    }
    append_jsonl(APPROVAL_LOG, record)
    return jsonify({"ok": True})


# ===========================================================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
