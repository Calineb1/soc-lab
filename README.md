# SOC Fortress Custom Dashboard

Custom Windows dashboard for Graylog SIEM with a local-AI analyst (Ollama).

## Pages

| Route | What it does |
|---|---|
| `/login` | Session-based authentication |
| `/dashboard` | KPI cards, severity donut, event trend, top hosts, MITRE tactics, recent alerts |
| `/incidents` | Live alert table from Graylog with per-row "Analyze" → AI page |
| `/ai-analyst` | 7-tab analyst workbench (see below) |

## AI Analyst tabs

1. **Analyze Event** — Pick an incident → AI returns JSON: title, severity pill, MITRE tactic, summary, why-it-matters, investigation steps, suggested response, copyable command, Approve/Reject buttons. Plus one-click **Remediation Script** (PowerShell) and **Incident Report** (markdown).
2. **Auto-Triage** — Sends every active alert to AI, returns prioritized briefing with patterns and recommended order.
3. **Threat Intel** — Extracts indicators from an incident (IPs, processes, files, command lines), AI provides reasoning-based reputation and enrichment guidance.
4. **Correlation** — Picks a base event, finds candidate related events (same host/user/dst-IP/process), AI determines if they're an attack chain.
5. **Rule Generator** — Generates Sigma or Wazuh detection rule from an incident.
6. **AI Chat** — Free-form chat with current alert context injected into system prompt.
7. **Setup** — Switch active model, change Ollama URL/timeout, toggle execution mode, test connections.

## File map

```
SOCDashboard/
├── app.py                     # Flask backend
├── requirements.txt           # Python deps
├── deploy_windows.ps1         # Windows deployment automation
├── README.md                  # This file
├── .env                       # (auto-generated) secrets
├── config.json                # (auto-generated) runtime settings
├── data/                      # (auto-generated)
│   ├── execution_log.jsonl    # All commands actually run
│   └── approvals.jsonl        # Approve/reject audit trail
└── templates/
    ├── login.html
    ├── dashboard.html
    ├── incidents.html
    └── ai_analyst.html
```

## Quick start (Windows)

1. Drop all files into one folder on the Windows machine (172.20.10.4).
2. Open **PowerShell as Administrator** in that folder.
3. Allow scripts for this session if needed:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
4. Run:
   ```powershell
   .\deploy_windows.ps1
   ```
   The script will:
   - Verify Python ≥ 3.9
   - Copy files to `C:\SOCDashboard`
   - Create venv and install deps
   - Generate `.env` with strong `FLASK_SECRET_KEY` and a random admin password (printed once)
   - Open inbound TCP 5000 in Windows Firewall
   - Pull `llama3.1` from Ollama (if Ollama is installed)
   - Create `start_dashboard.bat` and a desktop shortcut
5. Start the dashboard via the desktop shortcut, or:
   ```
   C:\SOCDashboard\start_dashboard.bat
   ```
6. Open `http://localhost:5000` (or `http://172.20.10.4:5000` from the LAN).

### Deploy script flags

```powershell
# Custom install location
.\deploy_windows.ps1 -InstallDir D:\SOC

# Different Ollama model
.\deploy_windows.ps1 -OllamaModel qwen2.5:7b

# Set admin password explicitly
.\deploy_windows.ps1 -AdminPassword "MyStrongPass!"

# Auto-start at boot via scheduled task
.\deploy_windows.ps1 -InstallAsService

# Skip firewall rule (e.g. if managed by GPO)
.\deploy_windows.ps1 -SkipFirewall

# Skip Ollama entirely
.\deploy_windows.ps1 -OllamaModel none
```

## Manual run (no deploy script)

```bash
pip install -r requirements.txt
python app.py
```

Defaults: `0.0.0.0:5000`, debug on, hardcoded admin/`ChangeMe123!`. Fix those for anything beyond local dev.

## Configuration

Two layers, in priority order:

1. **Environment variables** (highest) — read at startup. Useful keys:
   - `FLASK_SECRET_KEY` — session signing key
   - `ADMIN_PASSWORD` — login password for `admin`
   - `PORT` — default 5000
   - `FLASK_DEBUG` — `0` for prod, `1` for dev
   - `SOC_OLLAMA_MODEL`, `SOC_OLLAMA_URL`, `SOC_GRAYLOG_USER`, etc.

2. **`config.json`** — runtime-editable via the Setup tab:
   - `ollama_model`, `ollama_url`, `ollama_timeout`
   - `default_alert_range`
   - `execute_enabled`

Graylog credentials currently live as defaults in `app.py` (`graylog_user`, `graylog_pass`). Move those to env vars before going beyond the lab.

## Active Response — execution model

The Approve button next to an AI-suggested command behaves differently depending on `execute_enabled`:

| Mode | Behavior |
|---|---|
| `execute_enabled = false` (default) | Logs to `data/approvals.jsonl`. **No execution.** |
| `execute_enabled = true` | Validates the command against an allowlist, runs it via `subprocess.run`, captures stdout/stderr, logs to `data/execution_log.jsonl`. |

The allowlist (in `app.py` → `EXECUTE_ALLOWLIST`) currently permits:

- `netsh advfirewall firewall (add|delete|show) rule …`
- `taskkill /PID <num> /F` and `taskkill /IM <name> /F`
- `powershell -Command "Stop-Process -Id <num> -Force"`
- `powershell -Command "Get-Process"`

A separate `EXECUTE_FORBIDDEN` regex blocks anything matching `format`, `del /f`, `rm -rf`, `shutdown`, `reg delete`, `Remove-Item -Recurse`, etc. — even if it would otherwise match an allow pattern.

**Recommendation:** Leave `execute_enabled` off until you've watched several real AI suggestions and verified the allowlist behaves as intended. Then flip it on via the Setup tab.

## Hardening checklist before going beyond the lab

- [ ] Hash the admin password (`werkzeug.security.generate_password_hash`)
- [ ] Move Graylog credentials from `app.py` defaults into env vars
- [ ] Switch from `app.run(debug=True)` to a production WSGI (waitress on Windows: `pip install waitress`, then `waitress-serve --listen=0.0.0.0:5000 app:app`)
- [ ] Add HTTPS — either reverse-proxy (nginx/Caddy) or `ssl_context` on Flask with a real cert
- [ ] Enable `SESSION_COOKIE_SECURE = True` and `SESSION_COOKIE_HTTPONLY = True`
- [ ] Add CSRF protection (`flask-wtf`) to the login form and the per-row Analyze form
- [ ] Rate-limit `/login` (`flask-limiter`)
- [ ] Tighten the active-response allowlist for your specific environment
- [ ] Set up log rotation on `data/*.jsonl`

## Troubleshooting

**Ollama offline in status card** — Make sure `ollama serve` is running. On Windows it usually auto-starts; check with `Get-Process ollama`.

**"AI returned invalid JSON"** — Some smaller models drift off the schema. Try a stronger model (`llama3.1:8b` or `qwen2.5:7b`) in Setup.

**Empty alert list** — Confirm Graylog is reachable: `curl -u admin:Kaline1 http://ingest.socfortress.local:9000/api/system`. The Setup tab's "Test Connections" button does the same check.

**Slow analysis** — First-run model load takes 10-30s while Ollama warms up. Subsequent calls should be 5-15s on the RTX 4050.

**Login loops** — Cookie not being set. If running over HTTP and `SESSION_COOKIE_SECURE` is on, browsers will reject the cookie. Keep it off until HTTPS is in place.

## What's not built (yet)

- Live IOC enrichment via VirusTotal / AbuseIPDB / OTX (the Threat Intel tab does AI-only reasoning today). Wire up keys in `app.py` → `build_threat_intel_prompt` to add real lookups.
- Wazuh API direct integration for true "Active Agents" / "Agents Online" counts. Currently those numbers are derived from unique hostnames in recent Graylog alerts.
- Multi-user RBAC. There's one admin role.
- Incident-detail page (`/incidents/:id`). The handoff lists this; current flow goes from incidents row → AI Analyst directly, which covers the same intent.
