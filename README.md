# SOC Fortress — SIEM Monitoring & Incident Analysis Platform

A SOC-oriented security monitoring platform integrating **Wazuh SIEM**, **Graylog**, **OpenSearch**, and a custom **Flask-based dashboard** for centralized security event visualization and incident investigation.

The platform simulates a Security Operations Center workflow by collecting endpoint events, processing security alerts, visualizing incidents, and supporting analyst investigation workflows.

Optional local AI-assisted analysis features are integrated using **Ollama** to assist with alert interpretation, incident summaries, and remediation recommendations.

---

## Features

### Security Monitoring Dashboard

The dashboard provides:

- Security event visualization
- Severity distribution
- Event trends
- Monitored hosts overview
- MITRE ATT&CK tactic visualization
- Recent security alerts
- Incident investigation workflow

---

## Application Pages

| Route | Description |
|---|---|
| `/login` | Session-based authentication |
| `/dashboard` | Security monitoring overview and analytics |
| `/incidents` | Alert investigation interface |
| `/ai-analyst` | Optional AI-assisted security analysis workspace |

---

## AI-Assisted Analyst Features

The AI module is designed as an assistant for security analysts and includes:

### Incident Analysis
- Security event explanation
- Severity assessment
- MITRE ATT&CK mapping
- Investigation recommendations
- Remediation suggestions

### Auto-Triage
- Alert prioritization
- Detection of potential patterns
- Investigation guidance

### Threat Analysis Support
- Extraction of security indicators
- Analysis of processes, IPs, files, and command lines
- Investigation assistance

### Detection Rule Generation
- Sigma rule generation
- Wazuh detection rule suggestions

### Incident Documentation
- Incident report generation
- Investigation notes

> AI-generated results are designed to assist analysts and require human validation.

---

# Architecture Overview

The platform integrates:

- **Wazuh** — Endpoint monitoring and detection
- **Graylog** — Centralized log management and analysis
- **OpenSearch** — Log indexing and storage
- **Sysmon** — Windows endpoint telemetry
- **Fluent Bit** — Log forwarding pipeline
- **Flask** — Dashboard backend
- **Ollama** — Local AI inference

---

# Project Structure

```
SOCDashboard/
├── app.py
├── requirements.txt
├── deploy_windows.ps1
├── README.md
├── .env
├── config.json
├── data/
│   ├── execution_log.jsonl
│   └── approvals.jsonl
└── templates/
    ├── login.html
    ├── dashboard.html
    ├── incidents.html
    └── ai_analyst.html
```

---

# Installation (Windows)

## Automated Deployment

Run PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Execute:

```powershell
.\deploy_windows.ps1
```

The deployment script:

- Checks Python requirements
- Creates a virtual environment
- Installs dependencies
- Generates configuration files
- Configures local deployment settings
- Creates startup utilities

---

## Manual Installation

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

The dashboard will start on:

```
http://localhost:5000
```

---

# Configuration

Configuration can be managed through:

## Environment Variables

Examples:

```
FLASK_SECRET_KEY
ADMIN_PASSWORD
PORT
FLASK_DEBUG
SOC_OLLAMA_MODEL
SOC_OLLAMA_URL
```

## Runtime Configuration

The dashboard supports configuration through:

```
config.json
```

including:

- AI model selection
- Ollama connection settings
- Alert filtering range
- Execution mode

---

# Active Response Safety Model

The platform includes an optional command approval workflow.

Two modes are available:

| Mode | Behavior |
|---|---|
| Disabled | Commands are logged but not executed |
| Enabled | Commands are validated against an allowlist before execution |

The goal is to prevent unsafe automated actions and maintain analyst control.

---

# Security Hardening Recommendations

Before production deployment:

- Store credentials securely using environment variables
- Hash user passwords
- Disable Flask debug mode
- Deploy behind HTTPS
- Add CSRF protection
- Implement rate limiting
- Configure proper session security
- Review active response permissions
- Enable log rotation

---

# Technologies Used

## Cybersecurity

- Wazuh
- Graylog
- OpenSearch
- Sysmon
- MITRE ATT&CK

## Development

- Python
- Flask
- JavaScript
- HTML/CSS
- REST APIs

## Infrastructure

- Linux
- Windows
- Hyper-V virtualization
- PowerShell

---

# Future Improvements

Planned improvements:

- Real IOC enrichment using external threat intelligence APIs
- Direct Wazuh API integration
- Role-based access control
- Advanced incident management workflow
- Additional detection automation

---

# Project Context

Developed as part of a cybersecurity internship project focused on building a SOC-oriented monitoring environment, integrating security monitoring technologies, and exploring practical incident analysis workflows.
