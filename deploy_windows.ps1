<#
.SYNOPSIS
    SOC Fortress Custom Dashboard - Windows deployment script

.DESCRIPTION
    Sets up the dashboard on a Windows machine:
      - Validates / installs Python prerequisites
      - Creates virtualenv and installs requirements
      - Generates strong Flask secret key in .env
      - Opens firewall port 5000
      - Optional: pulls an Ollama model
      - Creates start_dashboard.bat
      - Optional: registers a scheduled task to start at boot

.PARAMETER InstallDir
    Where to install. Defaults to C:\SOCDashboard.

.PARAMETER OllamaModel
    Which Ollama model to pull. Defaults to llama3.1.
    Use 'none' to skip pulling.

.PARAMETER AdminPassword
    Initial admin password for the dashboard. Random-generated if not provided.

.PARAMETER InstallAsService
    If set, register a scheduled task to auto-start at boot.

.PARAMETER SkipFirewall
    Skip the firewall rule creation.

.EXAMPLE
    .\deploy_windows.ps1
    .\deploy_windows.ps1 -OllamaModel qwen2.5:7b -InstallAsService
    .\deploy_windows.ps1 -InstallDir D:\SOC -AdminPassword "MyStrongPass!"

.NOTES
    Run from an elevated PowerShell session (Run as Administrator).
    Source files (app.py, requirements.txt, templates/) must sit next to this script.
#>

[CmdletBinding()]
param(
    [string] $InstallDir = "C:\SOCDashboard",
    [string] $OllamaModel = "llama3.1",
    [string] $AdminPassword = "",
    [switch] $InstallAsService,
    [switch] $SkipFirewall
)

$ErrorActionPreference = "Stop"
$here = $PSScriptRoot

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}
function Write-OK($msg) { Write-Host "    [ OK ] $msg" -ForegroundColor Green }
function Write-Warn2($msg) { Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red }

# ===========================================================================
# 0. Banner + admin check
# ===========================================================================
Write-Host ""
Write-Host "  ____   ___   ____    _____           _   " -ForegroundColor Cyan
Write-Host " / ___| / _ \ / ___|  |  ___|__  _ __ | |_ " -ForegroundColor Cyan
Write-Host " \___ \| | | | |      | |_ / _ \| '__|| __|" -ForegroundColor Cyan
Write-Host "  ___) | |_| | |___   |  _| (_) | |   | |_ " -ForegroundColor Cyan
Write-Host " |____/ \___/ \____|  |_|  \___/|_|    \__|" -ForegroundColor Cyan
Write-Host "                Dashboard Deployment       " -ForegroundColor DarkCyan
Write-Host ""

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator (firewall + scheduled task require it)."
    exit 1
}
Write-OK "Running as Administrator"

# ===========================================================================
# 1. Verify source files
# ===========================================================================
Write-Step "Checking source files in $here"
$required = @("app.py", "requirements.txt", "templates\login.html",
              "templates\incidents.html", "templates\ai_analyst.html",
              "templates\dashboard.html")
$missing = @()
foreach ($f in $required) {
    if (-not (Test-Path (Join-Path $here $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Fail "Missing files:"
    $missing | ForEach-Object { Write-Host "       - $_" -ForegroundColor Red }
    Write-Host "    Make sure deploy_windows.ps1 is next to app.py and the templates/ folder."
    exit 1
}
Write-OK "All source files found"

# ===========================================================================
# 2. Python check
# ===========================================================================
Write-Step "Checking Python"
$python = Get-Command python -ErrorAction SilentlyContinue
if (-not $python) {
    Write-Fail "Python not found in PATH."
    Write-Host "    Install Python 3.10+ from https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "    Make sure 'Add Python to PATH' is checked during install."
    exit 1
}
$pyVersion = & python --version 2>&1
Write-OK "Found $pyVersion"

# Quick version sanity check (>= 3.9)
$verMatch = $pyVersion -match "Python (\d+)\.(\d+)"
if ($verMatch) {
    $major = [int]$Matches[1]; $minor = [int]$Matches[2]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 9)) {
        Write-Fail "Python 3.9+ required (found $pyVersion)"
        exit 1
    }
}

# ===========================================================================
# 3. Install directory
# ===========================================================================
Write-Step "Setting up install directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir | Out-Null
    Write-OK "Created $InstallDir"
} else {
    Write-OK "Directory already exists"
}

# ===========================================================================
# 4. Copy source files
# ===========================================================================
Write-Step "Copying application files"
Copy-Item -Path (Join-Path $here "app.py") -Destination $InstallDir -Force
Copy-Item -Path (Join-Path $here "requirements.txt") -Destination $InstallDir -Force

$templatesDest = Join-Path $InstallDir "templates"
if (-not (Test-Path $templatesDest)) {
    New-Item -ItemType Directory -Path $templatesDest | Out-Null
}
Copy-Item -Path (Join-Path $here "templates\*.html") -Destination $templatesDest -Force

# Optional README
if (Test-Path (Join-Path $here "README.md")) {
    Copy-Item -Path (Join-Path $here "README.md") -Destination $InstallDir -Force
}

Write-OK "Files copied"

# ===========================================================================
# 5. Create virtualenv
# ===========================================================================
Write-Step "Creating Python virtual environment"
$venvPath = Join-Path $InstallDir "venv"
if (-not (Test-Path $venvPath)) {
    & python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        Write-Fail "Failed to create venv"
        exit 1
    }
    Write-OK "Virtualenv created at $venvPath"
} else {
    Write-OK "Virtualenv already exists"
}

# ===========================================================================
# 6. Install Python dependencies
# ===========================================================================
Write-Step "Installing Python dependencies"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPip = Join-Path $venvPath "Scripts\pip.exe"

& $venvPython -m pip install --upgrade pip --quiet
& $venvPip install -r (Join-Path $InstallDir "requirements.txt") --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Fail "pip install failed"
    exit 1
}
Write-OK "Dependencies installed"

# ===========================================================================
# 7. Generate .env with secret key + admin password
# ===========================================================================
Write-Step "Generating .env"
$envFile = Join-Path $InstallDir ".env"

if (-not (Test-Path $envFile)) {
    # Generate strong secret key via Python
    $secret = & $venvPython -c "import secrets; print(secrets.token_hex(32))"

    # Admin password: provided or generated
    if ([string]::IsNullOrEmpty($AdminPassword)) {
        $AdminPassword = & $venvPython -c "import secrets, string; chars = string.ascii_letters+string.digits+'!@#$%'; print(''.join(secrets.choice(chars) for _ in range(20)))"
        $generated = $true
    } else {
        $generated = $false
    }

    @"
# SOC Dashboard environment - keep this file out of version control
FLASK_SECRET_KEY=$secret
ADMIN_PASSWORD=$AdminPassword
FLASK_DEBUG=0
PORT=5000
"@ | Out-File -FilePath $envFile -Encoding UTF8 -NoNewline

    Write-OK "Wrote $envFile"
    if ($generated) {
        Write-Host ""
        Write-Host "    *** GENERATED ADMIN PASSWORD ***" -ForegroundColor Magenta
        Write-Host "    Username: admin" -ForegroundColor Magenta
        Write-Host "    Password: $AdminPassword" -ForegroundColor Magenta
        Write-Host "    *** Save this somewhere safe ***" -ForegroundColor Magenta
        Write-Host ""
    }
} else {
    Write-OK ".env already exists - leaving alone"
}

# ===========================================================================
# 8. Firewall rule
# ===========================================================================
if (-not $SkipFirewall) {
    Write-Step "Configuring Windows Firewall (port 5000 inbound)"
    $existing = Get-NetFirewallRule -DisplayName "SOC Dashboard" -ErrorAction SilentlyContinue
    if (-not $existing) {
        New-NetFirewallRule `
            -DisplayName "SOC Dashboard" `
            -Direction Inbound `
            -LocalPort 5000 `
            -Protocol TCP `
            -Action Allow `
            -Profile Any | Out-Null
        Write-OK "Firewall rule created"
    } else {
        Write-OK "Firewall rule already exists"
    }
} else {
    Write-Warn2 "Firewall rule skipped (-SkipFirewall)"
}

# ===========================================================================
# 9. Ollama check + model pull
# ===========================================================================
Write-Step "Checking Ollama"
$ollama = Get-Command ollama -ErrorAction SilentlyContinue
if (-not $ollama) {
    Write-Warn2 "Ollama not found in PATH."
    Write-Host "    Install from: https://ollama.com/download/windows" -ForegroundColor Yellow
    Write-Host "    Then re-run with: .\deploy_windows.ps1 -OllamaModel $OllamaModel"
} else {
    Write-OK "Ollama found"
    if ($OllamaModel -ne "none") {
        Write-Step "Pulling model: $OllamaModel (this may take a while)"
        & ollama pull $OllamaModel
        if ($LASTEXITCODE -eq 0) {
            Write-OK "Model $OllamaModel ready"
        } else {
            Write-Warn2 "Model pull failed - you can run 'ollama pull $OllamaModel' manually later"
        }
    }
}

# ===========================================================================
# 10. Create start_dashboard.bat
# ===========================================================================
Write-Step "Creating start_dashboard.bat"
$startBat = Join-Path $InstallDir "start_dashboard.bat"
@"
@echo off
REM SOC Dashboard launcher
cd /d $InstallDir
call venv\Scripts\activate.bat
python app.py
pause
"@ | Out-File -FilePath $startBat -Encoding ASCII

Write-OK "Created $startBat"

# ===========================================================================
# 11. Create silent launcher (no console window) for service mode
# ===========================================================================
$silentVbs = Join-Path $InstallDir "start_dashboard_silent.vbs"
@"
Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "$InstallDir"
WshShell.Run "venv\Scripts\python.exe app.py", 0, False
"@ | Out-File -FilePath $silentVbs -Encoding ASCII

# ===========================================================================
# 12. Optional scheduled task at boot
# ===========================================================================
if ($InstallAsService) {
    Write-Step "Registering scheduled task: SOC-Dashboard"

    $taskName = "SOC-Dashboard"
    $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    $action = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "`"$silentVbs`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1)

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Settings $settings `
        -Description "SOC Fortress Custom Dashboard - starts at boot" | Out-Null

    Write-OK "Scheduled task '$taskName' registered (starts at boot as SYSTEM)"
    Write-Host "    Start now with: Start-ScheduledTask -TaskName $taskName" -ForegroundColor DarkCyan
}

# ===========================================================================
# 13. Desktop shortcut (best-effort)
# ===========================================================================
Write-Step "Creating desktop shortcut"
try {
    $WshShell = New-Object -ComObject WScript.Shell
    $shortcut = $WshShell.CreateShortcut(
        [System.IO.Path]::Combine([Environment]::GetFolderPath("CommonDesktopDirectory"), "SOC Dashboard.lnk")
    )
    $shortcut.TargetPath = $startBat
    $shortcut.WorkingDirectory = $InstallDir
    $shortcut.IconLocation = "shell32.dll,77"
    $shortcut.Description = "Start the SOC Dashboard"
    $shortcut.Save()
    Write-OK "Shortcut created on Public Desktop"
} catch {
    Write-Warn2 "Could not create desktop shortcut: $($_.Exception.Message)"
}

# ===========================================================================
# Done
# ===========================================================================
Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host " Deployment complete." -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host " Install dir : $InstallDir"
Write-Host " Start it    : double-click 'SOC Dashboard' on the desktop"
Write-Host "               or run: $startBat"
if ($InstallAsService) {
    Write-Host " Auto-start  : enabled (scheduled task 'SOC-Dashboard')"
}
Write-Host ""
Write-Host " Then open in browser:" -ForegroundColor Cyan
Write-Host "   http://localhost:5000"
Write-Host "   http://172.20.10.4:5000   (LAN)"
Write-Host ""
Write-Host " First login: see admin password printed above (or in .env)" -ForegroundColor Yellow
Write-Host ""
