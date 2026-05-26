<#
.SYNOPSIS
    Force Ollama to use the NVIDIA GPU instead of CPU.

.DESCRIPTION
    Diagnoses why Ollama is falling back to CPU and applies the standard fixes:
      - Verifies NVIDIA driver is installed
      - Sets Windows graphics preference to High Performance for ollama.exe
      - Sets Ollama-specific environment variables (OLLAMA_NUM_GPU, etc.)
      - Sets Windows power plan to High Performance
      - Restarts the Ollama service/process
      - Verifies GPU is actually being used after a test inference

.EXAMPLE
    # Run as Administrator
    .\force_ollama_gpu.ps1

.EXAMPLE
    # Test with a specific model
    .\force_ollama_gpu.ps1 -Model qwen3:8b

.EXAMPLE
    # Skip the test inference at the end
    .\force_ollama_gpu.ps1 -SkipTest

.NOTES
    Run from an elevated PowerShell. If your model is >85% of your VRAM,
    no amount of forcing will help — the script will tell you to use a
    smaller model.
#>

[CmdletBinding()]
param(
    [string] $Model = "qwen3:8b",
    [switch] $SkipTest
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-OK($msg)   { Write-Host "    [ OK ] $msg" -ForegroundColor Green }
function Write-Warn2($msg){ Write-Host "    [WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "    [FAIL] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "    $msg" -ForegroundColor Gray }

Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  Ollama GPU Forcer - RTX/NVIDIA"                                  -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan

# ===========================================================================
# 0. Admin check
# ===========================================================================
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Fail "Run this script as Administrator (registry + power plan changes need it)."
    exit 1
}
Write-OK "Running as Administrator"

# ===========================================================================
# 1. Verify NVIDIA driver
# ===========================================================================
Write-Step "Checking NVIDIA driver"
$nvsmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
if (-not $nvsmi) {
    Write-Fail "nvidia-smi not found. NVIDIA drivers are not installed (or not on PATH)."
    Write-Info "Download latest from https://www.nvidia.com/Download/index.aspx"
    exit 1
}

try {
    $gpuInfo = & nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader
    Write-OK "GPU detected: $gpuInfo"

    $vramMb = [int](((& nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits) -split "`n")[0])
    Write-Info "VRAM: $vramMb MB"
} catch {
    Write-Fail "nvidia-smi failed: $($_.Exception.Message)"
    exit 1
}

# ===========================================================================
# 2. Find ollama.exe
# ===========================================================================
Write-Step "Locating Ollama installation"
$candidates = @(
    "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe",
    "$env:ProgramFiles\Ollama\ollama.exe",
    "${env:ProgramFiles(x86)}\Ollama\ollama.exe"
)
$ollamaExe = $null
foreach ($c in $candidates) {
    if (Test-Path $c) { $ollamaExe = $c; break }
}
if (-not $ollamaExe) {
    $ollamaCmd = Get-Command ollama -ErrorAction SilentlyContinue
    if ($ollamaCmd) { $ollamaExe = $ollamaCmd.Source }
}
if (-not $ollamaExe) {
    Write-Fail "Could not find ollama.exe. Install from https://ollama.com/download/windows"
    exit 1
}
Write-OK "Found: $ollamaExe"

# Find the inference server too (this is the actual GPU consumer)
$serverExe = Join-Path (Split-Path $ollamaExe -Parent) "ollama_llama_server.exe"
if (-not (Test-Path $serverExe)) {
    # Some installs nest it
    $found = Get-ChildItem -Path (Split-Path $ollamaExe -Parent) -Filter "ollama_llama_server.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $serverExe = $found.FullName }
}
if (Test-Path $serverExe) {
    Write-OK "Inference server: $serverExe"
} else {
    $serverExe = $null
    Write-Warn2 "ollama_llama_server.exe not found - newer versions may not bundle it separately"
}

# ===========================================================================
# 3. Check Ollama version
# ===========================================================================
Write-Step "Checking Ollama version"
try {
    $version = (& ollama --version 2>&1) -join " "
    Write-OK "$version"
    Write-Info "If GPU still doesn't engage after this script, update from"
    Write-Info "https://ollama.com/download/windows (newer builds bundle CUDA 12+)"
} catch {
    Write-Warn2 "Could not get Ollama version"
}

# ===========================================================================
# 4. Windows graphics preference (per-app GPU selection)
# ===========================================================================
Write-Step "Setting Windows graphics preference -> High Performance"
$gfxKey = "HKCU:\SOFTWARE\Microsoft\DirectX\UserGpuPreferences"
if (-not (Test-Path $gfxKey)) {
    New-Item -Path $gfxKey -Force | Out-Null
}
# GpuPreference=2 means "High performance" (NVIDIA dGPU)
$exes = @($ollamaExe)
if ($serverExe) { $exes += $serverExe }
foreach ($e in $exes) {
    Set-ItemProperty -Path $gfxKey -Name $e -Value "GpuPreference=2;" -Force
    Write-OK "Forced High-Perf GPU for $(Split-Path $e -Leaf)"
}

# ===========================================================================
# 5. Ollama environment variables
# ===========================================================================
Write-Step "Setting Ollama environment variables"

$envVars = @{
    "OLLAMA_NUM_GPU"      = "999"        # Offload all layers
    "OLLAMA_GPU_OVERHEAD" = "0"          # Don't reserve VRAM headroom
    "OLLAMA_KEEP_ALIVE"   = "30m"        # Keep model loaded longer between calls
    "OLLAMA_FLASH_ATTN"   = "1"          # Faster attention if supported
}

foreach ($k in $envVars.Keys) {
    [Environment]::SetEnvironmentVariable($k, $envVars[$k], "User")
    # Also set for current session
    Set-Item -Path "env:$k" -Value $envVars[$k]
    Write-OK "$k = $($envVars[$k])"
}

# ===========================================================================
# 6. Power plan -> High performance
# ===========================================================================
Write-Step "Setting Windows power plan to High Performance"
try {
    # GUID for built-in High Performance plan
    $highPerfGuid = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
    $plans = powercfg /list
    if ($plans -match $highPerfGuid) {
        powercfg /setactive $highPerfGuid | Out-Null
        Write-OK "High Performance plan activated"
    } else {
        # Some OEM laptops hide it - duplicate Balanced as High Perf
        Write-Warn2 "High Performance plan not present, attempting to enable Ultimate Performance"
        $ultimateGuid = "e9a42b02-d5df-448d-aa00-03f14749eb61"
        powercfg /duplicatescheme $ultimateGuid 2>$null | Out-Null
        if ((powercfg /list) -match $ultimateGuid) {
            powercfg /setactive $ultimateGuid | Out-Null
            Write-OK "Ultimate Performance plan activated"
        } else {
            Write-Warn2 "Could not change power plan automatically. Set 'Best Performance' in Settings -> System -> Power."
        }
    }
} catch {
    Write-Warn2 "Power plan change failed: $($_.Exception.Message)"
}

# Battery warning
$battery = Get-WmiObject Win32_Battery -ErrorAction SilentlyContinue
if ($battery -and $battery.BatteryStatus -ne 2) {
    Write-Warn2 "You are running on battery. Plug in the charger - many laptops disable the dGPU on battery."
}

# ===========================================================================
# 7. Restart Ollama
# ===========================================================================
Write-Step "Restarting Ollama"

# Stop any existing processes
$procs = Get-Process -Name "ollama","ollama_llama_server","ollama app" -ErrorAction SilentlyContinue
if ($procs) {
    $procs | ForEach-Object {
        try {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
            Write-OK "Stopped $($_.ProcessName) (PID $($_.Id))"
        } catch {
            Write-Warn2 "Could not stop $($_.ProcessName): $($_.Exception.Message)"
        }
    }
    Start-Sleep -Seconds 3
} else {
    Write-Info "No existing Ollama processes"
}

# Start fresh - the desktop app launches the server when it runs
$ollamaApp = Join-Path (Split-Path $ollamaExe -Parent) "ollama app.exe"
if (Test-Path $ollamaApp) {
    Start-Process -FilePath $ollamaApp
    Write-OK "Started Ollama desktop app"
} else {
    # Headless: just run `ollama serve` in background
    Start-Process -FilePath $ollamaExe -ArgumentList "serve" -WindowStyle Hidden
    Write-OK "Started ollama serve"
}

Write-Info "Waiting 5s for service to come up..."
Start-Sleep -Seconds 5

# Verify it's listening
try {
    $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/tags" -UseBasicParsing -TimeoutSec 5
    Write-OK "Ollama API is responding on port 11434"
} catch {
    Write-Fail "Ollama API not responding. Try launching it manually from the Start menu."
    exit 1
}

# ===========================================================================
# 8. Test inference and verify GPU
# ===========================================================================
if ($SkipTest) {
    Write-Step "Skipping test (-SkipTest)"
} else {
    Write-Step "Running test inference with $Model"
    Write-Info "This may take 10-30s on first load while the model warms up..."

    try {
        # Trigger a load
        $body = @{
            model  = $Model
            prompt = "say hi"
            stream = $false
        } | ConvertTo-Json
        $null = Invoke-WebRequest -Uri "http://127.0.0.1:11434/api/generate" `
            -Method POST -Body $body -ContentType "application/json" `
            -UseBasicParsing -TimeoutSec 120
        Write-OK "Model responded"
    } catch {
        Write-Fail "Inference failed: $($_.Exception.Message)"
        Write-Info "Make sure '$Model' is pulled. Run: ollama pull $Model"
        exit 1
    }

    # Check ollama ps
    Write-Step "Checking model placement"
    $psOut = & ollama ps
    Write-Host $psOut

    if ($psOut -match "100%\s+GPU") {
        Write-Host ""
        Write-OK "SUCCESS - model is running 100% on GPU!"
    } elseif ($psOut -match "(\d+)%\s+GPU.*?(\d+)%\s+CPU" -or $psOut -match "(\d+)/(\d+)\s+GPU") {
        Write-Host ""
        Write-Warn2 "Model is split between GPU and CPU - VRAM is tight."
        Write-Info "Try a smaller model:  ollama pull qwen2.5:7b-instruct-q4_K_M"
        Write-Info "Or even smaller:      ollama pull qwen2.5:3b"
    } elseif ($psOut -match "100%\s+CPU") {
        Write-Host ""
        Write-Fail "Model is STILL on CPU. Likely causes:"
        Write-Info "  1. Ollama is too old - update from https://ollama.com/download/windows"
        Write-Info "  2. CUDA mismatch - update NVIDIA driver too"
        Write-Info "  3. Model size > VRAM - try: ollama pull qwen2.5:3b"
    }

    # Show nvidia-smi snapshot
    Write-Host ""
    Write-Host "GPU snapshot:" -ForegroundColor Cyan
    & nvidia-smi --query-gpu=name,memory.used,memory.total,utilization.gpu,power.draw,pstate `
                 --format=csv
}

# ===========================================================================
# Done
# ===========================================================================
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Green
Write-Host " Done. To verify in real time:" -ForegroundColor Green
Write-Host "===============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "   ollama ps       # PROCESSOR column should say '100% GPU'"
Write-Host "   nvidia-smi      # Memory-Usage should show ~5-6 GB used"
Write-Host ""
Write-Host " If still on CPU after this script:" -ForegroundColor Yellow
Write-Host "   - Update Ollama (likely fix): https://ollama.com/download/windows"
Write-Host "   - Try a smaller model:        ollama pull qwen2.5:3b"
Write-Host "   - Reboot once after the update"
Write-Host ""
