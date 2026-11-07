# =============================================================================
# SaiRecon -- install_tools_windows.ps1
# Run in PowerShell as Administrator:
#   Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
#   .\install_tools_windows.ps1
# =============================================================================

$ErrorActionPreference = "Continue"
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$VENV_DIR   = "$SCRIPT_DIR\.venv"
$ENV_FILE   = "$SCRIPT_DIR\.env"

function Info    { param($m) Write-Host "[*] $m" -ForegroundColor Cyan }
function Success { param($m) Write-Host "[+] $m" -ForegroundColor Green }
function Warn    { param($m) Write-Host "[!] $m" -ForegroundColor Yellow }

Write-Host @"
 =====================================================================
   =====     ===    ====  ======   ======   ====    ======  ==   ==
  ==        == ==    ==   ==   ==  ==      ==  ==  ==    == ===  ==
   ====    ==   ==   ==   ======   =====   ==      ==    == == = ==
      ==   =======   ==   ==  ==   ==      ==  ==  ==    == ==  ===
  =====    ==   ==  ====  ==   ==  ======   ====    ======  ==   ==
 =====================================================================

 SaiRecon -- Windows Installer
"@ -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# Step 1 -- Check prerequisites
# ---------------------------------------------------------------------------
Info "[1/5] Checking prerequisites"

# Python
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Warn "Python not found. Download from https://www.python.org/downloads/ (add to PATH during install)"
    Read-Host "Press ENTER after installing Python, then re-run this script"
    exit 1
}
Success "Python found: $(python --version)"

# Go
if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Warn "Go not found. Download Go 1.22+ from https://go.dev/dl/"
    Warn "Install it, restart PowerShell, then re-run this script."
    Start-Process "https://go.dev/dl/"
    Read-Host "Press ENTER after installing Go"
    exit 1
}
$goVer = (go version) -replace "go version go", "" -replace " .*", ""
Success "Go found: $goVer"

# Git
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Warn "Git not found. Download from https://git-scm.com/download/win"
    Read-Host "Press ENTER after installing Git"
    exit 1
}
Success "Git found"

# ---------------------------------------------------------------------------
# Step 2 -- Python venv + pip deps
# ---------------------------------------------------------------------------
Info "[2/5] Python virtualenv + dependencies"
if (-not (Test-Path $VENV_DIR)) {
    python -m venv $VENV_DIR
}
& "$VENV_DIR\Scripts\python.exe" -m pip install --upgrade pip -q
& "$VENV_DIR\Scripts\pip.exe" install -r "$SCRIPT_DIR\requirements.txt" -q
& "$VENV_DIR\Scripts\pip.exe" install wafw00f arjun -q
& "$VENV_DIR\Scripts\pip.exe" install -e "$SCRIPT_DIR" -q
Success "Python deps installed in $VENV_DIR"

# Create sairecon.bat wrapper
$BAT_PATH = "$env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\sairecon.bat"
$batContent = @"
@echo off
if exist "$ENV_FILE" (
    for /f "usebackq tokens=1,* delims==" %%A in ("$ENV_FILE") do set %%A=%%B
)
"$VENV_DIR\Scripts\python.exe" -m sairecon.cli %*
"@
Set-Content -Path $BAT_PATH -Value $batContent -Encoding ASCII
Success "sairecon.bat wrapper created"

# ---------------------------------------------------------------------------
# Step 3 -- Go tools
# ---------------------------------------------------------------------------
Info "[3/5] Go-based recon tools"
$goTools = @(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "github.com/projectdiscovery/uncover/cmd/uncover@latest",
    "github.com/tomnomnom/assetfinder@latest",
    "github.com/tomnomnom/anew@latest",
    "github.com/tomnomnom/unfurl@latest",
    "github.com/tomnomnom/gf@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
    "github.com/tomnomnom/waybackurls@latest",
    "github.com/sensepost/gowitness@latest",
    "github.com/gwen001/github-subdomains@latest",
    "github.com/ffuf/ffuf/v2@latest"
)
$failedGo = @()
foreach ($tool in $goTools) {
    $binary = ($tool -split "/")[-1] -replace "@.*", ""
    if (Get-Command $binary -ErrorAction SilentlyContinue) {
        Success "$binary already installed"
    } else {
        Info "Installing $binary..."
        go install $tool 2>$null
        if (Get-Command $binary -ErrorAction SilentlyContinue) {
            Success "$binary installed"
        } else {
            Warn "Failed: $tool"
            $failedGo += $tool
        }
    }
}

# ---------------------------------------------------------------------------
# Step 4 -- Manual downloads (nmap, findomain)
# ---------------------------------------------------------------------------
Info "[4/5] Manual installs check"
if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    Warn "nmap not found -- download: https://nmap.org/download.html"
    Start-Process "https://nmap.org/download.html"
} else { Success "nmap found" }

if (-not (Get-Command findomain -ErrorAction SilentlyContinue)) {
    Warn "findomain not found -- download findomain-windows.exe from:"
    Warn "  https://github.com/Findomain/Findomain/releases"
    Warn "  Rename to findomain.exe and add folder to PATH"
    Start-Process "https://github.com/Findomain/Findomain/releases"
} else { Success "findomain found" }

# gf patterns
$GF_DIR = "$env:USERPROFILE\.gf"
if (-not (Test-Path $GF_DIR) -or (Get-ChildItem $GF_DIR -Filter "*.json").Count -eq 0) {
    Info "Installing gf patterns..."
    New-Item -ItemType Directory -Path $GF_DIR -Force | Out-Null
    $TMP = [System.IO.Path]::GetTempPath() + "gf-patterns"
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns $TMP -q
    Copy-Item "$TMP\*.json" $GF_DIR
    Remove-Item $TMP -Recurse -Force
    Success "gf patterns installed"
}

# ---------------------------------------------------------------------------
# Step 5 -- API keys
# ---------------------------------------------------------------------------
Info "[5/5] API keys (optional)"
Write-Host "These unlock extra recon sources. Press ENTER to skip any." -ForegroundColor Yellow
Write-Host ""

function Prompt-Key {
    param($VarName, $Desc)
    $existing = ""
    if (Test-Path $ENV_FILE) {
        $existing = (Get-Content $ENV_FILE | Where-Object { $_ -match "^${VarName}=" }) -replace "^${VarName}=", ""
    }
    if ($existing) {
        Success "$VarName already in .env ($Desc)"
        return
    }
    $val = Read-Host "  $VarName ($Desc)"
    if ($val) {
        Add-Content -Path $ENV_FILE -Value "${VarName}=${val}"
        Success "Saved to .env"
    } else {
        Warn "Skipped"
    }
}

if (-not (Test-Path $ENV_FILE)) { New-Item $ENV_FILE -ItemType File | Out-Null }
Add-Content $ENV_FILE "# SaiRecon API keys"
Prompt-Key "GITHUB_TOKEN"      "github.com -> Settings -> Developer -> Personal access tokens"
Prompt-Key "PDCP_API_KEY"      "app.projectdiscovery.io -> API keys (free)"
Prompt-Key "SHODAN_API_KEY"    "account.shodan.io -> My Account (free tier)"
Prompt-Key "CENSYS_API_ID"     "search.censys.io -> Account -> API"
Prompt-Key "CENSYS_API_SECRET" "search.censys.io -> Account -> API"

Write-Host ""
Write-Host "=== Installation complete ===" -ForegroundColor Green
Write-Host ""
Write-Host "  Run: sairecon doctor       -> verify tools" -ForegroundColor Cyan
Write-Host "  Run: sairecon scan nasa.gov -> start scanning" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Reports saved to: .\sairecon_output\<target>_<timestamp>\" -ForegroundColor Cyan
Write-Host "    nasa.gov.html"
Write-Host "    nasa.gov.json"
Write-Host "    nasa.gov.md"
if ($failedGo.Count -gt 0) {
    Warn "Some Go tools failed. Run 'sairecon doctor' to see which."
}
