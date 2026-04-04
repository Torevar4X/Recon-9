# ============================================================================
# RECON 9 - Windows PowerShell Setup Script
# Version: 9.0
# Purpose: Automated installation with progress indicators and better error handling
# Usage: Right-click -> "Run with PowerShell"
# ============================================================================

# Set window appearance
$Host.UI.RawUI.WindowTitle = "Recon 9 - Installation Wizard"
$Host.UI.RawUI.BackgroundColor = "Black"
Clear-Host

# Color output functions
function Write-Success($message) { Write-Host "[OK] $message" -ForegroundColor Green }
function Write-Error2($message) { Write-Host "[ERROR] $message" -ForegroundColor Red }
function Write-Warning2($message) { Write-Host "[WARN] $message" -ForegroundColor Yellow }
function Write-Info($message) { Write-Host "[INFO] $message" -ForegroundColor Cyan }
function Write-Step($message) { Write-Host "`n$message" -ForegroundColor White -BackgroundColor DarkBlue }

# ============================================================================
# Header
# ============================================================================
Write-Host @"

 ============================================================================

    RECON 9 - Advanced OSINT Reconnaissance Platform
    Installation Wizard for Windows (PowerShell)
    Version 9.0

 ============================================================================

"@ -ForegroundColor Cyan

Write-Host "This script will:" -ForegroundColor Yellow
Write-Host "  1. Check Python installation (3.10+)" -ForegroundColor Gray
Write-Host "  2. Create virtual environment" -ForegroundColor Gray
Write-Host "  3. Install all dependencies" -ForegroundColor Gray
Write-Host "  4. Check optional external tools" -ForegroundColor Gray
Write-Host "  5. Verify installation" -ForegroundColor Gray
Write-Host ""

$continue = Read-Host "Press Enter to continue or 'Q' to quit"
if ($continue -eq 'Q' -or $continue -eq 'q') { exit }

# ============================================================================
# Step 1: Check Python
# ============================================================================
Write-Step "[1/5] Checking Python Installation"

try {
    $pythonVersion = python --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Python not found" }
    
    Write-Success "Python found: $pythonVersion"
    
    # Extract version numbers
    $versionMatch = [regex]::Match($pythonVersion, '(\d+)\.(\d+)')
    if ($versionMatch.Success) {
        $major = [int]$versionMatch.Groups[1].Value
        $minor = [int]$versionMatch.Groups[2].Value
        
        if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
            Write-Error2 "Python 3.10 or higher is required. Found: $pythonVersion"
            Write-Host "Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
            Read-Host "Press Enter to exit"
            exit 1
        }
        Write-Success "Python version is compatible (3.10+)"
    }
} catch {
    Write-Error2 "Python is not installed or not in PATH!"
    Write-Host ""
    Write-Host "Please install Python 3.10 or higher from:" -ForegroundColor Yellow
    Write-Host "https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "IMPORTANT: During installation, check the box:" -ForegroundColor Yellow
    Write-Host '"Add Python to PATH"' -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# ============================================================================
# Step 2: Create Virtual Environment
# ============================================================================
Write-Step "[2/5] Creating Virtual Environment"

if (Test-Path ".venv") {
    Write-Warning2 "Virtual environment already exists."
    $overwrite = Read-Host "Recreate it? (y/n)"
    if ($overwrite -eq 'y' -or $overwrite -eq 'Y') {
        Write-Info "Removing old virtual environment..."
        Remove-Item -Recurse -Force .venv
    } else {
        Write-Success "Using existing virtual environment."
    }
}

if (-not (Test-Path ".venv")) {
    Write-Info "Creating virtual environment..."
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Error2 "Failed to create virtual environment!"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Success "Virtual environment created!"
}

# ============================================================================
# Step 3: Install Dependencies
# ============================================================================
Write-Step "[3/5] Installing Python Dependencies"

Write-Info "Activating virtual environment..."
& .\.venv\Scripts\Activate.ps1
if ($LASTEXITCODE -ne 0) {
    Write-Error2 "Failed to activate virtual environment!"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Success "Virtual environment activated."

if (-not (Test-Path "requirements.txt")) {
    Write-Error2 "requirements.txt not found!"
    Read-Host "Press Enter to exit"
    exit 1
}

Write-Info "Upgrading pip..."
python -m pip install --upgrade pip --quiet

Write-Info "Installing dependencies from requirements.txt..."
Write-Info "This may take a few minutes..."
Write-Host ""

# Install with progress
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Warning2 "Some packages failed to install. Retrying..."
    pip install --no-cache-dir -r requirements.txt
}

Write-Success "Python dependencies installed!"

# ============================================================================
# Step 4: Check External Tools
# ============================================================================
Write-Step "[4/5] Checking Optional External Tools"

Write-Host ""
Write-Host "These tools are OPTIONAL but recommended for advanced features." -ForegroundColor Yellow
Write-Host ""

$tools = @(
    @{Name="Nmap"; Command="nmap"; Download="https://nmap.org/download.html"; Uses="Nmap Port Scanner, OS Detection, UPnP"},
    @{Name="RustScan"; Command="rustscan"; Download="https://github.com/RustScan/RustScan/releases"; Uses="Ultra-fast port scanning"},
    @{Name="Masscan"; Command="masscan"; Download="https://github.com/robertdavidgraham/masscan"; Uses="Internet-scale port scanning"},
    @{Name="Fping"; Command="fping"; Download="https://github.com/schweikert/fping/releases"; Uses="Fast ICMP host discovery"},
    @{Name="Netdiscover"; Command="netdiscover"; Download="https://github.com/allanlaird/netdiscover"; Uses="ARP-based network discovery"}
)

$installedCount = 0
foreach ($tool in $tools) {
    $found = Get-Command $tool.Command -ErrorAction SilentlyContinue
    if ($found) {
        Write-Success "$($tool.Name): Found"
        $installedCount++
    } else {
        Write-Host "[--] $($tool.Name): Not found" -ForegroundColor DarkGray
        Write-Host "     Download: $($tool.Download)" -ForegroundColor Gray
        Write-Host "     Required for: $($tool.Uses)" -ForegroundColor Gray
        Write-Host ""
    }
}

Write-Host ""
if ($installedCount -eq 0) {
    Write-Warning2 "No external tools found. Recon 9 will use Python fallbacks."
} else {
    Write-Success "$installedCount external tool(s) found!"
}

# ============================================================================
# Step 5: Verify Installation
# ============================================================================
Write-Step "[5/5] Verifying Installation"

Write-Host ""
Write-Info "Testing Python imports..."
Write-Host ""

$imports = @(
    @{Name="PyQt6"; Module="PyQt6"},
    @{Name="requests"; Module="requests"},
    @{Name="dnspython"; Module="dns.resolver"},
    @{Name="python-whois"; Module="whois"},
    @{Name="ipwhois"; Module="ipwhois"},
    @{Name="beautifulsoup4"; Module="bs4"},
    @{Name="netaddr"; Module="netaddr"},
    @{Name="lxml"; Module="lxml"}
)

$importSuccess = 0
$importFail = 0

foreach ($imp in $imports) {
    try {
        python -c "import $($imp.Module)" 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "  $($imp.Name)"
            $importSuccess++
        } else { throw }
    } catch {
        Write-Host "[FAIL] $($imp.Name)" -ForegroundColor Red
        $importFail++
    }
}

Write-Host ""

# Check main files
$mainFiles = @(
    "main.py", "main_window.py", "workers.py", "dns_tools.py",
    "network_tools.py", "ip_tools.py", "web_tools.py", "external_tools.py",
    "bulk_tools.py", "report_generator.py", "graph_extractor.py",
    "requirements.txt", "README.md"
)

$fileSuccess = 0
$fileFail = 0

Write-Info "Checking project files..."
Write-Host ""

foreach ($file in $mainFiles) {
    if (Test-Path $file) {
        Write-Success "  $file"
        $fileSuccess++
    } else {
        Write-Host "[FAIL] $file - Missing!" -ForegroundColor Red
        $fileFail++
    }
}

# ============================================================================
# Final Summary
# ============================================================================
Write-Host ""
Write-Host " ============================================================================" -ForegroundColor Cyan
Write-Host " Installation Summary" -ForegroundColor Cyan
Write-Host " ============================================================================" -ForegroundColor Cyan
Write-Host ""

if ($fileFail -eq 0 -and $importFail -eq 0) {
    Write-Success "All core files and dependencies are present!"
    Write-Host ""
    Write-Host "To run Recon 9:" -ForegroundColor Yellow
    Write-Host "  1. Double-click 'RUN_RECON9.bat'" -ForegroundColor Gray
    Write-Host "  2. Or run: .\RUN_RECON9.bat" -ForegroundColor Gray
    Write-Host "  3. Or run:" -ForegroundColor Gray
    Write-Host "     .venv\Scripts\activate" -ForegroundColor DarkGray
    Write-Host "     python main.py" -ForegroundColor DarkGray
    Write-Host ""
} else {
    Write-Warning2 "Some files or imports failed!"
    Write-Host "Please review the errors above and fix them before running Recon 9." -ForegroundColor Yellow
    Write-Host ""
}

Write-Host " ============================================================================" -ForegroundColor Cyan
Write-Host " Installation Complete!" -ForegroundColor Green
Write-Host " ============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "  - Configure API keys in api_config.py (optional)" -ForegroundColor Gray
Write-Host "  - Install external tools for advanced features (optional)" -ForegroundColor Gray
Write-Host "  - Run Recon 9 and start scanning!" -ForegroundColor Gray
Write-Host ""

$runNow = Read-Host "Do you want to run Recon 9 now? (y/n)"
if ($runNow -eq 'y' -or $runNow -eq 'Y') {
    Write-Host ""
    Write-Info "Starting Recon 9..."
    python main.py
}

Write-Host ""
Read-Host "Press Enter to exit"
