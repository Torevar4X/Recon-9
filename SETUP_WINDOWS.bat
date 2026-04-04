@echo off
setlocal EnableDelayedExpansion

:: ============================================================================
:: RECON 9 - Windows Setup Script
:: Version: 9.0
:: Purpose: Automated installation of Recon 9 and all dependencies
:: Usage: Double-click this file or run from Command Prompt
:: ============================================================================

title Recon 9 - Installation Wizard
color 0A

echo.
echo ============================================================================
echo.
echo    RECON 9 - Advanced OSINT Reconnaissance Platform
echo    Installation Wizard for Windows
echo    Version 9.0
echo.
echo ============================================================================
echo.
echo [INFO] This script will:
echo   1. Check Python installation
echo   2. Create virtual environment
echo   3. Install all Python dependencies
echo   4. Check for optional external tools (Nmap, RustScan, etc.)
echo   5. Verify installation
echo.
echo [NOTE] Administrator privileges are NOT required for this installation.
echo.
pause

:: ============================================================================
:: Step 1: Check Python Installation
:: ============================================================================
echo.
echo ============================================================================
echo [1/5] Checking Python Installation
echo ============================================================================
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo.
    echo Please install Python 3.10 or higher from:
    echo https://www.python.org/downloads/
    echo.
    echo IMPORTANT: During installation, check the box:
    echo "Add Python to PATH"
    echo.
    echo After installing Python, run this script again.
    echo.
    pause
    exit /b 1
)

:: Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Python found: %PYTHON_VERSION%

:: Check if Python version is 3.10+
for /f "tokens=1,2 delims=." %%a in ("%PYTHON_VERSION%") do (
    set MAJOR=%%a
    set MINOR=%%b
)

if %MAJOR% lss 3 (
    echo [ERROR] Python 3.10 or higher is required. Found: %PYTHON_VERSION%
    echo Please upgrade Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

if %MAJOR% equ 3 if %MINOR% lss 10 (
    echo [ERROR] Python 3.10 or higher is required. Found: %PYTHON_VERSION%
    echo Please upgrade Python from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [OK] Python version is compatible (3.10+)
echo.

:: ============================================================================
:: Step 2: Create Virtual Environment
:: ============================================================================
echo ============================================================================
echo [2/5] Creating Virtual Environment
echo ============================================================================
echo.

if exist ".venv" (
    echo [INFO] Virtual environment already exists.
    set /p OVERWRITE="Do you want to recreate it? (Y/N): "
    if /i "!OVERWRITE!"=="Y" (
        echo [INFO] Removing old virtual environment...
        rmdir /s /q .venv
        echo [INFO] Creating new virtual environment...
        python -m venv .venv
        if !errorlevel! neq 0 (
            echo [ERROR] Failed to create virtual environment!
            pause
            exit /b 1
        )
        echo [OK] Virtual environment created successfully!
    ) else (
        echo [OK] Using existing virtual environment.
    )
) else (
    echo [INFO] Creating virtual environment...
    python -m venv .venv
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to create virtual environment!
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created successfully!
)
echo.

:: ============================================================================
:: Step 3: Activate Virtual Environment and Install Dependencies
:: ============================================================================
echo ============================================================================
echo [3/5] Installing Python Dependencies
echo ============================================================================
echo.

echo [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat
if !errorlevel! neq 0 (
    echo [ERROR] Failed to activate virtual environment!
    pause
    exit /b 1
)

echo [OK] Virtual environment activated.
echo.

:: Check if requirements.txt exists
if not exist "requirements.txt" (
    echo [ERROR] requirements.txt not found!
    echo Please ensure requirements.txt is in the same directory as this script.
    pause
    exit /b 1
)

echo [INFO] Installing dependencies from requirements.txt...
echo [INFO] This may take a few minutes...
echo.

pip install --upgrade pip
pip install -r requirements.txt

if !errorlevel! neq 0 (
    echo.
    echo [WARNING] Some packages may have failed to install.
    echo Trying alternative installation method...
    echo.
    pip install --no-cache-dir -r requirements.txt
)

echo.
echo [OK] Python dependencies installed!
echo.

:: ============================================================================
:: Step 4: Check Optional External Tools
:: ============================================================================
echo ============================================================================
echo [4/5] Checking Optional External Tools
echo ============================================================================
echo.
echo [INFO] These tools are OPTIONAL but recommended for advanced features.
echo [INFO] You can install them later if needed.
echo.

:: Check Nmap
where nmap >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Nmap: Found
    set HAS_NMAP=1
) else (
    echo [--] Nmap: Not found
    echo      Download from: https://nmap.org/download.html
    echo      Required for: Nmap Port Scanner, OS Detection, UPnP Discovery
    set HAS_NMAP=0
)

:: Check RustScan
where rustscan >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] RustScan: Found
    set HAS_RUSTSCAN=1
) else (
    echo [--] RustScan: Not found
    echo      Download from: https://github.com/RustScan/RustScan/releases
    echo      Required for: RustScan (ultra-fast port scanning)
    set HAS_RUSTSCAN=0
)

:: Check Masscan
where masscan >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Masscan: Found
    set HAS_MASSCAN=1
) else (
    echo [--] Masscan: Not found
    echo      Download from: https://github.com/robertdavidgraham/masscan
    echo      Required for: Masscan (Internet-scale port scanning)
    set HAS_MASSCAN=0
)

:: Check Fping
where fping >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Fping: Found
    set HAS_FPING=1
) else (
    echo [--] Fping: Not found
    echo      Download from: https://github.com/schweikert/fping/releases
    echo      Required for: Fping (fast ICMP host discovery)
    set HAS_FPING=0
)

:: Check Netdiscover
where netdiscover >nul 2>&1
if !errorlevel! equ 0 (
    echo [OK] Netdiscover: Found
    set HAS_NETDISCOVER=1
) else (
    echo [--] Netdiscover: Not found
    echo      Download from: https://github.com/allanlaird/netdiscover
    echo      Required for: Netdiscover (ARP-based network discovery)
    set HAS_NETDISCOVER=0
)

echo.
echo [NOTE] Recon 9 works WITHOUT these tools (using Python fallbacks).
echo [NOTE] Install them later for advanced scanning capabilities.
echo.

:: ============================================================================
:: Step 5: Verify Installation
:: ============================================================================
echo ============================================================================
echo [5/5] Verifying Installation
echo ============================================================================
echo.

echo [INFO] Testing Python imports...
python -c "import PyQt6; print('  [OK] PyQt6')" 2>nul || echo "  [FAIL] PyQt6"
python -c "import requests; print('  [OK] requests')" 2>nul || echo "  [FAIL] requests"
python -c "import dns.resolver; print('  [OK] dnspython')" 2>nul || echo "  [FAIL] dnspython"
python -c "import whois; print('  [OK] python-whois')" 2>nul || echo "  [FAIL] python-whois"
python -c "import ipwhois; print('  [OK] ipwhois')" 2>nul || echo "  [FAIL] ipwhois"
python -c "import bs4; print('  [OK] beautifulsoup4')" 2>nul || echo "  [FAIL] beautifulsoup4"
python -c "import netaddr; print('  [OK] netaddr')" 2>nul || echo "  [FAIL] netaddr"
python -c "import lxml; print('  [OK] lxml')" 2>nul || echo "  [FAIL] lxml"

echo.

:: Check if main files exist
set MISSING_FILES=0
for %%F in (main.py main_window.py workers.py dns_tools.py network_tools.py ip_tools.py web_tools.py external_tools.py bulk_tools.py report_generator.py graph_extractor.py) do (
    if exist "%%F" (
        echo [OK] %%F
    ) else (
        echo [FAIL] %%F - Missing!
        set MISSING_FILES=1
    )
)

echo.

:: ============================================================================
:: Final Summary
:: ============================================================================
echo ============================================================================
echo Installation Summary
echo ============================================================================
echo.

if %MISSING_FILES% equ 0 (
    echo [SUCCESS] All core files are present!
    echo.
    echo To run Recon 9:
    echo   1. Double-click "RUN_RECON9.bat" (if exists)
    echo   2. Or run these commands:
    echo      cd "%CD%"
    echo      .venv\Scripts\activate
    echo      python main.py
    echo.
) else (
    echo [WARNING] Some files are missing!
    echo Please ensure all project files are in this directory.
    echo.
)

echo External Tools Status:
if !HAS_NMAP! equ 1 (echo   [OK] Nmap) else (echo   [ ] Nmap - Optional)
if !HAS_RUSTSCAN! equ 1 (echo   [OK] RustScan) else (echo   [ ] RustScan - Optional)
if !HAS_MASSCAN! equ 1 (echo   [OK] Masscan) else (echo   [ ] Masscan - Optional)
if !HAS_FPING! equ 1 (echo   [OK] Fping) else (echo   [ ] Fping - Optional)
if !HAS_NETDISCOVER! equ 1 (echo   [OK] Netdiscover) else (echo   [ ] Netdiscover - Optional)

echo.
echo ============================================================================
echo Installation Complete!
echo ============================================================================
echo.
echo Next Steps:
echo   - Configure API keys in api_config.py (optional)
echo   - Install external tools for advanced features (optional)
echo   - Run Recon 9 and start scanning!
echo.
echo For support, visit: https://github.com/YOUR_USERNAME/recon9
echo.

set /p RUN_NOW="Do you want to run Recon 9 now? (Y/N): "
if /i "!RUN_NOW!"=="Y" (
    echo.
    echo [INFO] Starting Recon 9...
    python main.py
) else (
    echo.
    echo [INFO] You can run Recon 9 later by executing:
    echo   python main.py
)

echo.
pause
