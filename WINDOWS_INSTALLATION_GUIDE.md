# Windows Installation Guide

## Quick Start (For Beginners)

### Method 1: Double-Click Installation (Recommended)

1. **Download or clone the repository** to your computer
2. **Double-click** `SETUP_WINDOWS.bat`
3. **Wait** for the installation to complete (may take 5-10 minutes)
4. **Double-click** `RUN_RECON9.bat` to start the application

That's it! The setup script will automatically:
- ✅ Check Python installation
- ✅ Create virtual environment
- ✅ Install all dependencies
- ✅ Check for optional tools
- ✅ Verify everything works

---

### Method 2: PowerShell Installation (Advanced)

If you prefer PowerShell with better progress indicators:

1. **Right-click** `SETUP_WINDOWS.ps1`
2. Select **"Run with PowerShell"**
3. Follow the prompts

**Note:** If you get an execution policy error, run this first in PowerShell (as Administrator):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### Method 3: Manual Installation

If the automatic scripts don't work:

#### Step 1: Install Python
1. Download Python 3.10+ from https://www.python.org/downloads/
2. **IMPORTANT:** Check the box **"Add Python to PATH"** during installation
3. Verify installation:
   ```cmd
   python --version
   ```

#### Step 2: Open Command Prompt
Press `Win + R`, type `cmd`, and press Enter.

#### Step 3: Navigate to Project Directory
```cmd
cd "C:\path\to\recon  process"
```

#### Step 4: Create Virtual Environment
```cmd
python -m venv .venv
```

#### Step 5: Activate Virtual Environment
```cmd
.venv\Scripts\activate
```

You should see `(.venv)` at the beginning of your prompt.

#### Step 6: Install Dependencies
```cmd
pip install --upgrade pip
pip install -r requirements.txt
```

#### Step 7: Run the Application
```cmd
python main.py
```

---

## Optional: Install External Tools

Recon 9 works **without** these tools (using Python fallbacks), but installing them unlocks advanced features:

### 1. Nmap (Highly Recommended)
- **Purpose:** Advanced port scanning, OS detection, vulnerability scanning
- **Download:** https://nmap.org/download.html
- **Installation:**
  1. Download the Windows installer
  2. Run the installer
  3. Add to PATH: Add `C:\Program Files (x86)\Nmap` to your system PATH
  4. Verify: `nmap --version`

### 2. RustScan (Recommended)
- **Purpose:** Ultra-fast port scanning (10x faster than Nmap)
- **Download:** https://github.com/RustScan/RustScan/releases
- **Installation:**
  1. Download the Windows `.exe`
  2. Place it in a folder (e.g., `C:\Tools\RustScan`)
  3. Add that folder to your system PATH
  4. Verify: `rustscan --version`

### 3. Masscan (Optional)
- **Purpose:** Internet-scale port scanning
- **Download:** https://github.com/robertdavidgraham/masscan
- **Note:** Requires WinPcap/Npcap driver

### 4. Fping (Optional)
- **Purpose:** Fast ICMP ping sweeps
- **Download:** https://github.com/schweikert/fping/releases

### 5. Netdiscover (Optional)
- **Purpose:** ARP-based network discovery
- **Download:** https://github.com/allanlaird/netdiscover
- **Note:** Requires WinPcap/Npcap driver

---

## How to Add a Program to Windows PATH

1. Press `Win + R`, type `sysdm.cpl`, press Enter
2. Go to **Advanced** tab
3. Click **Environment Variables**
4. Under **System variables**, find and select **Path**
5. Click **Edit**
6. Click **New**
7. Add the folder path (e.g., `C:\Program Files (x86)\Nmap`)
8. Click **OK** on all windows
9. **Restart** Command Prompt

---

## Troubleshooting

### Problem: "Python is not recognized"
**Solution:**
1. Reinstall Python from https://www.python.org/downloads/
2. **Make sure to check "Add Python to PATH"** during installation
3. Restart Command Prompt
4. Verify: `python --version`

### Problem: "Virtual environment creation failed"
**Solution:**
```cmd
python -m pip install --upgrade pip
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### Problem: "Some packages failed to install"
**Solution:**
```cmd
pip install --no-cache-dir -r requirements.txt
```

Or install packages one by one:
```cmd
pip install PyQt6
pip install dnspython
pip install python-whois
pip install ipwhois
pip install requests
pip install beautifulsoup4
pip install lxml
pip install netaddr
```

### Problem: "Missing DLL errors"
**Solution:**
Install Microsoft Visual C++ Redistributable:
https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads

### Problem: "Application won't start / crashes immediately"
**Solution:**
```cmd
cd "C:\path\to\recon  process"
.venv\Scripts\activate
python main.py
```
Check the error message in the console for specific issues.

### Problem: "Firewall blocking connections"
**Solution:**
1. Windows Defender will ask if you want to allow Python
2. Click **"Allow access"**
3. Or manually add Python to firewall exceptions:
   - Open Windows Defender Firewall
   - Advanced settings
   - Inbound Rules
   - New Rule → Program → Browse to `python.exe` in `.venv\Scripts`
   - Allow the connection

---

## Uninstallation

To completely remove Recon 9:

1. **Delete the project folder**
2. **Remove from PATH** (if you added external tools)
3. **Optional:** Uninstall Python if you don't need it for other projects

---

## System Requirements

- **OS:** Windows 10 or Windows 11 (64-bit)
- **Python:** 3.10 or higher
- **RAM:** 2 GB minimum, 4 GB recommended
- **Disk Space:** 500 MB (including dependencies)
- **Network:** Required for all scanning features

---

## Quick Reference Commands

```cmd
# Activate virtual environment
.venv\Scripts\activate

# Run Recon 9
python main.py

# Check installed packages
pip list

# Update dependencies
pip install -r requirements.txt --upgrade

# Deactivate virtual environment
deactivate

# Check Python version
python --version

# Check if tools are installed
where nmap
where rustscan
where masscan
where fping
where netdiscover
```

---

## Support

If you encounter issues not covered here:

1. Check the error messages in the console
2. Review the troubleshooting section above
3. Open an issue on GitHub with:
   - Windows version
   - Python version (`python --version`)
   - Error messages
   - Steps to reproduce

---

**Enjoy Recon 9!** 🚀
