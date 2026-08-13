# Frida Environment Setup for Windows

This guide covers setting up Frida for runtime inspection of `stellaris.exe` on Windows.

## Prerequisites

- **Windows 10/11** (64-bit)
- **Python 3.10+** (64-bit) — must match game's 64-bit process
- **Administrator privileges** — required for memory access and process attachment
- **OpenSSH Server** — for remote access from analysis machine

## 1. Download frida-server

Download the latest frida-server for Windows x64 from GitHub Releases:

- **Release page**: https://github.com/frida/frida/releases
- **Asset name**: `frida-server-{version}-win-x64.xz`
- **Current stable**: Check releases page for latest version

Example for version 16.x:
```
https://github.com/frida/frida/releases/download/16.x.x/frida-server-16.x.x-win-x64.xz
```

### Verify Download

After downloading, extract the `.xz` file:
```powershell
# Using 7-Zip or Windows built-in tar
tar xf frida-server-*.xz
# Or with 7-Zip
7z x frida-server-*.xz
```

Place `frida-server.exe` in a known location, e.g.:
```
C:\tools\frida\frida-server.exe
```

## 2. Install Python Frida Package

**Important**: Use 64-bit Python to match the 64-bit game process.

```powershell
# Install frida-tools (includes frida CLI)
pip install frida-tools

# Install frida Python bindings
pip install frida

# Verify installation
frida --version
python -c "import frida; print(frida.__version__)"
```

### Version Matching

The Python frida package version **must match** the frida-server version. Check both:
```powershell
# Python package version
python -c "import frida; print(frida.__version__)"

# Server version (run with --version flag)
frida-server.exe --version
```

If versions don't match, upgrade/downgrade:
```powershell
# Install specific version
pip install frida==16.x.x frida-tools==12.x.x
```

## 3. Configure SSH for Remote Access

### Enable OpenSSH Server

```powershell
# Check if OpenSSH is installed
Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'

# Install OpenSSH Server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable the service
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Verify it's running
Get-Service sshd
```

### Configure Key-Based Authentication

On your analysis machine (Linux/Mac):
```bash
# Generate SSH key if needed
ssh-keygen -t ed25519 -C "frida-analysis"

# Copy public key to Windows machine
# Option 1: Use ssh-copy-id (if available)
ssh-copy-id user@windows-machine

# Option 2: Manual setup
# Copy contents of ~/.ssh/id_ed25519.pub to:
# C:\Users\<username>\.ssh\authorized_keys
```

### Windows SSH Server Configuration

Edit `C:\ProgramData\ssh\sshd_config`:
```
# Enable key-based auth
PubkeyAuthentication yes

# Disable password auth (recommended for security)
PasswordAuthentication no

# Ensure admin user can login
AllowUsers your-username

# Set authorized keys file
AuthorizedKeysFile .ssh/authorized_keys
```

Restart the SSH service:
```powershell
Restart-Service sshd
```

### SSH Tunnel for frida

From your analysis machine:
```bash
# Create SSH tunnel for frida (port 27042)
ssh -L 27042:127.0.0.1:27042 user@windows-machine

# Or bind to all interfaces on server (less secure)
# Use when multiple analysis machines need access
ssh -L 0.0.0.0:27042:127.0.0.1:27042 user@windows-machine
```

## 4. Start frida-server

### Manual Start (Admin PowerShell)

```powershell
# Navigate to frida-server location
cd C:\tools\frida

# Start with network binding for remote access
.\frida-server.exe -l 0.0.0.0:27042

# Or bind to localhost only (local access only)
.\frida-server.exe -l 127.0.0.1:27042
```

### Using the Startup Script

```batch
# Run the batch script (right-click → Run as Administrator)
scripts\start-frida-server.bat
```

### Verify Server is Running

```powershell
# Check if frida-server process exists
Get-Process frida-server

# Test connection
frida-ps -H 127.0.0.1
```

## 5. Connect to Stellaris

### Basic Connection Test

```python
import frida

# Local connection
device = frida.get_local_device()

# Remote connection (via SSH tunnel)
# device = frida.get_usb_device()
# device = frida.get_device_manager().add_remote_device("127.0.0.1:27042")

# Find stellaris process
processes = device.enumerate_processes()
stellaris = [p for p in processes if 'stellaris' in p.name.lower()]

if not stellaris:
    print("Stellaris not running!")
    exit(1)

pid = stellaris[0].pid
print(f"Found stellaris.exe with PID: {pid}")

# Attach to process
session = device.attach(pid)
print(f"Attached to PID: {session.pid}")

# Keep session open for inspection
input("Press Enter to detach...")
session.detach()
```

### Run Test Script

```bash
# From analysis machine (via SSH tunnel)
python scripts/frida-test.py
```

## 6. Common Issues

### "Access Denied" Error

- **Cause**: frida-server not running as Administrator
- **Fix**: Right-click `start-frida-server.bat` → "Run as administrator"

### Version Mismatch Warning

```
Warning: ... version does not match server ...
```

- **Cause**: Python frida package version differs from frida-server version
- **Fix**: Download matching versions from https://github.com/frida/frida/releases

### Process Not Found

- **Cause**: Game not running or wrong process name
- **Fix**: Verify game is running, check `frida-ps` output for correct name

### SSH Connection Refused

- **Cause**: OpenSSH server not running or firewall blocking
- **Fix**:
  ```powershell
  # Check service status
  Get-Service sshd

  # Check firewall rule
  Get-NetFirewallRule -Name *ssh*

  # Add firewall rule if needed
  New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
  ```

### Python Architecture Mismatch

```
RuntimeError: ... not compatible with this Python ...
```

- **Cause**: Using 32-bit Python with 64-bit frida-server
- **Fix**: Install 64-bit Python from https://www.python.org/downloads/

## 7. Security Notes

- **Bind to localhost** unless you need remote access
- **Use SSH tunnels** instead of exposing frida-server directly
- **Disable password auth** on SSH if using key-based auth
- **Run frida-server as admin** only when actively debugging
- **Firewall**: Block port 27042 except through SSH tunnel

## File Locations

| File | Location | Purpose |
|------|----------|---------|
| `frida-server.exe` | `C:\tools\frida\` | Frida server binary |
| `start-frida-server.bat` | `scripts/` | Windows startup script |
| `frida-test.py` | `scripts/` | Connection test script |

## Quick Reference

```powershell
# Start frida-server (Admin)
scripts\start-frida-server.bat

# SSH tunnel from analysis machine
ssh -L 27042:127.0.0.1:27042 user@windows

# List processes
frida-ps -H 127.0.0.1

# Attach to process
frida -H 127.0.0.1 stellaris.exe

# Run test script
python scripts/frida-test.py
```
