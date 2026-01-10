#!/usr/bin/env python3
"""
VM Guest Command Execution Tool using PyVmomi
=============================================
Execute commands on guest VMs via VMware Tools.
Supports both Windows and Linux guests through vSphere API.
"""

import argparse
import getpass
import ssl
import sys
import time
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from pyVim import connect
from pyVmomi import vim


class VMGuestExecutor:
    """Execute commands on guest VMs via VMware Tools."""
    
    def __init__(self, host: str, username: str, password: str, 
                 port: int = 443, insecure: bool = True, 
                 verbose: bool = False):
        """
        Initialize connection to vSphere/ESXi host.
        
        Args:
            host: ESXi/vCenter hostname or IP
            username: Authentication username
            password: Authentication password
            port: Connection port (default: 443)
            insecure: Disable SSL verification (default: True)
            verbose: Enable verbose output
        """
        self.host = host
        self.username = username
        self.port = port
        self.verbose = verbose
        self.connected = False
        
        if verbose:
            print(f"[*] Connecting to {host}:{port} as {username}...", 
                  file=sys.stderr)
        
        try:
            # Create SSL context
            if insecure:
                context = ssl._create_unverified_context()
                if verbose:
                    print("[!] SSL verification disabled", file=sys.stderr)
            else:
                context = ssl.create_default_context()
            
            # Connect to vSphere
            self.si = connect.SmartConnect(
                host=host,
                port=port,
                user=username,
                pwd=password,
                sslContext=context
            )
            self.connected = True
            
            if verbose:
                print(f"[+] Successfully connected to {host}", file=sys.stderr)
                
        except vim.fault.InvalidLogin:
            print(f"[-] Authentication failed for {username}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"[-] Connection error: {e}", file=sys.stderr)
            sys.exit(1)
    
    def disconnect(self):
        """Disconnect from vSphere host."""
        if self.connected:
            connect.Disconnect(self.si)
            if self.verbose:
                print(f"[+] Disconnected from {self.host}", file=sys.stderr)
    
    def find_vm_by_name(self, vm_name: str) -> Optional[vim.VirtualMachine]:
        """
        Find VM by name in the inventory.
        
        Args:
            vm_name: Name of the VM to find
            
        Returns:
            VM object or None if not found
        """
        try:
            content = self.si.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.VirtualMachine],
                True  # recursive
            )
            
            vms = container_view.view
            for vm in vms:
                if vm.name == vm_name:
                    if self.verbose:
                        print(f"[+] Found VM: {vm_name}", file=sys.stderr)
                    container_view.Destroy()
                    return vm
            
            container_view.Destroy()
            print(f"[-] VM '{vm_name}' not found", file=sys.stderr)
            return None
            
        except Exception as e:
            print(f"[-] Error finding VM: {e}", file=sys.stderr)
            return None
    
    def list_all_vms(self) -> List[Dict[str, Any]]:
        """List all VMs with basic information."""
        try:
            content = self.si.RetrieveContent()
            container_view = content.viewManager.CreateContainerView(
                content.rootFolder,
                [vim.VirtualMachine],
                True
            )
            
            vms = []
            for vm in container_view.view:
                vm_info = {
                    'name': vm.name,
                    'power_state': str(vm.runtime.powerState),
                    'tools_status': str(vm.guest.toolsStatus) if vm.guest else 'N/A',
                    'guest_os': vm.config.guestFullName if hasattr(vm.config, 'guestFullName') else 'Unknown'
                }
                vms.append(vm_info)
            
            container_view.Destroy()
            return vms
            
        except Exception as e:
            print(f"[-] Error listing VMs: {e}", file=sys.stderr)
            return []
    
    def check_vmware_tools(self, vm: vim.VirtualMachine) -> bool:
        """
        Check if VMware Tools is running on the VM.
        
        Args:
            vm: VM object
            
        Returns:
            True if tools are running, False otherwise
        """
        try:
            if not vm.guest:
                return False
            
            tools_status = str(vm.guest.toolsStatus)
            if self.verbose:
                print(f"[*] VMware Tools status: {tools_status}", file=sys.stderr)
            
            return tools_status.lower() in ['toolsok', 'toolsold']
            
        except Exception as e:
            if self.verbose:
                print(f"[-] Error checking VMware Tools: {e}", file=sys.stderr)
            return False
    
    def execute_command(self, vm_name: str, guest_user: str, 
                       guest_pass: str, command: str, 
                       arguments: str = "", working_dir: str = "",
                       env_vars: Dict[str, str] = None, 
                       timeout: int = 30) -> Dict[str, Any]:
        """
        Execute command on guest VM.
        
        Args:
            vm_name: Name of target VM
            guest_user: Guest OS username
            guest_pass: Guest OS password
            command: Command to execute (full path recommended)
            arguments: Command arguments
            working_dir: Working directory for command
            env_vars: Environment variables to set
            timeout: Maximum execution time in seconds
            
        Returns:
            Dictionary with execution results
        """
        result = {
            'success': False,
            'vm': vm_name,
            'command': command,
            'arguments': arguments,
            'pid': None,
            'exit_code': None,
            'output': '',
            'error': '',
            'start_time': None,
            'end_time': None,
            'duration': None
        }
        
        try:
            # Find VM
            vm = self.find_vm_by_name(vm_name)
            if not vm:
                result['error'] = f"VM '{vm_name}' not found"
                return result
            
            # Check VMware Tools
            if not self.check_vmware_tools(vm):
                result['error'] = "VMware Tools not running or not installed"
                return result
            
            # Check power state
            if str(vm.runtime.powerState) != "poweredOn":
                result['error'] = f"VM is not powered on (state: {vm.runtime.powerState})"
                return result
            
            # Create authentication object
            auth = vim.vm.guest.NamePasswordAuthentication(
                username=guest_user,
                password=guest_pass
            )
            
            # Create program specification
            program_spec = vim.vm.guest.ProcessManager.ProgramSpec(
                programPath=command,
                arguments=arguments
            )
            
            if working_dir:
                program_spec.workingDirectory = working_dir
            
            if env_vars:
                program_spec.envVariables = [f"{k}={v}" for k, v in env_vars.items()]
            
            # Get process manager
            pm = self.si.content.guestOperationsManager.processManager
            
            # Start command execution
            start_time = datetime.now()
            result['start_time'] = start_time.isoformat()
            
            if self.verbose:
                print(f"[*] Executing command: {command} {arguments}", file=sys.stderr)
                print(f"[*] Guest user: {guest_user}", file=sys.stderr)
            
            pid = pm.StartProgramInGuest(vm, auth, program_spec)
            result['pid'] = pid
            
            if self.verbose:
                print(f"[+] Command started with PID: {pid}", file=sys.stderr)
            
            # Wait for completion with timeout
            end_time = None
            exit_code = None
            elapsed = 0
            
            while elapsed < timeout:
                time.sleep(1)
                elapsed += 1
                
                # Check process status
                processes = pm.ListProcessesInGuest(vm, auth, [pid])
                if processes:
                    process_info = processes[0]
                    if process_info.endTime:  # Process has finished
                        end_time = process_info.endTime
                        exit_code = process_info.exitCode
                        break
                
                if self.verbose and elapsed % 5 == 0:
                    print(f"[*] Waiting... ({elapsed}s/{timeout}s)", file=sys.stderr)
            
            if end_time is None:
                result['error'] = f"Command timed out after {timeout} seconds"
                # Try to get exit code anyway
                processes = pm.ListProcessesInGuest(vm, auth, [pid])
                if processes:
                    exit_code = processes[0].exitCode
            
            result['end_time'] = end_time.isoformat() if end_time else None
            result['exit_code'] = exit_code
            result['duration'] = elapsed
            
            # Determine success
            if exit_code == 0:
                result['success'] = True
                result['output'] = f"Command completed successfully (exit code: {exit_code})"
            elif exit_code is not None:
                result['success'] = False
                result['error'] = f"Command failed with exit code: {exit_code}"
            
            if self.verbose:
                status = "SUCCESS" if result['success'] else "FAILED"
                print(f"[{status}] Command completed in {elapsed}s (exit: {exit_code})", 
                      file=sys.stderr)
            
            return result
            
        except vim.fault.InvalidGuestLogin as e:
            result['error'] = f"Invalid guest credentials: {e.msg}"
            return result
        except vim.fault.GuestOperationsUnavailable as e:
            result['error'] = f"Guest operations unavailable: {e.msg}"
            return result
        except Exception as e:
            result['error'] = f"Execution error: {str(e)}"
            return result
    
    def execute_multiple_commands(self, vm_name: str, guest_user: str,
                                 guest_pass: str, commands: List[Dict[str, str]],
                                 delay: int = 1) -> List[Dict[str, Any]]:
        """
        Execute multiple commands sequentially.
        
        Args:
            vm_name: Name of target VM
            guest_user: Guest OS username
            guest_pass: Guest OS password
            commands: List of command dictionaries
            delay: Delay between commands in seconds
            
        Returns:
            List of execution results
        """
        results = []
        
        for i, cmd in enumerate(commands, 1):
            if self.verbose:
                print(f"\n[*] Executing command {i}/{len(commands)}", file=sys.stderr)
            
            result = self.execute_command(
                vm_name=vm_name,
                guest_user=guest_user,
                guest_pass=guest_pass,
                command=cmd.get('command', ''),
                arguments=cmd.get('arguments', ''),
                working_dir=cmd.get('working_dir', ''),
                env_vars=cmd.get('env_vars', {}),
                timeout=cmd.get('timeout', 30)
            )
            
            results.append(result)
            
            # Add delay between commands if specified
            if i < len(commands) and delay > 0:
                time.sleep(delay)
        
        return results


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Execute commands on guest VMs via VMware Tools",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H esxi01.company.com -u root -p password --vm UbuntuVM \\
    --guest-user ubuntu --guest-pass ubuntu --cmd /bin/ls --args "-la /home"
  
  %(prog)s -H vcenter.company.com -u admin@vsphere.local --vm WinServer \\
    --guest-user administrator --cmd "C:\\\\Windows\\\\System32\\\\cmd.exe" \\
    --args "/c whoami"
  
  %(prog)s -H 10.5.2.111 -u root --list-vms
  
  %(prog)s -H esxi01.company.com -u root --vm UbuntuVM \\
    --command-file commands.json
  
  %(prog)s -H esxi01.company.com -u root --vm UbuntuVM \\
    --guest-user ubuntu --cmd "sudo" --args "-S apt update" --interactive
  
Security Note:
  Avoid passing passwords on command line. Use --interactive flag or
  set environment variables VSPHERE_USER, VSPHERE_PASSWORD, etc.
        """
    )
    
    # Connection arguments
    parser.add_argument("-H", "--host",
                       required=True,
                       help="ESXi/vCenter hostname or IP address")
    
    parser.add_argument("-u", "--user",
                       required=True,
                       help="vSphere/ESXi username (e.g., root, administrator@vsphere.local)")
    
    parser.add_argument("-p", "--password",
                       help="vSphere/ESXi password (prompt if not provided)")
    
    parser.add_argument("--port",
                       type=int,
                       default=443,
                       help="Connection port (default: 443)")
    
    parser.add_argument("-k", "--insecure",
                       action="store_true",
                       help="Disable SSL certificate verification")
    
    # VM selection
    parser.add_argument("--vm",
                       help="Target VM name (use with --list-vms to find names)")
    
    parser.add_argument("-l", "--list-vms",
                       action="store_true",
                       help="List all available VMs and exit")
    
    # Guest authentication
    parser.add_argument("--guest-user",
                       help="Guest OS username")
    
    parser.add_argument("--guest-pass",
                       help="Guest OS password")
    
    # Command execution
    parser.add_argument("--cmd",
                       help="Command to execute (full path recommended)")
    
    parser.add_argument("--args",
                       default="",
                       help="Command arguments")
    
    parser.add_argument("--working-dir",
                       default="",
                       help="Working directory for command")
    
    parser.add_argument("--timeout",
                       type=int,
                       default=30,
                       help="Command timeout in seconds (default: 30)")
    
    # Advanced options
    parser.add_argument("-f", "--command-file",
                       help="JSON file with multiple commands to execute")
    
    parser.add_argument("-i", "--interactive",
                       action="store_true",
                       help="Interactive password prompts")
    
    parser.add_argument("--env",
                       nargs="*",
                       help="Environment variables (format: KEY=VALUE)")
    
    parser.add_argument("-o", "--output",
                       choices=["text", "json", "csv"],
                       default="text",
                       help="Output format (default: text)")
    
    parser.add_argument("-v", "--verbose",
                       action="store_true",
                       help="Enable verbose output")
    
    parser.add_argument("--delay",
                       type=int,
                       default=1,
                       help="Delay between multiple commands in seconds (default: 1)")
    
    return parser.parse_args()


def get_password_interactively(prompt: str = "Password: ") -> str:
    """Get password securely from terminal."""
    return getpass.getpass(prompt)


def parse_env_vars(env_args: List[str]) -> Dict[str, str]:
    """Parse environment variable arguments."""
    env_vars = {}
    if env_args:
        for env_arg in env_args:
            if "=" in env_arg:
                key, value = env_arg.split("=", 1)
                env_vars[key] = value
    return env_vars


def format_output(result: Dict[str, Any], output_format: str) -> str:
    """Format execution result based on output format."""
    if output_format == "json":
        import json
        return json.dumps(result, indent=2)
    
    elif output_format == "csv":
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)

        # Write single row with key data
        writer.writerow([
            result.get('vm', ''),
            result.get('command', ''),
            result.get('arguments', ''),
            result.get('success', False),
            result.get('exit_code', ''),
            result.get('pid', ''),
            result.get('duration', ''),
            result.get('error', '').replace('\n', ' ')
        ])
        
        return output.getvalue().strip()
    
    else:  # text format
        lines = []
        lines.append(f"{'='*60}")
        lines.append(f"EXECUTION RESULTS")
        lines.append(f"{'='*60}")
        lines.append(f"VM:            {result.get('vm', 'N/A')}")
        lines.append(f"Command:       {result.get('command', 'N/A')}")
        lines.append(f"Arguments:     {result.get('arguments', 'N/A')}")
        lines.append(f"Success:       {result.get('success', False)}")
        lines.append(f"Exit Code:     {result.get('exit_code', 'N/A')}")
        lines.append(f"PID:           {result.get('pid', 'N/A')}")
        lines.append(f"Start Time:    {result.get('start_time', 'N/A')}")
        lines.append(f"End Time:      {result.get('end_time', 'N/A')}")
        lines.append(f"Duration:      {result.get('duration', 'N/A')} seconds")
        
        if result.get('error'):
            lines.append(f"Error:         {result.get('error')}")
        
        lines.append(f"{'='*60}")
        return "\n".join(lines)


def main():
    """Main execution function."""
    args = parse_arguments()
    
    # Get vSphere password
    password = args.password
    if not password:
        if args.interactive:
            password = get_password_interactively(f"vSphere password for {args.user}: ")
        else:
            # Try environment variable
            import os
            password = os.environ.get('VSPHERE_PASSWORD')
            if not password:
                print("[-] Password required. Use --interactive or set VSPHERE_PASSWORD env var.", 
                      file=sys.stderr)
                sys.exit(1)
    
    # Get guest password if needed
    guest_pass = args.guest_pass
    if args.vm and args.guest_user and not guest_pass:
        if args.interactive:
            guest_pass = get_password_interactively(f"Guest password for {args.guest_user}: ")
        else:
            import os
            guest_pass = os.environ.get('GUEST_PASSWORD')
            if not guest_pass:
                print("[-] Guest password required. Use --interactive or set GUEST_PASSWORD env var.", 
                      file=sys.stderr)
                sys.exit(1)
    
    # Create executor
    executor = VMGuestExecutor(
        host=args.host,
        username=args.user,
        password=password,
        port=args.port,
        insecure=args.insecure,
        verbose=args.verbose
    )
    
    try:
        # List VMs if requested
        if args.list_vms:
            print(f"\n[*] Listing VMs on {args.host}", file=sys.stderr)
            vms = executor.list_all_vms()
            
            if args.output == "json":
                import json
                print(json.dumps(vms, indent=2))
            elif args.output == "csv":
                print("Name,PowerState,ToolsStatus,GuestOS")
                for vm in vms:
                    print(f"{vm['name']},{vm['power_state']},{vm['tools_status']},{vm['guest_os']}")
            else:
                print(f"\n{'='*60}")
                print(f"{'VM Name':<30} {'Power State':<12} {'Tools':<10} {'Guest OS'}")
                print(f"{'='*60}")
                for vm in vms:
                    print(f"{vm['name']:<30} {vm['power_state']:<12} {vm['tools_status']:<10} {vm['guest_os']}")
                print(f"{'='*60}")
                print(f"Total VMs: {len(vms)}")
            
            executor.disconnect()
            sys.exit(0)
        
        # Validate required arguments for command execution
        if not args.vm:
            print("[-] VM name required (use --vm)", file=sys.stderr)
            sys.exit(1)
        
        if not args.cmd and not args.command_file:
            print("[-] Command required (use --cmd or --command-file)", file=sys.stderr)
            sys.exit(1)
        
        # Parse environment variables
        env_vars = parse_env_vars(args.env) if args.env else {}
        
        # Execute command(s)
        if args.command_file:
            # Load commands from JSON file
            try:
                import json
                with open(args.command_file, 'r') as f:
                    commands = json.load(f)
                
                if not isinstance(commands, list):
                    commands = [commands]
                
                results = executor.execute_multiple_commands(
                    vm_name=args.vm,
                    guest_user=args.guest_user,
                    guest_pass=guest_pass,
                    commands=commands,
                    delay=args.delay
                )
                
                # Output results
                if args.output == "json":
                    print(json.dumps(results, indent=2))
                elif args.output == "csv":
                    print("VM,Command,Arguments,Success,ExitCode,PID,Duration,Error")
                    for result in results:
                        print(format_output(result, "csv"))
                else:
                    for i, result in enumerate(results, 1):
                        print(f"\n[ Command {i}/{len(results)} ]")
                        print(format_output(result, "text"))
                
            except FileNotFoundError:
                print(f"[-] Command file not found: {args.command_file}", file=sys.stderr)
                sys.exit(1)
            except json.JSONDecodeError as e:
                print(f"[-] Invalid JSON in command file: {e}", file=sys.stderr)
                sys.exit(1)
        
        else:
            # Execute single command
            result = executor.execute_command(
                vm_name=args.vm,
                guest_user=args.guest_user,
                guest_pass=guest_pass,
                command=args.cmd,
                arguments=args.args,
                working_dir=args.working_dir,
                env_vars=env_vars,
                timeout=args.timeout
            )
            # Output result
            print(format_output(result, args.output))
            
            # Set exit code based on command success
            if not result.get('success', False):
                sys.exit(1)
    
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    
    finally:
        executor.disconnect()


if __name__ == "__main__":
    main()
