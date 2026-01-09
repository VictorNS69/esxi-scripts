#!/usr/bin/env python3
"""
VM Enumeration Tool using PyVmomi
=================================
Extracts detailed information about all VMs from a vSphere/ESXi host.
Supports both standalone ESXi hosts and vCenter servers.
"""

import argparse
import ssl
import sys
from getpass import getpass
from typing import Dict, List, Any
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Extract Guest VM State from vSphere/ESXi",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -H 10.5.2.111 -u administrator@telecore.ad
  %(prog)s -H esxi01.company.com -u root -p
  %(prog)s -H vcenter.company.com -u admin@vsphere.local --output csv
  %(prog)s -H 10.5.2.111 -u admin --insecure --verbose
        """
    )
    
    parser.add_argument(
        "-H", "--host",
        required=True,
        help="ESXi/vCenter hostname or IP address"
    )
    
    parser.add_argument(
        "-u", "--username",
        required=True,
        help="Username (e.g., root, administrator@vsphere.local)"
    )
    
    parser.add_argument(
        "-p", "--password",
        help="Password (will prompt if not provided)",
        default=None
    )
    
    parser.add_argument(
        "-P", "--port",
        type=int,
        default=443,
        help="Port number (default: 443)"
    )
    
    parser.add_argument(
        "-i", "--insecure",
        action="store_true",
        help="Disable SSL certificate verification"
    )
    
    parser.add_argument(
        "-o", "--output",
        choices=["text", "csv", "json"],
        default="text",
        help="Output format (default: text)"
    )
    
    parser.add_argument(
        "-f", "--filter",
        help="Filter VMs by name (supports wildcards, e.g., '*prod*')"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (-v, -vv, -vvv)"
    )
    
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=30,
        help="Connection timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "-s", "--state",
        choices=["poweredOn", "poweredOff", "suspended", "all"],
        default="all",
        help="Filter by VM power state"
    )
    
    return parser.parse_args()


def get_password_interactively(username: str) -> str:
    """Prompt for password securely if not provided."""
    prompt = f"Password for {username}: "
    return getpass(prompt)


def create_ssl_context(insecure: bool) -> ssl.SSLContext:
    """Create SSL context with optional verification."""
    if insecure:
        context = ssl._create_unverified_context()
        if __debug__:
            print("[!] SSL certificate verification disabled", file=sys.stderr)
    else:
        context = ssl.create_default_context()
    return context


def connect_to_vsphere(host: str, port: int, username: str, 
                       password: str, ssl_context: ssl.SSLContext, 
                       timeout: int) -> vim.ServiceInstance:
    """Establish connection to vSphere/ESXi host."""
    try:
        if __debug__:
            print(f"[*] Connecting to {host}:{port} as {username}...", file=sys.stderr)
        
        si = SmartConnect(
            host=host,
            port=port,
            user=username,
            pwd=password,
            sslContext=ssl_context
        )
        
        if __debug__:
            print("[+] Connection successful", file=sys.stderr)
        
        return si
        
    except vim.fault.InvalidLogin:
        print(f"[-] Authentication failed for {username}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Connection error: {e}", file=sys.stderr)
        sys.exit(1)


def get_all_vms(content: vim.ServiceInstanceContent) -> List[vim.VirtualMachine]:
    """Retrieve all VM objects from the inventory."""
    container_view = content.viewManager.CreateContainerView(
        content.rootFolder,
        [vim.VirtualMachine],
        True  # recursive
    )
    vms = container_view.view
    container_view.Destroy()  # Clean up view
    return vms


def filter_vms(vms: List[vim.VirtualMachine], name_filter: str = None, 
               state_filter: str = "all") -> List[vim.VirtualMachine]:
    """Filter VMs based on name and power state."""
    filtered_vms = []
    
    for vm in vms:
        # Apply name filter
        if name_filter:
            import fnmatch
            if not fnmatch.fnmatch(vm.name, name_filter):
                continue
        
        # Apply state filter
        if state_filter != "all":
            current_state = str(vm.runtime.powerState)
            if current_state != state_filter:
                continue
        
        filtered_vms.append(vm)
    
    return filtered_vms


def extract_vm_info(vm: vim.VirtualMachine, verbose: int = 0) -> Dict[str, Any]:
    """Extract detailed information from a VM object."""
    info = {
        "name": vm.name,
        "power_state": str(vm.runtime.powerState),
        "os": vm.config.guestFullName if hasattr(vm.config, 'guestFullName') else "Unknown",
        "tools_status": str(vm.guest.toolsStatus) if vm.guest else "N/A",
        "annotation": vm.config.annotation if hasattr(vm.config, 'annotation') else "",
        "vm_path": vm.config.files.vmPathName if hasattr(vm.config, 'files') else "N/A",
        "num_cpu": vm.config.hardware.numCPU if hasattr(vm.config.hardware, 'numCPU') else 0,
        "memory_mb": vm.config.hardware.memoryMB if hasattr(vm.config.hardware, 'memoryMB') else 0,
        "uuid": vm.config.instanceUuid if hasattr(vm.config, 'instanceUuid') else "N/A",
        "guest_id": vm.config.guestId if hasattr(vm.config, 'guestId') else "N/A",
    }
    
    # Extract IP address(es)
    ip_addresses = []
    if vm.guest and vm.guest.net:
        for net in vm.guest.net:
            if hasattr(net, 'ipConfig') and net.ipConfig.ipAddress:
                for ip in net.ipConfig.ipAddress:
                    ip_addresses.append(ip.ipAddress)
    
    info["ip_addresses"] = ip_addresses if ip_addresses else ["N/A"]
    info["primary_ip"] = ip_addresses[0] if ip_addresses else "N/A"
    
    # Extended info for verbose mode
    if verbose >= 2:
        info["host_name"] = vm.guest.hostName if vm.guest else "N/A"
        info["tools_version"] = vm.guest.toolsVersionStatus2 if vm.guest else "N/A"
        info["guest_state"] = vm.guest.guestState if vm.guest else "N/A"
    
    if verbose >= 3:
        info["vmx_path"] = vm.config.files.vmPathName if hasattr(vm.config, 'files') else "N/A"
        info["snapshot"] = "Yes" if vm.snapshot else "No"
        info["storage_committed"] = vm.storage.perDatastoreUsage if hasattr(vm, 'storage') else "N/A"
    
    return info


def format_output(vm_info: Dict[str, Any], output_format: str) -> str:
    """Format VM information based on output format."""
    if output_format == "text":
        return format_text_output(vm_info)
    elif output_format == "csv":
        return format_csv_output(vm_info)
    elif output_format == "json":
        return format_json_output(vm_info)
    return ""


def format_text_output(vm_info: Dict[str, Any]) -> str:
    """Format VM info as readable text."""
    lines = [
        f"{'='*60}",
        f"VM Name:          {vm_info['name']}",
        f"Power State:      {vm_info['power_state']}",
        f"Guest OS:         {vm_info['os']}",
        f"VMware Tools:     {vm_info['tools_status']}",
        f"Primary IP:       {vm_info['primary_ip']}",
        f"All IPs:          {', '.join(vm_info['ip_addresses'])}",
        f"vCPUs:            {vm_info['num_cpu']}",
        f"Memory (MB):      {vm_info['memory_mb']}",
        f"VM UUID:          {vm_info['uuid']}",
        f"VM Path:          {vm_info['vm_path']}",
    ]
    
    if vm_info['annotation']:
        lines.append(f"Annotation:       {vm_info['annotation']}")
    
    # Add extended info if present
    if 'host_name' in vm_info:
        lines.append(f"Guest Hostname:   {vm_info['host_name']}")
    
    lines.append("")  # Empty line for separation
    return "\n".join(lines)


def format_csv_output(vm_info: Dict[str, Any]) -> str:
    """Format VM info as CSV line."""
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header (only once, handled by main function)
    writer.writerow([
        vm_info['name'],
        vm_info['power_state'],
        vm_info['os'],
        vm_info['tools_status'],
        vm_info['primary_ip'],
        ';'.join(vm_info['ip_addresses']),
        vm_info['num_cpu'],
        vm_info['memory_mb'],
        vm_info['uuid'],
        vm_info['vm_path'].replace(',', ';'),  # Sanitize for CSV
        vm_info['annotation'].replace(',', ';').replace('\n', ' ')  # Sanitize
    ])
    
    return output.getvalue().strip()


def format_json_output(vm_info: Dict[str, Any]) -> str:
    """Format VM info as JSON."""
    import json
    return json.dumps(vm_info, indent=2)


def print_summary(vms: List[vim.VirtualMachine], filtered_vms: List[vim.VirtualMachine], 
                  args: argparse.Namespace) -> None:
    """Print summary statistics."""
    if args.verbose >= 1:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"SUMMARY", file=sys.stderr)
        print(f"{'='*60}", file=sys.stderr)
        print(f"Total VMs found:      {len(vms)}", file=sys.stderr)
        print(f"VMs after filtering:  {len(filtered_vms)}", file=sys.stderr)
        print(f"Host:                 {args.host}", file=sys.stderr)
        print(f"User:                 {args.username}", file=sys.stderr)
        print(f"Output format:        {args.output.upper()}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)


def main():
    """Main execution function."""
    # Parse command line arguments
    args = parse_arguments()
    
    # Get password if not provided
    password = args.password or get_password_interactively(args.username)
    
    # Create SSL context
    ssl_context = create_ssl_context(args.insecure)
    
    try:
        # Connect to vSphere/ESXi
        si = connect_to_vsphere(
            host=args.host,
            port=args.port,
            username=args.username,
            password=password,
            ssl_context=ssl_context,
            timeout=args.timeout
        )
        
        # Get content and VMs
        content = si.RetrieveContent()
        all_vms = get_all_vms(content)
        
        # Apply filters
        filtered_vms = filter_vms(all_vms, args.filter, args.state)
        
        # Print summary
        print_summary(all_vms, filtered_vms, args)
        
        # Print CSV header if needed
        if args.output == "csv":
            print("Name,PowerState,OS,ToolsStatus,PrimaryIP,AllIPs,vCPUs,MemoryMB,UUID,VMPath,Annotation")
        
        # Process and display each VM
        for vm in filtered_vms:
            try:
                vm_info = extract_vm_info(vm, args.verbose)
                output = format_output(vm_info, args.output)
                print(output)
                
            except Exception as e:
                if args.verbose >= 1:
                    print(f"[!] Error processing VM '{vm.name}': {e}", file=sys.stderr)
                continue
        
        # Disconnect
        Disconnect(si)
        
        if args.verbose >= 1:
            print(f"\n[+] Disconnected from {args.host}", file=sys.stderr)
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"[-] Fatal error: {e}", file=sys.stderr)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
