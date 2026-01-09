# esxi-scripts
Automation script for enumerating the hypervisor environment

This script will connect to the ESXi and perform the following actions :
- Check the availability of the Guest VMs
- Check whether VMWare Tools are installed or not
- When VMware Tools are present, an attacker with ESXi root privileges can abuse management APIs and tooling to execute arbitrary actions against the host and its guests.
- Scrape the Annotations / Notes field
- High probability of admin writing credentials
