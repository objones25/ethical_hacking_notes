# Academy Setup

## Overview
The "Academy" machine is a Linux-based target focusing on web application vulnerabilities and privilege escalation techniques. This guide covers the setup process necessary before beginning the penetration testing exercise.

## System Requirements

- VMware Workstation/Player or VirtualBox
- Kali Linux VM (attacker machine)
- Minimum 4GB RAM recommended for both machines
- At least 30GB free disk space

## Download and Import

1. **Download Academy VM**:
   - Download from the course materials or provided links
   - Verify the hash to ensure integrity

2. **Import to Virtualization Platform**:
   - VMware: File -> Open -> Select OVA file
   - VirtualBox: File -> Import Appliance -> Select OVA file
   - Accept default settings during import

## Network Configuration

1. **Configure Network Adapter**:
   - Set both Academy and Kali VMs to use the same NAT Network or Host-only network
   - Ensure both machines can communicate on the same subnet

2. **Verify Network Settings**:
   - From Kali Linux, run `ifconfig` or `ip a` to note your IP address
   - The Academy machine should be on the same subnet

## Starting the Machine

1. **Power on the VM**:
   - Start the Academy machine
   - Allow it to boot completely (may take a few minutes on first boot)
   
2. **System Login (if needed)**:
   - The machine is configured to automatically start necessary services
   - Note: During the exercise, you'll be discovering credentials as part of the challenge

## Target Verification

1. **Verify the Target is Running**:
   - From Kali Linux, ping the target to verify connectivity:
     ```
     ping <target_ip>
     ```

2. **Port Scan Verification**:
   - Run a basic Nmap scan to verify services are running:
     ```
     nmap -sV <target_ip>
     ```
   - Verify that web server ports (likely 80 and/or 443) are open

3. **Web Application Check**:
   - Open a browser in Kali and navigate to `http://<target_ip>/`
   - Confirm the Academy website loads properly

## Troubleshooting Common Issues

1. **Network Connectivity Issues**:
   - Verify both VMs are on the same network segment
   - Check firewall settings on both systems
   - Ensure virtualization networking is properly configured

2. **VM Performance Issues**:
   - Allocate sufficient RAM (at least 2GB for Academy)
   - Consider enabling virtualization extensions in BIOS/UEFI
   - Close unnecessary applications to free system resources

3. **Web Server Not Responding**:
   - Allow more time for services to start
   - Try restarting the VM
   - Check if the IP address has changed using `arp-scan` or similar tools

## Snapshot Recommendation

Before beginning the attack process, create a snapshot of the Academy VM in its initial state:
- This allows you to easily revert to a clean state
- Helps if you need to restart the exercise
- Allows for practicing the attack multiple times

## Tools Preparation

Ensure these tools are updated and ready in your Kali Linux VM:
- Web application scanners (Nikto, Dirb/Gobuster)
- Burp Suite
- wfuzz
- Hydra (for brute forcing if necessary)
- LinPEAS/LinEnum (for Linux privilege escalation)

## Exercise Preparation

1. **Create a notes file** to document your findings
2. **Set up a directory structure** for organizing screenshots and output files
3. **Update all tools** on your Kali machine before beginning

## Security Considerations

- This VM contains deliberate vulnerabilities for educational purposes
- Never expose this VM to public networks or the internet
- Keep the VM powered off when not in use
- Consider using a dedicated VLAN if practicing in a shared environment
