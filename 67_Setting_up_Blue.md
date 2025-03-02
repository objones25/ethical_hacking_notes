# Setting up Blue

## Overview
The "Blue" machine is a Windows-based target vulnerable to the infamous MS17-010 (EternalBlue) exploit. This walkthrough covers the setup process to prepare for attacking this vulnerable system.

## System Requirements

- VMware Workstation/Player or VirtualBox
- Kali Linux VM (attacker machine)
- Minimum 4GB RAM recommended for both machines
- At least 40GB free disk space

## Download and Import

1. **Download Blue VM**:
   - Download from the course materials or provided links
   - Verify the hash to ensure integrity

2. **Import to Virtualization Platform**:
   - VMware: File -> Open -> Select OVA file
   - VirtualBox: File -> Import Appliance -> Select OVA file
   - Accept default settings during import

## Network Configuration

1. **Configure Network Adapter**:
   - Set both Blue and Kali VMs to use the same NAT Network or Host-only network
   - Ensure both machines can communicate on the same subnet

2. **Verify Network Settings**:
   - From Kali Linux, run `ifconfig` or `ip a` to note your IP address
   - The Blue machine should be on the same subnet

## Starting the Machine

1. **Power on the VM**:
   - Start the Blue machine
   - Allow it to boot completely (may take a few minutes on first boot)
   
2. **VM Login Credentials (if needed)**:
   - Username: Administrator
   - Password: Password123!
   - Note: You may not need these initially, as the exploitation focuses on network services

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
   - Verify that SMB ports (139, 445) are open

## Troubleshooting Common Issues

1. **Network Connectivity Issues**:
   - Verify both VMs are on the same network segment
   - Check firewall settings on both systems
   - Ensure virtualization networking is properly configured

2. **VM Performance Issues**:
   - Allocate sufficient RAM (at least 2GB for Blue)
   - Consider enabling virtualization extensions in BIOS/UEFI
   - Close unnecessary applications to free system resources

3. **Import Failures**:
   - Ensure you have the latest version of VMware/VirtualBox
   - Try extracting the OVA and importing the individual VMDK files

## Snapshot Recommendation

Before beginning the attack process, create a snapshot of the Blue VM in its initial state:
- This allows you to easily revert to a clean state
- Helps if the system becomes unstable after exploitation
- Allows for practicing the attack multiple times

## Security Considerations

- This VM contains deliberate vulnerabilities for educational purposes
- Never expose this VM to public networks or the internet
- Keep the VM powered off when not in use
- Consider using a dedicated VLAN if practicing in a shared environment
