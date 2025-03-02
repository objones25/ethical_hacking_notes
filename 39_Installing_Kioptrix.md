# Installing Kioptrix

## Introduction to Kioptrix

- Kioptrix is a deliberately vulnerable virtual machine for practicing penetration testing
- It's a beginner-level machine from VulnHub (https://www.vulnhub.com)
- Created to provide a safe, legal environment to practice exploitation
- Perfect for learning the fundamentals of ethical hacking

## Downloading Kioptrix

### Official Sources
- Available from VulnHub (https://www.vulnhub.com)
- Course provides a direct download link: https://tcm-sec.com/kioptrix

### Download Options
- OVA file (~250MB) - Preferred format
- OVF file - Alternative format if OVA doesn't work

## Installation on VMware

1. Open VMware Player/Workstation
2. Select "Open a Virtual Machine"
3. Navigate to the downloaded Kioptrix OVA file
4. Click "Open"
5. Choose a storage location when prompted
6. Set name to "Kioptrix Level One"
7. Click "Import"
8. If you get an error, click "Retry" (this is normal)

## Installation on VirtualBox

1. Open VirtualBox
2. Click on "Import"
3. Navigate to the downloaded Kioptrix OVA file
4. Click "Next"
5. Review settings (defaults are fine)
6. Click "Import"

## Configuring VM Settings

### VMware Configuration
1. Right-click on the imported VM and select "Settings"
2. Under "Memory", set to 256MB or 512MB (minimum 256MB recommended)
3. Under "Network Adapter", select "NAT"
4. Click "OK"

### VirtualBox Configuration
1. Right-click on the imported VM and select "Settings"
2. Under "System > Base Memory", set to 256MB or 512MB
3. Under "Network", ensure "NAT Network" is selected
4. Click "OK"

## Starting Kioptrix

1. Select the VM and click "Play" or "Start"
2. The machine will boot to a login screen
3. No need to log in yet - just confirm it boots correctly
4. When you see the login prompt, the installation is complete

## Finding Kioptrix on Your Network

After installation, you'll need to find the IP address of the Kioptrix machine. This will be covered in the scanning section, but there are several methods:

### Using a Login to Find the IP
1. Log in with username: `john`
2. Password: `TwoCows2` (case sensitive)
3. Run `ping 8.8.8.8` and press Ctrl+C quickly
4. Note the source IP address shown

### Using ARP-Scan
In Kali Linux, run:
```bash
arp-scan -l
```
Look for the entry with "VMware" in the vendor column.

## Troubleshooting

- If OVA import fails, try downloading again or using the OVF format
- If the VM doesn't boot, check memory settings (minimum 256MB)
- If networking issues occur, ensure NAT is selected
- If unable to find the IP address, confirm both Kali and Kioptrix are on the same virtual network
