# Scanning with Nessus - Part 1

## Introduction to Nessus

Nessus is a comprehensive vulnerability scanner developed by Tenable. It automates the detection of known vulnerabilities, misconfigurations, and potential security issues across networks, systems, and applications.

## Nessus Versions

1. **Nessus Essentials** (formerly Nessus Home)
   - Free version
   - Limited to scanning 16 IP addresses
   - Good for home use and learning
   - Requires registration with Tenable

2. **Nessus Professional**
   - Paid commercial version
   - Unlimited IP scanning
   - More comprehensive scanning capabilities
   - Additional features like compliance checks

3. **Tenable.io**
   - Cloud-based enterprise solution
   - Centralized management
   - Continuous scanning capabilities

## Installation Process

### System Requirements
- Minimum 4GB RAM (8GB recommended)
- 2GHz CPU
- At least 5GB of free disk space
- Supported operating systems: Windows, macOS, Linux

### Installation Steps

1. **Download Nessus**
   - Visit Tenable's website: https://www.tenable.com/products/nessus
   - Register for a Nessus Essentials activation code
   - Download the appropriate installer for your operating system

2. **Install Nessus**
   - **For Linux (Debian/Ubuntu):**
     ```
     sudo dpkg -i Nessus-<version>.deb
     sudo /etc/init.d/nessusd start
     ```
   - **For Windows:**
     - Run the installer executable (.exe)
     - Follow the installation wizard

3. **Initial Setup**
   - Open a web browser and navigate to: https://localhost:8834
   - Accept the security certificate warning
   - Choose "Nessus Essentials" option
   - Enter the activation code you received via email
   - Create an administrator account
   - Wait for plugins to download and install (may take 15-60 minutes)

## Nessus Interface Overview

The Nessus web interface is divided into several key sections:

1. **Dashboard**
   - Overview of scan results and system status
   - Quick access to recent scans
   - Vulnerability summary statistics

2. **Scans**
   - Create, manage, and view scan results
   - Schedule recurring scans
   - Import/export scan configurations

3. **Policies**
   - Create and manage scan policies
   - Customize scan settings
   - Define scanning parameters

4. **Settings**
   - User management
   - Scanner configuration
   - Update management
   - Advanced options

## Creating Your First Scan

1. **Navigate to the Scans tab**
   - Click the "+ New Scan" button

2. **Select a Scan Template**
   - **Basic Network Scan**: General-purpose scan for most environments
   - **Advanced Scan**: More thorough but potentially intrusive
   - **Host Discovery**: Quick scan to identify active hosts
   - Many other specialized templates are available

3. **Configure Scan Settings**
   - **Name**: Provide a descriptive scan name
   - **Description**: Optional details about the scan
   - **Targets**: Enter IP addresses, ranges, or hostnames
     - Individual IPs: 192.168.1.10
     - CIDR notation: 192.168.1.0/24
     - IP ranges: 192.168.1.1-192.168.1.254
     - Multiple targets can be comma-separated or on separate lines

4. **Schedule** (Optional)
   - Set scan to run once or on a recurring schedule
   - Define start time, frequency, and notifications

5. **Advanced Settings** (Optional)
   - Assessment, Credentials, Plugins, SNMP, etc.
   - Port scanning configuration
   - Performance options

6. **Save and Launch**
   - Click "Save" to save the scan configuration
   - Click "Launch" to start the scan immediately

## Understanding Scan Policies

Scan policies define the parameters of a vulnerability scan:

1. **Discovery Settings**
   - Port scan range and method
   - Host discovery methods
   - Service discovery options

2. **Assessment Settings**
   - Scan intensity
   - Thoroughness vs. performance balance
   - Web application scanning options

3. **Credentials**
   - Windows/SMB credentials
   - SSH credentials
   - Database credentials
   - Allows for more thorough scanning of authenticated systems

4. **Plugins**
   - Enable/disable specific vulnerability checks
   - Fine-tune which vulnerability families to scan for
   - Customize plugin thresholds and sensitivity

## Best Practices for Nessus Scanning

1. **Start with Limited Scope**
   - Begin with a small number of hosts
   - Expand gradually as you become more comfortable

2. **Use Appropriate Scan Types**
   - Host Discovery for initial reconnaissance
   - Basic Network Scan for general vulnerability assessment
   - Advanced Scan for thorough testing

3. **Consider Timing**
   - Run intensive scans during off-hours
   - Be mindful of network impact

4. **Use Credentials When Possible**
   - Authenticated scans provide much more thorough results
   - Reduces false positives

5. **Review and Validate Results**
   - Not all findings are exploitable or relevant
   - Verify critical findings manually

## Conclusion

Nessus is a powerful vulnerability scanning tool that automates the detection of security issues. Part 1 covered the installation, setup, and initial scan configuration. In Part 2, we'll explore analyzing scan results, understanding vulnerability reports, and leveraging Nessus findings in your penetration testing workflow.
