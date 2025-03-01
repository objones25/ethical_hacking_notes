# MAC Addresses

## Basic Concepts

MAC (Media Access Control) addresses are Layer 2 identifiers used in networking. Unlike IP addresses which operate at Layer 3, MAC addresses function at the data link layer.

### Key Characteristics:
* Also known as physical addresses
* Used for communication over switches
* Unique identifier for network interface cards (NICs)
* Associated with physical hardware devices
* Identified as "ether" in the `ifconfig` command output

## MAC Address Structure

A MAC address consists of six pairs of hexadecimal digits, for a total of 12 hex digits (48 bits).

Example: `00:50:56:c0:00:08`

### Vendor Identification
* The first three pairs (6 hex digits) identify the manufacturer/vendor
* Known as the Organizationally Unique Identifier (OUI)
* Can be looked up in online databases to identify device types
* Example: `00:50:56` corresponds to VMware

### Device Identification
* The last three pairs are assigned by the manufacturer
* Uniquely identifies the specific device
* Combination of OUI and device ID should be globally unique

## Practical Uses of MAC Addresses

### Device Identification
* MAC addresses can help identify unknown devices on a network
* Useful when IP addresses alone aren't descriptive enough
* Can help identify device types via OUI lookup
* Example: Determining if a device is a router, printer, or specialized equipment

### Network Switching
* Switches use MAC addresses to direct traffic
* MAC address tables map ports to physical addresses
* Enables efficient local network communication
* Foundation for Layer 2 network operations

## MAC Address Lookup

The instructor demonstrates looking up a MAC address vendor:
1. Take the first three pairs of the MAC address (e.g., `00:50:56`)
2. Use an online MAC address lookup tool
3. Discover the vendor (in this case, VMware)

This technique can be useful for:
* Identifying unknown devices on a network
* Determining if a device is what it claims to be
* Asset inventory and network mapping

## Importance in Ethical Hacking

Understanding MAC addresses is important for ethical hackers because:
* They allow for device fingerprinting
* They're used in certain attacks (MAC spoofing, ARP poisoning)
* They help with network mapping and reconnaissance
* They're crucial for wireless network testing
* They provide another data point for device identification

## Layer 2 vs. Layer 3

MAC addresses (Layer 2) and IP addresses (Layer 3) work together:
* MAC addresses work on the local network segment
* IP addresses work across routers and the broader internet
* Switches use MAC addresses to forward frames
* Routers use IP addresses to forward packets

Understanding this relationship is fundamental to networking and by extension, ethical hacking.

## MAC Address Formats and Vendor Identification

Different vendors format MAC addresses in distinct ways:

* **Cisco**: 00:1A:A1:xx:xx:xx
* **Dell**: 00:14:22:xx:xx:xx
* **Apple**: 00:03:93:xx:xx:xx or 00:05:02:xx:xx:xx
* **Microsoft**: 00:50:F2:xx:xx:xx
* **VMware**: 00:50:56:xx:xx:xx

Tools for MAC address lookup include:
* Online MAC lookup databases (e.g., macvendors.com)
* Local tools like `macchanger -l` in Linux
* Network analysis tools like Wireshark that identify vendors automatically

## MAC Address and ARP Relationship

ARP (Address Resolution Protocol) creates a mapping between Layer 3 (IP) and Layer 2 (MAC) addresses:

1. When a device needs to communicate with an IP address on the local network, it checks its ARP cache
2. If the MAC address is unknown, the device broadcasts an ARP request: "Who has IP x.x.x.x?"
3. The device with that IP responds with its MAC address
4. The mapping is stored in the ARP cache for future use

This relationship is critical in penetration testing as it forms the basis for:
* ARP spoofing/poisoning attacks
* Man-in-the-middle attacks
* Network sniffing on switched networks

## MAC Filtering

MAC filtering is a security measure used to control network access based on MAC addresses:

### How It Works
* Network devices (usually wireless access points or switches) maintain a list of allowed or denied MAC addresses
* Only devices with permitted MAC addresses can connect to the network
* Commonly used in wireless networks as an additional layer of security

### Limitations as a Security Measure
* Easily bypassed through MAC spoofing
* MAC addresses are transmitted in plaintext and can be captured
* Provides a false sense of security
* Administrative overhead in maintaining MAC lists

### Penetration Testing Implications
* Testing MAC filtering effectiveness is a common wireless assessment task
* Demonstrates the limitations of security by obscurity
* Highlights the importance of defense in depth

## MAC Spoofing Techniques

MAC spoofing is the practice of changing a device's MAC address to impersonate another device:

### Common Tools
* **Linux**: `macchanger`, `ifconfig`, or `ip link`
* **Windows**: Registry edits or specialized tools like TMAC
* **macOS**: `ifconfig` or System Preferences with terminal commands

### Basic Spoofing Process
1. Disable the network interface
2. Change the MAC address
3. Re-enable the network interface

### Example (Linux):
```bash
# Disable interface
sudo ifconfig eth0 down

# Change MAC address
sudo macchanger -m 00:11:22:33:44:55 eth0
# or
sudo ifconfig eth0 hw ether 00:11:22:33:44:55

# Re-enable interface
sudo ifconfig eth0 up
```

### Detection Methods
* Monitor for sudden MAC address changes
* Look for OUI inconsistencies
* Check for duplicate MAC addresses on the network
* Use network access control (NAC) solutions

### Ethical Hacking Applications
* Testing MAC filtering security controls
* Bypassing network access restrictions
* Demonstrating the ineffectiveness of MAC-based security
* Evading detection in certain scenarios