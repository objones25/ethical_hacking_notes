# Subnetting, Part 1: Understanding the Basics

## What is Subnetting?

Subnetting is the process of dividing a large network into smaller, more manageable sub-networks. It allows for more efficient use of IP addresses and better network management. Understanding subnetting is crucial for network design, troubleshooting, and security.

## IP Address Fundamentals

### IPv4 Structure
- IPv4 addresses consist of 32 bits divided into 4 octets (8 bits each)
- Each octet is represented as a decimal number from 0-255
- Example: 192.168.1.1

### Binary Representation
Each octet can be broken down into 8 bits with the following values:
| 128 | 64 | 32 | 16 | 8 | 4 | 2 | 1 |
|-----|----|----|----|----|---|---|---|

- If all bits are turned ON (11111111) = 255
- If all bits are turned OFF (00000000) = 0
- Other combinations create numbers in between (e.g., 10000000 = 128)

### Binary to Decimal Conversion Examples

| Binary | Calculation | Decimal |
|--------|-------------|---------|
| 10000000 | 128+0+0+0+0+0+0+0 | 128 |
| 11000000 | 128+64+0+0+0+0+0+0 | 192 |
| 10101010 | 128+0+32+0+8+0+2+0 | 170 |
| 11111111 | 128+64+32+16+8+4+2+1 | 255 |

## Subnet Masks

A subnet mask determines which portion of an IP address refers to the network and which portion refers to hosts.

### Standard Subnet Masks
- Represented with a series of 255s followed by 0s
- Example: 255.255.255.0
- Also represented in CIDR notation (e.g., /24)

### CIDR Notation
- Slash followed by the number of network bits
- /8 = 255.0.0.0
- /16 = 255.255.0.0
- /24 = 255.255.255.0

### Common Subnet Masks

| CIDR | Subnet Mask | Class |
|------|-------------|-------|
| /8 | 255.0.0.0 | Class A |
| /16 | 255.255.0.0 | Class B |
| /24 | 255.255.255.0 | Class C |

## IP Address Classes

### Class A (1.0.0.0 to 126.255.255.255)
- First bit always 0
- Default subnet mask: 255.0.0.0 (/8)
- Private range: 10.0.0.0 to 10.255.255.255
- Supports 16,777,214 hosts per network

### Class B (128.0.0.0 to 191.255.255.255)
- First two bits always 10
- Default subnet mask: 255.255.0.0 (/16)
- Private range: 172.16.0.0 to 172.31.255.255
- Supports 65,534 hosts per network

### Class C (192.0.0.0 to 223.255.255.255)
- First three bits always 110
- Default subnet mask: 255.255.255.0 (/24)
- Private range: 192.168.0.0 to 192.168.255.255
- Supports 254 hosts per network

## Private IP Addresses

Private IP addresses are reserved for internal networks and cannot be routed on the internet.

### Private IP Ranges
- **Class A**: 10.0.0.0 to 10.255.255.255 (10.0.0.0/8)
- **Class B**: 172.16.0.0 to 172.31.255.255 (172.16.0.0/12)
- **Class C**: 192.168.0.0 to 192.168.255.255 (192.168.0.0/16)

### Network Address Translation (NAT)
- NAT allows multiple devices with private IP addresses to share a single public IP address
- This has helped extend the life of IPv4 addressing despite address exhaustion
- Most home and small business networks use private addresses with NAT

## The Slash 24 Network: Most Common Subnet

The /24 network (255.255.255.0) is the most common subnet for home and small business networks:

- Provides 254 usable hosts (2^8 - 2 = 256 - 2 = 254)
- Two addresses are reserved:
  - Network ID (usually .0)
  - Broadcast address (usually .255)
- Example: 192.168.1.0/24
  - Network ID: 192.168.1.0
  - Broadcast: 192.168.1.255
  - Usable range: 192.168.1.1 to 192.168.1.254

## Key Concepts

### Network ID
- The first address in a subnet
- Used to identify the network itself
- Cannot be assigned to a host
- Example: 192.168.1.0 in a /24 network

### Broadcast Address
- The last address in a subnet
- Used to send packets to all hosts on the subnet
- Cannot be assigned to a host
- Example: 192.168.1.255 in a /24 network

### Available Hosts
- The number of usable IP addresses in a subnet
- Calculated as 2^(32-prefix) - 2
- For a /24 network: 2^8 - 2 = 254 hosts

## IPv6 vs IPv4

### IPv4
- 32-bit addresses (4.3 billion total addresses)
- Address exhaustion is a major concern
- Uses NAT to extend address space

### IPv6
- 128-bit addresses (approximately 3.4 × 10^38 addresses)
- Designed to replace IPv4 due to address exhaustion
- Adoption has been slow but ongoing
- Example: 2001:0db8:85a3:0000:0000:8a2e:0370:7334

## Binary Subnet Calculation (Step-by-Step)

Understanding how to calculate network boundaries is fundamental to mastering subnetting. Here's a step-by-step approach:

### 1. Convert IP Address and Subnet Mask to Binary

For IP address 192.168.10.15 with subnet mask 255.255.255.240 (/28):

**IP Address (Decimal):** 192.168.10.15
**IP Address (Binary):** 11000000.10101000.00001010.00001111

**Subnet Mask (Decimal):** 255.255.255.240
**Subnet Mask (Binary):** 11111111.11111111.11111111.11110000

### 2. Identify Network and Host Portions

Looking at the subnet mask in binary:
- 1's represent the network portion
- 0's represent the host portion

**Network portion (1's):** The first 28 bits
**Host portion (0's):** The last 4 bits

### 3. Calculate Network ID

To find the network ID, perform a bitwise AND operation between the IP address and subnet mask:

```
IP Address:  11000000.10101000.00001010.00001111
Subnet Mask: 11111111.11111111.11111111.11110000
Network ID:  11000000.10101000.00001010.00000000
```

Converting back to decimal: **192.168.10.0** (This is the network ID)

### 4. Calculate Broadcast Address

To find the broadcast address, set all host bits to 1:

```
Network ID:      11000000.10101000.00001010.00000000
Host bits set:   00000000.00000000.00000000.00001111
Broadcast:       11000000.10101000.00001010.00001111
```

Converting back to decimal: **192.168.10.15** (This is the broadcast address)

### 5. Determine Host Range

- **First host:** Network ID + 1 = 192.168.10.1
- **Last host:** Broadcast - 1 = 192.168.10.14

## The "Magic Number" Method for Quick Subnetting

The "magic number" method is a quick way to calculate subnet boundaries without binary conversion:

1. Identify the octet where the subnet boundary occurs (where the subnet mask is not 0 or 255)
2. Subtract the subnet mask value in that octet from 256
3. The result is your "magic number" or "subnet increment"
4. Multiples of this number define the subnet boundaries

### Example with 192.168.10.15/28 (255.255.255.240)

1. The interesting octet is the 4th (240)
2. 256 - 240 = 16 (this is your magic number)
3. Subnet boundaries occur at: 0, 16, 32, 48, 64, etc.
4. Therefore, 192.168.10.15 falls in the 0-15 subnet range:
   - Network ID: 192.168.10.0
   - Broadcast: 192.168.10.15
   - Host range: 192.168.10.1 - 192.168.10.14

## Visual Representation of Subnet Boundaries

For a /28 (255.255.255.240) subnet, here's how the last octet boundaries work:

```
     0                   15 16                   31
     |                    | |                    |
    [Network 1: 0-15]     [Network 2: 16-31]
          |                     |
          v                     v
First host: .1           First host: .17
Last host: .14           Last host: .30
Network ID: .0           Network ID: .16
Broadcast: .15           Broadcast: .31
```

## Relationship Between Prefix Length and Network Size

The prefix length directly determines the number of available networks and hosts per network:

- **Number of networks** = 2^(prefix length - default class prefix)
  - For Class C networks: 2^(prefix length - 24)
  - Example: /26 gives 2^(26-24) = 2^2 = 4 networks

- **Number of hosts per network** = 2^(32 - prefix length) - 2
  - Example: /26 gives 2^(32-26) - 2 = 2^6 - 2 = 64 - 2 = 62 hosts

### Prefix Length Quick Reference

| Prefix | Subnet Mask       | Borrowed Bits | Networks (in a /24) | Hosts per Network |
|--------|-------------------|---------------|---------------------|-------------------|
| /24    | 255.255.255.0     | 0             | 1                   | 254               |
| /25    | 255.255.255.128   | 1             | 2                   | 126               |
| /26    | 255.255.255.192   | 2             | 4                   | 62                |
| /27    | 255.255.255.224   | 3             | 8                   | 30                |
| /28    | 255.255.255.240   | 4             | 16                  | 14                |
| /29    | 255.255.255.248   | 5             | 32                  | 6                 |
| /30    | 255.255.255.252   | 6             | 64                  | 2                 |
| /31    | 255.255.255.254   | 7             | 128                 | 0*                |
| /32    | 255.255.255.255   | 8             | 256                 | 1**               |

*RFC 3021 allows /31 networks for point-to-point links with 2 usable addresses
**Used for single host routes

## Practical Subnet Boundary Calculation Examples

### Example 1: Subnet Information for 172.16.45.14/20

1. **Subnet mask in decimal**: 255.255.240.0
2. **Magic number calculation**:
   - Interesting octet: 3rd (240)
   - 256 - 240 = 16 (magic number)
3. **Network boundaries** occur at: 0, 16, 32, 48, etc. in the 3rd octet
4. **Network ID calculation**:
   - Integer division: 45 ÷ 16 = 2 (remainder 13)
   - Lower boundary: 2 × 16 = 32
   - Network ID: 172.16.32.0
5. **Broadcast address**: 172.16.47.255 (Next boundary - 1)
6. **Host range**: 172.16.32.1 - 172.16.47.254
7. **Number of hosts**: 2^(32-20) - 2 = 2^12 - 2 = 4,094 hosts

### Example 2: Subnet Information for 10.55.10.32/23

1. **Subnet mask in decimal**: 255.255.254.0
2. **Magic number calculation**:
   - Interesting octet: 3rd (254)
   - 256 - 254 = 2 (magic number)
3. **Network boundaries** occur at: 0, 2, 4, 6, etc. in the 3rd octet
4. **Network ID calculation**:
   - Integer division: 10 ÷ 2 = 5 (remainder 0)
   - Lower boundary: 5 × 2 = 10
   - Network ID: 10.55.10.0
5. **Broadcast address**: 10.55.11.255 (Next boundary - 1)
6. **Host range**: 10.55.10.1 - 10.55.11.254
7. **Number of hosts**: 2^(32-23) - 2 = 2^9 - 2 = 510 hosts