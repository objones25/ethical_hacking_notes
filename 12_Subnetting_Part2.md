# Subnetting, Part 2: Advanced Concepts & Practical Application

## Quick Subnetting Method

This quick method allows you to determine subnet information without complex binary calculations.

### Subnet Reference Chart

| CIDR | Subnet Mask | Number of Hosts | Subnet Value |
|------|-------------|-----------------|--------------|
| /24 | 255.255.255.0 | 254 | n/a |
| /25 | 255.255.255.128 | 126 | 128 |
| /26 | 255.255.255.192 | 62 | 64 |
| /27 | 255.255.255.224 | 30 | 32 |
| /28 | 255.255.255.240 | 14 | 16 |
| /29 | 255.255.255.248 | 6 | 8 |
| /30 | 255.255.255.252 | 2 | 4 |
| /23 | 255.255.254.0 | 510 | n/a |
| /22 | 255.255.252.0 | 1022 | n/a |

### Host Calculation Pattern

- For each prefix length decrease, the number of hosts doubles
- Formula: 2^(32-prefix) - 2
- Example: /24 = 2^(32-24) - 2 = 2^8 - 2 = 256 - 2 = 254 hosts

## Working with Networks Smaller than /24

### Slash 28 Network Example
- Address: 192.168.1.0/28
- Subnet mask: 255.255.255.240
- Network ID: 192.168.1.0
- Broadcast: 192.168.1.15
- Usable range: 192.168.1.1 - 192.168.1.14
- Number of hosts: 14

### Slash 28 Network Segmentation
Multiple /28 networks within the same subnet:
- 192.168.1.0/28 (Range: 0-15)
- 192.168.1.16/28 (Range: 16-31)
- 192.168.1.32/28 (Range: 32-47)
- 192.168.1.48/28 (Range: 48-63)
- ...and so on

## Working with Networks Larger than /24

### Slash 23 Network Example
- Address: 192.168.0.0/23
- Subnet mask: 255.255.254.0
- Network ID: 192.168.0.0
- Broadcast: 192.168.1.255
- Usable range: 192.168.0.1 - 192.168.1.254
- Number of hosts: 510
- Spans two full /24 networks

### Slash 22 Network Example
- Address: 192.168.0.0/22
- Subnet mask: 255.255.252.0
- Network ID: 192.168.0.0
- Broadcast: 192.168.3.255
- Usable range: 192.168.0.1 - 192.168.3.254
- Number of hosts: 1022
- Spans four full /24 networks (0, 1, 2, 3)

## Understanding Subnetting Binary Patterns

### Subnet Mask Binary Representation
- Each 255 in the subnet mask = 11111111 in binary
- Partial octets follow this pattern:
  - 128 = 10000000
  - 192 = 11000000
  - 224 = 11100000
  - 240 = 11110000
  - 248 = 11111000
  - 252 = 11111100
  - 254 = 11111110

### Building a Subnet Value Reference

For the fourth octet:
- /24 = 0 (00000000)
- /25 = 128 (10000000)
- /26 = 192 (11000000)
- /27 = 224 (11100000)
- /28 = 240 (11110000)
- /29 = 248 (11111000)
- /30 = 252 (11111100)

For the third octet:
- /16 = 0.0 (00000000.00000000)
- /17 = 128.0 (10000000.00000000)
- /18 = 192.0 (11000000.00000000)
- And so on...

## Real-World Network Design Considerations

### When to Use Different Subnet Sizes

- **/30 or /31**: Point-to-point links between routers (only need 2 hosts)
- **/29 to /27**: Small network segments (server clusters, management networks)
- **/24**: Standard for departmental networks (can accommodate ~250 devices)
- **/23 to /22**: Larger departments or small campus networks
- **/16**: Enterprise-wide networks (65,534 hosts)

### Network Segmentation Benefits

1. **Security**: Isolating sensitive systems on separate subnets
2. **Performance**: Reducing broadcast domains
3. **Management**: Easier to apply policies to specific subnets
4. **Troubleshooting**: Isolating network issues

## Practical Exercises

### Example 1: Analyze Given Network
- Network: 192.168.0.0/22
- Subnet mask: 255.255.252.0
- Host range: 192.168.0.1 - 192.168.3.254
- Number of hosts: 1022
- Spans 4 Class C networks

### Example 2: Analyze Given Network
- Network: 192.168.1.0/26
- Subnet mask: 255.255.255.192
- Host range: 192.168.1.1 - 192.168.1.62
- Number of hosts: 62

### Example 3: Analyze Given Network
- Network: 192.168.1.0/27
- Subnet mask: 255.255.255.224
- Host range: 192.168.1.1 - 192.168.1.30
- Number of hosts: 30

## Penetration Testing Perspective

As a penetration tester, understanding subnetting is crucial for:

1. **Network Reconnaissance**: Identifying the size and scope of target networks
2. **Target Assessment**: Estimating the number of potential targets in a subnet
3. **Scan Planning**: Efficiently scanning large networks by understanding subnet boundaries
4. **Network Segmentation Analysis**: Identifying potential paths between network segments

When given a subnet like 10.1.0.0/16, you should immediately understand this is a large network with approximately 65,534 hosts, which will require a different scanning approach than a /24 network with 254 hosts.

## Resources for Further Practice

- IP Address Calculator: ipaddressguide.com
- Seven Second Subnetting: A faster method for mental subnet calculations
- Create your own subnet cheat sheet with:
  - CIDR notation (/x)
  - Subnet mask (255.x.x.x)
  - Number of hosts (2^(32-x) - 2)
  - Subnet values for different masks
