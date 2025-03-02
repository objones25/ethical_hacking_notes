# Capstone Introduction

## Overview
The capstone section introduces practical machine walkthroughs that apply the techniques learned throughout the course. These machines represent real-world scenarios and provide hands-on experience with different vulnerabilities and exploitation methods.

## Key Objectives

- **Apply Knowledge**: Implement techniques learned in previous sections
- **Develop Methodology**: Practice a structured approach to penetration testing
- **Improve Documentation**: Learn to document findings effectively
- **Gain Practical Experience**: Work with real-world vulnerabilities

## Machines Overview

### 1. Blue
- Windows machine vulnerable to MS17-010 (EternalBlue)
- Focuses on SMB exploitation
- Demonstrates the impact of missing security patches

### 2. Academy
- Web application vulnerabilities
- Privilege escalation techniques
- User enumeration and credential attacks

### 3. Dev
- Development environment exploitation
- Misconfiguration vulnerabilities
- Service exploitation and lateral movement

### 4. Butler
- Advanced privilege escalation
- Windows-specific techniques
- Credential harvesting

### 5. Blackpearl
- Complex multi-stage exploitation
- Network service vulnerabilities
- Post-exploitation techniques

## Recommended Approach

1. **Reconnaissance**: Identify IP address and running services
2. **Enumeration**: Gather detailed information about identified services
3. **Vulnerability Analysis**: Research potential vulnerabilities based on enumeration
4. **Exploitation**: Develop and execute exploit strategy
5. **Post-Exploitation**: Gain additional access and extract sensitive information
6. **Documentation**: Record all steps and findings thoroughly

## Tools Used

- Nmap: Network scanning
- Metasploit Framework: Exploitation
- Various enumeration tools (GoBuster, SMBClient, etc.)
- Privilege escalation scripts
- Custom exploits when needed

## Success Metrics

- Gaining initial access to each system
- Obtaining user and root/administrator-level access
- Locating specific "flags" (proof.txt, user.txt, etc.)
- Documenting the complete attack path

## Learning Outcomes

- Developing a systematic approach to penetration testing
- Understanding common vulnerabilities and their exploitation
- Learning to adapt techniques based on target environment
- Building confidence in real-world penetration testing scenarios
