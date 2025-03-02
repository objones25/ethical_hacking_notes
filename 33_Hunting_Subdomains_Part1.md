# Hunting Subdomains Part 1

## Why Subdomain Hunting Is Important

- Essential for web penetration testing and bug bounty hunting
- Expands attack surface beyond the main domain
- May reveal:
  - Development environments (dev.example.com)
  - Test sites (test.example.com)
  - Login forms and authentication portals
  - Additional services that might be vulnerable

## Using Sublister Tool

Sublister is a tool designed for enumerating subdomains of websites using passive online sources.

### Installation
```bash
apt install sublister
```

### Basic Usage
```bash
sublister -d example.com
```

### Example Output
When running against a domain like tesla.com, Sublister:
- Searches through various search engines (Baidu, Yahoo, Google, etc.)
- Returns a list of discovered subdomains
- Can identify interesting targets like:
  - dev.tesla.com
  - staging.tesla.com
  - sso.tesla.com (Single Sign-On)
  - api.tesla.com
  - webmail.tesla.com

### Performance Tips
- Check the help menu for advanced options:
```bash
sublister -h
```
- Use threading to speed up the process:
```bash
sublister -d example.com -t 100
```
- Use verbosity to see results in real-time:
```bash
sublister -d example.com -v
```

## The Value of Subdomain Discovery

- Without subdomain enumeration, you're limited to a single website
- A single domain can have dozens, hundreds, or thousands of subdomains
- Each subdomain represents a potential entry point or vulnerability
- Thorough subdomain enumeration is a critical step in reconnaissance
