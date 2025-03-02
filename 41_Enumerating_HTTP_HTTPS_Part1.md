# Enumerating HTTP/HTTPS Part 1

## Initial Web Service Reconnaissance

Web services (HTTP/HTTPS on ports 80/443) are high-value targets because they:
- Often contain vulnerabilities
- Present a large attack surface
- May reveal sensitive information
- Frequently run outdated software

## Manual Web Enumeration Techniques

### Basic Browsing
1. Navigate to the target using the IP address:
   ```
   http://<target_ip>
   https://<target_ip>
   ```

2. Take note of:
   - Default pages (like Apache default page)
   - Web server software and versions
   - Technologies in use (PHP, ASP.NET, etc.)
   - Organization information

### Default Web Pages

If you encounter a default web page (like Apache's "It works!" page):
- Document as a security finding (indicates poor maintenance)
- Look for version information
- Check for comments in the source code
- Note that this doesn't mean there's nothing to find

### Examining Page Source
1. Right-click on the page and select "View Page Source"
2. Look for:
   - Hidden comments
   - JavaScript includes
   - API endpoints
   - Credentials or keys
   - Developer notes
   - Version information

### Error Pages
Error pages often reveal valuable information:
- Software versions
- File paths
- Server names
- Internal IP addresses
- Technology stack details

Example of information disclosure in a 404 page:
```
Apache/1.3.20 Server at kioptrix.level1 Port 80
```
This reveals:
- Apache version (1.3.20)
- Internal hostname (kioptrix.level1)

## Using Nikto for Web Vulnerability Scanning

Nikto is a comprehensive web server scanner that checks for multiple security issues.

### Basic Nikto Usage
```bash
nikto -h http://<target_ip>
```

### Understanding Nikto Output

Nikto will identify various issues including:
1. **Server information**:
   - Web server version (Apache, Nginx, IIS)
   - Programming language (PHP, ASP.NET)
   - Frameworks in use

2. **Common vulnerabilities**:
   - Missing security headers
   - Default files present
   - Dangerous HTTP methods enabled
   - Known vulnerabilities in detected software

3. **Configuration problems**:
   - Directory listings enabled
   - Backup files accessible
   - Administrative interfaces exposed

### Sample Nikto Findings

```
+ Server: Apache/1.3.20 (Unix) PHP/4.3.7 mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37)
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31)
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1)
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote buffer overflow
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE
```

### Prioritizing Nikto Results

Focus on findings related to:
1. Remote code execution possibilities
2. Buffer overflows
3. Outdated software versions
4. Authentication bypass issues
5. Information disclosure

## Documenting Your Findings

For each discovered issue:
1. Note the affected URL/page
2. Record the specific vulnerability or misconfiguration
3. Take screenshots as evidence
4. Document version numbers
5. Record HTTP responses when relevant

Example documentation format:
```
Target: 192.168.1.10:80
Finding: Information Disclosure
Details: Apache version 1.3.20 revealed in HTTP headers
Evidence: [Screenshot or HTTP response]
Notes: This version is outdated and has known vulnerabilities (CVE-XXXX-YYYY)
```

## Next Steps

After basic enumeration:
1. Research specific vulnerabilities for discovered software versions
2. Look deeper into interesting directories
3. Continue with more advanced enumeration techniques
