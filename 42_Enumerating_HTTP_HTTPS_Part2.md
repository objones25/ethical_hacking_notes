# Enumerating HTTP/HTTPS Part 2

## Directory and File Enumeration

Web servers often contain hidden directories and files that may provide valuable information or contain vulnerabilities.

### Using DirBuster for Directory Enumeration

DirBuster is a multi-threaded tool designed to brute force directories and files on web servers.

#### Launching DirBuster
```bash
dirbuster &
```

#### Basic Setup
1. Enter target URL (e.g., `http://192.168.57.134:80/`)
2. Set number of threads (higher = faster but noisier)
3. Select wordlist:
   - Path: `/usr/share/wordlists/dirbuster/`
   - Start with `directory-list-2.3-small.txt` for speed
   - Use medium or large lists for more thorough scanning

#### File Extensions
- Add relevant extensions based on the server type:
  - For Apache: php, txt, html, zip
  - For IIS: asp, aspx, txt, html
  - For general discovery: pdf, doc, docx, xls, xlsx, zip, bak

#### Understanding DirBuster Results
- **Response code 200**: File/directory exists
- **Response code 301/302**: Redirect
- **Response code 403**: Forbidden (but exists)
- **Response code 404**: Not found

#### Exploring DirBuster Findings
- Use the "Results - Tree View" to see the directory structure
- Right-click on entries to open them in browser
- Look for interesting files like:
  - Config files
  - Backup files (.bak, .old)
  - Admin interfaces
  - Test pages
  - Documentation

### Alternative Directory Scanning Tools
- **dirb**: Command-line based directory brute forcer
- **gobuster**: Fast directory/file enumeration tool written in Go

## Using Burp Suite for Web Enumeration

Burp Suite provides deeper insights into web applications beyond basic scanning.

### Configuring Browser Proxy for Burp Suite
1. Set Firefox to use Burp as proxy (127.0.0.1:8080)
2. Visit target website to capture traffic

### Analyzing HTTP Headers with Burp Suite
1. Navigate to the Proxy > HTTP History tab
2. Examine requests and responses
3. Look for informative headers like:
   ```
   Server: Apache/1.3.20 (Unix) PHP/4.3.7 mod_ssl/2.8.4 OpenSSL/0.9.6b
   X-Powered-By: PHP/7.3.7
   ```

### Using Burp Suite Repeater
1. Send interesting requests to Repeater (right-click > Send to Repeater)
2. Modify requests to test behavior
3. Analyze responses for information disclosure

### Target Scope Configuration
1. Go to Target > Scope
2. Add the target domain/IP to scope
3. Filter to show only in-scope items

## Common Web Enumeration Findings

### Usage Statistics and Analytics
- Web analytics tools may expose visitor information
- Usage statistics pages can reveal server information
- Example: Webalizer (often found at `/usage/` or `/stats/`)

### Monitoring Tools
- MRTG (Multi Router Traffic Grapher)
- System monitoring dashboards
- Log viewers

### Documentation and Help Pages
- API documentation
- Installation guides
- Admin manuals

### Testing Pages
- PHP info pages (phpinfo.php)
- Test scripts
- Debug pages

## Documenting Web Enumeration Results

Create comprehensive notes for each discovered item:
1. Note the exact URL path
2. Record response codes
3. Document any version information
4. Save screenshots or response contents
5. Identify potential vulnerabilities or misconfigurations

Example documentation:
```
URL: http://192.168.57.134/usage/
Finding: Webalizer Version 2.01 statistics page
Response: 200 OK
Notes: Shows web server usage statistics, potential information disclosure
```

## Prioritizing Next Steps

After thorough enumeration, prioritize follow-up actions:
1. Research vulnerabilities for discovered software versions
2. Test promising directories for access control issues
3. Check for default credentials on admin interfaces
4. Look for input validation issues on forms
5. Prepare for targeted exploitation based on findings
