# Gathering Information with Burp Suite

## Introduction to Burp Suite

Burp Suite is a powerful web application security testing tool that functions as a web proxy, allowing you to intercept and modify traffic between your browser and web applications.

### Installing and Launching Burp Suite
- Available in Kali Linux under Applications
- First launch will prompt for license agreement acceptance
- Use the Community Edition for this course (free version)

## Setting Up Browser Proxy for Burp Suite

### Firefox Configuration
1. Open Firefox and navigate to Settings/Preferences
2. Scroll to the bottom and click on "Settings" under Network Settings
3. Select "Manual proxy configuration"
4. Set HTTP Proxy to 127.0.0.1 and Port to 8080
5. Check "Use this proxy server for all protocols"
6. Click OK

### Installing Burp Suite Certificate
1. While proxy is configured, navigate to http://burp in Firefox
2. Click on "CA Certificate" to download the certificate
3. Go to Firefox Preferences > Privacy & Security
4. Scroll to the bottom to find "View Certificates"
5. Click "Import" and select the downloaded certificate
6. Check both trust options and click "OK"

## Basic Burp Suite Usage for Information Gathering

### Intercepting Web Traffic
1. Start Burp Suite and set up browser proxy
2. Enable Intercept in Burp Suite's Proxy tab
3. Browse to the target website
4. Review the requests intercepted by Burp Suite
5. Click "Forward" to allow requests to continue

### Analyzing Responses
1. Navigate to the Target tab in Burp Suite
2. Review the site map to see all requests made
3. Click on individual requests to see details
4. Examine HTTP headers for information disclosure
5. Look for server versions, technologies, and framework information

### Using Repeater Feature
1. Right-click on an intercepted request
2. Select "Send to Repeater"
3. Modify requests as needed
4. Click "Send" to submit the modified request
5. Analyze the response for valuable information

## Information Gathering Techniques with Burp Suite

### Header Analysis
- Server headers often disclose software versions
- X-Powered-By headers reveal backend technologies
- Custom headers may reveal internal infrastructure details

Example of information disclosure in headers:
```
Server: Apache/1.3.20 (Unix) PHP/4.3.7 mod_ssl/2.8.4 OpenSSL/0.9.6b
X-Powered-By: PHP/7.3.7
```

### Response Content Analysis
- Error messages may reveal file paths and software versions
- Comments in HTML source can contain sensitive information
- Hidden form fields might expose internal parameters
- JavaScript files might contain API endpoints or credentials

### Setting Target Scope
1. Navigate to Target > Scope
2. Add the domain to scope using "Add" button
3. Configure to only show in-scope items
4. Focus your testing on relevant targets

## Advantages Over Regular Browsing

- Ability to intercept and modify requests
- Detailed examination of HTTP headers
- Capability to replay and manipulate requests
- Historical view of all site interactions
- Automatic cataloging of site structure
- Detection of technologies and version information

## Security Considerations

- Information disclosure findings are typically low-severity
- Server name and version disclosure is a common issue
- Version information helps target specific vulnerabilities
- Headers should be analyzed for all tested web applications
- Proxy interception is mostly passive reconnaissance at this stage
