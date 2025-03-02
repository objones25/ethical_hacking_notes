# Scanning with Nessus - Part 2

## Reviewing Scan Results

After running a Nessus scan, understanding and analyzing the results is crucial:

1. **Scan Results Dashboard**
   - Overview of vulnerabilities by severity
   - Host breakdown
   - Visual representation of findings

2. **Vulnerability Severity Levels**
   - **Critical**: Severe vulnerabilities that should be addressed immediately
   - **High**: Serious vulnerabilities that represent significant risk
   - **Medium**: Moderate risk vulnerabilities
   - **Low**: Minor vulnerabilities with limited risk
   - **Info**: Informational findings, not necessarily vulnerabilities

3. **Navigating Results**
   - Filter by severity, plugin family, or host
   - Search for specific vulnerabilities
   - Group by various criteria (host, plugin, port, etc.)

## Understanding Vulnerability Reports

For each vulnerability, Nessus provides detailed information:

1. **Synopsis**
   - Brief description of the vulnerability

2. **Description**
   - Detailed explanation of the vulnerability
   - How it works and why it's a security concern

3. **Solution**
   - Recommended remediation steps
   - Often includes patch information or configuration changes

4. **Risk Information**
   - CVSS (Common Vulnerability Scoring System) score
   - Risk factors (attack vector, complexity, privileges required, etc.)
   - Underlying CVE (Common Vulnerabilities and Exposures) IDs

5. **Plugin Details**
   - Plugin ID and family
   - Publication date and last update
   - References to security bulletins and advisories

6. **Output**
   - Actual data collected that triggered the finding
   - Evidence of the vulnerability

## Leveraging Nessus Results in Penetration Testing

Integrating Nessus findings into your penetration testing workflow:

1. **Prioritizing Targets**
   - Focus on hosts with critical and high vulnerabilities
   - Look for services with known exploitable conditions

2. **Mapping to Exploits**
   - Use CVE references to find corresponding exploits
   - Search for Metasploit modules that target the vulnerabilities
   - Check Exploit-DB for proof-of-concept code

3. **False Positive Identification**
   - Not all findings are exploitable
   - Verify critical findings manually
   - Consider contextual factors that might mitigate risk

4. **Documentation**
   - Include Nessus findings in your penetration testing notes
   - Document which vulnerabilities were verified/exploited
   - Reference the specific Nessus plugin IDs

## Advanced Nessus Features

Beyond basic scanning, Nessus offers several advanced capabilities:

1. **Credential Management**
   - Windows/SMB authentication
   - SSH credentials
   - Database credentials
   - Web application credentials
   - Helps discover vulnerabilities that require authentication

2. **Compliance Scanning**
   - PCI DSS, HIPAA, CIS benchmarks
   - Custom compliance checks
   - Configuration auditing

3. **Custom Plugins**
   - NASL (Nessus Attack Scripting Language)
   - Create custom vulnerability checks
   - Tailor scans to your environment

4. **Report Generation**
   - Multiple format options (HTML, PDF, CSV, etc.)
   - Customizable report templates
   - Executive summaries and technical details

5. **API Integration**
   - Automate scanning and reporting
   - Integrate with other security tools
   - Build custom workflows

## Common Use Cases for Nessus

1. **Vulnerability Management**
   - Regular scanning of assets
   - Tracking remediation progress
   - Risk assessment

2. **Penetration Testing Support**
   - Initial reconnaissance
   - Vulnerability identification
   - Discovery of attack vectors

3. **Compliance Verification**
   - Assess compliance with security standards
   - Document security controls
   - Identify gaps in compliance

4. **Security Posture Assessment**
   - Baseline security measurements
   - Comparative analysis over time
   - Metrics for security program effectiveness

## Tips for Effective Nessus Usage

1. **Scan Regularly**
   - New vulnerabilities are discovered constantly
   - Regular scanning helps maintain security posture

2. **Update Plugins**
   - Keep plugins current for latest vulnerability coverage
   - Nessus plugin updates occur frequently

3. **Tune Scans for Environment**
   - Adjust scan policy based on network sensitivity
   - Consider business impact of scanning activities

4. **Use Scan Templates Appropriately**
   - Different templates serve different purposes
   - Select based on your specific objectives

5. **Incorporate Manual Verification**
   - Use Nessus as a starting point, not the final word
   - Manually verify critical findings

6. **Contextual Analysis**
   - Consider the business context of vulnerabilities
   - Not all vulnerabilities pose the same risk in every environment

## Limitations of Nessus

Understanding what Nessus can and cannot do:

1. **False Positives**
   - Nessus may report vulnerabilities that don't exist
   - Version detection isn't always 100% accurate

2. **False Negatives**
   - Some vulnerabilities may not be detected
   - Zero-day vulnerabilities won't be included

3. **Network Impact**
   - Intensive scanning can impact network performance
   - Some scans may trigger IDS/IPS alerts

4. **Limited Web Application Testing**
   - While Nessus can perform basic web scanning, dedicated web app scanners are more comprehensive
   - Complex web vulnerabilities often require manual testing

5. **Context Awareness**
   - Lacks understanding of business context
   - May not prioritize based on actual risk to your organization

## Conclusion

Nessus is a powerful tool in the penetration tester's arsenal, providing automated discovery of known vulnerabilities. By understanding how to interpret and leverage Nessus scan results, you can more efficiently identify potential attack vectors and focus your manual testing efforts on the most promising targets.

Remember that while Nessus is excellent at discovering known vulnerabilities, it should be one component of a broader testing methodology that includes manual testing, creative thinking, and understanding of the target environment's context.
