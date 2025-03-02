# Hunting Subdomains Part 2

## Certificate Fingerprinting with crt.sh

Crt.sh is a website that searches Certificate Transparency logs for SSL/TLS certificates.

### Using crt.sh
1. Navigate to https://crt.sh
2. Search for a domain using wildcard: `%.example.com`
3. This searches for certificates that have been registered for the domain and subdomains

### Advantages of crt.sh
- Finds subdomains that automated tools might miss
- Can discover fourth-level domains (e.g., `gridlogic.energy.tesla.com`)
- Provides historical certificate data
- Often finds different results than active scanning tools

## Advanced Subdomain Discovery Tools

### OWASP Amass
- More comprehensive tool for subdomain discovery
- Written in Go language
- Integrates multiple data sources including:
  - Certificate transparency logs
  - Search engines
  - DNS records
  - API integrations
- Installation: https://github.com/OWASP/Amass
- Much more thorough but takes longer to run

### Other Valuable Tools

- **HTTProbe** (by Tom Nom Nom): Verifies which discovered subdomains are actually accessible
  - Takes output from subdomain enumeration tools
  - Probes to see which subdomains are live
  - Filters out dead or inaccessible subdomains

## Methodology for Complete Subdomain Enumeration

For a thorough subdomain discovery process:

1. Run Sublister for initial discovery
2. Check crt.sh for additional subdomains
3. Use Amass for a comprehensive scan
4. Verify live subdomains with HTTProbe
5. Document all findings for further testing

## Important Considerations

- Not all discovered subdomains will be accessible
- Some subdomains may appear in search results but no longer exist
- Testing methodology should sort active from inactive targets
- Fourth-level domains (and beyond) can be valuable targets
- Different tools will yield different results - use multiple approaches
