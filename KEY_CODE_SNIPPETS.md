# Snippets Chiave - Ottimizzazioni Script 03_data_merger.py

## 1. Estrazione Porte da Greenbone

```python
def extract_ports_from_greenbone_host(self, gb_host: Dict) -> List[Dict]:
    """Extract port information from Greenbone host data"""
    ports = []
    port_dict = {}  # Track ports by (port_num, protocol) to avoid duplicates

    # Extract ports from the ports array (already structured)
    for gb_port in gb_host.get('ports', []):
        port_num = gb_port.get('port')
        protocol = gb_port.get('protocol', 'tcp')

        if port_num and (port_num, protocol) not in port_dict:
            port_entry = {
                'port': port_num,
                'protocol': protocol,
                'state': gb_port.get('state', 'open'),
                'source': 'greenbone'
            }

            # Add service information if available
            if gb_port.get('service'):
                port_entry['service'] = gb_port['service']
            if gb_port.get('product'):
                port_entry['product'] = gb_port['product']
            if gb_port.get('version'):
                port_entry['version'] = gb_port['version']

            ports.append(port_entry)
            port_dict[(port_num, protocol)] = port_entry

    return ports
```

## 2. Merge Intelligente Porte

```python
def find_or_create_port(self, host: Dict, port_num: int, protocol: str) -> Dict:
    """Find existing port or create new one in host's ports array"""
    for port in host.get('ports', []):
        if port['port'] == port_num and port['protocol'] == protocol:
            return port

    # Create new port entry
    new_port = {
        'port': port_num,
        'protocol': protocol,
        'state': 'open',
        'source': 'greenbone'
    }
    host['ports'].append(new_port)
    return new_port

def merge_port_info(self, existing_port: Dict, new_info: Dict) -> None:
    """Merge port information, keeping most detailed data"""
    # Update service info if more detailed
    for key in ['service', 'product', 'version']:
        if key in new_info and new_info[key]:
            if key not in existing_port or not existing_port[key]:
                existing_port[key] = new_info[key]

    # Track multiple sources
    if 'source' in new_info:
        if 'source' not in existing_port:
            existing_port['source'] = 'nmap'
        if isinstance(existing_port['source'], str):
            existing_port['source'] = [existing_port['source']]
        if new_info['source'] not in existing_port['source']:
            existing_port['source'].append(new_info['source'])
```

## 3. Estrazione CVE IDs Migliorata

```python
def extract_cve_ids(self, cve_string: str = None, cve_list: List[str] = None) -> List[str]:
    """Extract CVE IDs from various formats"""
    cves = []

    # Handle list input (already parsed CVE IDs from Greenbone)
    if cve_list:
        cves.extend([cve.upper() for cve in cve_list if cve])

    # Handle string input (extract from text)
    if cve_string:
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        found_cves = re.findall(cve_pattern, cve_string, re.IGNORECASE)
        cves.extend([cve.upper() for cve in found_cves])

    # Return unique CVE IDs, sorted
    return sorted(list(set(cves)))
```

## 4. Logica Merge Principale

```python
# Nel metodo merge_data()

# Start with Nmap data as base
for host in nmap_data.get('hosts', []):
    ip = host['ip']
    merged_hosts[ip] = host.copy()
    merged_hosts[ip]['vulnerabilities'] = host.get('vulnerabilities', [])
    merged_hosts[ip]['source'] = ['nmap']

    # Add source tag to all Nmap ports
    for port in merged_hosts[ip].get('ports', []):
        if 'source' not in port:
            port['source'] = 'nmap'

# Merge Greenbone data
for gb_host in greenbone_data.get('hosts', []):
    ip = gb_host['ip']

    if ip not in merged_hosts:
        # Create new host entry
        merged_hosts[ip] = self.create_minimal_host(ip, source='greenbone')
        merged_hosts[ip]['hostname'] = gb_host.get('hostname')
        merged_hosts[ip]['os'] = gb_host.get('os')
    else:
        # Add Greenbone as source
        if 'greenbone' not in merged_hosts[ip].get('source', []):
            merged_hosts[ip]['source'].append('greenbone')

    # Extract and merge ports from Greenbone
    gb_ports = self.extract_ports_from_greenbone_host(gb_host)
    for gb_port in gb_ports:
        port_num = gb_port['port']
        protocol = gb_port['protocol']

        # Find or create port in merged host
        existing_port = self.find_or_create_port(merged_hosts[ip], port_num, protocol)

        # Merge port information
        self.merge_port_info(existing_port, gb_port)

    # Merge vulnerabilities
    nmap_vulns = merged_hosts[ip].get('vulnerabilities', [])
    gb_vulns = []

    # Add port-specific vulnerabilities
    for port in gb_host.get('ports', []):
        for vuln in port.get('vulnerabilities', []):
            vuln_copy = vuln.copy()
            vuln_copy['port'] = port['port']
            vuln_copy['protocol'] = port['protocol']
            gb_vulns.append(vuln_copy)

    # Add general vulnerabilities
    for vuln in gb_host.get('general_vulnerabilities', []):
        gb_vulns.append(vuln)

    # Merge vulnerability lists
    merged_hosts[ip]['vulnerabilities'] = self.merge_vulnerabilities(nmap_vulns, gb_vulns)
```

## 5. Utilizzo nell'Estrazione CVE durante Merge

```python
# In merge_vulnerabilities()

# Normalize Greenbone vulnerability format
normalized_gb_vuln = {
    'title': gb_vuln.get('nvt_name', 'Unknown'),
    'description': gb_vuln.get('summary', ''),
    'severity': self.normalize_severity(gb_vuln.get('severity', ''), gb_vuln.get('cvss')),
    'cvss': gb_vuln.get('cvss'),
    'cve_ids': self.extract_cve_ids(
        cve_string=gb_vuln.get('cves', ''),      # Da campo CSV "CVEs"
        cve_list=gb_vuln.get('cve_ids', [])      # Da lista già parsata
    ),
    'port': gb_vuln.get('port'),
    'protocol': gb_vuln.get('protocol'),
    'source': ['greenbone'],
    'solution': gb_vuln.get('solution', ''),
    'solution_type': gb_vuln.get('solution_type', ''),
    'raw_data': {
        'greenbone': gb_vuln
    }
}

# Check for duplicates and merge CVEs
for existing_vuln in merged_vulns:
    if self.is_duplicate_vulnerability(existing_vuln, normalized_gb_vuln):
        # Merge CVE IDs
        existing_cves = set(existing_vuln.get('cve_ids', []))
        new_cves = set(normalized_gb_vuln.get('cve_ids', []))
        existing_vuln['cve_ids'] = sorted(list(existing_cves.union(new_cves)))
        # ... resto del merge
```

---

**Fine Snippets**
