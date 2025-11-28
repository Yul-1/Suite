# Vulnerability Assessment Suite - Technical Details

Documentazione tecnica completa: architettura, algoritmi, strutture dati e dettagli implementativi.

---

## Indice

1. [Architettura Generale](#1-architettura-generale)
2. [Data Collection Scripts (Phase 1)](#2-data-collection-scripts-phase-1)
3. [Data Analysis Scripts (Phase 2)](#3-data-analysis-scripts-phase-2)
4. [Data Structures & Formats](#4-data-structures--formats)
5. [Algoritmi e Logica](#5-algoritmi-e-logica)
6. [Data Dependencies](#6-data-dependencies)
7. [Error Handling](#7-error-handling)
8. [Performance & Scalability](#8-performance--scalability)
9. [Extensibility](#9-extensibility)
10. [Security Considerations](#10-security-considerations)
11. [Implementation Examples](#11-implementation-examples)
12. [Version History](#12-version-history)

---

## 1. Architettura Generale

### 1.1 Overview del Sistema

```
┌──────────────────────────────────────────────────────────────────┐
│                     INPUT: ip_lists.txt                          │
│                  (IP addresses to scan)                          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
                    ┌─────────────────┐
                    │   SCANNING      │ (Manual Phase)
                    │   - Nmap        │ → XML files
                    │   - Greenbone   │ → CSV files
                    └─────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                  PHASE 1: DATA COLLECTION                        │
│                                                                  │
│  ┌──────────────────────┐        ┌───────────────────────┐      │
│  │  01_nmap_unifier     │        │  02_greenbone_unifier │      │
│  │  XML → JSON          │        │  CSV → JSON           │      │
│  │  - Host detection    │        │  - Vulnerability data │      │
│  │  - Port scanning     │        │  - CVSS scores        │      │
│  │  - Service detection │        │  - CVE references     │      │
│  └──────────┬───────────┘        └───────────┬───────────┘      │
│             │                                │                  │
│             └────────────┬───────────────────┘                  │
│                          ↓                                      │
│              ┌───────────────────────┐                          │
│              │  03_data_merger       │                          │
│              │  Merge by IP address  │                          │
│              │  → master_data.json   │                          │
│              └───────────────────────┘                          │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                  PHASE 2: DATA ANALYSIS                          │
│                                                                  │
│  Step 2.1: Vulnerability Analyzer                               │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  04_vuln_analyzer.py                                       │ │
│  │  - Severity breakdown (Critical/High/Medium/Low)           │ │
│  │  - CVE distribution                                        │ │
│  │  - Top vulnerabilities by CVSS                             │ │
│  │  → vuln_stats.json, cve_distribution.csv, top_cves.csv    │ │
│  └────────────────────────────────────────────────────────────┘ │
│                          ↓                                      │
│  Step 2.2: Data Transformer                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  12_data_transformer.py                                    │ │
│  │  - Transform master_data.json + vuln_stats.json → CSV     │ │
│  │  → hosts.csv, vulnerabilities.csv, findings.csv,          │ │
│  │    services.csv, config.json                              │ │
│  └────────────────────────────────────────────────────────────┘ │
│                          ↓                                      │
│  Step 2.3-2.5: Service & Risk Analysis                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  05_service_analyzer.py                                    │ │
│  │  - Service/port/OS distribution (13 CSVs)                  │ │
│  │  → service_analysis.json                                   │ │
│  │                                                            │ │
│  │  06_surface_mapper.py                                      │ │
│  │  - Attack surface mapping per subnet                       │ │
│  │  → surface_mapping.json                                    │ │
│  │                                                            │ │
│  │  07_risk_scorer.py                                         │ │
│  │  - Risk score = CVSS + exposure factor                     │ │
│  │  → risk_scoring.json, top_high_risk_hosts.csv             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                          ↓                                      │
│  Step 2.6-2.9: Aggregation & Reporting                          │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  08_extract_services.py → services_export.csv              │ │
│  │  09_data_aggregator.py → aggregate CSVs for charts        │ │
│  │  10_chart_generator.py → PNG charts (300 DPI)             │ │
│  │  11_cleanup.py → validation + report_summary.txt          │ │
│  └────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
                              ↓
┌──────────────────────────────────────────────────────────────────┐
│                OUTPUT: output/report/                            │
│  - master_data.json (copy)                                       │
│  - Host_attivi.txt                                               │
│  - services_export.csv                                           │
│  - CSVs/ (13+ analysis CSV files)                               │
│  - charts/ (5+ PNG graphs at 300 DPI)                           │
│  - report_summary.txt                                            │
└──────────────────────────────────────────────────────────────────┘
```

### 1.2 Directory Structure

```
Suite/
├── run_suite.sh                # Orchestration script
├── requirements.txt            # Python dependencies
│
├── input/
│   └── ip_lists.txt           # IP targets (user-provided)
│
├── output/
│   ├── results/               # Unified data
│   │   ├── nmap_unified.json
│   │   ├── greenbone_unified.json
│   │   └── master_data.json   # Main database
│   │
│   ├── data_input/            # Intermediate CSVs
│   │   ├── hosts.csv
│   │   ├── vulnerabilities.csv
│   │   ├── findings.csv
│   │   ├── services.csv
│   │   └── config.json
│   │
│   ├── analysis/              # Analysis JSONs
│   │   ├── vuln_stats.json
│   │   ├── service_analysis.json
│   │   ├── surface_mapping.json
│   │   └── risk_scoring.json
│   │
│   └── report/                # Final report
│       ├── master_data.json
│       ├── Host_attivi.txt
│       ├── services_export.csv
│       ├── report_summary.txt
│       ├── CSVs/              # 13+ statistical CSVs
│       └── charts/            # PNG graphs
│
└── scripts/
    ├── collection/            # Phase 1 (3 scripts)
    │   ├── 01_nmap_unifier.py
    │   ├── 02_greenbone_unifier.py
    │   └── 03_data_merger.py
    │
    └── analysis/              # Phase 2 (9 scripts)
        ├── 04_vuln_analyzer.py
        ├── 05_service_analyzer.py
        ├── 06_surface_mapper.py
        ├── 07_risk_scorer.py
        ├── 08_extract_services.py
        ├── 09_data_aggregator.py
        ├── 10_chart_generator.py
        ├── 11_cleanup.py
        └── 12_data_transformer.py
```

---

## 2. Data Collection Scripts (Phase 1)

### 2.1 Script 01: Nmap Unifier

**File:** `scripts/collection/01_nmap_unifier.py`

**Purpose:** Parse Nmap XML output and convert to standardized JSON format.

**Input:**
- XML files from Nmap scans (`nmap -oX output.xml`)
- Directory containing multiple XML files

**Processing Logic:**

```python
# Core parsing algorithm
import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    hosts = []
    for host_elem in root.findall('host'):
        # Extract host status
        status = host_elem.find('status').get('state')  # up/down

        # Extract IP address
        address = host_elem.find('address[@addrtype="ipv4"]').get('addr')

        # Extract hostname (if available)
        hostname_elem = host_elem.find('.//hostname')
        hostname = hostname_elem.get('name') if hostname_elem else None

        # Extract OS information
        os_match = host_elem.find('.//osmatch')
        os_name = os_match.get('name') if os_match else None
        os_accuracy = os_match.get('accuracy') if os_match else None

        # Extract ports and services
        ports = []
        for port_elem in host_elem.findall('.//port'):
            port_num = port_elem.get('portid')
            protocol = port_elem.get('protocol')

            service = port_elem.find('service')
            if service is not None:
                service_name = service.get('name')
                product = service.get('product', '')
                version = service.get('version', '')
            else:
                service_name = 'unknown'
                product = version = ''

            ports.append({
                'port': int(port_num),
                'protocol': protocol,
                'service': service_name,
                'product': product,
                'version': version,
                'state': port_elem.find('state').get('state')
            })

        hosts.append({
            'ip': address,
            'hostname': hostname,
            'status': status,
            'os': {'name': os_name, 'accuracy': os_accuracy},
            'ports': ports,
            'source': 'nmap'
        })

    return hosts
```

**Output Structure:**
```json
{
  "metadata": {
    "generated_at": "2025-11-06T14:30:00",
    "total_hosts": 380,
    "source": "nmap"
  },
  "hosts": [
    {
      "ip": "192.168.1.10",
      "hostname": "server01.local",
      "status": "up",
      "os": {
        "name": "Linux 5.4",
        "accuracy": "95"
      },
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.2p1",
          "state": "open"
        }
      ],
      "source": "nmap"
    }
  ]
}
```

**Key Implementation Details:**
- Uses `xml.etree.ElementTree` for XML parsing
- Handles missing elements gracefully with `.get()` and conditional checks
- Normalizes port numbers to integers
- Preserves all Nmap metadata (OS accuracy, service versions)

---

### 2.2 Script 02: Greenbone Unifier

**File:** `scripts/collection/02_greenbone_unifier.py`

**Purpose:** Parse Greenbone/OpenVAS CSV export and convert to standardized JSON.

**Input:**
- CSV file exported from Greenbone Web UI
- Expected columns: IP, Host, Port, Port Protocol, CVSS, Severity, Solution Type, NVT Name, Summary, Description, Solution, CVEs, Task Name, Timestamp

**Processing Logic:**

```python
import csv

def parse_greenbone_csv(csv_file):
    vulnerabilities = []

    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)

        for row in reader:
            ip = row.get('IP')
            hostname = row.get('Host', '')
            port = row.get('Port', '0')
            protocol = row.get('Port Protocol', 'tcp')

            # Parse CVSS (может быть пустым или N/A)
            cvss_raw = row.get('CVSS', '0.0')
            try:
                cvss = float(cvss_raw) if cvss_raw not in ['', 'N/A'] else 0.0
            except ValueError:
                cvss = 0.0

            # Normalize severity
            severity = row.get('Severity', 'Unknown')
            # Map: Critical, High, Medium, Low, Info

            # Extract CVEs
            cve_string = row.get('CVEs', '')
            cve_list = [cve.strip() for cve in cve_string.split(',') if cve.strip()]

            vuln = {
                'ip': ip,
                'hostname': hostname if hostname != ip else '',
                'port': int(port) if port.isdigit() else 0,
                'protocol': protocol.lower(),
                'title': row.get('NVT Name', 'Unknown'),
                'severity': severity,
                'cvss': cvss,
                'summary': row.get('Summary', ''),
                'description': row.get('Description', ''),
                'solution': row.get('Solution', ''),
                'solution_type': row.get('Solution Type', ''),
                'cve_ids': cve_list,
                'source': 'greenbone',
                'raw_data': {
                    'greenbone': {
                        'qod': int(row.get('QoD', 70)),  # Quality of Detection
                        'task_name': row.get('Task Name', ''),
                        'timestamp': row.get('Timestamp', '')
                    }
                }
            }

            vulnerabilities.append(vuln)

    # Group by IP
    hosts_dict = {}
    for vuln in vulnerabilities:
        ip = vuln['ip']
        if ip not in hosts_dict:
            hosts_dict[ip] = {
                'ip': ip,
                'hostname': vuln['hostname'],
                'vulnerabilities': [],
                'source': 'greenbone'
            }
        hosts_dict[ip]['vulnerabilities'].append(vuln)

    return list(hosts_dict.values())
```

**Output Structure:**
```json
{
  "metadata": {
    "generated_at": "2025-11-06T14:35:00",
    "total_hosts": 375,
    "total_vulnerabilities": 637,
    "source": "greenbone"
  },
  "hosts": [
    {
      "ip": "192.168.1.10",
      "hostname": "server01.local",
      "vulnerabilities": [
        {
          "title": "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection",
          "severity": "Medium",
          "cvss": 5.3,
          "port": 443,
          "protocol": "tcp",
          "summary": "The remote service supports deprecated TLS versions.",
          "description": "...",
          "solution": "Disable TLSv1.0 and TLSv1.1 support.",
          "cve_ids": ["CVE-2011-3389"],
          "raw_data": {
            "greenbone": {
              "qod": 80,
              "task_name": "Full_Scan_2025"
            }
          }
        }
      ],
      "source": "greenbone"
    }
  ]
}
```

**Key Implementation Details:**
- Uses `csv.DictReader` for robust CSV parsing
- Handles missing/malformed CVSS values (defaults to 0.0)
- Splits CVE IDs by comma
- Groups vulnerabilities by IP address
- Preserves QoD (Quality of Detection) from Greenbone

---

### 2.3 Script 03: Data Merger

**File:** `scripts/collection/03_data_merger.py`

**Purpose:** Merge Nmap and Greenbone data into unified `master_data.json`.

**Merge Logic:**

```python
def merge_hosts(nmap_hosts, greenbone_hosts):
    """
    Merge strategy:
    - Primary key: IP address
    - Nmap provides: ports, services, OS info
    - Greenbone provides: vulnerabilities
    - Enrichment: Cross-reference port info from both sources
    """
    merged = {}

    # Phase 1: Process Nmap hosts
    for nmap_host in nmap_hosts:
        ip = nmap_host['ip']
        merged[ip] = {
            'ip': ip,
            'hostname': nmap_host.get('hostname', ''),
            'os': nmap_host.get('os', {}),
            'status': nmap_host.get('status', 'unknown'),
            'ports': nmap_host.get('ports', []),
            'vulnerabilities': [],
            'sources': ['nmap']
        }

    # Phase 2: Merge Greenbone data
    for gb_host in greenbone_hosts:
        ip = gb_host['ip']

        if ip in merged:
            # Host exists in Nmap data - enrich
            merged[ip]['vulnerabilities'] = gb_host.get('vulnerabilities', [])
            merged[ip]['sources'].append('greenbone')

            # If Nmap didn't have hostname, use Greenbone's
            if not merged[ip]['hostname'] and gb_host.get('hostname'):
                merged[ip]['hostname'] = gb_host['hostname']
        else:
            # Host only in Greenbone - create new entry
            merged[ip] = {
                'ip': ip,
                'hostname': gb_host.get('hostname', ''),
                'os': {},
                'status': 'up',  # Assume up if Greenbone found vulns
                'ports': [],
                'vulnerabilities': gb_host.get('vulnerabilities', []),
                'sources': ['greenbone']
            }

    # Phase 3: Calculate metadata
    metadata = {
        'generated_at': datetime.utcnow().isoformat() + 'Z',
        'total_hosts': len(merged),
        'nmap_hosts': sum(1 for h in merged.values() if 'nmap' in h['sources']),
        'greenbone_hosts': sum(1 for h in merged.values() if 'greenbone' in h['sources']),
        'both_sources': sum(1 for h in merged.values() if len(h['sources']) == 2),
        'total_vulnerabilities': sum(len(h['vulnerabilities']) for h in merged.values()),
        'total_ports': sum(len(h['ports']) for h in merged.values())
    }

    return {
        'metadata': metadata,
        'hosts': merged
    }
```

**Conflict Resolution:**
- **Hostname:** Prefer Nmap, fallback to Greenbone
- **OS:** Only Nmap provides this
- **Ports:** Only Nmap provides this
- **Vulnerabilities:** Only Greenbone provides this

**Output:** `output/results/master_data.json` (complete schema in section 4)

---

## 3. Data Analysis Scripts (Phase 2)

### 3.1 Script 04: Vulnerability Analyzer

**File:** `scripts/analysis/04_vuln_analyzer.py`

**Purpose:** Analyze vulnerability patterns, severity distribution, CVE stats.

**Key Algorithms:**

**A. Severity Breakdown**
```python
def calculate_severity_breakdown(master_data):
    """Count vulnerabilities by severity level"""
    severity_counts = Counter()

    for host in master_data['hosts'].values():
        for vuln in host.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] += 1

    # Normalize keys (Critical, High, Medium, Low, Info, Unknown)
    breakdown = {
        'Critical': severity_counts.get('Critical', 0),
        'High': severity_counts.get('High', 0),
        'Medium': severity_counts.get('Medium', 0),
        'Low': severity_counts.get('Low', 0),
        'Info': severity_counts.get('Info', 0),
        'Unknown': severity_counts.get('Unknown', 0)
    }

    return breakdown
```

**B. Top Vulnerabilities by CVSS**
```python
def get_top_vulns_by_cvss(master_data, top_n=20):
    """Identify highest CVSS vulnerabilities across all hosts"""
    vuln_scores = []

    for host in master_data['hosts'].values():
        for vuln in host.get('vulnerabilities', []):
            vuln_scores.append({
                'title': vuln.get('title'),
                'cvss': vuln.get('cvss', 0.0),
                'severity': vuln.get('severity'),
                'affected_ips': [host['ip']],  # Will aggregate later
                'cve_ids': vuln.get('cve_ids', [])
            })

    # Aggregate by title (same vuln on multiple hosts)
    aggregated = {}
    for vs in vuln_scores:
        title = vs['title']
        if title in aggregated:
            aggregated[title]['count'] += 1
            aggregated[title]['affected_ips'].extend(vs['affected_ips'])
        else:
            aggregated[title] = vs
            aggregated[title]['count'] = 1

    # Sort by CVSS descending
    sorted_vulns = sorted(aggregated.values(), key=lambda x: x['cvss'], reverse=True)

    return sorted_vulns[:top_n]
```

**C. CVE Distribution**
```python
def analyze_cve_distribution(master_data):
    """Extract all CVEs and count occurrences"""
    cve_counter = Counter()

    for host in master_data['hosts'].values():
        for vuln in host.get('vulnerabilities', []):
            for cve in vuln.get('cve_ids', []):
                if cve.startswith('CVE-'):
                    cve_counter[cve] += 1

    # Sort by occurrence
    distribution = [
        {'cve': cve, 'count': count}
        for cve, count in cve_counter.most_common()
    ]

    return distribution
```

**Output Files:**
- `vuln_stats.json` - Complete statistics
- `cve_distribution.csv` - All CVEs with counts
- `top_cves.csv` - Top 50 CVEs by impact

---

### 3.2 Script 12: Data Transformer

**File:** `scripts/analysis/12_data_transformer.py`

**Purpose:** Transform master_data.json and vuln_stats.json into structured CSV files.

**Key Transformations:**

**A. Hosts CSV**
```python
def transform_hosts(master_data):
    """
    Output: hosts.csv
    Columns: ip, hostname, os, status, first_seen, last_seen
    """
    hosts_data = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in master_data['hosts'].values():
        os_info = ''
        if 'os' in host and host['os']:
            if isinstance(host['os'], dict):
                os_info = host['os'].get('name', '')
            elif isinstance(host['os'], str):
                os_info = host['os']

        hosts_data.append([
            host['ip'],
            host.get('hostname', ''),
            os_info,
            host.get('status', 'up'),
            scan_date,
            scan_date
        ])

    return hosts_data
```

**B. Vulnerabilities CSV with Unique IDs**
```python
def transform_vulnerabilities(master_data):
    """
    Output: vulnerabilities.csv
    Columns: vuln_id, name, severity, cvss_score, qod, description, solution, cve_ids

    Generate unique vuln_id (V0001, V0002, ...) for each unique vulnerability name
    """
    vulns_dict = {}
    vuln_counter = 1

    for host in master_data['hosts'].values():
        for vuln in host.get('vulnerabilities', []):
            vuln_name = vuln.get('title', 'Unknown')

            if vuln_name not in vulns_dict:
                vuln_id = f"V{vuln_counter:04d}"
                vuln_counter += 1

                # Extract QoD (Quality of Detection) from raw_data
                qod = 70  # Default
                raw_data = vuln.get('raw_data', {})
                if isinstance(raw_data, dict):
                    if 'greenbone' in raw_data:
                        qod = raw_data['greenbone'].get('qod', 70)

                vulns_dict[vuln_name] = {
                    'vuln_id': vuln_id,
                    'name': vuln_name,
                    'severity': vuln.get('severity', 'Unknown'),
                    'cvss_score': vuln.get('cvss', 0.0),
                    'qod': qod,
                    'description': vuln.get('description', '')[:500],
                    'solution': vuln.get('solution', '')[:500],
                    'cve_ids': '; '.join(vuln.get('cve_ids', []))
                }

    return vulns_dict
```

**C. Findings CSV (IP-Port-Vuln Associations)**
```python
def transform_findings(master_data, vuln_id_map):
    """
    Output: findings.csv
    Columns: ip, port, protocol, vuln_id, first_detected, last_detected, status

    Links: IP + Port + Protocol → Vulnerability ID
    """
    findings_data = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in master_data['hosts'].values():
        ip = host['ip']

        for vuln in host.get('vulnerabilities', []):
            vuln_name = vuln.get('title', 'Unknown')
            vuln_id = vuln_id_map.get(vuln_name, 'V0000')

            port = vuln.get('port', 0)
            protocol = vuln.get('protocol', 'tcp')

            findings_data.append([
                ip,
                port,
                protocol,
                vuln_id,
                scan_date,
                scan_date,
                'active'
            ])

    return findings_data
```

**Output Files:**
- `output/data_input/hosts.csv`
- `output/data_input/vulnerabilities.csv`
- `output/data_input/findings.csv`
- `output/data_input/services.csv`
- `output/data_input/config.json`

---

### 3.3 Script 05: Service Analyzer

**File:** `scripts/analysis/05_service_analyzer.py`

**Purpose:** Analyze services, ports, OS distribution across network.

**Key Analyses:**

**A. Service Distribution**
```python
def analyze_service_distribution(master_data):
    """Count occurrences of each service"""
    service_counter = Counter()

    for host in master_data['hosts'].values():
        for port_info in host.get('ports', []):
            service = port_info.get('service', 'unknown')
            service_counter[service] += 1

    # Sort by count descending
    distribution = [
        {'service': svc, 'count': cnt}
        for svc, cnt in service_counter.most_common()
    ]

    return distribution
```

**B. OS Distribution**
```python
def analyze_os_distribution(master_data):
    """Group hosts by operating system"""
    os_counter = Counter()

    for host in master_data['hosts'].values():
        os_info = host.get('os', {})
        if isinstance(os_info, dict):
            os_name = os_info.get('name', 'Unknown')
        else:
            os_name = str(os_info) if os_info else 'Unknown'

        # Normalize OS names (Linux variants, Windows versions)
        os_family = normalize_os_name(os_name)
        os_counter[os_family] += 1

    return os_counter.most_common()

def normalize_os_name(os_name):
    """Group similar OS versions"""
    os_lower = os_name.lower()

    if 'linux' in os_lower:
        return 'Linux'
    elif 'windows server 2019' in os_lower:
        return 'Windows Server 2019'
    elif 'windows server 2016' in os_lower:
        return 'Windows Server 2016'
    elif 'windows' in os_lower:
        return 'Windows'
    elif 'freebsd' in os_lower:
        return 'FreeBSD'
    else:
        return os_name
```

**C. Port-Service Mapping**
```python
def create_port_service_mapping(master_data):
    """
    Detailed mapping: IP → Port → Service → Product → Version
    For appendix tables
    """
    mappings = []

    for host in master_data['hosts'].values():
        ip = host['ip']

        for port_info in host.get('ports', []):
            mappings.append({
                'ip': ip,
                'hostname': host.get('hostname', ''),
                'port': port_info.get('port'),
                'protocol': port_info.get('protocol'),
                'service': port_info.get('service'),
                'product': port_info.get('product', ''),
                'version': port_info.get('version', ''),
                'state': port_info.get('state', 'open')
            })

    # Sort by IP, then port
    mappings.sort(key=lambda x: (x['ip'], x['port']))

    return mappings
```

**Output:** 13 CSV files including:
- `services_distribution.csv`
- `ports_distribution.csv`
- `os_distribution.csv`
- `detailed_service_port_mapping.csv`
- etc.

---

### 3.4 Script 06: Surface Mapper

**File:** `scripts/analysis/06_surface_mapper.py`

**Purpose:** Map attack surface by analyzing exposed services and hosts.

**Attack Surface Algorithm:**

```python
def calculate_attack_surface(master_data):
    """
    Attack surface score per subnet:
    - Number of exposed hosts
    - Number of critical services (RDP, SMB, SQL)
    - Number of open ports
    - Weighted by service criticality
    """

    CRITICAL_SERVICES = {
        'rdp': 10,       # Remote Desktop (high risk)
        'smb': 9,        # File sharing
        'sql': 8,        # Database
        'mysql': 8,
        'postgresql': 8,
        'telnet': 10,    # Unencrypted remote access
        'ftp': 7,
        'ssh': 5,        # Secure but still exposure
        'http': 4,
        'https': 3
    }

    surface_by_subnet = defaultdict(lambda: {
        'hosts': set(),
        'critical_services': Counter(),
        'total_ports': 0,
        'exposure_score': 0
    })

    for host in master_data['hosts'].values():
        ip = host['ip']
        subnet = get_subnet(ip)  # e.g., 192.168.1.0/24

        surface_by_subnet[subnet]['hosts'].add(ip)

        for port_info in host.get('ports', []):
            service = port_info.get('service', '').lower()

            surface_by_subnet[subnet]['total_ports'] += 1

            if service in CRITICAL_SERVICES:
                surface_by_subnet[subnet]['critical_services'][service] += 1
                surface_by_subnet[subnet]['exposure_score'] += CRITICAL_SERVICES[service]

    # Convert to list format
    results = []
    for subnet, data in surface_by_subnet.items():
        results.append({
            'subnet': subnet,
            'host_count': len(data['hosts']),
            'total_ports': data['total_ports'],
            'critical_services': dict(data['critical_services']),
            'exposure_score': data['exposure_score']
        })

    # Sort by exposure score descending
    results.sort(key=lambda x: x['exposure_score'], reverse=True)

    return results
```

**Output:**
- `surface_mapping.json` - Complete attack surface data
- `entry_points.csv` - Critical exposed services
- `exposure_matrix.csv` - Per-subnet exposure

---

### 3.5 Script 07: Risk Scorer

**File:** `scripts/analysis/07_risk_scorer.py`

**Purpose:** Calculate risk score for each host based on vulnerabilities and exposure.

**Risk Scoring Formula:**

```python
def calculate_host_risk_score(host):
    """
    Risk Score = Vulnerability Score + Exposure Factor

    Vulnerability Score:
      Critical: 10 points each
      High: 7 points each
      Medium: 4 points each
      Low: 1 point each

    Exposure Factor:
      +10 if critical service exposed (RDP, Telnet, SMB)
      +5 if medium risk service (FTP, MySQL)
      +2 if low risk service (HTTP)
      +1 per additional open port
    """

    # Count vulnerabilities by severity
    vuln_counts = Counter()
    for vuln in host.get('vulnerabilities', []):
        severity = vuln.get('severity', 'Unknown')
        vuln_counts[severity] += 1

    # Vulnerability component
    vuln_score = (
        vuln_counts['Critical'] * 10 +
        vuln_counts['High'] * 7 +
        vuln_counts['Medium'] * 4 +
        vuln_counts['Low'] * 1
    )

    # Exposure component
    exposure_score = 0

    CRITICAL_PORTS = {3389, 23, 445, 139}  # RDP, Telnet, SMB
    MEDIUM_PORTS = {21, 3306, 5432, 1433}  # FTP, MySQL, PostgreSQL, MSSQL

    open_ports = set()
    for port_info in host.get('ports', []):
        port_num = port_info.get('port')
        if port_num in CRITICAL_PORTS:
            exposure_score += 10
        elif port_num in MEDIUM_PORTS:
            exposure_score += 5
        elif port_num in {80, 8080, 443}:
            exposure_score += 2

        open_ports.add(port_num)

    # Add 1 point per additional open port
    exposure_score += len(open_ports)

    # Total risk score
    total_risk = vuln_score + exposure_score

    return {
        'ip': host['ip'],
        'hostname': host.get('hostname', ''),
        'vuln_score': vuln_score,
        'exposure_score': exposure_score,
        'total_risk': total_risk,
        'vulnerability_counts': dict(vuln_counts),
        'open_ports_count': len(open_ports)
    }
```

**Risk Classification:**
```python
def classify_risk_level(risk_score):
    """Classify host into risk tiers"""
    if risk_score >= 100:
        return 'CRITICAL'
    elif risk_score >= 50:
        return 'HIGH'
    elif risk_score >= 20:
        return 'MEDIUM'
    else:
        return 'LOW'
```

**Output:**
- `risk_scoring.json` - All hosts with risk scores
- `top_high_risk_hosts.csv` - Top 10 highest risk hosts

---

## 4. Data Structures & Formats

### 4.1 master_data.json - Complete Schema

```json
{
  "metadata": {
    "generated_at": "2025-11-06T14:30:00Z",
    "total_hosts": 382,
    "nmap_hosts": 380,
    "greenbone_hosts": 375,
    "both_sources": 373,
    "total_vulnerabilities": 637,
    "total_ports": 1842
  },
  "hosts": {
    "192.168.1.10": {
      "ip": "192.168.1.10",
      "hostname": "server01.local",
      "os": {
        "name": "Linux 5.4.0-42-generic",
        "accuracy": "95"
      },
      "status": "up",
      "sources": ["nmap", "greenbone"],
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "8.2p1 Ubuntu 4ubuntu0.1",
          "state": "open"
        },
        {
          "port": 443,
          "protocol": "tcp",
          "service": "https",
          "product": "nginx",
          "version": "1.18.0",
          "state": "open"
        }
      ],
      "vulnerabilities": [
        {
          "title": "SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection",
          "severity": "Medium",
          "cvss": 5.3,
          "port": 443,
          "protocol": "tcp",
          "summary": "The remote service supports deprecated TLS versions.",
          "description": "The remote service accepts connections with TLS 1.0 and/or TLS 1.1...",
          "solution": "Enable TLS 1.2+ and disable older versions in the server configuration.",
          "solution_type": "Mitigation",
          "cve_ids": ["CVE-2011-3389"],
          "source": "greenbone",
          "raw_data": {
            "greenbone": {
              "qod": 80,
              "task_name": "Full_Network_Scan",
              "timestamp": "2025-11-06T12:00:00"
            }
          }
        }
      ]
    }
  }
}
```

### 4.2 CSV Format Standards

**All CSV files follow these conventions:**
- **Encoding:** UTF-8
- **Delimiter:** `,` (comma)
- **Newline:** Unix style (`\n`)
- **Header:** Always present as first row
- **Quoting:** Fields with commas/newlines are quoted

**Example: severity_breakdown.csv**
```csv
Severity,Open,Remediated,Total
Critical,3,0,3
High,14,0,14
Medium,262,0,262
Low,205,0,205
```

### 4.3 Intermediate CSV Schemas

**hosts.csv:**
```
ip,hostname,os,status,first_seen,last_seen
192.168.1.10,server01.local,Linux 5.4,up,2025-11-06 14:30:00,2025-11-06 14:30:00
```

**vulnerabilities.csv:**
```
vuln_id,name,severity,cvss_score,qod,description,solution,cve_ids
V0001,SSL/TLS Deprecated Protocol,Medium,5.3,80,"Supports TLS 1.0/1.1","Upgrade to TLS 1.2+",CVE-2011-3389
```

**findings.csv:**
```
ip,port,protocol,vuln_id,first_detected,last_detected,status
192.168.1.10,443,tcp,V0001,2025-11-06 14:30:00,2025-11-06 14:30:00,active
```

**services.csv:**
```
ip,port,protocol,service_name,product,version
192.168.1.10,22,tcp,ssh,OpenSSH,8.2p1
192.168.1.10,443,tcp,https,nginx,1.18.0
```

---

## 5. Algoritmi e Logica

### 5.1 Severity Aggregation

**Algorithm:** Group and count vulnerabilities by severity tier.

**Complexity:** O(n × m) where n = hosts, m = avg vulnerabilities per host

**Implementation:**
```python
from collections import Counter

def aggregate_severity(master_data):
    severity_counter = Counter()

    for host in master_data['hosts'].values():
        for vuln in host['vulnerabilities']:
            severity_counter[vuln['severity']] += 1

    return severity_counter
```

**Performance:**
- Small network (<50 hosts): <0.1s
- Medium (50-500 hosts): 0.1-1s
- Large (>500 hosts): 1-5s

---

### 5.2 CVSS Histogram Generation

**Purpose:** Create distribution buckets for CVSS scores (0-10).

**Buckets:**
- 0.0-1.0: Informational
- 1.1-3.9: Low
- 4.0-6.9: Medium
- 7.0-8.9: High
- 9.0-10.0: Critical

```python
def generate_cvss_histogram(master_data):
    buckets = {
        '0.0-1.0': 0,
        '1.1-3.9': 0,
        '4.0-6.9': 0,
        '7.0-8.9': 0,
        '9.0-10.0': 0
    }

    for host in master_data['hosts'].values():
        for vuln in host['vulnerabilities']:
            cvss = vuln.get('cvss', 0.0)

            if cvss <= 1.0:
                buckets['0.0-1.0'] += 1
            elif cvss <= 3.9:
                buckets['1.1-3.9'] += 1
            elif cvss <= 6.9:
                buckets['4.0-6.9'] += 1
            elif cvss <= 8.9:
                buckets['7.0-8.9'] += 1
            else:
                buckets['9.0-10.0'] += 1

    return buckets
```

---

### 5.3 Deduplication Logic

**Problem:** Same vulnerability may appear on multiple hosts with slight variations.

**Solution:** Deduplicate by vulnerability title (case-insensitive).

```python
def deduplicate_vulnerabilities(all_vulns):
    """
    Group vulnerabilities by normalized title
    Track affected hosts for each unique vulnerability
    """
    unique_vulns = {}

    for vuln in all_vulns:
        # Normalize title (lowercase, strip whitespace)
        title_normalized = vuln['title'].lower().strip()

        if title_normalized in unique_vulns:
            # Vulnerability already seen - add this host
            unique_vulns[title_normalized]['affected_hosts'].append(vuln['ip'])
            unique_vulns[title_normalized]['count'] += 1
        else:
            # New vulnerability
            unique_vulns[title_normalized] = {
                'title': vuln['title'],  # Keep original case
                'severity': vuln['severity'],
                'cvss': vuln['cvss'],
                'cve_ids': vuln.get('cve_ids', []),
                'affected_hosts': [vuln['ip']],
                'count': 1
            }

    return list(unique_vulns.values())
```

---

## 6. Data Dependencies

### 6.1 Dependency Graph (DAG)

```
Nmap XML ──┐
           ├──> 01_nmap_unifier ──┐
           │                       │
Greenbone  │                       ├──> 03_data_merger ──> master_data.json
CSV ───────┼──> 02_greenbone_     │
           │    unifier ───────────┘
           │
           └──> (Independent)

master_data.json ──┬──> 04_vuln_analyzer ──> vuln_stats.json
                   │                           │
                   │                           ├──> 12_data_transformer ──> CSVs (data_input/)
                   │                           │                             │
                   ├──> 05_service_analyzer ───┤                             │
                   ├──> 06_surface_mapper ─────┤                             │
                   ├──> 07_risk_scorer ────────┤                             │
                   │                           │                             │
                   └─────────────────────────> ├──> 09_data_aggregator ──────┘
                                               │         │
                   08_extract_services ────────┘         │
                                                         ├──> 10_chart_generator
                                                         │         │
                                                         └──> 11_cleanup
```

### 6.2 Parallelization Opportunities

**Phase 1 - Collection:**
- `01_nmap_unifier` and `02_greenbone_unifier` can run in parallel
- `03_data_merger` depends on both → sequential

**Phase 2 - Analysis:**
- After `12_data_transformer`, these can run in parallel:
  - `05_service_analyzer`
  - `06_surface_mapper`
  - `07_risk_scorer`
  - `08_extract_services`

**Potential speedup:** 40-60% reduction in Phase 2 time with parallelization.

---

## 7. Error Handling

### 7.1 Common Error Patterns

**File I/O Errors:**
```python
try:
    with open(file_path, 'r') as f:
        data = json.load(f)
except FileNotFoundError:
    logger.error(f"File not found: {file_path}")
    sys.exit(1)
except json.JSONDecodeError as e:
    logger.error(f"Invalid JSON in {file_path}: {e}")
    sys.exit(1)
```

**Missing Keys:**
```python
# BAD: May raise KeyError
hostname = host['hostname']

# GOOD: Safe with default
hostname = host.get('hostname', '')
```

**Type Validation:**
```python
# Ensure CVSS is float
cvss_raw = vuln.get('cvss', 0.0)
try:
    cvss = float(cvss_raw)
except (ValueError, TypeError):
    cvss = 0.0
```

### 7.2 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | File not found / I/O error |
| 2 | Invalid data format |
| 3 | Missing required field |

---

## 8. Performance & Scalability

### 8.1 Performance Metrics

**Test Environment:** Ubuntu 20.04, 16GB RAM, i7 CPU

| Network Size | Hosts | Vulns | master_data.json | Phase 1 Time | Phase 2 Time |
|--------------|-------|-------|------------------|--------------|--------------|
| Small | 10-50 | 50-200 | 500KB-2MB | 5-15s | 10-30s |
| Medium | 50-500 | 200-2000 | 2MB-20MB | 15s-2min | 30s-3min |
| Large | 500-2000 | 2000-10000 | 20MB-100MB | 2-10min | 3-15min |
| Very Large | >2000 | >10000 | >100MB | >10min | >15min |

### 8.2 Memory Consumption

**Bottleneck:** Loading entire `master_data.json` into memory.

**Optimization for large files (>100MB):**

```python
import ijson  # Streaming JSON parser

def process_large_json(file_path):
    """Stream processing for large JSON files"""
    with open(file_path, 'rb') as f:
        # Parse incrementally
        for host in ijson.items(f, 'hosts.item'):
            process_host(host)  # Process one at a time
```

### 8.3 Scalability Recommendations

**For >500 hosts:**
1. Split by subnet before processing
2. Use streaming JSON parsers (ijson)
3. Process in batches
4. Consider multiprocessing for analysis phase

**Example subnet split:**
```bash
# Split master_data.json by subnet
python3 scripts/utils/split_by_subnet.py \
  --input output/results/master_data.json \
  --output output/subnets/

# Process each subnet independently
for subnet in output/subnets/*.json; do
  ./run_suite.sh --skip-collection --master-data="$subnet"
done

# Merge results
python3 scripts/utils/merge_results.py
```

---

## 9. Extensibility

### 9.1 Adding New Scanner Support

**Example: Add Nessus support**

1. Create `scripts/collection/02b_nessus_unifier.py`
2. Implement standard output format:

```python
def parse_nessus_csv(file_path):
    """
    Parse Nessus CSV export
    Must return same structure as greenbone_unifier
    """
    hosts = []

    # Parse Nessus CSV format
    # ...

    # Return standardized format
    return {
        'metadata': {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'total_hosts': len(hosts),
            'source': 'nessus'
        },
        'hosts': hosts
    }
```

3. Update `03_data_merger.py` to include Nessus data

### 9.2 Adding Custom Analysis

**Example: Add compliance checker**

```python
# scripts/analysis/13_compliance_checker.py

def check_compliance(master_data):
    """
    Check network against compliance standards
    (PCI-DSS, HIPAA, etc.)
    """
    issues = []

    for host in master_data['hosts'].values():
        # Check for PCI-DSS requirements
        if has_credit_card_data(host):
            if not check_pci_compliance(host):
                issues.append({
                    'ip': host['ip'],
                    'standard': 'PCI-DSS',
                    'issue': 'Non-compliant TLS version'
                })

    return issues
```

---

## 10. Security Considerations

### 10.1 Data Sensitivity

**Files containing sensitive data:**
- `master_data.json` - Complete network topology
- `Host_attivi.txt` - Active IP addresses
- All CSV files - Service versions, vulnerabilities

**Protection:**
```bash
# Set restrictive permissions
chmod 600 output/results/master_data.json
chmod 700 output/

# Encrypt for storage
gpg --encrypt --recipient admin@company.com output/results/master_data.json

# Secure delete when done
shred -vfz -n 10 output/results/master_data.json
```

### 10.2 Data Sanitization

**Before sharing reports:**
```python
def sanitize_for_sharing(master_data):
    """Remove sensitive fields before sharing"""
    sanitized = copy.deepcopy(master_data)

    for host in sanitized['hosts'].values():
        # Remove actual IPs (replace with generic)
        host['ip'] = f"10.0.0.{hash(host['ip']) % 255}"

        # Remove hostnames
        host['hostname'] = ''

        # Keep vulnerability data but remove identifying info

    return sanitized
```

---

## 11. Implementation Examples

### 11.1 Example: Parsing Nmap Port

**XML Structure:**
```xml
<port protocol="tcp" portid="443">
  <state state="open" reason="syn-ack" reason_ttl="64"/>
  <service name="https" product="nginx" version="1.18.0" method="probed" conf="10">
    <cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
  </service>
</port>
```

**Python Code:**
```python
port_elem = host_elem.find('.//port[@portid="443"]')

port_data = {
    'port': int(port_elem.get('portid')),
    'protocol': port_elem.get('protocol'),
    'state': port_elem.find('state').get('state'),
    'service': port_elem.find('service').get('name'),
    'product': port_elem.find('service').get('product', ''),
    'version': port_elem.find('service').get('version', '')
}
```

### 11.2 Example: Risk Score Calculation

**Input:**
```json
{
  "ip": "192.168.1.10",
  "vulnerabilities": [
    {"severity": "Critical", "cvss": 9.8},
    {"severity": "Critical", "cvss": 9.1},
    {"severity": "High", "cvss": 7.5}
  ],
  "ports": [
    {"port": 3389, "service": "rdp"},
    {"port": 443, "service": "https"}
  ]
}
```

**Calculation:**
```python
# Vulnerability Score
vuln_score = (2 * 10) + (1 * 7) = 27

# Exposure Score
# RDP (3389) = +10 (critical)
# HTTPS (443) = +2 (low risk)
# +2 additional ports = +2
exposure_score = 10 + 2 + 2 = 14

# Total Risk
total_risk = 27 + 14 = 41  → Classified as "MEDIUM"
```

---

## 12. Version History

### v1.0 (2025-11-04)
- Initial release
- 12 scripts (4 collection + 8 analysis)
- master_data.json as central database
- 13+ CSV outputs
- 5 PNG charts

### v1.1 (2025-11-06)
- **BREAKING CHANGE:** Moved `04_data_transformer.py` from collection to analysis phase
  - Now: `scripts/analysis/12_data_transformer.py`
  - Reason: Dependency on `vuln_stats.json` from vuln_analyzer
- Fixed circular dependency between collection and analysis phases
- Updated `run_suite.sh` execution order:
  - Phase 1: Scripts 01-03 (collection)
  - Phase 2: Script 04 (vuln_analyzer) → Script 12 (data_transformer) → Scripts 05-11

### Roadmap (Future)

**v1.2 (Planned):**
- PDF report generation (Task 4.4)
- Parallel execution for analysis scripts
- Web dashboard for results visualization

**v2.0 (Planned):**
- Nessus scanner support
- Qualys scanner support
- Continuous monitoring mode
- Delta reporting (compare scans over time)

---

**For usage instructions, setup, and troubleshooting, see `USER_GUIDE.md`.**
