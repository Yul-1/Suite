#!/usr/bin/env python3
"""
Data Transformer - Task 4.1
Trasforma master_data.json e analysis/*.json in CSV standardizzati per il report PDF.
"""

import json
import csv
import os
from datetime import datetime
from pathlib import Path

# Paths - Suite structure
BASE_DIR = Path(__file__).parent.parent.parent  # Suite/
RESULTS_DIR = BASE_DIR / "output" / "results"
ANALYSIS_DIR = BASE_DIR / "output" / "analysis"
DATA_INPUT_DIR = BASE_DIR / "output" / "data_input"

def load_json(filepath):
    """Carica file JSON."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_csv(filepath, data, headers):
    """Salva dati in CSV."""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(data)
    print(f"✓ Created: {filepath}")

def transform_hosts(master_data):
    """Trasforma hosts in CSV."""
    hosts_data = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in master_data['hosts']:
        ip = host['ip']
        hostname = host.get('hostname') or ''
        status = host.get('status', 'up')

        # Extract OS info
        os_info = ''
        os_accuracy = ''
        if 'os' in host and host['os']:
            if isinstance(host['os'], dict):
                os_info = host['os'].get('name', '')
                os_accuracy = host['os'].get('accuracy', '')
            elif isinstance(host['os'], str):
                os_info = host['os']

        hosts_data.append([
            ip,
            hostname,
            os_info,
            status,
            scan_date,  # first_seen
            scan_date   # last_seen
        ])

    headers = ['ip', 'hostname', 'os', 'status', 'first_seen', 'last_seen']
    save_csv(DATA_INPUT_DIR / 'hosts.csv', hosts_data, headers)
    return len(hosts_data)

def transform_vulnerabilities(master_data):
    """Trasforma vulnerabilities in CSV con vuln_id unico e QoD."""
    vulns_dict = {}
    vuln_counter = 1

    for host in master_data['hosts']:
        for vuln in host.get('vulnerabilities', []):
            vuln_name = vuln.get('title', 'Unknown')

            # Create unique key based on name
            if vuln_name not in vulns_dict:
                vuln_id = f"V{vuln_counter:04d}"
                vuln_counter += 1

                # Extract QoD from raw_data (default 70%)
                qod = 70
                raw_data = vuln.get('raw_data', {})
                if isinstance(raw_data, dict):
                    if 'greenbone' in raw_data and isinstance(raw_data['greenbone'], dict):
                        qod = raw_data['greenbone'].get('qod', 70)
                    elif 'nmap' in raw_data and isinstance(raw_data['nmap'], dict):
                        # Nmap potrebbe avere QoD in futuro
                        qod = raw_data['nmap'].get('qod', 70)

                vulns_dict[vuln_name] = {
                    'vuln_id': vuln_id,
                    'name': vuln_name,
                    'severity': vuln.get('severity', 'Unknown'),
                    'cvss_score': vuln.get('cvss', 0.0),
                    'qod': qod,
                    'description': vuln.get('description', '')[:500],  # Limit length
                    'solution': vuln.get('solution', '')[:500],
                    'cve_ids': '; '.join(vuln.get('cve_ids', []))
                }

    vulns_data = [
        [v['vuln_id'], v['name'], v['severity'], v['cvss_score'], v['qod'],
         v['description'], v['solution'], v['cve_ids']]
        for v in vulns_dict.values()
    ]

    headers = ['vuln_id', 'name', 'severity', 'cvss_score', 'qod', 'description', 'solution', 'cve_ids']
    save_csv(DATA_INPUT_DIR / 'vulnerabilities.csv', vulns_data, headers)

    # Return mapping for findings
    return {name: data['vuln_id'] for name, data in vulns_dict.items()}

def transform_findings(master_data, vuln_id_map):
    """Trasforma findings (IP-Port-Vuln associations) in CSV."""
    findings_data = []
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for host in master_data['hosts']:
        ip = host['ip']

        for vuln in host.get('vulnerabilities', []):
            vuln_name = vuln.get('title', 'Unknown')
            vuln_id = vuln_id_map.get(vuln_name, 'V0000')

            # Get port info if available
            port = vuln.get('port', 0)
            protocol = vuln.get('protocol', 'tcp')

            findings_data.append([
                ip,
                port,
                protocol,
                vuln_id,
                scan_date,  # first_detected
                scan_date,  # last_detected
                'active'    # status (always active for single scan)
            ])

    headers = ['ip', 'port', 'protocol', 'vuln_id', 'first_detected', 'last_detected', 'status']
    save_csv(DATA_INPUT_DIR / 'findings.csv', findings_data, headers)
    return len(findings_data)

def transform_services(master_data):
    """Trasforma services in CSV."""
    services_data = []

    for host in master_data['hosts']:
        ip = host['ip']

        for port_info in host.get('ports', []):
            port = port_info.get('port', 0)
            protocol = port_info.get('protocol', 'tcp')
            service_name = port_info.get('service', 'unknown')
            product = port_info.get('product', '')
            version = port_info.get('version', '')

            services_data.append([
                ip,
                port,
                protocol,
                service_name,
                product,
                version
            ])

    headers = ['ip', 'port', 'protocol', 'service_name', 'product', 'version']
    save_csv(DATA_INPUT_DIR / 'services.csv', services_data, headers)
    return len(services_data)

def create_config(master_data, vuln_stats):
    """Crea config.json con metadata."""
    config = {
        "organization": "Sample Organization",
        "report_number": "VAXX001",
        "report_date": datetime.now().strftime("%Y-%m-%d"),
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "addresses_owned": master_data['metadata']['total_hosts'],
        "addresses_scanned": master_data['metadata']['total_hosts'],
        "scan_metadata": {
            "nmap_hosts": master_data['metadata']['nmap_hosts'],
            "greenbone_hosts": master_data['metadata']['greenbone_hosts'],
            "total_vulnerabilities": master_data['metadata']['total_vulnerabilities'],
            "total_ports": master_data['metadata']['total_ports']
        },
        "severity_summary": vuln_stats['severity_distribution']['counts']
    }

    config_path = DATA_INPUT_DIR / 'config.json'
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    print(f"✓ Created: {config_path}")

def main():
    """Main execution."""
    print("=" * 60)
    print("DATA TRANSFORMER - Task 4.1")
    print("=" * 60)

    # Create output directory
    DATA_INPUT_DIR.mkdir(exist_ok=True)
    print(f"\n✓ Output directory: {DATA_INPUT_DIR}")

    # Load data
    print("\n[1/5] Loading master_data.json...")
    master_data = load_json(RESULTS_DIR / 'master_data.json')
    print(f"  → {master_data['metadata']['total_hosts']} hosts loaded")

    print("\n[2/5] Loading vuln_stats.json...")
    vuln_stats = load_json(ANALYSIS_DIR / 'vuln_stats.json')
    print(f"  → {vuln_stats['summary']['total_vulnerabilities']} vulnerabilities")

    # Transform data
    print("\n[3/5] Transforming hosts...")
    hosts_count = transform_hosts(master_data)
    print(f"  → {hosts_count} hosts")

    print("\n[4/5] Transforming vulnerabilities...")
    vuln_id_map = transform_vulnerabilities(master_data)
    print(f"  → {len(vuln_id_map)} unique vulnerabilities")

    print("\n[5/5] Transforming findings...")
    findings_count = transform_findings(master_data, vuln_id_map)
    print(f"  → {findings_count} findings")

    print("\n[6/6] Transforming services...")
    services_count = transform_services(master_data)
    print(f"  → {services_count} services")

    print("\n[7/7] Creating config.json...")
    create_config(master_data, vuln_stats)

    # Summary
    print("\n" + "=" * 60)
    print("TRANSFORMATION COMPLETE")
    print("=" * 60)
    print(f"\nOutput files in: {DATA_INPUT_DIR}")
    print(f"  - hosts.csv: {hosts_count} rows")
    print(f"  - vulnerabilities.csv: {len(vuln_id_map)} rows")
    print(f"  - findings.csv: {findings_count} rows")
    print(f"  - services.csv: {services_count} rows")
    print(f"  - config.json: metadata")
    print("\n✓ Ready for Task 4.2 (Data Aggregation)")

if __name__ == '__main__':
    main()
