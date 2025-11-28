#!/usr/bin/env python3
"""
Data Merger for Vulnerability Assessment Project
Combines Nmap and Greenbone scan results into unified dataset

Author: AI Assistant
Version: 1.0
"""

import json
import csv
import sys
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataMerger:
    def __init__(self, results_dir: str = "output/results"):
        self.results_dir = results_dir
        self.nmap_file = os.path.join(results_dir, "nmap_unified.json")
        self.greenbone_file = os.path.join(results_dir, "greenbone_unified.json")
        self.output_json = os.path.join(results_dir, "master_data.json")
        self.output_csv = os.path.join(results_dir, "master_data.csv")

    def load_data(self) -> tuple:
        """Load and validate both Nmap and Greenbone data files"""
        logger.info("Loading Nmap and Greenbone data files...")

        # Load Nmap data
        try:
            with open(self.nmap_file, 'r', encoding='utf-8') as f:
                nmap_data = json.load(f)
            logger.info(f"Loaded Nmap data: {len(nmap_data.get('hosts', []))} hosts")
        except FileNotFoundError:
            logger.error(f"Nmap file not found: {self.nmap_file}")
            return None, None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in Nmap file: {e}")
            return None, None

        # Load Greenbone data
        try:
            with open(self.greenbone_file, 'r', encoding='utf-8') as f:
                greenbone_data = json.load(f)
            logger.info(f"Loaded Greenbone data: {len(greenbone_data.get('hosts', []))} hosts")
        except FileNotFoundError:
            logger.error(f"Greenbone file not found: {self.greenbone_file}")
            return None, None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in Greenbone file: {e}")
            return None, None

        return nmap_data, greenbone_data

    def normalize_severity(self, severity: str, cvss: float = None) -> str:
        """Normalize severity to standard scale: Critical/High/Medium/Low/Info"""
        if not severity:
            severity = ""

        severity_lower = severity.lower().strip()

        # If we have CVSS score, use it for mapping
        if cvss is not None:
            if cvss >= 9.0:
                return "Critical"
            elif cvss >= 7.0:
                return "High"
            elif cvss >= 4.0:
                return "Medium"
            elif cvss >= 0.1:
                return "Low"
            else:
                return "Info"

        # Fallback to text-based mapping
        if severity_lower in ['critical', 'crit']:
            return "Critical"
        elif severity_lower in ['high', 'hi']:
            return "High"
        elif severity_lower in ['medium', 'med', 'moderate']:
            return "Medium"
        elif severity_lower in ['low', 'lo']:
            return "Low"
        elif severity_lower in ['info', 'informational', 'note']:
            return "Info"
        else:
            # Default based on common patterns
            if 'critical' in severity_lower:
                return "Critical"
            elif 'high' in severity_lower:
                return "High"
            elif 'medium' in severity_lower or 'moderate' in severity_lower:
                return "Medium"
            elif 'low' in severity_lower:
                return "Low"
            else:
                return "Info"

    def extract_cve_ids(self, cve_string: str) -> List[str]:
        """Extract CVE IDs from various formats"""
        if not cve_string:
            return []

        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        cves = re.findall(cve_pattern, cve_string, re.IGNORECASE)
        return [cve.upper() for cve in cves]

    def is_duplicate_vulnerability(self, vuln1: Dict, vuln2: Dict) -> bool:
        """Check if two vulnerabilities are duplicates"""
        # Check by CVE ID first
        cves1 = set(vuln1.get('cve_ids', []))
        cves2 = set(vuln2.get('cve_ids', []))

        if cves1 and cves2 and cves1.intersection(cves2):
            return True

        # Check by port and vulnerability name/title similarity
        port1 = vuln1.get('port')
        port2 = vuln2.get('port')

        if port1 == port2:
            name1 = vuln1.get('title', '').lower()
            name2 = vuln2.get('title', '').lower()

            # Simple similarity check
            if name1 and name2 and (name1 in name2 or name2 in name1):
                return True

        return False

    def merge_vulnerabilities(self, nmap_vulns: List[Dict], gb_vulns: List[Dict]) -> List[Dict]:
        """Merge vulnerability lists, handling duplicates"""
        merged_vulns = []

        # Start with all Nmap vulnerabilities
        for nmap_vuln in nmap_vulns:
            # Normalize Nmap vulnerability format
            normalized_vuln = {
                'title': nmap_vuln.get('title', nmap_vuln.get('id', 'Unknown')),
                'description': nmap_vuln.get('description', ''),
                'severity': self.normalize_severity(nmap_vuln.get('severity', ''), nmap_vuln.get('cvss')),
                'cvss': nmap_vuln.get('cvss'),
                'cve_ids': self.extract_cve_ids(nmap_vuln.get('cve', '')),
                'port': nmap_vuln.get('port'),
                'protocol': nmap_vuln.get('protocol'),
                'source': ['nmap'],
                'raw_data': {
                    'nmap': nmap_vuln
                }
            }
            merged_vulns.append(normalized_vuln)

        # Add Greenbone vulnerabilities, checking for duplicates
        for gb_vuln in gb_vulns:
            # Normalize Greenbone vulnerability format
            normalized_gb_vuln = {
                'title': gb_vuln.get('nvt_name', 'Unknown'),
                'description': gb_vuln.get('summary', ''),
                'severity': self.normalize_severity(gb_vuln.get('severity', ''), gb_vuln.get('cvss')),
                'cvss': gb_vuln.get('cvss'),
                'cve_ids': self.extract_cve_ids(gb_vuln.get('cves', '')),
                'port': gb_vuln.get('port'),
                'protocol': gb_vuln.get('protocol'),
                'source': ['greenbone'],
                'solution': gb_vuln.get('solution', ''),
                'solution_type': gb_vuln.get('solution_type', ''),
                'raw_data': {
                    'greenbone': gb_vuln
                }
            }

            # Check for duplicates
            is_duplicate = False
            for existing_vuln in merged_vulns:
                if self.is_duplicate_vulnerability(existing_vuln, normalized_gb_vuln):
                    # Merge with existing vulnerability
                    existing_vuln['source'].append('greenbone')
                    existing_vuln['raw_data']['greenbone'] = gb_vuln

                    # Use higher CVSS score if available
                    if normalized_gb_vuln['cvss'] and (not existing_vuln['cvss'] or normalized_gb_vuln['cvss'] > existing_vuln['cvss']):
                        existing_vuln['cvss'] = normalized_gb_vuln['cvss']
                        existing_vuln['severity'] = normalized_gb_vuln['severity']

                    # Add Greenbone-specific fields if missing
                    if not existing_vuln.get('solution') and normalized_gb_vuln['solution']:
                        existing_vuln['solution'] = normalized_gb_vuln['solution']
                        existing_vuln['solution_type'] = normalized_gb_vuln['solution_type']

                    is_duplicate = True
                    break

            if not is_duplicate:
                merged_vulns.append(normalized_gb_vuln)

        return merged_vulns

    def calculate_host_metrics(self, host: Dict) -> Dict:
        """Calculate aggregate metrics for a host"""
        vulnerabilities = host.get('vulnerabilities', [])
        ports = host.get('ports', [])

        # Count ports by protocol
        tcp_ports = len([p for p in ports if p.get('protocol') == 'tcp' and p.get('state') == 'open'])
        udp_ports = len([p for p in ports if p.get('protocol') == 'udp' and p.get('state') == 'open'])

        # Count vulnerabilities by severity
        severity_counts = {
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }

        cve_list = set()
        services_list = set()

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Info')
            if severity in severity_counts:
                severity_counts[severity] += 1

            # Collect CVE IDs
            for cve in vuln.get('cve_ids', []):
                cve_list.add(cve)

        # Collect services from ports
        for port in ports:
            if port.get('state') == 'open' and port.get('service'):
                services_list.add(port.get('service'))

        metrics = {
            'total_ports': tcp_ports + udp_ports,
            'tcp_ports': tcp_ports,
            'udp_ports': udp_ports,
            'total_vulnerabilities': len(vulnerabilities),
            'critical_vulns': severity_counts['Critical'],
            'high_vulns': severity_counts['High'],
            'medium_vulns': severity_counts['Medium'],
            'low_vulns': severity_counts['Low'],
            'info_vulns': severity_counts['Info'],
            'unique_cves': len(cve_list),
            'cve_list': sorted(list(cve_list)),
            'services_list': sorted(list(services_list)),
            'services_count': len(services_list)
        }

        return metrics

    def create_minimal_host(self, ip: str) -> Dict:
        """Create minimal host entry for IPs only found in one source"""
        return {
            'ip': ip,
            'hostname': None,
            'status': 'up',
            'ports': [],
            'vulnerabilities': [],
            'os': None,
            'scripts': [],
            'source': ['greenbone']  # Assuming it's from Greenbone if not in Nmap
        }

    def merge_data(self) -> Dict:
        """Main method to merge Nmap and Greenbone data"""
        logger.info("Starting data merge process...")

        # Load data
        nmap_data, greenbone_data = self.load_data()
        if not nmap_data or not greenbone_data:
            logger.error("Failed to load required data files")
            return None

        merged_hosts = {}

        # Start with Nmap data as base
        logger.info("Processing Nmap hosts...")
        for host in nmap_data.get('hosts', []):
            ip = host['ip']
            merged_hosts[ip] = host.copy()
            merged_hosts[ip]['vulnerabilities'] = host.get('vulnerabilities', [])
            merged_hosts[ip]['source'] = ['nmap']

        logger.info(f"Base hosts from Nmap: {len(merged_hosts)}")

        # Merge Greenbone data
        logger.info("Merging Greenbone data...")
        for gb_host in greenbone_data.get('hosts', []):
            ip = gb_host['ip']

            if ip not in merged_hosts:
                # Create new host entry
                merged_hosts[ip] = self.create_minimal_host(ip)
                merged_hosts[ip]['hostname'] = gb_host.get('hostname')
            else:
                # Add Greenbone as source
                if 'greenbone' not in merged_hosts[ip].get('source', []):
                    merged_hosts[ip]['source'].append('greenbone')

                # Update hostname if not present
                if not merged_hosts[ip].get('hostname') and gb_host.get('hostname'):
                    merged_hosts[ip]['hostname'] = gb_host.get('hostname')

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

        logger.info(f"Total hosts after merge: {len(merged_hosts)}")

        # Calculate metrics for each host
        logger.info("Calculating host metrics...")
        for ip, host in merged_hosts.items():
            host['metrics'] = self.calculate_host_metrics(host)

        # Create master data structure
        master_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_hosts': len(merged_hosts),
                'nmap_hosts': len([h for h in merged_hosts.values() if 'nmap' in h.get('source', [])]),
                'greenbone_hosts': len([h for h in merged_hosts.values() if 'greenbone' in h.get('source', [])]),
                'both_sources': len([h for h in merged_hosts.values() if len(h.get('source', [])) > 1]),
                'version': '1.0'
            },
            'hosts': list(merged_hosts.values())
        }

        # Calculate aggregate statistics
        total_vulns = sum(len(h.get('vulnerabilities', [])) for h in merged_hosts.values())
        total_ports = sum(h.get('metrics', {}).get('total_ports', 0) for h in merged_hosts.values())

        master_data['metadata']['total_vulnerabilities'] = total_vulns
        master_data['metadata']['total_ports'] = total_ports

        logger.info(f"Merge complete: {len(merged_hosts)} hosts, {total_vulns} vulnerabilities, {total_ports} open ports")

        return master_data

    def export_json(self, data: Dict) -> bool:
        """Export merged data to JSON"""
        try:
            # Create backup if file exists
            if os.path.exists(self.output_json):
                backup_name = f"{self.output_json}.backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                os.rename(self.output_json, backup_name)
                logger.info(f"Created backup: {backup_name}")

            with open(self.output_json, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            # Check file size
            file_size = os.path.getsize(self.output_json) / (1024 * 1024)  # MB
            logger.info(f"JSON exported: {self.output_json} ({file_size:.2f} MB)")
            return True

        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")
            return False

    def export_csv(self, data: Dict) -> bool:
        """Export merged data to flat CSV format"""
        try:
            fieldnames = [
                'IP', 'Hostname', 'Status', 'OS', 'OS_Accuracy',
                'Total_Ports', 'TCP_Ports', 'UDP_Ports',
                'Total_Vulns', 'Critical', 'High', 'Medium', 'Low', 'Info',
                'Unique_CVEs', 'Top_CVE_1', 'Top_CVE_2', 'Top_CVE_3',
                'Services_Count', 'Services_Summary', 'Sources'
            ]

            with open(self.output_csv, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for host in data.get('hosts', []):
                    metrics = host.get('metrics', {})
                    cve_list = metrics.get('cve_list', [])
                    services = metrics.get('services_list', [])

                    row = {
                        'IP': host.get('ip', ''),
                        'Hostname': host.get('hostname', ''),
                        'Status': host.get('status', ''),
                        'OS': host.get('os', {}).get('name', '') if host.get('os') else '',
                        'OS_Accuracy': host.get('os', {}).get('accuracy', '') if host.get('os') else '',
                        'Total_Ports': metrics.get('total_ports', 0),
                        'TCP_Ports': metrics.get('tcp_ports', 0),
                        'UDP_Ports': metrics.get('udp_ports', 0),
                        'Total_Vulns': metrics.get('total_vulnerabilities', 0),
                        'Critical': metrics.get('critical_vulns', 0),
                        'High': metrics.get('high_vulns', 0),
                        'Medium': metrics.get('medium_vulns', 0),
                        'Low': metrics.get('low_vulns', 0),
                        'Info': metrics.get('info_vulns', 0),
                        'Unique_CVEs': metrics.get('unique_cves', 0),
                        'Top_CVE_1': cve_list[0] if len(cve_list) > 0 else '',
                        'Top_CVE_2': cve_list[1] if len(cve_list) > 1 else '',
                        'Top_CVE_3': cve_list[2] if len(cve_list) > 2 else '',
                        'Services_Count': metrics.get('services_count', 0),
                        'Services_Summary': '; '.join(services[:10]),  # Limit to first 10 services
                        'Sources': '; '.join(host.get('source', []))
                    }
                    writer.writerow(row)

            logger.info(f"CSV exported: {self.output_csv}")
            return True

        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            return False

    def run(self) -> bool:
        """Run the complete merge process"""
        print("=" * 60)
        print("Data Merger - Vulnerability Assessment Project")
        print("=" * 60)

        # Merge data
        merged_data = self.merge_data()
        if not merged_data:
            logger.error("Merge process failed")
            return False

        # Export results
        json_success = self.export_json(merged_data)
        csv_success = self.export_csv(merged_data)

        if json_success and csv_success:
            print("\n" + "=" * 60)
            print("MERGE COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"JSON output: {self.output_json}")
            print(f"CSV output: {self.output_csv}")
            print(f"Total hosts: {merged_data['metadata']['total_hosts']}")
            print(f"Total vulnerabilities: {merged_data['metadata']['total_vulnerabilities']}")
            print(f"Total open ports: {merged_data['metadata']['total_ports']}")
            return True
        else:
            logger.error("Export process failed")
            return False

def main():
    """Main function"""
    if len(sys.argv) > 1:
        results_dir = sys.argv[1]
    else:
        results_dir = "output/results" 
        
    merger = DataMerger(results_dir)
    success = merger.run()

    if success:
        print("\n✅ Data merge completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Data merge failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()