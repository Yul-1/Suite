#!/usr/bin/env python3
"""
Data Merger for Vulnerability Assessment Project
Combines Nmap and Greenbone scan results into unified dataset

Optimized for security, performance, and data integrity
Author: AI Assistant & Security Optimizer
Version: 2.0
"""

import json
import csv
import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from pathlib import Path
import logging

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

class DataMerger:
    def __init__(self, results_dir: str = "output/results"):
        self.results_dir = self._validate_directory(results_dir)
        self.nmap_file = os.path.join(self.results_dir, "nmap_unified.json")
        self.greenbone_file = os.path.join(self.results_dir, "greenbone_unified.json")
        self.output_json = os.path.join(self.results_dir, "master_data.json")
        self.output_csv = os.path.join(self.results_dir, "master_data.csv")

    @staticmethod
    def _validate_directory(dir_path: str) -> str:
        """Validate and sanitize directory path to prevent path traversal attacks"""
        clean_path = os.path.normpath(dir_path)
        if '..' in clean_path or clean_path.startswith('/etc') or clean_path.startswith('/sys'):
            raise ValueError(f"Invalid directory path: {dir_path}")
        return clean_path

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IP address format (IPv4 and IPv6)"""
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){7}[0-9a-fA-F]{0,4}$'

        if re.match(ipv4_pattern, ip):
            octets = [int(x) for x in ip.split('.')]
            return all(0 <= octet <= 255 for octet in octets)
        return bool(re.match(ipv6_pattern, ip))

    def load_data(self) -> Tuple[Optional[Dict], Optional[Dict]]:
        """Load and validate both Nmap and Greenbone data files"""
        logger.info("Loading Nmap and Greenbone data files...")

        nmap_data = self._load_json_file(self.nmap_file, "Nmap")
        greenbone_data = self._load_json_file(self.greenbone_file, "Greenbone")

        if not nmap_data or not greenbone_data:
            return None, None

        self._validate_data_structure(nmap_data, "Nmap")
        self._validate_data_structure(greenbone_data, "Greenbone")

        return nmap_data, greenbone_data

    def _load_json_file(self, filepath: str, source_name: str) -> Optional[Dict]:
        """Load and validate JSON file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            logger.info(f"Loaded {source_name} data: {len(data.get('hosts', []))} hosts")
            return data
        except FileNotFoundError:
            logger.error(f"{source_name} file not found: {filepath}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {source_name} file: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading {source_name} file: {e}")
            return None

    def _validate_data_structure(self, data: Dict, source_name: str) -> None:
        """Validate data structure and IP addresses"""
        if 'hosts' not in data or not isinstance(data['hosts'], list):
            raise ValueError(f"{source_name} data missing 'hosts' array")

        for idx, host in enumerate(data['hosts']):
            if 'ip' not in host:
                logger.warning(f"{source_name} host #{idx} missing IP address")
                continue

            if not self._validate_ip(host['ip']):
                logger.warning(f"{source_name} invalid IP address: {host['ip']}")

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
                'title': nmap_vuln.get('title', nmap_vuln.get('id', nmap_vuln.get('script', 'Unknown'))),
                'description': nmap_vuln.get('description', ''),
                'severity': self.normalize_severity(nmap_vuln.get('severity', ''), nmap_vuln.get('cvss')),
                'cvss': nmap_vuln.get('cvss'),
                'cve_ids': self.extract_cve_ids(
                    cve_string=nmap_vuln.get('cve', ''),
                    cve_list=nmap_vuln.get('cve_ids', [])
                ),
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
                'cve_ids': self.extract_cve_ids(
                    cve_string=gb_vuln.get('cves', ''),
                    cve_list=gb_vuln.get('cve_ids', [])
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

            # Check for duplicates
            is_duplicate = False
            for existing_vuln in merged_vulns:
                if self.is_duplicate_vulnerability(existing_vuln, normalized_gb_vuln):
                    # Merge with existing vulnerability
                    existing_vuln['source'].append('greenbone')
                    existing_vuln['raw_data']['greenbone'] = gb_vuln

                    # Merge CVE IDs
                    existing_cves = set(existing_vuln.get('cve_ids', []))
                    new_cves = set(normalized_gb_vuln.get('cve_ids', []))
                    existing_vuln['cve_ids'] = sorted(list(existing_cves.union(new_cves)))

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

    def create_minimal_host(self, ip: str, source: str = 'greenbone') -> Dict:
        """Create minimal host entry for IPs only found in one source"""
        return {
            'ip': ip,
            'hostname': None,
            'status': 'up',
            'ports': [],
            'vulnerabilities': [],
            'os': None,
            'scripts': [],
            'source': [source]
        }

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

    def merge_data(self) -> Optional[Dict]:
        """
        Main method to merge Nmap and Greenbone data.
        CRITICAL: Ensures ALL IPs from BOTH sources are included in final output.
        """
        logger.info("Starting data merge process...")

        nmap_data, greenbone_data = self.load_data()
        if not nmap_data or not greenbone_data:
            logger.error("Failed to load required data files")
            return None

        merged_hosts: Dict[str, Dict] = {}

        logger.info("Processing Nmap hosts...")
        for host in nmap_data.get('hosts', []):
            ip = host['ip']
            if not self._validate_ip(ip):
                logger.warning(f"Skipping invalid IP from Nmap: {ip}")
                continue

            merged_hosts[ip] = self._deep_copy_host(host)
            merged_hosts[ip]['vulnerabilities'] = list(host.get('vulnerabilities', []))
            merged_hosts[ip]['source'] = ['nmap']

            for port in merged_hosts[ip].get('ports', []):
                if 'source' not in port:
                    port['source'] = 'nmap'

        logger.info(f"Base hosts from Nmap: {len(merged_hosts)}")

        logger.info("Merging Greenbone data...")
        for gb_host in greenbone_data.get('hosts', []):
            ip = gb_host['ip']
            if not self._validate_ip(ip):
                logger.warning(f"Skipping invalid IP from Greenbone: {ip}")
                continue

            if ip not in merged_hosts:
                logger.info(f"New IP from Greenbone (not in Nmap): {ip}")
                merged_hosts[ip] = self.create_minimal_host(ip, source='greenbone')
                merged_hosts[ip]['hostname'] = gb_host.get('hostname')
                merged_hosts[ip]['os'] = gb_host.get('os')
            else:
                if 'greenbone' not in merged_hosts[ip].get('source', []):
                    merged_hosts[ip]['source'].append('greenbone')

                if not merged_hosts[ip].get('hostname') and gb_host.get('hostname'):
                    merged_hosts[ip]['hostname'] = gb_host.get('hostname')

                if not merged_hosts[ip].get('os') and gb_host.get('os'):
                    merged_hosts[ip]['os'] = gb_host.get('os')

            gb_ports = self.extract_ports_from_greenbone_host(gb_host)
            for gb_port in gb_ports:
                existing_port = self.find_or_create_port(
                    merged_hosts[ip],
                    gb_port['port'],
                    gb_port['protocol']
                )
                self.merge_port_info(existing_port, gb_port)

            nmap_vulns = merged_hosts[ip].get('vulnerabilities', [])
            gb_vulns = []

            for port in gb_host.get('ports', []):
                for vuln in port.get('vulnerabilities', []):
                    vuln_copy = vuln.copy()
                    vuln_copy['port'] = port['port']
                    vuln_copy['protocol'] = port['protocol']
                    gb_vulns.append(vuln_copy)

            for vuln in gb_host.get('general_vulnerabilities', []):
                gb_vulns.append(vuln)

            merged_hosts[ip]['vulnerabilities'] = self.merge_vulnerabilities(nmap_vulns, gb_vulns)

        logger.info(f"Total hosts after merge: {len(merged_hosts)}")

        for ip, host in merged_hosts.items():
            host['metrics'] = self.calculate_host_metrics(host)

        nmap_ips = {h['ip'] for h in nmap_data.get('hosts', [])}
        gb_ips = {h['ip'] for h in greenbone_data.get('hosts', [])}
        merged_ips = set(merged_hosts.keys())

        nmap_only = nmap_ips - gb_ips
        gb_only = gb_ips - nmap_ips
        both = nmap_ips & gb_ips

        logger.info(f"IP distribution: Nmap-only={len(nmap_only)}, Greenbone-only={len(gb_only)}, Both={len(both)}")

        if nmap_ips - merged_ips:
            logger.error(f"CRITICAL: Missing Nmap IPs: {nmap_ips - merged_ips}")
        if gb_ips - merged_ips:
            logger.error(f"CRITICAL: Missing Greenbone IPs: {gb_ips - merged_ips}")

        master_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_hosts': len(merged_hosts),
                'nmap_hosts': len([h for h in merged_hosts.values() if 'nmap' in h.get('source', [])]),
                'greenbone_hosts': len([h for h in merged_hosts.values() if 'greenbone' in h.get('source', [])]),
                'both_sources': len([h for h in merged_hosts.values() if len(h.get('source', [])) > 1]),
                'nmap_only_count': len(nmap_only),
                'greenbone_only_count': len(gb_only),
                'version': '2.0'
            },
            'hosts': sorted(merged_hosts.values(), key=lambda h: h['ip'])
        }

        total_vulns = sum(len(h.get('vulnerabilities', [])) for h in merged_hosts.values())
        total_ports = sum(h.get('metrics', {}).get('total_ports', 0) for h in merged_hosts.values())

        master_data['metadata']['total_vulnerabilities'] = total_vulns
        master_data['metadata']['total_ports'] = total_ports

        logger.info(f"Merge complete: {len(merged_hosts)} hosts, {total_vulns} vulns, {total_ports} ports")

        return master_data

    @staticmethod
    def _deep_copy_host(host: Dict) -> Dict:
        """Create deep copy of host data to prevent reference issues"""
        import copy
        return copy.deepcopy(host)

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

    @staticmethod
    def _sanitize_csv_field(value: Any) -> str:
        """Sanitize CSV field to prevent CSV injection attacks"""
        if value is None:
            return ''

        str_value = str(value)

        if str_value and str_value[0] in ['=', '+', '-', '@', '\t', '\r']:
            str_value = "'" + str_value

        str_value = str_value.replace('\n', ' ').replace('\r', ' ')

        return str_value

    def export_csv(self, data: Dict) -> bool:
        """Export merged data to flat CSV format with injection protection"""
        try:
            fieldnames = [
                'IP', 'Hostname', 'Status', 'OS', 'OS_Accuracy',
                'Total_Ports', 'TCP_Ports', 'UDP_Ports',
                'Total_Vulns', 'Critical', 'High', 'Medium', 'Low', 'Info',
                'Unique_CVEs', 'Top_CVE_1', 'Top_CVE_2', 'Top_CVE_3',
                'Services_Count', 'Services_Summary', 'Sources'
            ]

            with open(self.output_csv, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()

                for host in data.get('hosts', []):
                    metrics = host.get('metrics', {})
                    cve_list = metrics.get('cve_list', [])
                    services = metrics.get('services_list', [])

                    row = {
                        'IP': self._sanitize_csv_field(host.get('ip', '')),
                        'Hostname': self._sanitize_csv_field(host.get('hostname', '')),
                        'Status': self._sanitize_csv_field(host.get('status', '')),
                        'OS': self._sanitize_csv_field(host.get('os', {}).get('name', '') if host.get('os') else ''),
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
                        'Services_Summary': self._sanitize_csv_field('; '.join(services[:10])),
                        'Sources': '; '.join(host.get('source', []))
                    }
                    writer.writerow(row)

            file_size_kb = os.path.getsize(self.output_csv) / 1024
            logger.info(f"CSV exported: {self.output_csv} ({file_size_kb:.2f} KB)")
            return True

        except Exception as e:
            logger.error(f"Failed to export CSV: {e}")
            import traceback
            traceback.print_exc()
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