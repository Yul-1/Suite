#!/usr/bin/env python3
"""
Service Analyzer for Vulnerability Assessment Project
Analyzes exposed services, categorizes them, and identifies outdated/EOL services

Author: AI Assistant
Version: 1.0
"""

import json
import csv
import sys
import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Counter
from collections import Counter, defaultdict
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ServiceAnalyzer:
    def __init__(self, results_dir: str = "output/results", analysis_dir: str = "output/analysis"):
        self.results_dir = results_dir
        self.analysis_dir = analysis_dir
        self.master_data_file = os.path.join(results_dir, "master_data.json")

        # Output files
        self.services_summary_file = os.path.join(analysis_dir, "services_summary.json")
        self.services_distribution_file = os.path.join(analysis_dir, "services_distribution.csv")
        self.outdated_services_file = os.path.join(analysis_dir, "outdated_services.csv")

        # Ensure analysis directory exists
        os.makedirs(analysis_dir, exist_ok=True)

        # Service categories mapping
        self.service_categories = {
            'Web': [
                'http', 'https', 'apache', 'nginx', 'iis', 'httpd', 'lighttpd',
                'http-proxy', 'http-alt', 'webcache', 'web', 'www', 'tomcat'
            ],
            'Database': [
                'mysql', 'postgresql', 'mssql', 'mongodb', 'oracle', 'redis',
                'ms-sql-s', 'postgres', 'mariadb', 'cassandra', 'couchdb',
                'influxdb', 'elasticsearch', 'neo4j'
            ],
            'File Share': [
                'smb', 'cifs', 'nfs', 'ftp', 'ftps', 'sftp', 'samba',
                'netbios-ssn', 'microsoft-ds', 'afp', 'tftp'
            ],
            'Remote Access': [
                'ssh', 'rdp', 'telnet', 'vnc', 'rlogin', 'rsh', 'rexec',
                'ms-wbt-server', 'terminal-server', 'vnc-http', 'ssh-2.0'
            ],
            'Email': [
                'smtp', 'pop3', 'imap', 'pop3s', 'imaps', 'smtps',
                'submission', 'esmtp', 'mail'
            ],
            'Directory': [
                'ldap', 'ldaps', 'active-directory', 'kerberos', 'ldap-admin',
                'msrpc', 'rpc', 'portmapper'
            ],
            'Management': [
                'snmp', 'wmi', 'ssh-mgmt', 'http-mgmt', 'https-mgmt',
                'ipmi', 'telnet-mgmt', 'winrm'
            ],
            'DNS': [
                'dns', 'domain', 'mdns', 'llmnr'
            ],
            'Network Services': [
                'dhcp', 'ntp', 'syslog', 'radius', 'tacacs', 'kerberos',
                'netbios-ns', 'netbios-dgm', 'wins'
            ],
            'Monitoring': [
                'nagios', 'zabbix', 'cacti', 'mrtg', 'prtg', 'monitor'
            ],
            'Proxy': [
                'proxy', 'socks', 'squid', 'http-proxy', 'https-proxy'
            ]
        }

        # EOL (End of Life) service versions database
        self.eol_database = {
            'apache': {
                '2.2': {'eol_date': '2017-07-11', 'status': 'EOL'},
                '2.0': {'eol_date': '2013-07-10', 'status': 'EOL'},
                '1.3': {'eol_date': '2010-02-03', 'status': 'EOL'}
            },
            'nginx': {
                '1.0': {'eol_date': '2012-04-11', 'status': 'EOL'},
                '1.1': {'eol_date': '2012-08-07', 'status': 'EOL'},
                '1.2': {'eol_date': '2013-12-17', 'status': 'EOL'}
            },
            'openssh': {
                '5.': {'eol_date': '2014-01-30', 'status': 'EOL'},
                '6.0': {'eol_date': '2015-08-11', 'status': 'EOL'},
                '6.1': {'eol_date': '2015-08-11', 'status': 'EOL'}
            },
            'mysql': {
                '5.0': {'eol_date': '2012-01-09', 'status': 'EOL'},
                '5.1': {'eol_date': '2013-12-31', 'status': 'EOL'},
                '5.5': {'eol_date': '2018-12-31', 'status': 'EOL'},
                '5.6': {'eol_date': '2021-02-05', 'status': 'EOL'}
            },
            'php': {
                '5.': {'eol_date': '2019-01-01', 'status': 'EOL'},
                '7.0': {'eol_date': '2019-01-10', 'status': 'EOL'},
                '7.1': {'eol_date': '2019-12-01', 'status': 'EOL'},
                '7.2': {'eol_date': '2020-11-30', 'status': 'EOL'}
            },
            'microsoft': {
                '2003': {'eol_date': '2015-07-14', 'status': 'EOL'},
                '2008': {'eol_date': '2020-01-14', 'status': 'EOL'},
                '2012': {'eol_date': '2023-10-10', 'status': 'EOL'}
            },
            'iis': {
                '6.0': {'eol_date': '2015-07-14', 'status': 'EOL'},
                '7.0': {'eol_date': '2020-01-14', 'status': 'EOL'}
            }
        }

        # Insecure services (should be flagged regardless of version)
        self.insecure_services = [
            'telnet', 'ftp', 'rlogin', 'rsh', 'rexec', 'tftp',
            'snmp-v1', 'snmp-v2c', 'http-basic-auth'
        ]

    def load_master_data(self) -> Optional[Dict]:
        """Load the master data file"""
        logger.info(f"Loading master data from: {self.master_data_file}")

        try:
            with open(self.master_data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            hosts_count = len(data.get('hosts', []))
            logger.info(f"Loaded master data: {hosts_count} hosts")

            if hosts_count == 0:
                logger.error("No hosts found in master data")
                return None

            return data

        except FileNotFoundError:
            logger.error(f"Master data file not found: {self.master_data_file}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in master data file: {e}")
            return None

    def normalize_service_name(self, service: str, version: str = "") -> str:
        """Normalize service names for better grouping"""
        if not service:
            return "unknown"

        service_lower = service.lower().strip()

        # Common normalizations
        normalizations = {
            'http': 'http',
            'https': 'https',
            'httpd': 'http',
            'apache': 'apache',
            'nginx': 'nginx',
            'iis': 'iis',
            'mysql': 'mysql',
            'mariadb': 'mysql',
            'postgresql': 'postgresql',
            'postgres': 'postgresql',
            'mssql': 'mssql',
            'ms-sql-s': 'mssql',
            'mongodb': 'mongodb',
            'redis': 'redis',
            'ssh': 'ssh',
            'ssh-2.0': 'ssh',
            'openssh': 'ssh',
            'rdp': 'rdp',
            'ms-wbt-server': 'rdp',
            'terminal-server': 'rdp',
            'telnet': 'telnet',
            'ftp': 'ftp',
            'ftps': 'ftp',
            'sftp': 'ftp',
            'smtp': 'smtp',
            'smtps': 'smtp',
            'pop3': 'pop3',
            'pop3s': 'pop3',
            'imap': 'imap',
            'imaps': 'imap',
            'dns': 'dns',
            'domain': 'dns',
            'snmp': 'snmp',
            'ldap': 'ldap',
            'ldaps': 'ldap',
            'smb': 'smb',
            'cifs': 'smb',
            'netbios-ssn': 'smb',
            'microsoft-ds': 'smb'
        }

        # Try exact match first
        if service_lower in normalizations:
            return normalizations[service_lower]

        # Try partial match
        for key, normalized in normalizations.items():
            if key in service_lower:
                return normalized

        return service_lower

    def categorize_service(self, service: str) -> str:
        """Categorize a service into predefined categories"""
        service_lower = service.lower()

        for category, services in self.service_categories.items():
            for service_pattern in services:
                if service_pattern in service_lower:
                    return category

        return 'Other'

    def check_eol_status(self, service: str, version: str) -> Optional[Dict]:
        """Check if service version is End of Life"""
        service_lower = service.lower()
        version_lower = version.lower() if version else ""

        for eol_service, versions in self.eol_database.items():
            if eol_service in service_lower:
                for version_pattern, eol_info in versions.items():
                    if version_pattern in version_lower:
                        return {
                            'service': f"{service} {version}".strip(),
                            'eol_date': eol_info['eol_date'],
                            'status': eol_info['status']
                        }

        return None

    def is_insecure_service(self, service: str, port: int) -> bool:
        """Check if service is inherently insecure"""
        service_lower = service.lower()

        # Check insecure services list
        for insecure_service in self.insecure_services:
            if insecure_service in service_lower:
                return True

        # Check for HTTP on management ports (should be HTTPS)
        if service_lower == 'http' and port in [8080, 8443, 9443, 10443]:
            return True

        # Check for unencrypted database connections
        if service_lower in ['mysql', 'postgresql', 'mssql'] and port in [3306, 5432, 1433]:
            return True

        return False

    def extract_version_info(self, service_info: str) -> tuple:
        """Extract version information from service string"""
        if not service_info:
            return "", ""

        # Common version patterns
        version_patterns = [
            r'(\w+)\s+(\d+\.\d+\.\d+)',  # service 1.2.3
            r'(\w+)\s+(\d+\.\d+)',       # service 1.2
            r'(\w+)/(\d+\.\d+\.\d+)',    # service/1.2.3
            r'(\w+)/(\d+\.\d+)',         # service/1.2
            r'(\w+)-(\d+\.\d+)',         # service-1.2
        ]

        for pattern in version_patterns:
            match = re.search(pattern, service_info, re.IGNORECASE)
            if match:
                return match.group(1), match.group(2)

        # If no version found, return service name only
        service_name = service_info.split()[0] if service_info else "unknown"
        return service_name, ""

    def analyze_services(self, data: Dict) -> Dict:
        """Comprehensive service analysis"""
        logger.info("Starting service analysis...")

        # Data structures for analysis
        service_inventory = defaultdict(lambda: {
            'instances': 0,
            'hosts': set(),
            'versions': Counter(),
            'ports': set(),
            'categories': set()
        })

        category_stats = defaultdict(lambda: {
            'service_count': 0,
            'host_count': set(),
            'port_count': set()
        })

        port_analysis = defaultdict(lambda: {
            'services': set(),
            'hosts': set(),
            'protocols': set()
        })

        outdated_services = []
        insecure_services = []
        non_standard_ports = []

        total_services = 0
        total_open_ports = 0
        hosts_with_services = 0

        # Standard port mappings for detecting non-standard services
        standard_ports = {
            'http': [80, 8080],
            'https': [443, 8443],
            'ssh': [22],
            'ftp': [21],
            'telnet': [23],
            'smtp': [25, 587],
            'dns': [53],
            'pop3': [110],
            'imap': [143],
            'snmp': [161],
            'ldap': [389],
            'mysql': [3306],
            'rdp': [3389],
            'postgresql': [5432],
            'mongodb': [27017]
        }

        # Process each host
        for host in data.get('hosts', []):
            host_ip = host.get('ip', 'Unknown')
            ports = host.get('ports', [])

            if ports:
                hosts_with_services += 1

            # Process each port/service
            for port_info in ports:
                if port_info.get('state') != 'open':
                    continue

                total_open_ports += 1
                port_num = port_info.get('port', 0)
                protocol = port_info.get('protocol', 'tcp')
                service_raw = port_info.get('service', 'unknown')
                version_raw = port_info.get('version', '')

                # Extract service name and version
                service_name, version = self.extract_version_info(f"{service_raw} {version_raw}")
                service_normalized = self.normalize_service_name(service_name, version)

                total_services += 1

                # Update service inventory
                service_key = service_normalized
                service_inventory[service_key]['instances'] += 1
                service_inventory[service_key]['hosts'].add(host_ip)
                service_inventory[service_key]['ports'].add(port_num)

                if version:
                    service_inventory[service_key]['versions'][version] += 1

                # Categorize service
                category = self.categorize_service(service_normalized)
                service_inventory[service_key]['categories'].add(category)

                # Update category stats
                category_stats[category]['service_count'] += 1
                category_stats[category]['host_count'].add(host_ip)
                category_stats[category]['port_count'].add(port_num)

                # Update port analysis
                port_analysis[port_num]['services'].add(service_normalized)
                port_analysis[port_num]['hosts'].add(host_ip)
                port_analysis[port_num]['protocols'].add(protocol)

                # Check for EOL status
                eol_info = self.check_eol_status(service_name, version)
                if eol_info:
                    eol_info.update({
                        'host': host_ip,
                        'port': port_num,
                        'protocol': protocol,
                        'severity': 'HIGH' if eol_info['status'] == 'EOL' else 'MEDIUM'
                    })
                    outdated_services.append(eol_info)

                # Check for insecure services
                if self.is_insecure_service(service_normalized, port_num):
                    insecure_services.append({
                        'host': host_ip,
                        'port': port_num,
                        'protocol': protocol,
                        'service': service_normalized,
                        'version': version,
                        'reason': 'Inherently insecure protocol',
                        'severity': 'HIGH'
                    })

                # Check for non-standard ports
                normalized_service = service_normalized.lower()
                if normalized_service in standard_ports:
                    if port_num not in standard_ports[normalized_service]:
                        non_standard_ports.append({
                            'host': host_ip,
                            'port': port_num,
                            'service': service_normalized,
                            'standard_ports': standard_ports[normalized_service],
                            'risk': 'Potential security through obscurity'
                        })

        # Convert sets to counts and lists for JSON serialization
        service_summary = {}
        for service, info in service_inventory.items():
            service_summary[service] = {
                'instances': info['instances'],
                'unique_hosts': len(info['hosts']),
                'unique_ports': len(info['ports']),
                'common_versions': dict(info['versions'].most_common(10)),
                'categories': list(info['categories']),
                'host_list': sorted(list(info['hosts']))[:20]  # Limit for readability
            }

        category_summary = {}
        for category, info in category_stats.items():
            category_summary[category] = {
                'service_instances': info['service_count'],
                'unique_hosts': len(info['host_count']),
                'unique_ports': len(info['port_count'])
            }

        # Calculate service diversity metrics
        unique_services = len(service_inventory)
        service_distribution = Counter({k: v['instances'] for k, v in service_inventory.items()})
        top_services = service_distribution.most_common(20)

        # Generate analysis results
        analysis_results = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_hosts': len(data.get('hosts', [])),
                'analysis_version': '1.0'
            },
            'summary': {
                'total_services': total_services,
                'unique_services': unique_services,
                'total_open_ports': total_open_ports,
                'hosts_with_services': hosts_with_services,
                'hosts_without_services': len(data.get('hosts', [])) - hosts_with_services,
                'service_diversity_index': round(unique_services / total_services, 3) if total_services > 0 else 0,
                'average_services_per_host': round(total_services / hosts_with_services, 1) if hosts_with_services > 0 else 0
            },
            'by_category': category_summary,
            'service_inventory': service_summary,
            'top_services': top_services,
            'security_issues': {
                'outdated_services': len(outdated_services),
                'insecure_services': len(insecure_services),
                'non_standard_ports': len(non_standard_ports)
            },
            'outdated_details': outdated_services[:50],  # Limit for file size
            'insecure_details': insecure_services[:50],
            'non_standard_details': non_standard_ports[:50]
        }

        logger.info(f"Service analysis complete: {unique_services} unique services, {total_services} total instances")

        return analysis_results

    def export_services_summary(self, analysis: Dict) -> bool:
        """Export service summary to JSON"""
        try:
            with open(self.services_summary_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)

            file_size = os.path.getsize(self.services_summary_file) / 1024  # KB
            logger.info(f"Service summary exported: {self.services_summary_file} ({file_size:.1f} KB)")
            return True

        except Exception as e:
            logger.error(f"Failed to export service summary: {e}")
            return False

    def export_services_distribution(self, analysis: Dict) -> bool:
        """Export service distribution to CSV"""
        try:
            fieldnames = [
                'Service', 'Category', 'Instances', 'Unique_Hosts',
                'Unique_Ports', 'Top_Version', 'Host_Percentage'
            ]

            total_hosts = analysis['metadata']['total_hosts']

            with open(self.services_distribution_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for service, info in analysis['service_inventory'].items():
                    # Get most common version
                    top_version = max(info['common_versions'].items(), key=lambda x: x[1])[0] if info['common_versions'] else 'Unknown'

                    # Calculate category
                    category = info['categories'][0] if info['categories'] else 'Other'

                    row = {
                        'Service': service,
                        'Category': category,
                        'Instances': info['instances'],
                        'Unique_Hosts': info['unique_hosts'],
                        'Unique_Ports': info['unique_ports'],
                        'Top_Version': top_version,
                        'Host_Percentage': round((info['unique_hosts'] / total_hosts) * 100, 1) if total_hosts > 0 else 0
                    }
                    writer.writerow(row)

            logger.info(f"Service distribution exported: {self.services_distribution_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to export service distribution: {e}")
            return False

    def export_outdated_services(self, analysis: Dict) -> bool:
        """Export outdated services to CSV"""
        try:
            fieldnames = [
                'Host', 'Port', 'Protocol', 'Service', 'EOL_Date',
                'Status', 'Severity', 'Age_Years'
            ]

            current_year = datetime.now().year

            with open(self.outdated_services_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                # Combine outdated and insecure services
                all_issues = []

                # Add outdated services
                for service in analysis['outdated_details']:
                    try:
                        eol_year = int(service['eol_date'].split('-')[0])
                        age_years = current_year - eol_year
                    except:
                        age_years = 'Unknown'

                    all_issues.append({
                        'Host': service['host'],
                        'Port': service['port'],
                        'Protocol': service['protocol'],
                        'Service': service['service'],
                        'EOL_Date': service['eol_date'],
                        'Status': service['status'],
                        'Severity': service['severity'],
                        'Age_Years': age_years
                    })

                # Add insecure services
                for service in analysis['insecure_details']:
                    all_issues.append({
                        'Host': service['host'],
                        'Port': service['port'],
                        'Protocol': service['protocol'],
                        'Service': f"{service['service']} {service['version']}".strip(),
                        'EOL_Date': 'N/A',
                        'Status': 'INSECURE',
                        'Severity': service['severity'],
                        'Age_Years': 'N/A'
                    })

                # Sort by severity and host
                all_issues.sort(key=lambda x: (x['Severity'], x['Host']))

                for issue in all_issues:
                    writer.writerow(issue)

            logger.info(f"Outdated services exported: {self.outdated_services_file} ({len(all_issues)} issues)")
            return True

        except Exception as e:
            logger.error(f"Failed to export outdated services: {e}")
            return False

    def run(self) -> bool:
        """Run the complete service analysis process"""
        print("=" * 60)
        print("Service Analyzer - Vulnerability Assessment Project")
        print("=" * 60)

        # Load master data
        data = self.load_master_data()
        if not data:
            return False

        # Analyze services
        analysis = self.analyze_services(data)
        if not analysis:
            logger.error("Service analysis failed")
            return False

        # Export results
        summary_success = self.export_services_summary(analysis)
        dist_success = self.export_services_distribution(analysis)
        outdated_success = self.export_outdated_services(analysis)

        if all([summary_success, dist_success, outdated_success]):
            print("\n" + "=" * 60)
            print("SERVICE ANALYSIS COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"Total service instances: {analysis['summary']['total_services']}")
            print(f"Unique services: {analysis['summary']['unique_services']}")
            print(f"Hosts with services: {analysis['summary']['hosts_with_services']}")
            print(f"Average services per host: {analysis['summary']['average_services_per_host']}")
            print()
            print("Service Categories:")
            for category, info in analysis['by_category'].items():
                print(f"  {category}: {info['service_instances']} instances on {info['unique_hosts']} hosts")

            print()
            print("Top 10 Services:")
            for i, (service, count) in enumerate(analysis['top_services'][:10]):
                hosts = analysis['service_inventory'][service]['unique_hosts']
                print(f"{i+1:2d}. {service:20s} | {count:3d} instances | {hosts:3d} hosts")

            print()
            print("Security Issues:")
            print(f"  Outdated services: {analysis['security_issues']['outdated_services']}")
            print(f"  Insecure services: {analysis['security_issues']['insecure_services']}")
            print(f"  Non-standard ports: {analysis['security_issues']['non_standard_ports']}")

            print()
            print("Files generated:")
            print(f"  - Service summary: {self.services_summary_file}")
            print(f"  - Service distribution: {self.services_distribution_file}")
            print(f"  - Outdated services: {self.outdated_services_file}")

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

    if len(sys.argv) > 2:
        analysis_dir = sys.argv[2]
    else:
        analysis_dir = "output/analysis"

    analyzer = ServiceAnalyzer(results_dir, analysis_dir)
    success = analyzer.run()

    if success:
        print("\n✅ Service analysis completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Service analysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()