#!/usr/bin/env python3
"""
Attack Surface Mapper for Vulnerability Assessment Project
Maps and analyzes the attack surface, entry points, and exposure matrix

Author: AI Assistant
Version: 1.0
"""

import json
import csv
import sys
import os
import ipaddress
from datetime import datetime
from typing import Dict, List, Any, Optional, Counter
from collections import Counter, defaultdict
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AttackSurfaceMapper:
    def __init__(self, results_dir: str = "output/results", analysis_dir: str = "output/analysis"):
        self.results_dir = results_dir
        self.analysis_dir = analysis_dir
        self.master_data_file = os.path.join(results_dir, "master_data.json")

        # Output files
        self.attack_surface_file = os.path.join(analysis_dir, "attack_surface.json")
        self.entry_points_file = os.path.join(analysis_dir, "entry_points.csv")
        self.exposure_matrix_file = os.path.join(analysis_dir, "exposure_matrix.csv")

        # Ensure analysis directory exists
        os.makedirs(analysis_dir, exist_ok=True)

        # Entry point categories
        self.entry_point_categories = {
            'Web Applications': {
                'ports': [80, 443, 8080, 8443, 8000, 8888, 9000, 9080, 9443],
                'services': ['http', 'https', 'apache', 'nginx', 'iis', 'tomcat'],
                'risk_level': 'HIGH',
                'description': 'Web-based applications and services'
            },
            'Remote Administration': {
                'ports': [22, 3389, 5900, 23, 992, 5901, 5902],
                'services': ['ssh', 'rdp', 'vnc', 'telnet', 'ms-wbt-server'],
                'risk_level': 'CRITICAL',
                'description': 'Remote access and administration services'
            },
            'File Transfer': {
                'ports': [21, 445, 139, 2049, 69, 115],
                'services': ['ftp', 'smb', 'cifs', 'nfs', 'tftp', 'sftp'],
                'risk_level': 'HIGH',
                'description': 'File sharing and transfer protocols'
            },
            'Email Services': {
                'ports': [25, 110, 143, 587, 993, 995, 465],
                'services': ['smtp', 'pop3', 'imap', 'smtps', 'pop3s', 'imaps'],
                'risk_level': 'MEDIUM',
                'description': 'Email communication services'
            },
            'Databases': {
                'ports': [3306, 5432, 1433, 1521, 27017, 6379, 5984],
                'services': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis'],
                'risk_level': 'CRITICAL',
                'description': 'Database management systems'
            },
            'Network Services': {
                'ports': [53, 161, 389, 636, 88, 464],
                'services': ['dns', 'snmp', 'ldap', 'ldaps', 'kerberos'],
                'risk_level': 'MEDIUM',
                'description': 'Core network infrastructure services'
            },
            'Messaging & Communication': {
                'ports': [5060, 5061, 1720, 5222, 5223],
                'services': ['sip', 'sips', 'h323', 'xmpp', 'jabber'],
                'risk_level': 'MEDIUM',
                'description': 'VoIP and messaging protocols'
            },
            'Monitoring & Management': {
                'ports': [161, 162, 623, 9100, 10050],
                'services': ['snmp', 'ipmi', 'jetdirect', 'zabbix'],
                'risk_level': 'LOW',
                'description': 'System monitoring and management'
            }
        }

        # High-value target indicators
        self.high_value_indicators = {
            'database_services': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
            'admin_services': ['ssh', 'rdp', 'vnc', 'telnet'],
            'file_services': ['smb', 'nfs', 'ftp'],
            'web_services': ['http', 'https'],
            'multiple_categories': 3,  # Host with 3+ different service categories
            'high_port_count': 10      # Host with 10+ open ports
        }

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

    def detect_network_segments(self, hosts: List[Dict]) -> Dict:
        """Analyze network segmentation patterns"""
        ip_analysis = defaultdict(lambda: {
            'hosts': [],
            'subnets': set(),
            'ip_ranges': []
        })

        # Group IPs by network patterns
        for host in hosts:
            ip_str = host.get('ip', '')
            if not ip_str:
                continue

            try:
                ip_obj = ipaddress.ip_address(ip_str)

                # Extract /24 subnet
                if ip_obj.version == 4:
                    subnet_24 = str(ipaddress.ip_network(f"{ip_str}/24", strict=False))
                    ip_analysis[subnet_24]['hosts'].append(host)
                    ip_analysis[subnet_24]['subnets'].add(subnet_24)

            except Exception:
                continue

        # Calculate segmentation metrics
        segmentation_analysis = {
            'total_subnets': len(ip_analysis),
            'subnet_distribution': {},
            'largest_segment': None,
            'segment_diversity': {}
        }

        for subnet, info in ip_analysis.items():
            host_count = len(info['hosts'])
            segmentation_analysis['subnet_distribution'][subnet] = host_count

            # Analyze service diversity within segment
            segment_services = set()
            segment_categories = set()

            for host in info['hosts']:
                for port in host.get('ports', []):
                    if port.get('state') == 'open':
                        service = port.get('service', '').lower()
                        segment_services.add(service)

                        # Categorize service
                        for category, config in self.entry_point_categories.items():
                            if (port.get('port') in config['ports'] or
                                any(s in service for s in config['services'])):
                                segment_categories.add(category)

            segmentation_analysis['segment_diversity'][subnet] = {
                'unique_services': len(segment_services),
                'service_categories': len(segment_categories),
                'hosts': host_count
            }

        # Find largest segment
        if segmentation_analysis['subnet_distribution']:
            largest = max(segmentation_analysis['subnet_distribution'].items(), key=lambda x: x[1])
            segmentation_analysis['largest_segment'] = {
                'subnet': largest[0],
                'host_count': largest[1]
            }

        return segmentation_analysis

    def categorize_entry_point(self, port: int, service: str) -> Optional[str]:
        """Categorize a port/service as an entry point"""
        service_lower = service.lower()

        for category, config in self.entry_point_categories.items():
            # Check by port number
            if port in config['ports']:
                return category

            # Check by service name
            for service_pattern in config['services']:
                if service_pattern in service_lower:
                    return category

        return None

    def calculate_centrality_score(self, host: Dict) -> float:
        """Calculate how central/important a host might be for lateral movement"""
        score = 0.0
        ports = host.get('ports', [])
        metrics = host.get('metrics', {})

        # Base score from open ports (more ports = potential for more connections)
        open_ports = len([p for p in ports if p.get('state') == 'open'])
        score += min(open_ports * 2, 20)  # Max 20 points

        # Admin services bonus (potential jump boxes)
        admin_services = 0
        for port in ports:
            if port.get('state') == 'open':
                service = port.get('service', '').lower()
                if any(admin in service for admin in ['ssh', 'rdp', 'vnc', 'telnet']):
                    admin_services += 1

        score += min(admin_services * 10, 30)  # Max 30 points

        # Multiple service categories (diverse functionality)
        categories = set()
        for port in ports:
            if port.get('state') == 'open':
                category = self.categorize_entry_point(port.get('port', 0), port.get('service', ''))
                if category:
                    categories.add(category)

        score += len(categories) * 5  # 5 points per category

        # High vulnerability count (attractive target)
        vuln_count = metrics.get('total_vulnerabilities', 0)
        if vuln_count > 10:
            score += 10
        elif vuln_count > 5:
            score += 5

        return min(score, 100)  # Normalize to 0-100

    def identify_high_value_targets(self, hosts: List[Dict]) -> List[Dict]:
        """Identify hosts that are high-value targets"""
        high_value_targets = []

        for host in hosts:
            host_ip = host.get('ip', '')
            ports = host.get('ports', [])
            metrics = host.get('metrics', {})

            # Calculate value score
            value_score = 0
            reasons = []

            # Check for database services
            db_count = 0
            for port in ports:
                if port.get('state') == 'open':
                    service = port.get('service', '').lower()
                    for db_service in self.high_value_indicators['database_services']:
                        if db_service in service:
                            db_count += 1
                            break

            if db_count > 0:
                value_score += 30
                reasons.append(f"{db_count} database service(s)")

            # Check for admin services
            admin_count = 0
            for port in ports:
                if port.get('state') == 'open':
                    service = port.get('service', '').lower()
                    for admin_service in self.high_value_indicators['admin_services']:
                        if admin_service in service:
                            admin_count += 1
                            break

            if admin_count > 0:
                value_score += 20
                reasons.append(f"{admin_count} admin service(s)")

            # Check for multiple service categories
            categories = set()
            for port in ports:
                if port.get('state') == 'open':
                    category = self.categorize_entry_point(port.get('port', 0), port.get('service', ''))
                    if category:
                        categories.add(category)

            if len(categories) >= self.high_value_indicators['multiple_categories']:
                value_score += 15
                reasons.append(f"{len(categories)} service categories")

            # Check for high port count
            open_ports = len([p for p in ports if p.get('state') == 'open'])
            if open_ports >= self.high_value_indicators['high_port_count']:
                value_score += 10
                reasons.append(f"{open_ports} open ports")

            # Check for vulnerabilities
            critical_vulns = metrics.get('critical_vulns', 0)
            high_vulns = metrics.get('high_vulns', 0)

            if critical_vulns > 0:
                value_score += critical_vulns * 5
                reasons.append(f"{critical_vulns} critical vulnerabilities")

            if high_vulns > 0:
                value_score += high_vulns * 2
                reasons.append(f"{high_vulns} high vulnerabilities")

            # Only include if significant value
            if value_score >= 25:  # Threshold for high-value
                centrality = self.calculate_centrality_score(host)

                high_value_targets.append({
                    'ip': host_ip,
                    'hostname': host.get('hostname'),
                    'value_score': value_score,
                    'centrality_score': centrality,
                    'combined_score': (value_score + centrality) / 2,
                    'reasons': reasons,
                    'open_ports': open_ports,
                    'service_categories': len(categories),
                    'vulnerabilities': metrics.get('total_vulnerabilities', 0)
                })

        # Sort by combined score
        high_value_targets.sort(key=lambda x: x['combined_score'], reverse=True)

        return high_value_targets

    def analyze_attack_surface(self, data: Dict) -> Dict:
        """Comprehensive attack surface analysis"""
        logger.info("Starting attack surface analysis...")

        hosts = data.get('hosts', [])
        total_hosts = len(hosts)

        # Initialize counters
        entry_point_stats = defaultdict(lambda: {
            'exposed_hosts': set(),
            'total_ports': 0,
            'protocols': Counter(),
            'services': Counter(),
            'risk_score': 0
        })

        surface_metrics = {
            'total_hosts': total_hosts,
            'hosts_with_open_ports': 0,
            'total_open_ports': 0,
            'unique_services': set(),
            'total_entry_points': 0,
            'internet_facing_estimate': 0
        }

        all_ports_analysis = defaultdict(lambda: {
            'hosts': set(),
            'services': set(),
            'protocols': set()
        })

        # Process each host
        for host in hosts:
            host_ip = host.get('ip', '')
            ports = host.get('ports', [])

            if not ports:
                continue

            surface_metrics['hosts_with_open_ports'] += 1

            # Process each port
            for port_info in ports:
                if port_info.get('state') != 'open':
                    continue

                port_num = port_info.get('port', 0)
                protocol = port_info.get('protocol', 'tcp')
                service = port_info.get('service', 'unknown')

                surface_metrics['total_open_ports'] += 1
                surface_metrics['unique_services'].add(service)

                # Update port analysis
                all_ports_analysis[port_num]['hosts'].add(host_ip)
                all_ports_analysis[port_num]['services'].add(service)
                all_ports_analysis[port_num]['protocols'].add(protocol)

                # Categorize as entry point
                category = self.categorize_entry_point(port_num, service)
                if category:
                    surface_metrics['total_entry_points'] += 1

                    entry_point_stats[category]['exposed_hosts'].add(host_ip)
                    entry_point_stats[category]['total_ports'] += 1
                    entry_point_stats[category]['protocols'][protocol] += 1
                    entry_point_stats[category]['services'][service] += 1

        # Calculate surface index (normalized complexity metric)
        unique_services_count = len(surface_metrics['unique_services'])
        surface_index = 0

        if surface_metrics['hosts_with_open_ports'] > 0:
            # Formula: (hosts_with_ports * avg_ports_per_host * unique_services) / normalizing_factor
            avg_ports = surface_metrics['total_open_ports'] / surface_metrics['hosts_with_open_ports']
            raw_index = (surface_metrics['hosts_with_open_ports'] * avg_ports * unique_services_count) / 1000
            surface_index = min(raw_index, 10.0)  # Normalize to 0-10 scale

        # Estimate internet-facing services (common external ports)
        internet_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
        internet_facing = 0

        for port_num, port_data in all_ports_analysis.items():
            if port_num in internet_ports:
                internet_facing += len(port_data['hosts'])

        surface_metrics['internet_facing_estimate'] = internet_facing

        # Convert sets to counts and prepare entry point data
        entry_points_summary = {}
        for category, stats in entry_point_stats.items():
            config = self.entry_point_categories[category]

            entry_points_summary[category] = {
                'exposed_hosts': len(stats['exposed_hosts']),
                'total_ports': stats['total_ports'],
                'risk_level': config['risk_level'],
                'description': config['description'],
                'protocols': dict(stats['protocols']),
                'top_services': dict(stats['services'].most_common(10)),
                'host_list': sorted(list(stats['exposed_hosts']))[:20]  # Limit for file size
            }

        # Network segmentation analysis
        segmentation = self.detect_network_segments(hosts)

        # High-value targets identification
        high_value_targets = self.identify_high_value_targets(hosts)

        # Generate final analysis
        attack_surface_analysis = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_hosts_analyzed': total_hosts,
                'analysis_version': '1.0'
            },
            'attack_surface': {
                'total_hosts': surface_metrics['total_hosts'],
                'hosts_with_open_ports': surface_metrics['hosts_with_open_ports'],
                'hosts_without_open_ports': total_hosts - surface_metrics['hosts_with_open_ports'],
                'total_open_ports': surface_metrics['total_open_ports'],
                'unique_services': unique_services_count,
                'entry_point_categories': len(entry_points_summary),
                'total_entry_points': surface_metrics['total_entry_points'],
                'internet_facing_estimate': surface_metrics['internet_facing_estimate'],
                'surface_index': round(surface_index, 2),
                'avg_ports_per_host': round(surface_metrics['total_open_ports'] / surface_metrics['hosts_with_open_ports'], 1) if surface_metrics['hosts_with_open_ports'] > 0 else 0
            },
            'entry_points': entry_points_summary,
            'network_segmentation': segmentation,
            'high_value_targets': high_value_targets[:20],  # Top 20
            'pivot_points': [target for target in high_value_targets if target['centrality_score'] >= 50][:10]
        }

        logger.info(f"Attack surface analysis complete: {surface_metrics['total_entry_points']} entry points across {len(entry_points_summary)} categories")

        return attack_surface_analysis

    def export_attack_surface(self, analysis: Dict) -> bool:
        """Export attack surface analysis to JSON"""
        try:
            with open(self.attack_surface_file, 'w', encoding='utf-8') as f:
                json.dump(analysis, f, indent=2, ensure_ascii=False)

            file_size = os.path.getsize(self.attack_surface_file) / 1024  # KB
            logger.info(f"Attack surface exported: {self.attack_surface_file} ({file_size:.1f} KB)")
            return True

        except Exception as e:
            logger.error(f"Failed to export attack surface: {e}")
            return False

    def export_entry_points(self, analysis: Dict) -> bool:
        """Export entry points analysis to CSV"""
        try:
            fieldnames = [
                'Category', 'Risk_Level', 'Exposed_Hosts', 'Total_Ports',
                'Top_Services', 'Description'
            ]

            with open(self.entry_points_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for category, info in analysis['entry_points'].items():
                    top_services = ', '.join([f"{svc}({cnt})" for svc, cnt in
                                            list(info['top_services'].items())[:5]])

                    row = {
                        'Category': category,
                        'Risk_Level': info['risk_level'],
                        'Exposed_Hosts': info['exposed_hosts'],
                        'Total_Ports': info['total_ports'],
                        'Top_Services': top_services,
                        'Description': info['description']
                    }
                    writer.writerow(row)

            logger.info(f"Entry points exported: {self.entry_points_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to export entry points: {e}")
            return False

    def export_exposure_matrix(self, analysis: Dict) -> bool:
        """Export exposure matrix for visualization"""
        try:
            fieldnames = [
                'IP', 'Hostname', 'Web_Apps', 'Remote_Admin', 'File_Transfer',
                'Email', 'Databases', 'Network_Services', 'Total_Categories',
                'Value_Score', 'Centrality_Score', 'Risk_Level'
            ]

            # Create matrix data from high-value targets and entry points
            matrix_data = []

            # Process high-value targets first
            for target in analysis.get('high_value_targets', []):
                ip = target['ip']

                # Initialize row
                row = {field: 0 for field in fieldnames}
                row['IP'] = ip
                row['Hostname'] = target.get('hostname', '')
                row['Total_Categories'] = target.get('service_categories', 0)
                row['Value_Score'] = target.get('value_score', 0)
                row['Centrality_Score'] = target.get('centrality_score', 0)

                # Determine risk level
                combined_score = target.get('combined_score', 0)
                if combined_score >= 70:
                    row['Risk_Level'] = 'CRITICAL'
                elif combined_score >= 50:
                    row['Risk_Level'] = 'HIGH'
                elif combined_score >= 30:
                    row['Risk_Level'] = 'MEDIUM'
                else:
                    row['Risk_Level'] = 'LOW'

                # Check which categories this host appears in
                for category, info in analysis['entry_points'].items():
                    if ip in info.get('host_list', []):
                        category_key = category.replace(' ', '_').replace('&', '').replace(' ', '')
                        if category_key in row:
                            row[category_key] = 1

                matrix_data.append(row)

            with open(self.exposure_matrix_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for row in matrix_data:
                    writer.writerow(row)

            logger.info(f"Exposure matrix exported: {self.exposure_matrix_file} ({len(matrix_data)} hosts)")
            return True

        except Exception as e:
            logger.error(f"Failed to export exposure matrix: {e}")
            return False

    def run(self) -> bool:
        """Run the complete attack surface mapping process"""
        print("=" * 60)
        print("Attack Surface Mapper - Vulnerability Assessment Project")
        print("=" * 60)

        # Load master data
        data = self.load_master_data()
        if not data:
            return False

        # Analyze attack surface
        analysis = self.analyze_attack_surface(data)
        if not analysis:
            logger.error("Attack surface analysis failed")
            return False

        # Export results
        surface_success = self.export_attack_surface(analysis)
        entry_success = self.export_entry_points(analysis)
        matrix_success = self.export_exposure_matrix(analysis)

        if all([surface_success, entry_success, matrix_success]):
            surface = analysis['attack_surface']

            print("\n" + "=" * 60)
            print("ATTACK SURFACE ANALYSIS COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"Total hosts analyzed: {surface['total_hosts']}")
            print(f"Hosts with open ports: {surface['hosts_with_open_ports']}")
            print(f"Total open ports: {surface['total_open_ports']}")
            print(f"Unique services: {surface['unique_services']}")
            print(f"Entry point categories: {surface['entry_point_categories']}")
            print(f"Total entry points: {surface['total_entry_points']}")
            print(f"Internet-facing estimate: {surface['internet_facing_estimate']}")
            print(f"Attack surface index: {surface['surface_index']}/10")

            print()
            print("Entry Point Categories:")
            for category, info in analysis['entry_points'].items():
                print(f"  {category}: {info['exposed_hosts']} hosts, {info['total_ports']} ports ({info['risk_level']})")

            print()
            print("Network Segmentation:")
            seg = analysis['network_segmentation']
            print(f"  Total subnets: {seg['total_subnets']}")
            if seg.get('largest_segment'):
                print(f"  Largest segment: {seg['largest_segment']['subnet']} ({seg['largest_segment']['host_count']} hosts)")

            print()
            print("High-Value Targets:")
            for i, target in enumerate(analysis['high_value_targets'][:10]):
                print(f"{i+1:2d}. {target['ip']:15s} | Score: {target['combined_score']:5.1f} | "
                      f"Ports: {target['open_ports']:2d} | Vulns: {target['vulnerabilities']:2d}")

            print()
            print("Files generated:")
            print(f"  - Attack surface: {self.attack_surface_file}")
            print(f"  - Entry points: {self.entry_points_file}")
            print(f"  - Exposure matrix: {self.exposure_matrix_file}")

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

    mapper = AttackSurfaceMapper(results_dir, analysis_dir)
    success = mapper.run()

    if success:
        print("\n✅ Attack surface mapping completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Attack surface mapping failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()