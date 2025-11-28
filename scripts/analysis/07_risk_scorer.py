#!/usr/bin/env python3
"""
Risk Scorer for Vulnerability Assessment Project
Calculates risk scores for hosts based on vulnerabilities, services, and exposure

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

class RiskScorer:
    def __init__(self, results_dir: str = "output/results", analysis_dir: str = "output/analysis"):
        self.results_dir = results_dir
        self.analysis_dir = analysis_dir
        self.master_data_file = os.path.join(results_dir, "master_data.json")
        self.hosts_ranked_file = os.path.join(analysis_dir, "hosts_ranked.json")
        self.critical_hosts_file = os.path.join(analysis_dir, "critical_hosts.csv")

        # Ensure analysis directory exists
        os.makedirs(analysis_dir, exist_ok=True)

        # Critical services that increase risk when exposed
        self.critical_services = [
            'rdp', 'ms-wbt-server', 'terminal-server',  # RDP
            'ssh', 'ssh-2.0',  # SSH
            'telnet',  # Telnet
            'ftp', 'ftp-data',  # FTP
            'mysql', 'mysql-admin',  # MySQL
            'mssql', 'ms-sql-s', 'microsoft-ds',  # SQL Server
            'postgresql', 'postgres',  # PostgreSQL
            'mongodb', 'mongo',  # MongoDB
            'smb', 'netbios-ssn', 'microsoft-ds',  # SMB
            'ldap', 'ldaps',  # LDAP
            'snmp',  # SNMP
            'vnc', 'vnc-http',  # VNC
            'rlogin', 'rsh', 'rexec',  # R-services
            'oracle', 'oracle-tns'  # Oracle
        ]

        # Services that indicate outdated/EOL systems
        self.eol_indicators = [
            'windows-2008', 'windows-2003', 'windows-xp',
            'apache-2.2', 'nginx-1.0', 'nginx-1.1',
            'openssh-5', 'openssh-6',
            'mysql-5.0', 'mysql-5.1',
            'php-5', 'php-7.0', 'php-7.1', 'php-7.2'
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

    def count_critical_services(self, host: Dict) -> int:
        """Count critical services exposed on a host"""
        critical_count = 0
        ports = host.get('ports', [])

        for port in ports:
            if port.get('state') != 'open':
                continue

            service = port.get('service', '').lower()

            # Check if service matches any critical service
            for critical_service in self.critical_services:
                if critical_service in service:
                    critical_count += 1
                    break

        return critical_count

    def has_eol_services(self, host: Dict) -> bool:
        """Check if host has end-of-life or outdated services"""
        ports = host.get('ports', [])
        os_info = host.get('os', {})

        # Check OS for EOL indicators
        if os_info:
            os_name = os_info.get('name', '').lower()
            for eol_indicator in self.eol_indicators:
                if eol_indicator in os_name:
                    return True

        # Check services for EOL indicators
        for port in ports:
            service = port.get('service', '').lower()
            version = port.get('version', '').lower()

            service_info = f"{service} {version}".strip()

            for eol_indicator in self.eol_indicators:
                if eol_indicator in service_info:
                    return True

        return False

    def calculate_avg_cvss(self, vulnerabilities: List[Dict]) -> float:
        """Calculate average CVSS score from vulnerabilities"""
        cvss_scores = []

        for vuln in vulnerabilities:
            cvss = vuln.get('cvss')
            if cvss is not None and isinstance(cvss, (int, float)) and cvss > 0:
                cvss_scores.append(float(cvss))

        if not cvss_scores:
            return 0.0

        return sum(cvss_scores) / len(cvss_scores)

    def calculate_risk_score(self, host: Dict) -> Dict:
        """Calculate comprehensive risk score for a host (0-100 scale)"""
        metrics = host.get('metrics', {})
        vulnerabilities = host.get('vulnerabilities', [])

        base_score = 0.0
        contributing_factors = {}

        # 1. Vulnerabilities (max 40 points)
        critical_vulns = metrics.get('critical_vulns', 0)
        high_vulns = metrics.get('high_vulns', 0)
        medium_vulns = metrics.get('medium_vulns', 0)

        vuln_score = min(critical_vulns * 10 + high_vulns * 3 + medium_vulns * 1, 40)
        base_score += vuln_score

        contributing_factors['vulnerability_score'] = vuln_score
        contributing_factors['critical_vulns'] = critical_vulns
        contributing_factors['high_vulns'] = high_vulns
        contributing_factors['medium_vulns'] = medium_vulns

        # 2. CVSS average (max 20 points)
        avg_cvss = self.calculate_avg_cvss(vulnerabilities)
        cvss_score = (avg_cvss / 10.0) * 20 if avg_cvss > 0 else 0
        base_score += cvss_score

        contributing_factors['avg_cvss'] = round(avg_cvss, 1)
        contributing_factors['cvss_score'] = round(cvss_score, 1)

        # 3. Open ports (max 15 points)
        open_ports = metrics.get('total_ports', 0)

        if open_ports > 20:
            ports_score = 15
        elif open_ports > 10:
            ports_score = 10
        elif open_ports > 5:
            ports_score = 5
        else:
            ports_score = min(open_ports, 5)

        base_score += ports_score

        contributing_factors['open_ports'] = open_ports
        contributing_factors['ports_score'] = ports_score

        # 4. Critical services exposed (max 15 points)
        critical_services_count = self.count_critical_services(host)
        critical_services_score = min(critical_services_count * 3, 15)
        base_score += critical_services_score

        contributing_factors['critical_services'] = critical_services_count
        contributing_factors['critical_services_score'] = critical_services_score

        # 5. End-of-life/outdated services (max 10 points)
        has_eol = self.has_eol_services(host)
        eol_score = 10 if has_eol else 0
        base_score += eol_score

        contributing_factors['has_eol_services'] = has_eol
        contributing_factors['eol_score'] = eol_score

        # Normalize to 0-100 and determine risk category
        final_score = min(base_score, 100)

        if final_score >= 80:
            risk_category = "CRITICAL"
        elif final_score >= 60:
            risk_category = "HIGH"
        elif final_score >= 40:
            risk_category = "MEDIUM"
        elif final_score >= 20:
            risk_category = "LOW"
        else:
            risk_category = "MINIMAL"

        # Identify specific risk factors for remediation
        risk_factors = []

        if critical_vulns > 0:
            risk_factors.append(f"{critical_vulns} critical vulnerabilities")
        if high_vulns > 5:
            risk_factors.append(f"{high_vulns} high vulnerabilities")
        if critical_services_count > 0:
            critical_service_list = []
            for port in host.get('ports', []):
                if port.get('state') == 'open':
                    service = port.get('service', '').lower()
                    for cs in self.critical_services:
                        if cs in service and service not in critical_service_list:
                            critical_service_list.append(service)
                            break
            if critical_service_list:
                risk_factors.append(f"Critical services: {', '.join(critical_service_list[:3])}")
        if has_eol:
            risk_factors.append("Outdated/EOL services detected")
        if open_ports > 15:
            risk_factors.append(f"High port exposure ({open_ports} open ports)")

        return {
            'risk_score': round(final_score, 1),
            'risk_category': risk_category,
            'contributing_factors': contributing_factors,
            'risk_factors': risk_factors,
            'remediation_priority': self.get_remediation_priority(final_score)
        }

    def get_remediation_priority(self, risk_score: float) -> str:
        """Get remediation priority based on risk score"""
        if risk_score >= 80:
            return "P0 (Critical - immediate action required)"
        elif risk_score >= 60:
            return "P1 (High - action required within 7 days)"
        elif risk_score >= 40:
            return "P2 (Medium - action required within 30 days)"
        elif risk_score >= 20:
            return "P3 (Low - action required within 90 days)"
        else:
            return "P4 (Minimal - routine maintenance)"

    def rank_hosts(self, data: Dict) -> List[Dict]:
        """Calculate risk scores for all hosts and rank them"""
        logger.info("Calculating risk scores for all hosts...")

        hosts_with_scores = []

        for i, host in enumerate(data.get('hosts', [])):
            if i % 50 == 0:
                logger.info(f"Processing host {i+1}/{len(data['hosts'])}")

            risk_analysis = self.calculate_risk_score(host)

            # Create ranked host entry
            ranked_host = {
                'ip': host.get('ip'),
                'hostname': host.get('hostname'),
                'status': host.get('status'),
                'os': host.get('os', {}).get('name') if host.get('os') else None,
                'os_accuracy': host.get('os', {}).get('accuracy') if host.get('os') else None,
                'risk_score': risk_analysis['risk_score'],
                'risk_category': risk_analysis['risk_category'],
                'remediation_priority': risk_analysis['remediation_priority'],
                'contributing_factors': risk_analysis['contributing_factors'],
                'risk_factors': risk_analysis['risk_factors'],
                'metrics': host.get('metrics', {}),
                'sources': host.get('source', [])
            }

            hosts_with_scores.append(ranked_host)

        # Sort by risk score (descending)
        hosts_with_scores.sort(key=lambda x: x['risk_score'], reverse=True)

        # Add rank
        for i, host in enumerate(hosts_with_scores):
            host['rank'] = i + 1

        logger.info(f"Risk scoring completed for {len(hosts_with_scores)} hosts")

        return hosts_with_scores

    def generate_statistics(self, ranked_hosts: List[Dict]) -> Dict:
        """Generate aggregate statistics"""
        total_hosts = len(ranked_hosts)

        # Count by risk category
        risk_distribution = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'MINIMAL': 0
        }

        total_score = 0
        total_vulns = 0

        for host in ranked_hosts:
            risk_cat = host['risk_category']
            if risk_cat in risk_distribution:
                risk_distribution[risk_cat] += 1

            total_score += host['risk_score']
            total_vulns += host['metrics'].get('total_vulnerabilities', 0)

        # Calculate percentages
        risk_percentages = {}
        for category, count in risk_distribution.items():
            risk_percentages[category] = round((count / total_hosts) * 100, 1) if total_hosts > 0 else 0

        return {
            'total_hosts': total_hosts,
            'average_risk_score': round(total_score / total_hosts, 1) if total_hosts > 0 else 0,
            'total_vulnerabilities': total_vulns,
            'risk_distribution': risk_distribution,
            'risk_percentages': risk_percentages,
            'critical_hosts': risk_distribution['CRITICAL'],
            'high_risk_hosts': risk_distribution['HIGH'],
            'critical_and_high': risk_distribution['CRITICAL'] + risk_distribution['HIGH']
        }

    def export_ranked_hosts(self, ranked_hosts: List[Dict], statistics: Dict) -> bool:
        """Export ranked hosts to JSON"""
        try:
            output_data = {
                'scoring_metadata': {
                    'algorithm_version': '1.0',
                    'max_score': 100,
                    'scored_hosts': len(ranked_hosts),
                    'generated_at': datetime.now().isoformat(),
                    'statistics': statistics
                },
                'hosts_ranked': ranked_hosts
            }

            with open(self.hosts_ranked_file, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)

            file_size = os.path.getsize(self.hosts_ranked_file) / (1024 * 1024)
            logger.info(f"Ranked hosts exported: {self.hosts_ranked_file} ({file_size:.2f} MB)")

            return True

        except Exception as e:
            logger.error(f"Failed to export ranked hosts: {e}")
            return False

    def export_critical_hosts_csv(self, ranked_hosts: List[Dict]) -> bool:
        """Export critical and high-risk hosts to CSV"""
        try:
            # Filter critical and high-risk hosts
            critical_hosts = [h for h in ranked_hosts if h['risk_category'] in ['CRITICAL', 'HIGH']]

            if not critical_hosts:
                logger.warning("No critical or high-risk hosts found")
                # Create empty CSV with headers
                critical_hosts = []

            fieldnames = [
                'Rank', 'IP', 'Hostname', 'Risk_Score', 'Risk_Category',
                'Remediation_Priority', 'Critical_Vulns', 'High_Vulns',
                'Medium_Vulns', 'Total_Vulns', 'Open_Ports', 'Critical_Services',
                'CVSS_Avg', 'OS', 'Risk_Factors', 'Sources'
            ]

            with open(self.critical_hosts_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for host in critical_hosts:
                    metrics = host.get('metrics', {})
                    factors = host.get('contributing_factors', {})

                    row = {
                        'Rank': host.get('rank', ''),
                        'IP': host.get('ip', ''),
                        'Hostname': host.get('hostname', ''),
                        'Risk_Score': host.get('risk_score', 0),
                        'Risk_Category': host.get('risk_category', ''),
                        'Remediation_Priority': host.get('remediation_priority', ''),
                        'Critical_Vulns': metrics.get('critical_vulns', 0),
                        'High_Vulns': metrics.get('high_vulns', 0),
                        'Medium_Vulns': metrics.get('medium_vulns', 0),
                        'Total_Vulns': metrics.get('total_vulnerabilities', 0),
                        'Open_Ports': metrics.get('total_ports', 0),
                        'Critical_Services': factors.get('critical_services', 0),
                        'CVSS_Avg': factors.get('avg_cvss', 0),
                        'OS': host.get('os', ''),
                        'Risk_Factors': '; '.join(host.get('risk_factors', [])),
                        'Sources': '; '.join(host.get('sources', []))
                    }
                    writer.writerow(row)

            logger.info(f"Critical hosts CSV exported: {self.critical_hosts_file} ({len(critical_hosts)} hosts)")
            return True

        except Exception as e:
            logger.error(f"Failed to export critical hosts CSV: {e}")
            return False

    def run(self) -> bool:
        """Run the complete risk scoring process"""
        print("=" * 60)
        print("Risk Scorer - Vulnerability Assessment Project")
        print("=" * 60)

        # Load master data
        data = self.load_master_data()
        if not data:
            return False

        # Calculate risk scores and rank hosts
        ranked_hosts = self.rank_hosts(data)
        if not ranked_hosts:
            logger.error("No hosts to rank")
            return False

        # Generate statistics
        statistics = self.generate_statistics(ranked_hosts)

        # Export results
        json_success = self.export_ranked_hosts(ranked_hosts, statistics)
        csv_success = self.export_critical_hosts_csv(ranked_hosts)

        if json_success and csv_success:
            print("\n" + "=" * 60)
            print("RISK SCORING COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"Total hosts analyzed: {statistics['total_hosts']}")
            print(f"Average risk score: {statistics['average_risk_score']}")
            print(f"Critical risk hosts: {statistics['critical_hosts']} ({statistics['risk_percentages']['CRITICAL']}%)")
            print(f"High risk hosts: {statistics['high_risk_hosts']} ({statistics['risk_percentages']['HIGH']}%)")
            print(f"Critical + High: {statistics['critical_and_high']} hosts")
            print()
            print("Files generated:")
            print(f"  - Ranked hosts: {self.hosts_ranked_file}")
            print(f"  - Critical hosts CSV: {self.critical_hosts_file}")

            # Show top 10 most risky hosts
            print("\nTop 10 Most Risky Hosts:")
            print("-" * 80)
            for i, host in enumerate(ranked_hosts[:10]):
                print(f"{i+1:2d}. {host['ip']:15s} | Score: {host['risk_score']:5.1f} | {host['risk_category']:8s} | {host.get('hostname', 'N/A')}")

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

    scorer = RiskScorer(results_dir, analysis_dir)
    success = scorer.run()

    if success:
        print("\n✅ Risk scoring completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Risk scoring failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()