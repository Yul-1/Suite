#!/usr/bin/env python3
"""
Vulnerability Analyzer for Vulnerability Assessment Project
Analyzes vulnerability patterns, CVE distribution, and provides insights

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

class VulnerabilityAnalyzer:
    def __init__(self, results_dir: str = "output/results", analysis_dir: str = "output/analysis"):
        self.results_dir = results_dir
        self.analysis_dir = analysis_dir
        self.master_data_file = os.path.join(results_dir, "master_data.json")

        # Output files
        self.vuln_stats_file = os.path.join(analysis_dir, "vuln_stats.json")
        self.cve_distribution_file = os.path.join(analysis_dir, "cve_distribution.csv")
        self.top_cves_file = os.path.join(analysis_dir, "top_cves.csv")
        self.vuln_families_file = os.path.join(analysis_dir, "vuln_families.json")

        # Ensure analysis directory exists
        os.makedirs(analysis_dir, exist_ok=True)

        # Vulnerability family patterns
        self.vuln_types = {
            'RCE': [
                'remote code execution', 'command injection', 'arbitrary code',
                'code execution', 'shell injection', 'rce', 'execute arbitrary',
                'command execution', 'remote execution'
            ],
            'SQLi': [
                'sql injection', 'sqli', 'sql inject', 'database injection'
            ],
            'XSS': [
                'cross-site scripting', 'xss', 'script injection', 'cross site scripting'
            ],
            'Authentication': [
                'authentication bypass', 'default credentials', 'weak authentication',
                'auth bypass', 'login bypass', 'credential', 'password',
                'unauthorized access', 'authentication'
            ],
            'Information Disclosure': [
                'information disclosure', 'sensitive data', 'data leakage',
                'sensitive information', 'information leak', 'disclosure',
                'directory traversal', 'path traversal', 'file disclosure'
            ],
            'DoS': [
                'denial of service', 'dos', 'crash', 'resource exhaustion',
                'denial-of-service', 'service disruption'
            ],
            'Privilege Escalation': [
                'privilege escalation', 'elevation', 'privilege elevation',
                'escalation of privilege', 'local privilege', 'root access'
            ],
            'CSRF': [
                'cross-site request forgery', 'csrf', 'request forgery'
            ],
            'Buffer Overflow': [
                'buffer overflow', 'stack overflow', 'heap overflow',
                'memory corruption', 'buffer overrun'
            ],
            'Directory Traversal': [
                'directory traversal', 'path traversal', '../', 'file inclusion',
                'local file inclusion', 'remote file inclusion'
            ],
            'Cryptographic': [
                'weak encryption', 'cryptographic', 'ssl', 'tls', 'certificate',
                'cipher', 'encryption', 'hash', 'crypto'
            ],
            'Configuration': [
                'misconfiguration', 'configuration', 'default configuration',
                'insecure configuration', 'security configuration'
            ]
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

    def extract_cve_year(self, cve_id: str) -> Optional[int]:
        """Extract year from CVE ID (e.g., CVE-2021-44228 -> 2021)"""
        if not cve_id:
            return None

        match = re.match(r'CVE-(\d{4})-\d+', cve_id.upper())
        if match:
            return int(match.group(1))

        return None

    def classify_vulnerability(self, vuln: Dict) -> str:
        """Classify vulnerability into families based on title/description"""
        title = vuln.get('title', '').lower()
        description = vuln.get('description', '').lower()
        combined_text = f"{title} {description}"

        # Check each vulnerability type
        for vuln_type, keywords in self.vuln_types.items():
            for keyword in keywords:
                if keyword in combined_text:
                    return vuln_type

        return 'Other'

    def calculate_impact_score(self, cve_data: Dict) -> float:
        """Calculate impact score: hosts_affected * avg_cvss_score"""
        hosts_affected = cve_data['hosts_affected']
        avg_cvss = cve_data['avg_cvss']

        if avg_cvss is None or avg_cvss == 0:
            avg_cvss = 5.0  # Default moderate score

        return hosts_affected * avg_cvss

    def analyze_vulnerabilities(self, data: Dict) -> Dict:
        """Comprehensive vulnerability analysis"""
        logger.info("Starting vulnerability analysis...")

        # Data structures for analysis
        all_vulnerabilities = []
        cve_data = defaultdict(lambda: {
            'cve_id': '',
            'hosts_affected': 0,
            'cvss_scores': [],
            'severities': [],
            'titles': set(),
            'descriptions': set(),
            'affected_hosts': set()
        })

        severity_counts = Counter()
        vulnerability_families = Counter()
        hosts_with_vulns = 0
        hosts_without_vulns = 0

        # Process each host
        for host in data.get('hosts', []):
            host_ip = host.get('ip', 'Unknown')
            vulnerabilities = host.get('vulnerabilities', [])

            if vulnerabilities:
                hosts_with_vulns += 1
            else:
                hosts_without_vulns += 1

            # Process each vulnerability
            for vuln in vulnerabilities:
                all_vulnerabilities.append(vuln)

                # Count by severity
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity] += 1

                # Classify vulnerability family
                vuln_family = self.classify_vulnerability(vuln)
                vulnerability_families[vuln_family] += 1

                # Process CVE data
                cve_ids = vuln.get('cve_ids', [])
                if not cve_ids and vuln.get('cve'):  # Fallback for single CVE field
                    cve_match = re.findall(r'CVE-\d{4}-\d{4,7}', vuln.get('cve', ''), re.IGNORECASE)
                    cve_ids = [cve.upper() for cve in cve_match]

                for cve_id in cve_ids:
                    if cve_id:
                        cve_data[cve_id]['cve_id'] = cve_id
                        cve_data[cve_id]['affected_hosts'].add(host_ip)
                        cve_data[cve_id]['hosts_affected'] = len(cve_data[cve_id]['affected_hosts'])

                        # Add CVSS score if available
                        cvss = vuln.get('cvss')
                        if cvss is not None and isinstance(cvss, (int, float)) and cvss > 0:
                            cve_data[cve_id]['cvss_scores'].append(float(cvss))

                        # Add severity
                        if severity and severity != 'Unknown':
                            cve_data[cve_id]['severities'].append(severity)

                        # Add title and description
                        if vuln.get('title'):
                            cve_data[cve_id]['titles'].add(vuln.get('title'))
                        if vuln.get('description'):
                            cve_data[cve_id]['descriptions'].add(vuln.get('description'))

        # Calculate CVE statistics
        cve_list = []
        for cve_id, cve_info in cve_data.items():
            # Calculate average CVSS
            cvss_scores = cve_info['cvss_scores']
            avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else None

            # Determine most common severity
            severities = cve_info['severities']
            most_common_severity = Counter(severities).most_common(1)[0][0] if severities else 'Unknown'

            # Get representative title and description
            titles = list(cve_info['titles'])
            descriptions = list(cve_info['descriptions'])

            cve_entry = {
                'cve_id': cve_id,
                'hosts_affected': cve_info['hosts_affected'],
                'hosts_percentage': round((cve_info['hosts_affected'] / len(data['hosts'])) * 100, 1),
                'avg_cvss': avg_cvss,
                'severity': most_common_severity,
                'title': titles[0] if titles else 'Unknown',
                'description': descriptions[0] if descriptions else 'Unknown',
                'impact_score': 0,  # Will be calculated below
                'cve_year': self.extract_cve_year(cve_id),
                'vulnerability_type': self.classify_vulnerability({
                    'title': titles[0] if titles else '',
                    'description': descriptions[0] if descriptions else ''
                })
            }

            cve_entry['impact_score'] = self.calculate_impact_score(cve_entry)
            cve_list.append(cve_entry)

        # Sort CVEs by impact score
        cve_list.sort(key=lambda x: x['impact_score'], reverse=True)

        # Add rank to CVEs
        for i, cve in enumerate(cve_list):
            cve['rank'] = i + 1

        # Calculate age distribution
        cve_years = [cve['cve_year'] for cve in cve_list if cve['cve_year'] is not None]
        current_year = datetime.now().year
        age_distribution = Counter()

        for year in cve_years:
            age = current_year - year
            if age <= 1:
                age_distribution['0-1 years'] += 1
            elif age <= 3:
                age_distribution['1-3 years'] += 1
            elif age <= 5:
                age_distribution['3-5 years'] += 1
            else:
                age_distribution['5+ years'] += 1

        # Generate statistics
        total_hosts = len(data.get('hosts', []))
        total_vulnerabilities = len(all_vulnerabilities)
        unique_cves = len(cve_list)

        vulnerability_stats = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_hosts': total_hosts,
                'analysis_version': '1.0'
            },
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'unique_cves': unique_cves,
                'hosts_with_vulnerabilities': hosts_with_vulns,
                'hosts_without_vulnerabilities': hosts_without_vulns,
                'vulnerability_density': round(total_vulnerabilities / total_hosts, 1) if total_hosts > 0 else 0,
                'average_vulnerabilities_per_host': round(total_vulnerabilities / hosts_with_vulns, 1) if hosts_with_vulns > 0 else 0
            },
            'severity_distribution': {
                'counts': dict(severity_counts),
                'percentages': {
                    severity: round((count / total_vulnerabilities) * 100, 1) if total_vulnerabilities > 0 else 0
                    for severity, count in severity_counts.items()
                }
            },
            'vulnerability_families': {
                'counts': dict(vulnerability_families),
                'percentages': {
                    family: round((count / total_vulnerabilities) * 100, 1) if total_vulnerabilities > 0 else 0
                    for family, count in vulnerability_families.items()
                }
            },
            'cve_age_distribution': dict(age_distribution),
            'top_vulnerability_families': vulnerability_families.most_common(10),
            'systemtic_issues': {
                'widespread_cves': len([cve for cve in cve_list if cve['hosts_percentage'] >= 20]),
                'legacy_cves': len([cve for cve in cve_list if cve['cve_year'] and (current_year - cve['cve_year']) > 5]),
                'critical_cves': len([cve for cve in cve_list if cve['severity'] == 'Critical']),
                'high_cves': len([cve for cve in cve_list if cve['severity'] == 'High'])
            }
        }

        logger.info(f"Analysis complete: {total_vulnerabilities} vulnerabilities, {unique_cves} unique CVEs")

        return {
            'statistics': vulnerability_stats,
            'cve_list': cve_list,
            'all_vulnerabilities': all_vulnerabilities
        }

    def export_vulnerability_stats(self, stats: Dict) -> bool:
        """Export vulnerability statistics to JSON"""
        try:
            with open(self.vuln_stats_file, 'w', encoding='utf-8') as f:
                json.dump(stats, f, indent=2, ensure_ascii=False)

            file_size = os.path.getsize(self.vuln_stats_file) / 1024  # KB
            logger.info(f"Vulnerability stats exported: {self.vuln_stats_file} ({file_size:.1f} KB)")
            return True

        except Exception as e:
            logger.error(f"Failed to export vulnerability stats: {e}")
            return False

    def export_cve_distribution(self, cve_list: List[Dict]) -> bool:
        """Export CVE distribution to CSV"""
        try:
            fieldnames = [
                'CVE_ID', 'Hosts_Affected', 'Hosts_Percentage', 'CVSS_Score',
                'Severity', 'Impact_Score', 'CVE_Year', 'Age_Years',
                'Vulnerability_Type', 'Title'
            ]

            current_year = datetime.now().year

            with open(self.cve_distribution_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for cve in cve_list:
                    age_years = current_year - cve['cve_year'] if cve['cve_year'] else None

                    row = {
                        'CVE_ID': cve['cve_id'],
                        'Hosts_Affected': cve['hosts_affected'],
                        'Hosts_Percentage': cve['hosts_percentage'],
                        'CVSS_Score': cve['avg_cvss'] if cve['avg_cvss'] is not None else 'N/A',
                        'Severity': cve['severity'],
                        'Impact_Score': round(cve['impact_score'], 1),
                        'CVE_Year': cve['cve_year'] if cve['cve_year'] else 'Unknown',
                        'Age_Years': age_years if age_years is not None else 'Unknown',
                        'Vulnerability_Type': cve['vulnerability_type'],
                        'Title': cve['title']
                    }
                    writer.writerow(row)

            logger.info(f"CVE distribution exported: {self.cve_distribution_file} ({len(cve_list)} CVEs)")
            return True

        except Exception as e:
            logger.error(f"Failed to export CVE distribution: {e}")
            return False

    def export_top_cves(self, cve_list: List[Dict]) -> bool:
        """Export top CVEs by impact score to CSV"""
        try:
            # Take top 50 CVEs by impact score
            top_cves = cve_list[:50]

            fieldnames = [
                'Rank', 'CVE_ID', 'CVSS', 'Severity', 'Hosts_Affected',
                'Percentage', 'Impact_Score', 'Type', 'Description'
            ]

            with open(self.top_cves_file, 'w', newline='', encoding='utf-8-sig') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()

                for cve in top_cves:
                    row = {
                        'Rank': cve['rank'],
                        'CVE_ID': cve['cve_id'],
                        'CVSS': cve['avg_cvss'] if cve['avg_cvss'] is not None else 'N/A',
                        'Severity': cve['severity'],
                        'Hosts_Affected': cve['hosts_affected'],
                        'Percentage': f"{cve['hosts_percentage']}%",
                        'Impact_Score': round(cve['impact_score'], 1),
                        'Type': cve['vulnerability_type'],
                        'Description': cve['title'][:100] + '...' if len(cve['title']) > 100 else cve['title']
                    }
                    writer.writerow(row)

            logger.info(f"Top CVEs exported: {self.top_cves_file} ({len(top_cves)} CVEs)")
            return True

        except Exception as e:
            logger.error(f"Failed to export top CVEs: {e}")
            return False

    def export_vulnerability_families(self, stats: Dict) -> bool:
        """Export vulnerability families analysis to JSON"""
        try:
            families_data = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'classification_version': '1.0'
                },
                'vulnerability_families': stats['vulnerability_families'],
                'family_definitions': self.vuln_types,
                'top_families': stats['top_vulnerability_families']
            }

            with open(self.vuln_families_file, 'w', encoding='utf-8') as f:
                json.dump(families_data, f, indent=2, ensure_ascii=False)

            logger.info(f"Vulnerability families exported: {self.vuln_families_file}")
            return True

        except Exception as e:
            logger.error(f"Failed to export vulnerability families: {e}")
            return False

    def run(self) -> bool:
        """Run the complete vulnerability analysis process"""
        print("=" * 60)
        print("Vulnerability Analyzer - Vulnerability Assessment Project")
        print("=" * 60)

        # Load master data
        data = self.load_master_data()
        if not data:
            return False

        # Analyze vulnerabilities
        analysis_results = self.analyze_vulnerabilities(data)
        if not analysis_results:
            logger.error("Vulnerability analysis failed")
            return False

        stats = analysis_results['statistics']
        cve_list = analysis_results['cve_list']

        # Export results
        stats_success = self.export_vulnerability_stats(stats)
        dist_success = self.export_cve_distribution(cve_list)
        top_success = self.export_top_cves(cve_list)
        families_success = self.export_vulnerability_families(stats)

        if all([stats_success, dist_success, top_success, families_success]):
            print("\n" + "=" * 60)
            print("VULNERABILITY ANALYSIS COMPLETED SUCCESSFULLY")
            print("=" * 60)
            print(f"Total vulnerabilities: {stats['summary']['total_vulnerabilities']}")
            print(f"Unique CVEs: {stats['summary']['unique_cves']}")
            print(f"Hosts with vulnerabilities: {stats['summary']['hosts_with_vulnerabilities']}")
            print(f"Average vulnerabilities per host: {stats['summary']['average_vulnerabilities_per_host']}")
            print()
            print("Severity Distribution:")
            for severity, count in stats['severity_distribution']['counts'].items():
                percentage = stats['severity_distribution']['percentages'][severity]
                print(f"  {severity}: {count} ({percentage}%)")

            print()
            print("Top 5 Vulnerability Families:")
            for family, count in stats['top_vulnerability_families'][:5]:
                percentage = stats['vulnerability_families']['percentages'][family]
                print(f"  {family}: {count} ({percentage}%)")

            print()
            print("Top 10 Most Critical CVEs:")
            print("-" * 100)
            for i, cve in enumerate(cve_list[:10]):
                print(f"{i+1:2d}. {cve['cve_id']:15s} | CVSS: {str(cve['avg_cvss'])[:4]:>4s} | "
                      f"Hosts: {cve['hosts_affected']:3d} | {cve['severity']:8s} | {cve['vulnerability_type']}")

            print()
            print("Files generated:")
            print(f"  - Vulnerability stats: {self.vuln_stats_file}")
            print(f"  - CVE distribution: {self.cve_distribution_file}")
            print(f"  - Top CVEs: {self.top_cves_file}")
            print(f"  - Vulnerability families: {self.vuln_families_file}")

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

    analyzer = VulnerabilityAnalyzer(results_dir, analysis_dir)
    success = analyzer.run()

    if success:
        print("\n✅ Vulnerability analysis completed successfully!")
        sys.exit(0)
    else:
        print("\n❌ Vulnerability analysis failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()