#!/usr/bin/env python3
"""
Data Aggregator - Task 4.2
Aggrega metriche dai CSV di input e genera CSV per i grafici.
"""

import csv
import json
from pathlib import Path
from collections import Counter, defaultdict

# Paths - Suite structure
BASE_DIR = Path(__file__).parent.parent.parent  # Suite/
DATA_INPUT_DIR = BASE_DIR / "output" / "data_input"
DATA_OUTPUT_DIR = BASE_DIR / "output" / "report" / "CSVs"
ANALYSIS_DIR = BASE_DIR / "output" / "analysis"

def load_csv(filepath):
    """Carica CSV e ritorna lista di dict."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def save_csv(filepath, data, headers):
    """Salva dati in CSV."""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(data)
    print(f"✓ Created: {filepath}")

def aggregate_severity_breakdown(vulns, findings):
    """Calcola breakdown per severity (escluso Info)."""
    # Count vulnerabilities by severity
    severity_counts = Counter()

    for finding in findings:
        vuln_id = finding['vuln_id']
        # Find vulnerability info
        vuln = next((v for v in vulns if v['vuln_id'] == vuln_id), None)
        if vuln:
            severity = vuln['severity']
            # Exclude Info severity
            if severity != 'Info':
                severity_counts[severity] += 1

    data = [
        ['Critical', severity_counts.get('Critical', 0), 0, severity_counts.get('Critical', 0)],
        ['High', severity_counts.get('High', 0), 0, severity_counts.get('High', 0)],
        ['Medium', severity_counts.get('Medium', 0), 0, severity_counts.get('Medium', 0)],
        ['Low', severity_counts.get('Low', 0), 0, severity_counts.get('Low', 0)]
    ]

    headers = ['severity', 'count', 'resolved', 'new']
    save_csv(DATA_OUTPUT_DIR / 'severity_breakdown.csv', data, headers)
    return severity_counts

def aggregate_top_vulns_by_occurrence(vulns, findings):
    """Top 10 vulnerabilità per numero di occorrenze (escluso Info)."""
    vuln_counts = Counter()

    for finding in findings:
        vuln_id = finding['vuln_id']
        vuln_counts[vuln_id] += 1

    # Get top 10 (exclude Info severity)
    top_vulns = []
    for vuln_id, count in vuln_counts.most_common(50):  # Check more to filter Info
        vuln = next((v for v in vulns if v['vuln_id'] == vuln_id), None)
        if vuln and vuln['severity'] != 'Info':
            top_vulns.append([
                len(top_vulns) + 1,  # rank
                vuln['name'],
                vuln['severity'],
                count,
                vuln['cvss_score']
            ])
            if len(top_vulns) >= 10:
                break

    headers = ['rank', 'vuln_name', 'severity', 'occurrences', 'cvss']
    save_csv(DATA_OUTPUT_DIR / 'top_vulns_by_occurrence.csv', top_vulns, headers)
    return len(top_vulns)

def aggregate_top_high_risk_hosts(findings, vulns, hosts_ranked_path):
    """Top 10 host per risk score con breakdown severity."""
    # Load hosts_ranked.json
    with open(hosts_ranked_path, 'r') as f:
        hosts_ranked = json.load(f)

    top_hosts = []
    for i, host in enumerate(hosts_ranked['hosts_ranked'][:10]):
        ip = host['ip']
        hostname = host.get('hostname', '')
        risk_score = host['risk_score']

        # Count vulns by severity for this host
        host_findings = [f for f in findings if f['ip'] == ip]
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

        for finding in host_findings:
            vuln_id = finding['vuln_id']
            vuln = next((v for v in vulns if v['vuln_id'] == vuln_id), None)
            if vuln:
                sev = vuln['severity']
                if sev in severity_counts:
                    severity_counts[sev] += 1

        top_hosts.append([
            i + 1,  # rank
            ip,
            hostname,
            risk_score,
            severity_counts['Critical'],
            severity_counts['High'],
            severity_counts['Medium'],
            severity_counts['Low']
        ])

    headers = ['rank', 'ip', 'hostname', 'risk_score', 'critical', 'high', 'medium', 'low']
    save_csv(DATA_OUTPUT_DIR / 'top_high_risk_hosts.csv', top_hosts, headers)
    return len(top_hosts)

def aggregate_cvss_histogram(vulns, findings):
    """Distribuzione CVSS in bins da 0 a 10 (step 0.5) - escluso Info."""
    cvss_counts = defaultdict(int)

    for finding in findings:
        vuln_id = finding['vuln_id']
        vuln = next((v for v in vulns if v['vuln_id'] == vuln_id), None)
        if vuln and vuln['severity'] != 'Info':
            try:
                cvss = float(vuln['cvss_score'])
                # Round to nearest 0.5
                bin_value = round(cvss * 2) / 2
                cvss_counts[bin_value] += 1
            except (ValueError, TypeError):
                pass

    # Create bins from 0 to 10
    data = []
    for i in range(21):  # 0.0, 0.5, 1.0, ... 10.0
        bin_value = i * 0.5
        count = cvss_counts.get(bin_value, 0)
        data.append([f"{bin_value:.1f}", count])

    headers = ['cvss_bin', 'count']
    save_csv(DATA_OUTPUT_DIR / 'cvss_histogram_data.csv', data, headers)
    return len(data)

def aggregate_vuln_count_per_host(findings, hosts, vulns):
    """Distribuzione vulnerabilità per host (1-5, 6-9, 10+) - escluso Info."""
    host_vuln_counts = Counter()

    # Create vuln map for quick lookup
    vuln_map = {v['vuln_id']: v for v in vulns}

    for finding in findings:
        vuln = vuln_map.get(finding['vuln_id'])
        if vuln and vuln['severity'] != 'Info':
            host_vuln_counts[finding['ip']] += 1

    # Categorize
    categories = {'1-5': 0, '6-9': 0, '10+': 0}

    for ip in set(h['ip'] for h in hosts):
        count = host_vuln_counts.get(ip, 0)
        if count == 0:
            continue
        elif 1 <= count <= 5:
            categories['1-5'] += 1
        elif 6 <= count <= 9:
            categories['6-9'] += 1
        else:
            categories['10+'] += 1

    data = [
        ['1-5', categories['1-5']],
        ['6-9', categories['6-9']],
        ['10+', categories['10+']]
    ]

    headers = ['category', 'count']
    save_csv(DATA_OUTPUT_DIR / 'vuln_count_per_host.csv', data, headers)
    return data

def aggregate_top_vulns_by_cvss(vulns, findings):
    """Top 10 vulnerabilità per CVSS score (escluso Info)."""
    vuln_cvss = []

    # Get unique vulns with their CVSS and occurrence count
    vuln_counts = Counter()
    for finding in findings:
        vuln_counts[finding['vuln_id']] += 1

    for vuln in vulns:
        if vuln['severity'] != 'Info':
            try:
                cvss = float(vuln['cvss_score'])
                count = vuln_counts.get(vuln['vuln_id'], 0)
                vuln_cvss.append((vuln, cvss, count))
            except (ValueError, TypeError):
                pass

    # Sort by CVSS descending
    vuln_cvss.sort(key=lambda x: x[1], reverse=True)

    top_cvss = []
    for i, (vuln, cvss, count) in enumerate(vuln_cvss[:10]):
        top_cvss.append([
            i + 1,  # rank
            vuln['name'],
            vuln['severity'],
            cvss,
            count
        ])

    headers = ['rank', 'vuln_name', 'severity', 'cvss', 'hosts_affected']
    save_csv(DATA_OUTPUT_DIR / 'top_vulns_by_cvss.csv', top_cvss, headers)
    return len(top_cvss)

def aggregate_appendix_a_vulnerability_summary(vulns, findings):
    """
    Appendix A: Vulnerability Summary
    Tutte le vulnerabilità con count current (no previous, no change per single scan).
    """
    vuln_counts = Counter()
    for finding in findings:
        vuln_counts[finding['vuln_id']] += 1

    # Build summary data sorted by severity then by count
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Unknown': 5}
    summary_data = []

    for vuln in vulns:
        vuln_id = vuln['vuln_id']
        current_count = vuln_counts.get(vuln_id, 0)

        summary_data.append([
            vuln['name'],
            vuln['severity'],
            0,  # previous (always 0 for single scan)
            current_count,
            'N/A'  # change (N/A for single scan)
        ])

    # Sort by severity then by current count descending
    summary_data.sort(key=lambda x: (severity_order.get(x[1], 99), -x[3]))

    headers = ['vulnerability', 'severity', 'previous', 'current', 'change']
    save_csv(DATA_OUTPUT_DIR / 'appendix_a_vuln_summary.csv', summary_data, headers)
    return len(summary_data)

def aggregate_appendix_b1_detailed_findings(vulns, findings):
    """
    Appendix B.1: Detailed Findings
    Tutti i findings con dettagli vulnerabilità (senza last_detected, status e Info severity).
    Include QoD (Quality of Detection) estratto dai dati originali.
    """
    # Create mapping from vuln_id to vuln details
    vuln_map = {v['vuln_id']: v for v in vulns}

    # Build detailed findings
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Unknown': 5}
    detailed_findings = []

    for finding in findings:
        vuln_id = finding['vuln_id']
        vuln = vuln_map.get(vuln_id)

        # Skip Info severity
        if vuln and vuln['severity'] != 'Info':
            # QoD from vulnerabilities table (already extracted from raw_data)
            qod = int(vuln.get('qod', 70))

            detailed_findings.append([
                finding['ip'],
                finding['port'],
                finding['protocol'],
                vuln_id,
                vuln['name'],
                vuln['severity'],
                vuln['cvss_score'],
                qod,
                finding['first_detected']
            ])

    # Sort by severity, then by IP, then by port
    detailed_findings.sort(key=lambda x: (severity_order.get(x[5], 99), x[0], int(x[1]) if str(x[1]).isdigit() else 0))

    headers = ['ip', 'port', 'protocol', 'vuln_id', 'vuln_name', 'severity', 'cvss', 'qod', 'first_detected']
    save_csv(DATA_OUTPUT_DIR / 'appendix_b1_detailed_findings.csv', detailed_findings, headers)
    return len(detailed_findings)

def main():
    """Main execution."""
    print("=" * 60)
    print("DATA AGGREGATOR - Task 4.2")
    print("=" * 60)

    # Create output directory
    DATA_OUTPUT_DIR.mkdir(exist_ok=True)
    print(f"\n✓ Output directory: {DATA_OUTPUT_DIR}")

    # Load input data
    print("\n[1/7] Loading input CSV files...")
    hosts = load_csv(DATA_INPUT_DIR / 'hosts.csv')
    vulns = load_csv(DATA_INPUT_DIR / 'vulnerabilities.csv')
    findings = load_csv(DATA_INPUT_DIR / 'findings.csv')
    print(f"  → {len(hosts)} hosts")
    print(f"  → {len(vulns)} unique vulnerabilities")
    print(f"  → {len(findings)} findings")

    # Aggregate metrics
    print("\n[2/7] Aggregating severity breakdown...")
    severity_counts = aggregate_severity_breakdown(vulns, findings)
    print(f"  → {len(severity_counts)} severity levels")

    print("\n[3/7] Aggregating top vulnerabilities by occurrence...")
    top_vulns_count = aggregate_top_vulns_by_occurrence(vulns, findings)
    print(f"  → {top_vulns_count} top vulnerabilities")

    print("\n[4/7] Aggregating top high-risk hosts...")
    top_hosts_count = aggregate_top_high_risk_hosts(
        findings, vulns, ANALYSIS_DIR / 'hosts_ranked.json'
    )
    print(f"  → {top_hosts_count} top hosts")

    print("\n[5/7] Aggregating CVSS histogram...")
    cvss_bins = aggregate_cvss_histogram(vulns, findings)
    print(f"  → {cvss_bins} CVSS bins")

    print("\n[6/7] Aggregating vulnerability count per host...")
    vuln_dist = aggregate_vuln_count_per_host(findings, hosts, vulns)
    print(f"  → {len(vuln_dist)} categories")

    print("\n[7/8] Aggregating top vulnerabilities by CVSS...")
    top_cvss_count = aggregate_top_vulns_by_cvss(vulns, findings)
    print(f"  → {top_cvss_count} top CVSS vulnerabilities")

    print("\n[8/9] Aggregating Appendix A - Vulnerability Summary...")
    appendix_a_count = aggregate_appendix_a_vulnerability_summary(vulns, findings)
    print(f"  → {appendix_a_count} vulnerabilities in summary")

    print("\n[9/9] Aggregating Appendix B.1 - Detailed Findings...")
    appendix_b1_count = aggregate_appendix_b1_detailed_findings(vulns, findings)
    print(f"  → {appendix_b1_count} detailed findings")

    # Summary
    print("\n" + "=" * 60)
    print("AGGREGATION COMPLETE")
    print("=" * 60)
    print(f"\nOutput files in: {DATA_OUTPUT_DIR}")
    print(f"  - severity_breakdown.csv")
    print(f"  - top_vulns_by_occurrence.csv")
    print(f"  - top_high_risk_hosts.csv")
    print(f"  - cvss_histogram_data.csv")
    print(f"  - vuln_count_per_host.csv")
    print(f"  - top_vulns_by_cvss.csv")
    print(f"  - appendix_a_vuln_summary.csv")
    print(f"  - appendix_b1_detailed_findings.csv")
    print("\n✓ Ready for Task 4.3 (Chart Generation)")

if __name__ == '__main__':
    main()
