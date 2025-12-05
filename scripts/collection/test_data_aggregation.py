#!/usr/bin/env python3
"""
Test Script for Data Aggregation - Vulnerability Assessment Suite
Verifica che tutti gli IP, porte e servizi siano correttamente aggregati

Utilizzo: python3 test_data_aggregation.py
"""

import json
import sys
from pathlib import Path

def load_json(file_path):
    """Carica file JSON"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] File non trovato: {file_path}")
        return None
    except json.JSONDecodeError as e:
        print(f"[ERROR] JSON malformato in {file_path}: {e}")
        return None

def test_all_nmap_hosts_included(nmap_data, master_data):
    """Test 1: Verifica che tutti gli IP da Nmap siano nel master_data"""
    print("\n[TEST 1] Verifica inclusione host Nmap...")

    nmap_ips = {host['ip'] for host in nmap_data.get('hosts', [])}
    master_ips = {host['ip'] for host in master_data.get('hosts', [])}

    missing_ips = nmap_ips - master_ips

    if missing_ips:
        print(f"  [FAIL] IP Nmap mancanti nel master_data: {missing_ips}")
        return False
    else:
        print(f"  [PASS] Tutti i {len(nmap_ips)} IP Nmap sono presenti nel master_data")
        return True

def test_all_greenbone_hosts_included(greenbone_data, master_data):
    """Test 2: Verifica che tutti gli IP da Greenbone siano nel master_data"""
    print("\n[TEST 2] Verifica inclusione host Greenbone...")

    gb_ips = {host['ip'] for host in greenbone_data.get('hosts', [])}
    master_ips = {host['ip'] for host in master_data.get('hosts', [])}

    missing_ips = gb_ips - master_ips

    if missing_ips:
        print(f"  [FAIL] IP Greenbone mancanti nel master_data: {missing_ips}")
        return False
    else:
        print(f"  [PASS] Tutti i {len(gb_ips)} IP Greenbone sono presenti nel master_data")
        return True

def test_nmap_ports_preserved(nmap_data, master_data):
    """Test 3: Verifica che le porte Nmap siano preservate"""
    print("\n[TEST 3] Verifica preservazione porte Nmap...")

    issues = []

    for nmap_host in nmap_data.get('hosts', []):
        ip = nmap_host['ip']
        nmap_ports = {(p['port'], p['protocol']) for p in nmap_host.get('ports', [])}

        # Trova host corrispondente in master_data
        master_host = next((h for h in master_data['hosts'] if h['ip'] == ip), None)

        if not master_host:
            issues.append(f"Host {ip} non trovato in master_data")
            continue

        master_ports = {(p['port'], p['protocol']) for p in master_host.get('ports', [])}

        missing_ports = nmap_ports - master_ports

        if missing_ports:
            issues.append(f"IP {ip}: porte Nmap mancanti {missing_ports}")

    if issues:
        print(f"  [FAIL] Problemi rilevati:")
        for issue in issues:
            print(f"    - {issue}")
        return False
    else:
        print(f"  [PASS] Tutte le porte Nmap sono preservate nel master_data")
        return True

def test_greenbone_ports_extracted(greenbone_data, master_data):
    """Test 4: Verifica che le porte Greenbone siano estratte"""
    print("\n[TEST 4] Verifica estrazione porte Greenbone...")

    issues = []

    for gb_host in greenbone_data.get('hosts', []):
        ip = gb_host['ip']
        gb_ports = {(p['port'], p['protocol']) for p in gb_host.get('ports', [])}

        # Trova host corrispondente in master_data
        master_host = next((h for h in master_data['hosts'] if h['ip'] == ip), None)

        if not master_host:
            issues.append(f"Host {ip} non trovato in master_data")
            continue

        master_ports = {(p['port'], p['protocol']) for p in master_host.get('ports', [])}

        missing_ports = gb_ports - master_ports

        if missing_ports:
            issues.append(f"IP {ip}: porte Greenbone mancanti {missing_ports}")

    if issues:
        print(f"  [FAIL] Problemi rilevati:")
        for issue in issues:
            print(f"    - {issue}")
        return False
    else:
        print(f"  [PASS] Tutte le porte Greenbone sono estratte nel master_data")
        return True

def test_source_tracking(master_data):
    """Test 5: Verifica tracciamento fonte dati"""
    print("\n[TEST 5] Verifica tracciamento fonte dati...")

    issues = []

    for host in master_data['hosts']:
        ip = host['ip']

        # Verifica campo source a livello host
        if 'source' not in host or not host['source']:
            issues.append(f"IP {ip}: campo 'source' mancante a livello host")

        # Verifica campo source a livello porta
        for port in host.get('ports', []):
            if 'source' not in port or not port['source']:
                issues.append(f"IP {ip}, porta {port['port']}: campo 'source' mancante")

    if issues:
        print(f"  [FAIL] Problemi rilevati:")
        for issue in issues:
            print(f"    - {issue}")
        return False
    else:
        print(f"  [PASS] Tracciamento fonte dati completo")
        return True

def test_cve_extraction(master_data):
    """Test 6: Verifica estrazione CVE IDs"""
    print("\n[TEST 6] Verifica estrazione CVE IDs...")

    total_cves = 0
    hosts_with_cves = 0

    for host in master_data['hosts']:
        for vuln in host.get('vulnerabilities', []):
            cve_ids = vuln.get('cve_ids', [])
            if cve_ids:
                total_cves += len(cve_ids)
                hosts_with_cves += 1

                # Verifica formato CVE
                for cve in cve_ids:
                    if not cve.startswith('CVE-'):
                        print(f"  [WARN] CVE ID malformato: {cve}")

    print(f"  [INFO] CVE IDs trovati: {total_cves}")
    print(f"  [INFO] Host con CVE: {hosts_with_cves}")
    print(f"  [PASS] Estrazione CVE completata")
    return True

def test_metrics_accuracy(master_data):
    """Test 7: Verifica accuratezza metriche"""
    print("\n[TEST 7] Verifica accuratezza metriche...")

    issues = []

    for host in master_data['hosts']:
        ip = host['ip']
        metrics = host.get('metrics', {})

        # Verifica conteggio porte
        actual_ports = len(host.get('ports', []))
        metrics_ports = metrics.get('total_ports', 0)

        if actual_ports != metrics_ports:
            issues.append(f"IP {ip}: porte reali={actual_ports}, metrics={metrics_ports}")

        # Verifica conteggio vulnerabilità
        actual_vulns = len(host.get('vulnerabilities', []))
        metrics_vulns = metrics.get('total_vulnerabilities', 0)

        if actual_vulns != metrics_vulns:
            issues.append(f"IP {ip}: vuln reali={actual_vulns}, metrics={metrics_vulns}")

    if issues:
        print(f"  [FAIL] Discrepanze rilevate:")
        for issue in issues:
            print(f"    - {issue}")
        return False
    else:
        print(f"  [PASS] Tutte le metriche sono accurate")
        return True

def print_summary(master_data):
    """Stampa riepilogo dati aggregati"""
    print("\n" + "=" * 70)
    print("RIEPILOGO AGGREGAZIONE DATI")
    print("=" * 70)

    metadata = master_data.get('metadata', {})

    print(f"\nHost totali: {metadata.get('total_hosts', 0)}")
    print(f"  - Da Nmap: {metadata.get('nmap_hosts', 0)}")
    print(f"  - Da Greenbone: {metadata.get('greenbone_hosts', 0)}")
    print(f"  - Da entrambe le fonti: {metadata.get('both_sources', 0)}")

    print(f"\nPorte totali: {metadata.get('total_ports', 0)}")
    print(f"Vulnerabilità totali: {metadata.get('total_vulnerabilities', 0)}")

    # Statistiche per fonte
    nmap_only = 0
    gb_only = 0
    both = 0

    for host in master_data.get('hosts', []):
        sources = host.get('source', [])
        if len(sources) == 1:
            if 'nmap' in sources:
                nmap_only += 1
            else:
                gb_only += 1
        elif len(sources) > 1:
            both += 1

    print(f"\nDistribuzione host per fonte:")
    print(f"  - Solo Nmap: {nmap_only}")
    print(f"  - Solo Greenbone: {gb_only}")
    print(f"  - Entrambe: {both}")

def main():
    """Main test function"""
    print("=" * 70)
    print("TEST SUITE - AGGREGAZIONE DATI VULNERABILITY ASSESSMENT")
    print("=" * 70)

    # Percorsi file
    results_dir = Path(__file__).parent.parent.parent / "output" / "results"
    nmap_file = results_dir / "nmap_unified.json"
    greenbone_file = results_dir / "greenbone_unified.json"
    master_file = results_dir / "master_data.json"

    print(f"\nCaricamento file...")
    print(f"  - Nmap: {nmap_file}")
    print(f"  - Greenbone: {greenbone_file}")
    print(f"  - Master: {master_file}")

    # Carica dati
    nmap_data = load_json(nmap_file)
    greenbone_data = load_json(greenbone_file)
    master_data = load_json(master_file)

    if not nmap_data or not greenbone_data or not master_data:
        print("\n[ERROR] Impossibile caricare i file necessari")
        sys.exit(1)

    print("\n[INFO] File caricati con successo")

    # Esegui test
    results = []

    results.append(test_all_nmap_hosts_included(nmap_data, master_data))
    results.append(test_all_greenbone_hosts_included(greenbone_data, master_data))
    results.append(test_nmap_ports_preserved(nmap_data, master_data))
    results.append(test_greenbone_ports_extracted(greenbone_data, master_data))
    results.append(test_source_tracking(master_data))
    results.append(test_cve_extraction(master_data))
    results.append(test_metrics_accuracy(master_data))

    # Riepilogo
    print_summary(master_data)

    # Risultato finale
    passed = sum(results)
    total = len(results)

    print("\n" + "=" * 70)
    print("RISULTATO FINALE")
    print("=" * 70)
    print(f"\nTest superati: {passed}/{total}")

    if passed == total:
        print("\n✅ TUTTI I TEST SUPERATI - Aggregazione dati corretta!")
        sys.exit(0)
    else:
        print(f"\n❌ {total - passed} TEST FALLITI - Verificare l'aggregazione")
        sys.exit(1)

if __name__ == "__main__":
    main()
