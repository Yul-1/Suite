#!/usr/bin/env python3
"""
Greenbone CSV to JSON Converter - Converte report CSV Greenbone in formato JSON unificato
Autore: Script generato per vulnerability assessment
Utilizzo: python3 greenbone_unifier.py [input_dir] [output.json]
Default: Processa tutti i file .csv da input/greenbone/ -> output/results/greenbone_unified.json
"""

import csv
import json
import sys
import re
from pathlib import Path
from typing import Dict, List, Any, Optional


class GreenboneUnifier:
    def __init__(self):
        self.hosts_data = {}  # Dizionario: IP -> dati host

        # Mapping colonne CSV comuni (Greenbone usa nomi diversi a seconda della versione)
        self.column_mappings = {
            'ip': ['IP', 'Host', 'Hostname', 'Target'],
            'hostname': ['Hostname', 'Host', 'DNS Name'],
            'port': ['Port', 'Port Protocol'],
            'cvss': ['CVSS', 'Severity (CVSS)', 'CVSS Score'],
            'severity': ['Severity', 'Risk', 'Threat'],
            'qod': ['QoD', 'Quality of Detection', 'QOD'],
            'nvt_name': ['NVT Name', 'Name', 'Vulnerability', 'Test'],
            'nvt_oid': ['NVT OID', 'OID', 'NVT-OID'],
            'summary': ['Summary', 'Description', 'Synopsis'],
            'specific_result': ['Specific Result', 'Result', 'Details'],
            'solution': ['Solution', 'Fix', 'Recommendation'],
            'solution_type': ['Solution Type', 'Solution_Type'],
            'cves': ['CVEs', 'CVE', 'CVE IDs'],
            'threat': ['Threat', 'Risk Factor', 'Severity'],
            'qod_type': ['QoD Type', 'QoD_Type', 'Detection Method'],
            'cvss_vector': ['CVSS Vector', 'CVSS_Vector', 'Vector'],
            'service': ['Service', 'Service Name'],
            'product': ['Product', 'Application'],
            'version': ['Version', 'Application Version'],
            'os': ['Operating System', 'OS', 'OS Name']
        }
    
    def find_column(self, row: Dict, field: str) -> Optional[str]:
        """Trova il valore di una colonna usando i mapping"""
        possible_names = self.column_mappings.get(field, [field])
        for name in possible_names:
            if name in row:
                value = row[name].strip()
                return value if value else None
        return None
    
    def parse_port(self, port_str: str) -> Dict[str, Any]:
        """Parse della stringa porta (es: '80/tcp' o 'general/tcp')"""
        if not port_str or port_str == '':
            return {'type': 'general', 'port': None, 'protocol': None}
        
        # Formato tipico: "80/tcp" o "general/tcp"
        parts = port_str.split('/')
        if len(parts) >= 1:
            port_part = parts[0].strip()
            protocol = parts[1].strip() if len(parts) > 1 else 'tcp'
            
            if port_part.lower() == 'general' or port_part == '':
                return {'type': 'general', 'port': None, 'protocol': None}
            
            try:
                port_num = int(port_part)
                return {'type': 'port', 'port': port_num, 'protocol': protocol}
            except ValueError:
                return {'type': 'general', 'port': None, 'protocol': None}
        
        return {'type': 'general', 'port': None, 'protocol': None}
    
    def parse_cvss(self, cvss_str: str) -> float:
        """Parse del CVSS score"""
        if not cvss_str:
            return 0.0
        
        # Rimuovi spazi e prendi solo il numero
        cvss_str = cvss_str.strip()
        
        # A volte il formato è "7.5 (High)" - prendi solo il numero
        match = re.search(r'(\d+\.?\d*)', cvss_str)
        if match:
            try:
                score = float(match.group(1))
                return min(max(score, 0.0), 10.0)  # Clamp tra 0 e 10
            except ValueError:
                return 0.0
        
        return 0.0
    
    def parse_qod(self, qod_str: str) -> int:
        """Parse del QoD (Quality of Detection)"""
        if not qod_str:
            return 0
        
        qod_str = qod_str.strip().replace('%', '')
        
        try:
            qod = int(float(qod_str))
            return min(max(qod, 0), 100)  # Clamp tra 0 e 100
        except ValueError:
            return 0
    
    def parse_cves(self, cve_str: str) -> List[str]:
        """Parse dei CVE IDs (formato: 'CVE-2021-1234, CVE-2021-5678')"""
        if not cve_str:
            return []
        
        # Trova tutti i CVE con regex
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, cve_str, re.IGNORECASE)
        
        # Normalizza a uppercase e rimuovi duplicati
        cves = list(set([cve.upper() for cve in cves]))
        cves.sort()
        
        return cves
    
    def normalize_severity(self, severity_str: str, cvss: float) -> str:
        """Normalizza severity in formato standard"""
        if not severity_str:
            # Calcola da CVSS se manca
            if cvss >= 9.0:
                return "Critical"
            elif cvss >= 7.0:
                return "High"
            elif cvss >= 4.0:
                return "Medium"
            elif cvss > 0.0:
                return "Low"
            else:
                return "Log"
        
        severity_str = severity_str.strip().lower()
        
        severity_map = {
            'critical': 'Critical',
            'high': 'High',
            'medium': 'Medium',
            'low': 'Low',
            'log': 'Log',
            'info': 'Log',
            'informational': 'Log',
            'none': 'Log'
        }
        
        return severity_map.get(severity_str, 'Log')
    
    def find_or_create_port(self, host: Dict, port_num: int, protocol: str, service: str = None, product: str = None, version: str = None) -> Dict:
        """Trova una porta esistente o la crea"""
        # Cerca porta esistente
        for port in host['ports']:
            if port['port'] == port_num and port['protocol'] == protocol:
                # Aggiorna info se più complete
                if service and not port.get('service'):
                    port['service'] = service
                if product and not port.get('product'):
                    port['product'] = product
                if version and not port.get('version'):
                    port['version'] = version
                return port
        
        # Crea nuova porta
        new_port = {
            'port': port_num,
            'protocol': protocol,
            'state': 'open',
            'vulnerabilities': []
        }
        
        if service:
            new_port['service'] = service
        if product:
            new_port['product'] = product
        if version:
            new_port['version'] = version
        
        host['ports'].append(new_port)
        return new_port
    
    def parse_csv(self, csv_file: Path) -> None:
        """Parse del file CSV Greenbone"""
        print(f"[INFO] Parsing CSV: {csv_file.name}")

        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                # Prova diversi delimitatori comuni
                sample = f.read(1024)
                f.seek(0)
                
                # Rileva delimitatore
                sniffer = csv.Sniffer()
                try:
                    dialect = sniffer.sniff(sample)
                    delimiter = dialect.delimiter
                except:
                    delimiter = ','  # Fallback
                
                print(f"[INFO] Delimitatore rilevato: '{delimiter}'")
                
                reader = csv.DictReader(f, delimiter=delimiter)
                
                row_count = 0
                for row in reader:
                    row_count += 1
                    
                    # Estrai IP
                    ip_addr = self.find_column(row, 'ip')
                    if not ip_addr:
                        print(f"[WARNING] Riga {row_count}: IP non trovato, skip")
                        continue
                    
                    # Inizializza host se non esiste
                    if ip_addr not in self.hosts_data:
                        self.hosts_data[ip_addr] = {
                            'ip': ip_addr,
                            'hostname': None,
                            'status': 'up',
                            'ports': [],
                            'general_vulnerabilities': []
                        }
                    
                    host = self.hosts_data[ip_addr]
                    
                    # Hostname
                    hostname = self.find_column(row, 'hostname')
                    if hostname and hostname != ip_addr and not host['hostname']:
                        host['hostname'] = hostname
                    
                    # Parse vulnerabilità
                    nvt_name = self.find_column(row, 'nvt_name')
                    if not nvt_name:
                        continue  # Skip se non c'è nome vulnerabilità
                    
                    # CVSS e Severity
                    cvss_str = self.find_column(row, 'cvss')
                    cvss = self.parse_cvss(cvss_str)
                    
                    severity_str = self.find_column(row, 'severity')
                    severity = self.normalize_severity(severity_str, cvss)
                    
                    # QoD
                    qod_str = self.find_column(row, 'qod')
                    qod = self.parse_qod(qod_str)
                    
                    qod_type = self.find_column(row, 'qod_type')
                    
                    # CVEs
                    cve_str = self.find_column(row, 'cves')
                    cve_ids = self.parse_cves(cve_str)
                    
                    # Altri campi
                    nvt_oid = self.find_column(row, 'nvt_oid')
                    threat = self.find_column(row, 'threat')
                    if not threat:
                        threat = severity  # Fallback
                    
                    summary = self.find_column(row, 'summary')
                    specific_result = self.find_column(row, 'specific_result')
                    solution = self.find_column(row, 'solution')
                    solution_type = self.find_column(row, 'solution_type')
                    cvss_vector = self.find_column(row, 'cvss_vector')
                    
                    # Service info
                    service = self.find_column(row, 'service')
                    product = self.find_column(row, 'product')
                    version = self.find_column(row, 'version')
                    
                    # Parse porta
                    port_str = self.find_column(row, 'port')
                    port_info = self.parse_port(port_str) if port_str else {'type': 'general', 'port': None, 'protocol': None}
                    
                    # Crea oggetto vulnerabilità (SENZA location, sarà implicita dalla posizione)
                    vuln_data = {
                        'nvt_oid': nvt_oid,
                        'nvt_name': nvt_name,
                        'severity': severity,
                        'cvss': cvss,
                        'cvss_vector': cvss_vector,
                        'threat': threat,
                        'qod': qod,
                        'qod_type': qod_type,
                        'cve_ids': cve_ids,
                        'summary': summary,
                        'specific_result': specific_result,
                        'solution': solution,
                        'solution_type': solution_type
                    }
                    
                    # Rimuovi campi None per pulizia
                    vuln_data = {k: v for k, v in vuln_data.items() if v is not None and v != '' and v != []}
                    
                    # Aggiungi vulnerabilità nel posto giusto
                    if port_info['type'] == 'port' and port_info['port']:
                        # Vulnerabilità su porta specifica
                        port_num = port_info['port']
                        protocol = port_info['protocol']
                        
                        # Trova o crea porta
                        port_obj = self.find_or_create_port(host, port_num, protocol, service, product, version)
                        
                        # Verifica duplicati nella porta
                        is_duplicate = False
                        for existing_vuln in port_obj['vulnerabilities']:
                            if existing_vuln.get('nvt_oid') == nvt_oid:
                                is_duplicate = True
                                break
                        
                        if not is_duplicate:
                            port_obj['vulnerabilities'].append(vuln_data)
                    
                    else:
                        # Vulnerabilità general (host-level)
                        # Verifica duplicati
                        is_duplicate = False
                        for existing_vuln in host['general_vulnerabilities']:
                            if existing_vuln.get('nvt_oid') == nvt_oid:
                                is_duplicate = True
                                break
                        
                        if not is_duplicate:
                            host['general_vulnerabilities'].append(vuln_data)
                
                print(f"[INFO] Processate {row_count} righe CSV")
        
        except Exception as e:
            print(f"[ERRORE] Errore durante il parsing CSV: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def process_directory(self, input_dir: str) -> int:
        """Processa tutti i file CSV in una directory"""
        input_path = Path(input_dir)

        if not input_path.exists():
            print(f"[ERRORE] Directory non trovata: {input_dir}")
            return 0

        if not input_path.is_dir():
            print(f"[ERRORE] Il percorso non è una directory: {input_dir}")
            return 0

        # Cerca tutti i file .csv nella directory
        csv_files = sorted(input_path.glob("*.csv"))

        if not csv_files:
            print(f"[WARNING] Nessun file CSV trovato in: {input_dir}")
            return 0

        print(f"[INFO] Trovati {len(csv_files)} file CSV in {input_dir}")
        print()

        # Processa ogni file
        for csv_file in csv_files:
            print(f"[INFO] Processando: {csv_file.name}")
            self.parse_csv(csv_file)
            print()

        return len(csv_files)

    def add_os_info(self) -> None:
        """Estrae informazioni OS dalle vulnerabilità Log/Info"""
        for ip, host in self.hosts_data.items():
            # Cerca in general_vulnerabilities
            for vuln in host['general_vulnerabilities']:
                # Cerca detection OS nelle vulnerabilità Log
                if vuln.get('severity') == 'Log':
                    nvt_name_lower = vuln['nvt_name'].lower()
                    specific_result = vuln.get('specific_result', '')
                    
                    # Pattern comuni per OS detection
                    if any(keyword in nvt_name_lower for keyword in ['os detection', 'operating system', 'os guess', 'os identification']):
                        # Estrai nome OS dal result
                        if specific_result:
                            # Cerca pattern tipo "Detected OS: Linux 5.x"
                            os_match = re.search(r'(?:Detected|Operating System|OS)[:\s]+([^\n]+)', specific_result, re.IGNORECASE)
                            if os_match:
                                os_name = os_match.group(1).strip()
                                
                                if 'os' not in host or not host.get('os'):
                                    host['os'] = {'name': os_name}
                                
                                # Cerca CPE
                                cpe_match = re.search(r'cpe:/[oa]:[^\s\n]+', specific_result, re.IGNORECASE)
                                if cpe_match:
                                    host['os']['cpe'] = cpe_match.group(0)
    
    def clean_data(self) -> None:
        """Pulizia finale dei dati"""
        for ip, host in self.hosts_data.items():
            # Ordina porte per numero
            host['ports'].sort(key=lambda x: (x['port'], x['protocol']))
            
            # Per ogni porta, ordina le vulnerabilità
            severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Log': 4}
            for port in host['ports']:
                port['vulnerabilities'].sort(key=lambda x: (
                    severity_order.get(x.get('severity', 'Log'), 4),
                    -x.get('cvss', 0.0)
                ))
            
            # Ordina general_vulnerabilities
            host['general_vulnerabilities'].sort(key=lambda x: (
                severity_order.get(x.get('severity', 'Log'), 4),
                -x.get('cvss', 0.0)
            ))
    
    def export_json(self, output_file: str = "greenbone_unified.json") -> None:
        """Esporta i dati in JSON"""
        # Converti dizionario in lista
        hosts_list = list(self.hosts_data.values())
        
        # Ordina per IP
        hosts_list.sort(key=lambda x: tuple(map(int, x['ip'].split('.'))))
        
        output_data = {
            "hosts": hosts_list
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        
        print(f"\n[SUCCESS] JSON unificato creato: {output_file}")
        print(f"[INFO] Totale host processati: {len(hosts_list)}")
        
        # Statistiche rapide
        total_ports = sum(len(h['ports']) for h in hosts_list)
        total_vulns_in_ports = sum(
            len(port['vulnerabilities']) 
            for host in hosts_list 
            for port in host['ports']
        )
        total_general_vulns = sum(len(h['general_vulnerabilities']) for h in hosts_list)
        total_vulns = total_vulns_in_ports + total_general_vulns
        
        # Conta per severity (da tutte le vulnerabilità)
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Log': 0}
        for host in hosts_list:
            # Vulnerabilità nelle porte
            for port in host['ports']:
                for vuln in port['vulnerabilities']:
                    severity = vuln.get('severity', 'Log')
                    if severity in severity_counts:
                        severity_counts[severity] += 1
            # Vulnerabilità generali
            for vuln in host['general_vulnerabilities']:
                severity = vuln.get('severity', 'Log')
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        print(f"[INFO] Totale porte uniche trovate: {total_ports}")
        print(f"[INFO] Totale vulnerabilità trovate: {total_vulns}")
        print(f"  - Vulnerabilità su porte specifiche: {total_vulns_in_ports}")
        print(f"  - Vulnerabilità host-level (general): {total_general_vulns}")
        print(f"[INFO] Breakdown per severity:")
        for sev, count in severity_counts.items():
            if count > 0:
                print(f"  - {sev}: {count}")


def main():
    print("=" * 60)
    print("Greenbone CSV to JSON Converter")
    print("=" * 60)
    print()

    # Determina le directory
    script_dir = Path(__file__).parent
    suite_root = script_dir.parent.parent  # Due livelli sopra: Suite/
    input_dir = suite_root / "input" / "greenbone"
    output_dir = suite_root / "output" / "results"
    output_file = output_dir / "greenbone_unified.json"

    # Permetti override tramite argomenti (opzionale)
    if len(sys.argv) > 1:
        input_dir = Path(sys.argv[1])
    if len(sys.argv) > 2:
        output_file = Path(sys.argv[2])

    print(f"[INFO] Directory input: {input_dir}")
    print(f"[INFO] File JSON output: {output_file}")
    print()

    # Verifica che la directory input esista
    if not input_dir.exists():
        print(f"[ERRORE] Directory input non trovata: {input_dir}")
        print(f"[INFO] Creare la directory e inserire i file CSV di Greenbone")
        sys.exit(1)

    # Crea directory output se non esiste
    output_dir.mkdir(parents=True, exist_ok=True)

    # Crea converter e processa tutti i file CSV
    converter = GreenboneUnifier()
    num_files = converter.process_directory(str(input_dir))

    if num_files == 0:
        print("[ERRORE] Nessun file CSV processato")
        sys.exit(1)

    print(f"[INFO] Processati {num_files} file CSV")
    print()

    # Post-processing
    converter.add_os_info()
    converter.clean_data()
    converter.export_json(str(output_file))

    print()
    print("=" * 60)
    print("[DONE] Conversione completata!")
    print("=" * 60)


if __name__ == "__main__":
    main()