#!/usr/bin/env python3
"""
Nmap Results Unifier - Versione Ottimizzata e Robusta
Estrae e unifica i risultati delle scansioni Nmap con:
- Validazione XML robusta con fallback
- Filtraggio intelligente (mantiene dati utili, rimuove solo rumore)
- Sistema di backup automatico
- Error handling avanzato per XML malformati
- Gestione encoding UTF-8 per caratteri speciali

Autore: Script per vulnerability assessment
Utilizzo: python3 nmap_unifier.py [input_dir] [output_dir]
Default: Legge XML da input/nmap/ -> Scrive JSON in output/results/nmap_unified.json
"""

import json
import xml.etree.ElementTree as ET
import os
import sys
import re
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import shutil


class NmapUnifier:
    def __init__(self, input_dir: str = None, output_dir: str = None):
        # Determina le directory se non specificate
        if input_dir is None or output_dir is None:
            script_dir = Path(__file__).parent
            suite_root = script_dir.parent.parent  # Due livelli sopra: Suite/

        self.input_dir = Path(input_dir) if input_dir else suite_root / "input" / "nmap"
        self.output_dir = Path(output_dir) if output_dir else suite_root / "output" / "results"
        self.hosts_data = {}
        
        # Script con output potenzialmente lungo (limite caratteri più generoso)
        self.long_output_scripts = {
            'http-enum': 8000,      # Aumentato per mantenere più directory
            'http-methods': 3000,
            'http-title': 2000,
            'ssl-cert': 5000,       # Certificati possono essere lunghi
            'ssh-hostkey': 3000,
        }
        
        # Pattern da filtrare - SOLO rumore tecnico inutile
        self.noise_patterns = [
            # Fingerprint submission requests (inutili per assessment)
            r'Service Info:.*unrecognized despite returning data.*',
            r'If you know the service/version.*please submit.*',
            r'please submit the following fingerprint.*',
            
            # Fingerprint raw data (troppo tecnico e inutile)
            r'SF-Port\d+-TCP:.*',
            r'SF:.*',
            
            # Metadati nmap inutili
            r'Service detection performed\. Please report.*',
        ]
        
        # Pattern che indicano contenuto UTILE (non filtrare mai)
        self.useful_patterns = [
            r'CVE-\d{4}-\d{4,}',        # CVE IDs
            r'VULNERABLE',               # Keyword vulnerabilità
            r'version\s+\d+',            # Versioni software
            r'port\s+\d+',               # Porte
            r'http[s]?://',              # URLs
            r'default\s+credentials?',   # Credenziali default
            r'authentication',           # Info autenticazione
            r'encryption',               # Info cifratura
            r'certificate',              # Certificati
        ]
    
    def is_useful_content(self, text: str) -> bool:
        """Verifica se il contenuto contiene informazioni utili per security assessment"""
        if not text or len(text.strip()) < 10:
            return False
        
        text_lower = text.lower()
        
        # Se contiene pattern utili, mantienilo sempre
        for pattern in self.useful_patterns:
            if re.search(pattern, text_lower):
                return True
        
        # Mantieni descrizioni di servizi
        if any(keyword in text_lower for keyword in [
            'server', 'service', 'version', 'protocol', 'running',
            'detected', 'identified', 'listening', 'open'
        ]):
            return True
        
        return True  # Di default mantieni (cambio filosofia: filtro solo rumore esplicito)
    
    def should_filter_text(self, text: str) -> bool:
        """Verifica se il testo è RUMORE da filtrare (approccio conservativo)"""
        if not text or len(text.strip()) < 5:
            return True
        
        text_lower = text.lower()
        
        # NON filtrare se contiene contenuto utile
        if self.is_useful_content(text):
            # Ma controlla se è SOLO fingerprint submission
            if 'please submit the following fingerprint' in text_lower and len(text) > 500:
                # Se è principalmente fingerprint data, filtra
                if text.count('SF-Port') > 0 or text.count('SF:') > 3:
                    return True
            return False
        
        # Filtra se contiene solo metadati tecnici inutili
        metadata_count = sum(1 for pattern in [
            'unrecognized despite',
            'sf-port',
            'sf:',
            'service detection performed'
        ] if pattern in text_lower)
        
        if metadata_count >= 2:
            return True
        
        # Filtra se troppo lungo E senza contenuto utile (> 15000 caratteri)
        if len(text) > 15000 and not self.is_useful_content(text):
            return True
        
        return False
    
    def clean_script_output(self, script_id: str, output: str) -> Optional[str]:
        """Pulisce l'output degli script mantenendo dati utili"""
        if not output:
            return None
        
        # Prima verifica: se tutto il contenuto è rumore, scarta
        if self.should_filter_text(output):
            return None
        
        cleaned = output
        
        # Rimuovi solo pattern di rumore espliciti (mantenendo resto)
        for pattern in self.noise_patterns:
            cleaned = re.sub(pattern, '', cleaned, flags=re.IGNORECASE | re.MULTILINE)
        
        cleaned = cleaned.strip()
        
        # Gestione script con output lungo (tronca intelligentemente)
        if script_id in self.long_output_scripts:
            max_length = self.long_output_scripts[script_id]
            
            if len(cleaned) > max_length:
                lines = cleaned.split('\n')
                
                if script_id == 'http-enum':
                    # Per http-enum mantieni più contenuto (directory interessanti)
                    truncated_lines = []
                    useful_lines = 0
                    
                    for line in lines:
                        # Mantieni header, descrizioni e linee con path
                        if any(marker in line for marker in ['|', '/', 'http', 'directory', 'file']):
                            truncated_lines.append(line)
                            if line.strip() and not line.strip().startswith('|'):
                                useful_lines += 1
                        elif useful_lines < 100:  # Prime 100 righe utili
                            truncated_lines.append(line)
                            if line.strip():
                                useful_lines += 1
                        else:
                            break
                    
                    if useful_lines >= 100:
                        omitted = len(lines) - len(truncated_lines)
                        truncated_lines.append(f"\n... [Output troncato: {omitted} righe omesse per brevità]")
                    
                    cleaned = '\n'.join(truncated_lines)
                
                elif script_id in ['ssl-cert', 'ssh-hostkey']:
                    # Per certificati/chiavi, mantieni tutto se contiene info utili
                    if not self.is_useful_content(cleaned[:max_length]):
                        cleaned = cleaned[:max_length] + f"\n... [Output troncato]"
                
                else:
                    # Altri script: tronca a caratteri mantenendo linee complete
                    cleaned = cleaned[:max_length]
                    if len(output) > max_length:
                        last_newline = cleaned.rfind('\n')
                        if last_newline > max_length * 0.8:  # Se c'è newline negli ultimi 20%
                            cleaned = cleaned[:last_newline]
                        cleaned += f"\n... [Output troncato: {len(output) - len(cleaned)} caratteri omessi]"
        
        # Verifica finale: se dopo pulizia rimane poco, valuta se scartare
        if len(cleaned) < 15:
            return None
        
        return cleaned
    
    def extract_cve_from_text(self, text: str) -> List[str]:
        """Estrae CVE IDs da un testo"""
        if not text:
            return []
        
        cve_pattern = r'CVE-\d{4}-\d{4,}'
        cves = re.findall(cve_pattern, text, re.IGNORECASE)
        cves = list(set([cve.upper() for cve in cves]))
        cves.sort()
        
        return cves
    
    def is_vulnerability_script(self, script_id: str, output: str) -> bool:
        """Determina se uno script rappresenta una vulnerabilità"""
        # Lista estesa di keyword per vulnerabilità
        vuln_keywords = [
            'vuln', 'cve', 'vulnerable', 'exploit', 'weakness',
            'attack', 'compromise', 'malicious', 'backdoor',
            'injection', 'overflow', 'bypass', 'privilege'
        ]
        
        # Script che sono sempre considerati vulnerabilità
        vuln_scripts = [
            'vuln', 'vulscan', 'vulners', 'cve',
            'ssl-poodle', 'ssl-heartbleed', 'ssl-dh',
            'smb-vuln', 'http-vuln', 'ftp-vuln'
        ]
        
        script_lower = script_id.lower()
        
        # Check script ID
        if any(vs in script_lower for vs in vuln_scripts):
            return True
        
        if any(keyword in script_lower for keyword in vuln_keywords):
            return True
        
        # Check output
        if output:
            output_lower = output.lower()
            if any(keyword in output_lower for keyword in ['vulnerable', 'cve-', 'exploit', 'weakness']):
                return True
        
        return False
    
    def find_or_create_port(self, host: Dict, port_num: int, protocol: str) -> Dict:
        """Trova una porta esistente o la crea"""
        for port in host['ports']:
            if port['port'] == port_num and port['protocol'] == protocol:
                return port
        
        new_port = {
            'port': port_num,
            'protocol': protocol,
            'state': 'open',
            'scripts': []
        }
        host['ports'].append(new_port)
        return new_port
    
    def merge_port_data(self, existing: Dict, new_data: Dict) -> None:
        """Merge intelligente dei dati di una porta"""
        # Aggiorna campi semplici se più completi
        for key in ['service', 'product', 'version', 'extrainfo', 'ostype', 'hostname']:
            if key in new_data and new_data[key]:
                if key not in existing or not existing[key]:
                    existing[key] = new_data[key]
                elif len(str(new_data[key])) > len(str(existing.get(key, ''))):
                    # Usa il valore più lungo/dettagliato
                    existing[key] = new_data[key]
        
        # Merge script evitando duplicati
        if 'scripts' in new_data and new_data['scripts']:
            if 'scripts' not in existing:
                existing['scripts'] = []
            
            existing_script_ids = {s['id'] for s in existing['scripts']}
            
            for script in new_data['scripts']:
                if script['id'] not in existing_script_ids:
                    existing['scripts'].append(script)
                    existing_script_ids.add(script['id'])
                else:
                    # Se script già esiste, aggiorna se nuovo output è più lungo
                    for idx, existing_script in enumerate(existing['scripts']):
                        if existing_script['id'] == script['id']:
                            if len(script.get('output', '')) > len(existing_script.get('output', '')):
                                existing['scripts'][idx] = script
                            break
    
    def fix_malformed_xml(self, xml_content: str) -> str:
        """Tenta di correggere XML malformato"""
        # Fix 1: Sostituisci START_TIME placeholder se presente
        xml_content = re.sub(
            r'start="START_TIME"',
            f'start="{int(datetime.now().timestamp())}"',
            xml_content
        )
        
        # Fix 2: Escape caratteri speciali non escaped in attributi
        # Questo è un fix basilare, XML molto corrotto potrebbe comunque fallire
        
        # Fix 3: Rimuovi caratteri di controllo non validi
        xml_content = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', '', xml_content)
        
        # Fix 4: Assicurati che ci sia un root tag di chiusura
        if '<nmaprun' in xml_content and '</nmaprun>' not in xml_content:
            xml_content += '</nmaprun>'
        
        return xml_content
    
    def parse_xml_file(self, xml_file: Path, phase_name: str) -> int:
        """Parse del file XML Nmap con validazione e error recovery"""
        print(f"[INFO] Parsing: {xml_file.name} ({phase_name})")
        
        parsed_hosts = 0
        
        try:
            # Leggi file con encoding UTF-8
            with open(xml_file, 'r', encoding='utf-8') as f:
                xml_content = f.read()
            
            # Primo tentativo: parse diretto
            try:
                tree = ET.fromstring(xml_content)
            except ET.ParseError as e:
                print(f"  [WARNING] XML malformato, tentativo correzione automatica...")
                print(f"  [DEBUG] Errore originale: {e}")
                
                # Tentativo di fix
                xml_content_fixed = self.fix_malformed_xml(xml_content)
                
                try:
                    tree = ET.fromstring(xml_content_fixed)
                    print(f"  [SUCCESS] XML corretto con successo")
                except ET.ParseError as e2:
                    print(f"  [ERROR] Impossibile correggere XML: {e2}")
                    print(f"  [INFO] Saltando file {xml_file.name}")
                    return 0
            
            # Parse degli host
            for host_elem in tree.findall('.//host'):
                # Estrai IP
                ip_addr = None
                for addr in host_elem.findall('address'):
                    if addr.get('addrtype') in ['ipv4', 'ipv6']:
                        ip_addr = addr.get('addr')
                        break
                
                if not ip_addr:
                    continue
                
                # Inizializza host se non esiste
                if ip_addr not in self.hosts_data:
                    self.hosts_data[ip_addr] = {
                        'ip': ip_addr,
                        'hostname': None,
                        'status': 'unknown',
                        'ports': [],
                        'host_scripts': [],
                        'vulnerabilities': [],
                        'os': None
                    }
                
                host = self.hosts_data[ip_addr]
                parsed_hosts += 1
                
                # Status
                status_elem = host_elem.find('status')
                if status_elem is not None:
                    state = status_elem.get('state', 'unknown')
                    # Aggiorna solo se più specifico
                    if host['status'] == 'unknown' or state == 'up':
                        host['status'] = state
                
                # Hostname
                hostnames_elem = host_elem.find('hostnames')
                if hostnames_elem is not None:
                    for hostname_elem in hostnames_elem.findall('hostname'):
                        hostname = hostname_elem.get('name')
                        if hostname and not host['hostname']:
                            host['hostname'] = hostname
                            break
                
                # OS Detection (migliora rilevamento)
                os_elem = host_elem.find('os')
                if os_elem is not None:
                    osmatch_list = os_elem.findall('osmatch')
                    if osmatch_list:
                        best_os = max(osmatch_list, key=lambda x: int(x.get('accuracy', 0)))
                        accuracy = int(best_os.get('accuracy', 0))
                        
                        # Abbassa soglia a 70% (era 80%)
                        if accuracy >= 70:
                            os_data = {
                                'name': best_os.get('name'),
                                'accuracy': accuracy
                            }
                            
                            osclass = best_os.find('osclass')
                            if osclass is not None:
                                os_data['type'] = osclass.get('type')
                                os_data['vendor'] = osclass.get('vendor')
                                os_data['osfamily'] = osclass.get('osfamily')
                                os_data['osgen'] = osclass.get('osgen')
                            
                            # Aggiorna solo se più accurato
                            if host['os'] is None or host['os'].get('accuracy', 0) < accuracy:
                                host['os'] = os_data
                
                # Porte e servizi
                ports_elem = host_elem.find('ports')
                if ports_elem is not None:
                    for port_elem in ports_elem.findall('port'):
                        try:
                            port_id = int(port_elem.get('portid'))
                            protocol = port_elem.get('protocol', 'tcp')
                            
                            state_elem = port_elem.find('state')
                            if state_elem is None:
                                continue
                            
                            state = state_elem.get('state')
                            
                            # Mantieni solo porte aperte
                            if state != 'open':
                                continue
                            
                            port_data = {
                                'port': port_id,
                                'protocol': protocol,
                                'state': state,
                                'scripts': []
                            }
                            
                            # Informazioni servizio (più campi)
                            service_elem = port_elem.find('service')
                            if service_elem is not None:
                                for attr in ['name', 'product', 'version', 'extrainfo', 'ostype', 'method', 'conf']:
                                    value = service_elem.get(attr)
                                    if value and (attr == 'extrainfo' and not self.should_filter_text(value) or attr != 'extrainfo'):
                                        port_data[attr if attr != 'name' else 'service'] = value
                            
                            # Script output (mantieni di più)
                            for script_elem in port_elem.findall('script'):
                                script_id = script_elem.get('id')
                                script_output = script_elem.get('output', '')
                                
                                cleaned_output = self.clean_script_output(script_id, script_output)
                                
                                if cleaned_output:
                                    script_data = {
                                        'id': script_id,
                                        'output': cleaned_output
                                    }
                                    
                                    # Aggiungi elementi table se presenti (struttura dati)
                                    tables = script_elem.findall('.//table')
                                    if tables:
                                        script_data['tables'] = []
                                        for table in tables[:10]:  # Max 10 tabelle
                                            table_data = {'key': table.get('key')}
                                            elems = table.findall('elem')
                                            if elems:
                                                table_data['elements'] = {
                                                    e.get('key'): e.text for e in elems if e.text
                                                }
                                            script_data['tables'].append(table_data)
                                    
                                    port_data['scripts'].append(script_data)
                            
                            # Merge con porta esistente o aggiungi nuova
                            existing_port = self.find_or_create_port(host, port_data['port'], port_data['protocol'])
                            self.merge_port_data(existing_port, port_data)
                        
                        except (ValueError, TypeError) as e:
                            print(f"  [WARNING] Errore parsing porta: {e}")
                            continue
                
                # Host scripts
                hostscript_elem = host_elem.find('hostscript')
                if hostscript_elem is not None:
                    for script_elem in hostscript_elem.findall('script'):
                        script_id = script_elem.get('id')
                        script_output = script_elem.get('output', '')
                        
                        cleaned_output = self.clean_script_output(script_id, script_output)
                        
                        if not cleaned_output:
                            continue
                        
                        script_data = {
                            'id': script_id,
                            'output': cleaned_output
                        }
                        
                        # Aggiungi tabelle se presenti
                        tables = script_elem.findall('.//table')
                        if tables:
                            script_data['tables'] = []
                            for table in tables[:10]:
                                table_data = {'key': table.get('key')}
                                elems = table.findall('elem')
                                if elems:
                                    table_data['elements'] = {
                                        e.get('key'): e.text for e in elems if e.text
                                    }
                                script_data['tables'].append(table_data)
                        
                        # Distingui vulnerabilità da info
                        if self.is_vulnerability_script(script_id, cleaned_output):
                            cve_ids = self.extract_cve_from_text(cleaned_output)
                            
                            vuln_data = {
                                'source': 'nmap',
                                'script': script_id,
                                'description': cleaned_output,
                                'cve_ids': cve_ids,
                                'phase': phase_name
                            }
                            
                            if 'tables' in script_data:
                                vuln_data['tables'] = script_data['tables']
                            
                            # Evita duplicati
                            if not any(v.get('script') == script_id for v in host['vulnerabilities']):
                                host['vulnerabilities'].append(vuln_data)
                        else:
                            # Host script informativo
                            if not any(s.get('id') == script_id for s in host['host_scripts']):
                                host['host_scripts'].append(script_data)
            
            print(f"  -> Processati {parsed_hosts} host")
            return parsed_hosts
        
        except Exception as e:
            print(f"[ERROR] Errore generico in {xml_file.name}: {e}")
            import traceback
            traceback.print_exc()
            return 0
    
    def process_all_phases(self) -> None:
        """Processa tutti i file XML trovati nella directory di input."""
        
        xml_files = sorted(list(self.input_dir.glob("*.xml")))
        
        total_processed = 0
        total_found = len(xml_files)
        
        print("\n" + "=" * 70)
        print("INIZIO PARSING FILE NMAP (Modalità Flessibile)")
        print(f"Trovati {total_found} file XML in: {self.input_dir.resolve()}")
        print("=" * 70 + "\n")
        
        if total_found == 0:
            print(f"[ERROR] Nessun file XML trovato nella directory: {self.input_dir}")
            sys.exit(1)

        for xml_file in xml_files:
            # Usa il nome del file (senza estensione) come nome della fase
            phase_name = xml_file.stem.replace('_', ' ').title()
            
            # Parsing del file
            count = self.parse_xml_file(xml_file, phase_name)
            if count > 0:
                total_processed += 1
            
        
        print(f"\n[INFO] File trovati: {total_found}")
        print(f"[INFO] File processati con successo: {total_processed}/{total_found}")
        
        if total_processed == 0:
            print("\n[ERROR] Nessun file XML processato con successo!")
            sys.exit(1)
        elif total_processed < total_found:
            print("\n[WARNING] Alcuni file non sono stati processati a causa di errori")
            print("[INFO] Continuo con i dati disponibili...")
    
    def clean_and_enrich_data(self) -> None:
        """Pulizia finale e arricchimento dati"""
        print("\n[INFO] Pulizia e arricchimento dati...")
        
        for ip, host in list(self.hosts_data.items()):
            # Rimuovi host down
            if host['status'] != 'up':
                del self.hosts_data[ip]
                continue
            
            # Ordina porte per numero
            host['ports'].sort(key=lambda x: (x['protocol'], x['port']))
            
            # Per ogni porta, estrai vulnerabilità dagli script
            for port in host['ports']:
                port_vulns = []
                scripts_to_keep = []
                
                for script in port.get('scripts', []):
                    if self.is_vulnerability_script(script['id'], script.get('output', '')):
                        cve_ids = self.extract_cve_from_text(script.get('output', ''))
                        
                        vuln_data = {
                            'source': 'nmap',
                            'script': script['id'],
                            'description': script.get('output', ''),
                            'cve_ids': cve_ids,
                            'port': port['port'],
                            'protocol': port['protocol']
                        }
                        
                        if 'tables' in script:
                            vuln_data['tables'] = script['tables']
                        
                        port_vulns.append(vuln_data)
                    else:
                        scripts_to_keep.append(script)
                
                # Aggiorna scripts (solo non-vulnerabilità)
                if scripts_to_keep:
                    port['scripts'] = scripts_to_keep
                else:
                    # Rimuovi chiave scripts se vuota
                    if 'scripts' in port:
                        del port['scripts']
                
                # Aggiungi vulnerabilità a livello porta
                if port_vulns:
                    port['vulnerabilities'] = port_vulns
                    # Aggiungi anche a livello host per facilità
                    host['vulnerabilities'].extend(port_vulns)
            
            # Rimuovi liste vuote
            if not host.get('host_scripts'):
                if 'host_scripts' in host:
                    del host['host_scripts']
            
            if not host.get('vulnerabilities'):
                if 'vulnerabilities' in host:
                    del host['vulnerabilities']
            
            if not host.get('os'):
                if 'os' in host:
                    del host['os']
        
        print(f"[INFO] Host attivi dopo pulizia: {len(self.hosts_data)}")
    
    def create_backup(self, output_file: str) -> Optional[Path]:
        """Crea backup del JSON esistente"""
        output_path = self.output_dir / output_file
        
        if not output_path.exists():
            return None
        
        # Genera nome backup con timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"{output_path.stem}_backup_{timestamp}{output_path.suffix}"
        backup_path = self.output_dir / backup_name
        
        try:
            shutil.copy2(output_path, backup_path)
            print(f"[INFO] Backup creato: {backup_name}")
            return backup_path
        except Exception as e:
            print(f"[WARNING] Impossibile creare backup: {e}")
            return None
    
    def export_json(self, output_file: str = "nmap_unified.json") -> None:
        """Esporta i dati in JSON con backup automatico"""
        # Crea directory output se non esiste
        self.output_dir.mkdir(parents=True, exist_ok=True)

        output_path = self.output_dir / output_file
        
        # Crea backup se file esiste
        if output_path.exists():
            backup = self.create_backup(output_file)
            if backup:
                # Mantieni solo ultimi 5 backup
                self.cleanup_old_backups(output_file, keep=5)
        
        # Prepara dati per export
        hosts_list = list(self.hosts_data.values())
        
        # Ordina per IP
        def ip_sort_key(host):
            try:
                parts = host['ip'].split('.')
                return tuple(int(part) for part in parts)
            except:
                return (0, 0, 0, 0)
        
        hosts_list.sort(key=ip_sort_key)
        
        # Calcola statistiche
        total_ports = sum(len(h['ports']) for h in hosts_list)
        hosts_with_os = sum(1 for h in hosts_list if h.get('os'))
        
        total_host_vulns = sum(len(h.get('vulnerabilities', [])) for h in hosts_list)
        
        # Conta CVE unici
        all_cves = set()
        for host in hosts_list:
            for vuln in host.get('vulnerabilities', []):
                all_cves.update(vuln.get('cve_ids', []))
        
        # Prepara metadata
        output_data = {
            "scan_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_hosts": len(hosts_list),
                "total_ports": total_ports,
                "hosts_with_os": hosts_with_os,
                "total_vulnerabilities": total_host_vulns,
                "unique_cves": len(all_cves),
                "source": "nmap",
                "version": "2.0"
            },
            "hosts": hosts_list
        }
        
        # Scrivi JSON con formattazione pulita
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            print("\n" + "=" * 70)
            print("STATISTICHE FINALI")
            print("=" * 70)
            print(f"\n[SUCCESS] JSON creato: {output_path}")
            print(f"[INFO] Dimensione file: {output_path.stat().st_size / 1024:.2f} KB")
            print(f"\n[STATISTICHE GENERALI]")
            print(f"  Host attivi: {len(hosts_list)}")
            print(f"  Porte aperte totali: {total_ports}")
            print(f"  Host con OS identificato: {hosts_with_os} ({hosts_with_os*100//len(hosts_list) if hosts_list else 0}%)")
            
            if total_host_vulns > 0:
                print(f"\n[VULNERABILITA']")
                print(f"  Totale vulnerabilità: {total_host_vulns}")
                print(f"  CVE unici: {len(all_cves)}")
                
                # Host più vulnerabili
                hosts_by_vulns = [(h['ip'], len(h.get('vulnerabilities', []))) 
                                  for h in hosts_list if h.get('vulnerabilities')]
                hosts_by_vulns.sort(key=lambda x: x[1], reverse=True)
                
                if hosts_by_vulns:
                    print(f"\n  Top 5 host più vulnerabili:")
                    for ip, count in hosts_by_vulns[:5]:
                        print(f"    - {ip}: {count} vulnerabilità")
            
            # Top servizi
            services = {}
            for host in hosts_list:
                for port in host['ports']:
                    service = port.get('service', 'unknown')
                    services[service] = services.get(service, 0) + 1
            
            if services:
                print(f"\n[SERVIZI]")
                print(f"  Top 10 servizi più comuni:")
                top_services = sorted(services.items(), key=lambda x: x[1], reverse=True)[:10]
                for service, count in top_services:
                    print(f"    - {service}: {count} istanze")
            
            # Distribuzione porte
            port_protocols = {'tcp': 0, 'udp': 0}
            for host in hosts_list:
                for port in host['ports']:
                    proto = port.get('protocol', 'tcp')
                    port_protocols[proto] = port_protocols.get(proto, 0) + 1
            
            print(f"\n[PORTE]")
            for proto, count in port_protocols.items():
                print(f"  {proto.upper()}: {count} porte")
            
        except Exception as e:
            print(f"\n[ERROR] Errore durante scrittura JSON: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    
    def cleanup_old_backups(self, output_file: str, keep: int = 5) -> None:
        """Rimuove backup vecchi mantenendo solo gli ultimi N"""
        output_stem = Path(output_file).stem
        backup_pattern = f"{output_stem}_backup_*.json"

        backups = sorted(
            self.output_dir.glob(backup_pattern),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        
        # Rimuovi backup eccedenti
        for old_backup in backups[keep:]:
            try:
                old_backup.unlink()
                print(f"[INFO] Rimosso backup vecchio: {old_backup.name}")
            except Exception as e:
                print(f"[WARNING] Impossibile rimuovere {old_backup.name}: {e}")


def main():
    print("=" * 70)
    print("Nmap Results Unifier - Versione Ottimizzata v2.1 (Scanner Flessibile)")
    print("=" * 70)

    # Usa argparse per gestire gli argomenti in modo robusto
    parser = argparse.ArgumentParser(
        description="Estrae, unifica e arricchisce i risultati delle scansioni Nmap da file XML.",
        epilog="Utilizzo: python3 nmap_unifier.py --input-dir /path/ai/xmls --output-dir /path/alla/risultati"
    )
    
    # Argomento per la directory di input (rimane opzionale)
    parser.add_argument(
        '--input-dir', 
        type=str, 
        help="Path alla directory contenente i file XML di Nmap (es. 'input/nmap/')."
    )
    
    # Argomento per la directory di output (rimane opzionale)
    parser.add_argument(
        '--output-dir', 
        type=str, 
        help="Path alla directory dove salvare il file JSON unificato (es. 'output/results/')."
    )
    
    args = parser.parse_args()

    # Determina le directory (priorità: argomento > default)
    script_dir = Path(__file__).parent
    suite_root = script_dir.parent.parent  # Due livelli sopra: Suite/

    input_dir = Path(args.input_dir) if args.input_dir else suite_root / "input" / "nmap"
    output_dir = Path(args.output_dir) if args.output_dir else suite_root / "output" / "results"

    print(f"\n[INFO] Directory input: {input_dir.resolve()}")
    print(f"[INFO] Directory output: {output_dir.resolve()}")
    print(f"[INFO] Encoding: UTF-8\n")

    # Verifica che la directory input esista
    if not input_dir.exists():
        print(f"\n[ERROR] Directory input non trovata: {input_dir.resolve()}")
        print(f"[INFO] Assicurarsi che la directory esista e contenga file .xml")
        sys.exit(1)

    try:
        unifier = NmapUnifier(str(input_dir), str(output_dir))
        unifier.process_all_phases() # Usa la nuova logica flessibile
        unifier.clean_and_enrich_data()
        unifier.export_json()

        print("\n" + "=" * 70)
        print("COMPLETATO CON SUCCESSO")
        print("=" * 70 + "\n")

    except KeyboardInterrupt:
        print("\n\n[WARNING] Processo interrotto dall'utente")
        sys.exit(130)
    except Exception as e:
        print(f"\n\n[ERROR] Errore fatale: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()