# Vulnerability Assessment Suite - User Guide

Guida completa all'utilizzo e configurazione della Vulnerability Assessment Suite.

---

## Indice

1. [Quick Start](#1-quick-start)
2. [Prerequisiti](#2-prerequisiti)
3. [Preparazione Scansioni](#3-preparazione-scansioni)
4. [Configurazione Path](#4-configurazione-path)
5. [Esecuzione Suite](#5-esecuzione-suite)
6. [Verifica Output](#6-verifica-output)
7. [Analisi Risultati](#7-analisi-risultati)
8. [Troubleshooting](#8-troubleshooting)
9. [Best Practices](#9-best-practices)
10. [Workflow Completo End-to-End](#10-workflow-completo-end-to-end)

---

## 1. Quick Start

### Setup in 5 minuti

```bash
# 1. Posizionarsi nella directory Suite
cd Suite

# 2. Verificare Python 3.8+
python3 --version

# 3. Installare dipendenze (se necessario)
pip install -r requirements.txt

# 4. Preparare lista IP
echo "192.168.1.0/24" > input/ip_lists.txt

# 5. Eseguire scansioni (vedi sezione 3)
# ... [Nmap e Greenbone scan] ...

# 6. Configurare path negli script (vedi sezione 4)
# ... [Modificare NMAP_DIR e GREENBONE_CSV] ...

# 7. Eseguire la suite
./run_suite.sh

# 8. Verificare risultati
ls -lh output/report/CSVs/
```

---

## 2. Prerequisiti

### Software Richiesto

- **Python 3.8+** con moduli:
  - `json`, `csv`, `xml.etree.ElementTree` (built-in)
  - `matplotlib`, `pandas` (per grafici)

- **Nmap** (per port scanning)
  ```bash
  sudo apt install nmap  # Debian/Ubuntu
  brew install nmap      # macOS
  ```

- **Greenbone/OpenVAS** (per vulnerability scanning)
  - Installazione completa o accesso a istanza esistente
  - Accesso web UI per export CSV

### Verifiche Preliminari

```bash
# Controllare Python
python3 --version  # Dovrebbe essere >= 3.8

# Controllare Nmap
nmap --version

# Verificare struttura directory
ls -la Suite/
# Devono esistere: input/, output/, scripts/
```

---

## 3. Preparazione Scansioni

### 3.1 Preparare Lista IP Target

Editare `input/ip_lists.txt` con gli IP da scansionare:

```bash
nano input/ip_lists.txt
```

**Formati supportati:**
- IP singolo: `192.168.1.10`
- Range CIDR: `192.168.1.0/24`
- Range esteso: `192.168.1.0-192.168.1.255`
- Hostname: `server.example.com`

**Esempio:**
```
192.168.1.0/24
10.0.0.0/24
172.16.50.1
webserver.company.com
```

### 3.2 Eseguire Nmap Scan

**Scan base (veloce):**
```bash
nmap -sV -sC -oX /tmp/nmap_scan.xml -iL input/ip_lists.txt
```

**Scan completo (più lento ma dettagliato):**
```bash
nmap -A -p- -oX /tmp/nmap_full_scan.xml -iL input/ip_lists.txt
```

**Scan per subnet specifiche:**
```bash
nmap -sV -oX /tmp/nmap_subnet1.xml 192.168.1.0/24
nmap -sV -oX /tmp/nmap_subnet2.xml 10.0.0.0/24
```

**Opzioni Nmap consigliate:**
- `-sV`: Service version detection
- `-sC`: Default scripts
- `-A`: OS detection + traceroute
- `-p-`: Scan tutte le 65535 porte (lento)
- `-oX`: Output XML (richiesto!)
- `-iL`: Input da file

**Output atteso:** File XML in `/tmp/` o directory a scelta

### 3.3 Eseguire Greenbone/OpenVAS Scan

**Step-by-step via Web UI:**

1. **Login a Greenbone**
   - Accedere a `https://greenbone-server:9392`
   - Inserire credenziali

2. **Creare Target**
   - Scans → Targets → New Target
   - Nome: `Network_Assessment_2025`
   - Hosts: Copiare IP da `input/ip_lists.txt`
   - Save

3. **Creare Task**
   - Scans → Tasks → New Task
   - Nome: `Full_Vuln_Scan`
   - Scan Config: `Full and fast`
   - Target: Selezionare target creato
   - Save

4. **Avviare Scan**
   - Click su ▶️ (Play) nella task
   - Attendere completamento (può richiedere ore)

5. **Esportare Risultati**
   - Click su task completata
   - Export → CSV Results
   - Salvare come `/tmp/greenbone_scan.csv`

**Output atteso:** File CSV in `/tmp/`

---

## 4. Configurazione Path

### 4.1 Configurare 01_nmap_unifier.py

Aprire lo script e modificare il path:

```bash
nano scripts/collection/01_nmap_unifier.py
```

**Modificare la riga:**
```python
# Prima (esempio)
NMAP_DIR = "/path/to/nmap/scans/"

# Dopo (il tuo path)
NMAP_DIR = "/tmp/"
```

**Metodo automatico con sed:**
```bash
sed -i 's|NMAP_DIR = .*|NMAP_DIR = "/tmp/"|' scripts/collection/01_nmap_unifier.py
```

### 4.2 Configurare 02_greenbone_unifier.py

```bash
nano scripts/collection/02_greenbone_unifier.py
```

**Modificare la riga:**
```python
# Prima
GREENBONE_CSV = "/path/to/greenbone_scan.csv"

# Dopo
GREENBONE_CSV = "/tmp/greenbone_scan.csv"
```

**Metodo automatico:**
```bash
sed -i 's|GREENBONE_CSV = .*|GREENBONE_CSV = "/tmp/greenbone_scan.csv"|' scripts/collection/02_greenbone_unifier.py
```

### 4.3 Verificare Configurazione

```bash
# Controllare path configurati
grep "NMAP_DIR" scripts/collection/01_nmap_unifier.py
grep "GREENBONE_CSV" scripts/collection/02_greenbone_unifier.py

# Verificare che i file esistano
ls -lh /tmp/nmap_scan.xml
ls -lh /tmp/greenbone_scan.csv
```

---

## 5. Esecuzione Suite

### 5.1 Metodo 1: Esecuzione Automatica (Raccomandato)

```bash
# Eseguire tutto
./run_suite.sh
```

**Output atteso:**
```
================================================================================
VULNERABILITY ASSESSMENT SUITE
Version: 1.0
Date: 2025-11-06 14:30:00
================================================================================

[INFO] Checking prerequisites...
[INFO] Python version: 3.10.12
[SUCCESS] Output directories ready

================================================================================
PHASE 1: DATA COLLECTION
================================================================================

[INFO] Running: 01_nmap_unifier.py
...
[SUCCESS] 01_nmap_unifier.py completed successfully

[INFO] Running: 02_greenbone_unifier.py
...
[SUCCESS] 02_greenbone_unifier.py completed successfully

[INFO] Running: 03_data_merger.py
...
[SUCCESS] PHASE 1 COMPLETED - master_data.json created

================================================================================
PHASE 2: DATA ANALYSIS
================================================================================

[INFO] Running: 04_vuln_analyzer.py
...
[SUCCESS] PHASE 2 COMPLETED - All analyses, charts, and cleanup completed

================================================================================
SUITE EXECUTION COMPLETED SUCCESSFULLY
================================================================================
```

### 5.2 Metodo 2: Esecuzione Step-by-Step

**Fase 1 - Data Collection:**
```bash
python3 scripts/collection/01_nmap_unifier.py
python3 scripts/collection/02_greenbone_unifier.py
python3 scripts/collection/03_data_merger.py
```

**Fase 2 - Data Analysis:**
```bash
python3 scripts/analysis/04_vuln_analyzer.py
python3 scripts/analysis/12_data_transformer.py
python3 scripts/analysis/05_service_analyzer.py
python3 scripts/analysis/06_surface_mapper.py
python3 scripts/analysis/07_risk_scorer.py
python3 scripts/analysis/08_extract_services.py
python3 scripts/analysis/09_data_aggregator.py
python3 scripts/analysis/10_chart_generator.py
python3 scripts/analysis/11_cleanup.py
```

### 5.3 Metodo 3: Esecuzione Parziale

**Skip collection (usa master_data.json esistente):**
```bash
./run_suite.sh --skip-collection
```

**Skip analysis (solo collection):**
```bash
./run_suite.sh --skip-analysis
```

**Mostrare help:**
```bash
./run_suite.sh --help
```

---

## 6. Verifica Output

### 6.1 Controllare master_data.json

```bash
# Visualizzare metadata
jq '.metadata' output/results/master_data.json

# Output atteso:
# {
#   "generated_at": "2025-11-06T14:30:00",
#   "total_hosts": 382,
#   "nmap_hosts": 380,
#   "greenbone_hosts": 375,
#   "both_sources": 373,
#   "total_vulnerabilities": 637,
#   "total_ports": 1842
# }
```

```bash
# Contare host
jq '.hosts | length' output/results/master_data.json

# Vedere primo host
jq '.hosts[0]' output/results/master_data.json
```

### 6.2 Controllare CSV Generati

```bash
# Listare tutti i CSV
ls -lh output/report/CSVs/

# Visualizzare severity breakdown
cat output/report/CSVs/severity_breakdown.csv

# Output atteso:
# Severity,Open,Remediated,Total
# Critical,3,0,3
# High,14,0,14
# Medium,262,0,262
# Low,205,0,205
```

```bash
# Vedere top vulnerabilità
head -10 output/report/CSVs/top_vulns_by_cvss.csv

# Vedere host ad alto rischio
cat output/report/CSVs/top_high_risk_hosts.csv
```

### 6.3 Controllare Grafici

```bash
# Listare grafici generati
ls -lh output/report/charts/

# Aprire grafico (esempio)
xdg-open output/report/charts/vuln_heatmap.png  # Linux
open output/report/charts/vuln_heatmap.png      # macOS
```

**Grafici generati:**
- `vuln_heatmap.png` - Heatmap vulnerabilità per severity
- `top_vulns_occurrence.png` - Top 10 vulnerabilità per occorrenze
- `top_risk_hosts.png` - Top 10 host ad alto rischio
- `cvss_histogram.png` - Distribuzione CVSS scores
- `vuln_per_host.png` - Count vulnerabilità per host

---

## 7. Analisi Risultati

### 7.1 Identificare Host ad Alto Rischio

```bash
# Vedere top 10 host più critici
cat output/report/CSVs/top_high_risk_hosts.csv
```

**Interpretazione:**
- `risk_score`: Score aggregato (CVSS + exposure)
- Host con score > 100: **Priorità CRITICA**
- Host con score 50-100: **Priorità ALTA**
- Host con score < 50: **Priorità MEDIA**

### 7.2 Analizzare Vulnerabilità Prioritarie

```bash
# Top vulnerabilità per CVSS
head -20 output/report/CSVs/top_vulns_by_cvss.csv

# Top vulnerabilità per diffusione
head -20 output/report/CSVs/top_vulns_by_occurrence.csv
```

**Focus su:**
- Vulnerabilità con CVSS >= 9.0 (Critical)
- Vulnerabilità presenti su >10% degli host
- CVE noti con exploit pubblici

### 7.3 Mappare Servizi Esposti

```bash
# Servizi più comuni
cat output/report/CSVs/services_distribution.csv

# Porte più esposte
cat output/report/CSVs/ports_distribution.csv

# Export completo servizi
head -50 output/report/services_export.csv
```

**Cercare:**
- Servizi critici esposti (RDP, SMB, SSH su Internet)
- Versioni obsolete (MySQL 5.5, Apache 2.2)
- Porte non standard

### 7.4 Import in Excel/Google Sheets

1. Aprire Excel/Google Sheets
2. File → Import → CSV
3. Selezionare file da `output/report/CSVs/`
4. Configurare delimitatore: `,` (virgola)
5. Encoding: `UTF-8`
6. Creare tabelle pivot per analisi

**CSV principali per import:**
- `severity_breakdown.csv` - Overview severity
- `top_high_risk_hosts.csv` - Prioritizzazione remediation
- `appendix_b1_detailed_findings.csv` - Dettaglio completo findings
- `services_export.csv` - Inventario servizi

---

## 8. Troubleshooting

### 8.1 Problema: "File not found"

**Sintomo:**
```
FileNotFoundError: [Errno 2] No such file or directory: '/path/to/nmap_scan.xml'
```

**Soluzione:**
```bash
# Verificare path negli script
grep -n "NMAP_DIR\|GREENBONE_CSV" scripts/collection/*.py

# Verificare che i file esistano
ls -lh /tmp/nmap_scan.xml
ls -lh /tmp/greenbone_scan.csv

# Assicurarsi di eseguire dalla directory Suite/
pwd  # Dovrebbe mostrare: .../Suite
```

### 8.2 Problema: "JSON parsing error"

**Sintomo:**
```
json.decoder.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
```

**Soluzione:**
```bash
# Validare JSON con jq
jq '.' output/results/master_data.json

# Se il file è vuoto o corrotto
ls -lh output/results/master_data.json

# Rieseguire 03_data_merger.py
python3 scripts/collection/03_data_merger.py
```

### 8.3 Problema: "CSV vuoti"

**Sintomo:**
File CSV con solo header, nessun dato

**Soluzione:**
```bash
# Verificare master_data.json non vuoto
jq '.metadata' output/results/master_data.json

# Se total_hosts = 0, controllare unifier scripts
python3 scripts/collection/01_nmap_unifier.py
python3 scripts/collection/02_greenbone_unifier.py

# Verificare file input non corrotti
file /tmp/nmap_scan.xml
file /tmp/greenbone_scan.csv
```

### 8.4 Problema: "Permission denied"

**Sintomo:**
```
bash: ./run_suite.sh: Permission denied
```

**Soluzione:**
```bash
# Rendere eseguibile lo script
chmod +x run_suite.sh

# Verificare permessi
ls -la run_suite.sh
# Dovrebbe mostrare: -rwxr-xr-x
```

### 8.5 Problema: "No module named 'matplotlib'"

**Sintomo:**
```
ModuleNotFoundError: No module named 'matplotlib'
```

**Soluzione:**
```bash
# Installare dipendenze
pip install matplotlib pandas

# O usare requirements.txt
pip install -r requirements.txt
```

### 8.6 Debug Generale

```bash
# Abilitare verbose logging (editare script)
# Cambiare: logging.basicConfig(level=logging.INFO)
# In:      logging.basicConfig(level=logging.DEBUG)

# Eseguire singolo script per identificare errore
python3 -v scripts/collection/01_nmap_unifier.py

# Controllare log di sistema
tail -f /var/log/syslog  # Linux
tail -f /var/log/system.log  # macOS
```

---

## 9. Best Practices

### 9.1 Protezione Dati Sensibili

```bash
# Proteggere output con permessi restrittivi
chmod 600 output/results/master_data.json
chmod 700 output/

# NON committare output in repository pubblici
echo "output/" >> .gitignore
echo "input/ip_lists.txt" >> .gitignore
```

### 9.2 Backup e Archiviazione

```bash
# Creare report finale con timestamp
REPORT_DATE=$(date +%Y%m%d_%H%M%S)
cp -r output/report Report_${REPORT_DATE}

# Comprimere per archiviazione
tar -czf Report_${REPORT_DATE}.tar.gz Report_${REPORT_DATE}/

# Backup su storage sicuro
scp Report_${REPORT_DATE}.tar.gz user@backup-server:/secure/archives/
```

### 9.3 Naming Convention

**Format:** `Report_YYYYMMDD_HHMM_[NetworkName]`

**Esempi:**
- `Report_20251106_1430_Production`
- `Report_20251106_0900_DMZ`
- `Report_20251106_1600_Internal`

### 9.4 Quando Eseguire Scansioni

**Raccomandazioni:**
- **Production**: Fuori orario lavorativo (sera/weekend)
- **Scan invasivi**: Ambiente di staging prima
- **Frequenza**: Mensile per production, settimanale per sviluppo
- **Notifiche**: Avvisare team networking prima di scan estesi

### 9.5 Gestione Risultati

```bash
# Mantenere cronologia
mkdir -p archives/2025/11/
mv Report_202511* archives/2025/11/

# Cleanup old data (esempio: >90 giorni)
find archives/ -type f -mtime +90 -name "Report_*.tar.gz" -delete
```

---

## 10. Workflow Completo End-to-End

### Esempio Pratico: Assessment di Rete Aziendale

**Scenario:** Network 192.168.1.0/24 + 10.0.0.0/24

#### Step 1: Preparazione (5 minuti)

```bash
cd Suite

# Creare lista IP
cat > input/ip_lists.txt <<EOF
192.168.1.0/24
10.0.0.0/24
EOF

# Verificare prerequisiti
python3 --version
nmap --version
```

#### Step 2: Scansioni (2-4 ore)

```bash
# Nmap scan (parallelo per velocità)
nmap -sV -sC -oX /tmp/nmap_192.xml 192.168.1.0/24 &
nmap -sV -sC -oX /tmp/nmap_10.xml 10.0.0.0/24 &
wait

# Greenbone scan (via Web UI)
# - Esportare come /tmp/greenbone_scan.csv
```

#### Step 3: Configurazione (2 minuti)

```bash
# Configurare path automaticamente
sed -i 's|NMAP_DIR = .*|NMAP_DIR = "/tmp/"|' scripts/collection/01_nmap_unifier.py
sed -i 's|GREENBONE_CSV = .*|GREENBONE_CSV = "/tmp/greenbone_scan.csv"|' scripts/collection/02_greenbone_unifier.py

# Verificare
grep "NMAP_DIR" scripts/collection/01_nmap_unifier.py
```

#### Step 4: Esecuzione Suite (5-15 minuti)

```bash
# Eseguire pipeline completa
./run_suite.sh

# Verificare successo
echo $?  # Dovrebbe essere 0
```

#### Step 5: Verifica Risultati (3 minuti)

```bash
# Metadata
jq '.metadata' output/results/master_data.json

# Output:
# {
#   "total_hosts": 156,
#   "total_vulnerabilities": 423,
#   "total_ports": 892
# }

# Top issues
head -10 output/report/CSVs/top_high_risk_hosts.csv
head -10 output/report/CSVs/top_vulns_by_cvss.csv
```

#### Step 6: Analisi Dettagliata (30-60 minuti)

```bash
# Import CSV in Excel
# - severity_breakdown.csv
# - top_high_risk_hosts.csv
# - appendix_b1_detailed_findings.csv

# Identificare:
# 1. Host con score > 100 (remediation immediata)
# 2. Vulnerabilità Critical/High diffuse
# 3. Servizi obsoleti
```

#### Step 7: Report Finale (10 minuti)

```bash
# Creare cartella report
REPORT_DATE=$(date +%Y%m%d_%H%M)
cp -r output/report Report_${REPORT_DATE}_Production

# Comprimere
tar -czf Report_${REPORT_DATE}_Production.tar.gz Report_${REPORT_DATE}_Production/

# Verificare dimensione
ls -lh Report_${REPORT_DATE}_Production.tar.gz
```

#### Step 8: Archiviazione e Cleanup

```bash
# Backup sicuro
scp Report_${REPORT_DATE}_Production.tar.gz user@backup:/archive/

# Cleanup dati temporanei
rm /tmp/nmap_*.xml
rm /tmp/greenbone_scan.csv

# Proteggere dati locali
chmod 700 Report_${REPORT_DATE}_Production/
```

### Timeline Totale

| Fase | Tempo | Descrizione |
|------|-------|-------------|
| Preparazione | 5 min | Setup input e verifiche |
| Scansioni | 2-4 ore | Nmap + Greenbone |
| Configurazione | 2 min | Path negli script |
| Esecuzione Suite | 5-15 min | Pipeline completa |
| Verifica | 3 min | Validazione output |
| Analisi | 30-60 min | Review dettagliata |
| Report | 10 min | Packaging finale |
| **TOTALE** | **3-5 ore** | End-to-end completo |

---

## Comandi Utili di Riferimento

### Validazione JSON
```bash
jq '.' file.json                    # Valida e formatta
jq '.metadata' file.json            # Estrae sezione
jq '.hosts | length' file.json      # Conta elementi
```

### Analisi CSV
```bash
head -n 20 file.csv                 # Prime 20 righe
wc -l file.csv                      # Conta righe
sort -t',' -k2 -rn file.csv         # Ordina per colonna 2
```

### File Management
```bash
du -sh output/                      # Dimensione totale
find output/ -name "*.csv" -ls      # Lista tutti CSV
tree output/                        # Struttura ad albero
```

### Backup
```bash
tar -czf backup.tar.gz output/      # Comprimi
tar -xzf backup.tar.gz              # Decomprimi
rsync -av output/ user@host:/path/  # Sync remoto
```

---

**Per dettagli tecnici su algoritmi, strutture dati e implementazione, consultare `TECHNICAL_DETAILS.md`.**
