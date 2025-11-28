#!/usr/bin/env python3
"""
Script per estrarre informazioni su servizi e porte dal master_data.json
Genera un CSV con: IP, Porta, Servizio, Prodotto
"""

import json
import csv
import sys
import os


def extract_services_data(input_file, output_file):
    """
    Estrae dati su IP, porte, servizi e prodotti dal master_data.json

    Args:
        input_file: percorso del file JSON di input (master_data.json)
        output_file: percorso del file CSV di output
    """

    try:
        print(f"Lettura file: {input_file}")

        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        print(f"File caricato. Trovati {len(data.get('hosts', []))} hosts")
        print(f"\nEstrazione dati in corso...\n")

        # Prepara i dati da scrivere
        services_data = []

        # Itera su tutti gli host
        for host in data.get('hosts', []):
            ip = host.get('ip', 'N/A')

            # Itera su tutte le porte di ogni host
            for port_info in host.get('ports', []):
                port = port_info.get('port', 'N/A')
                protocol = port_info.get('protocol', 'N/A')
                service = port_info.get('service', 'N/A')
                product = port_info.get('product', 'N/A')
                version = port_info.get('version', '')

                # Combina product e version se entrambi presenti
                product_full = product
                if product != 'N/A' and version:
                    product_full = f"{product} {version}"

                services_data.append({
                    'IP': ip,
                    'Porta': f"{port}/{protocol}",
                    'Servizio': service,
                    'Prodotto': product_full
                })

        # Scrivi il CSV
        if services_data:
            with open(output_file, 'w', newline='', encoding='utf-8') as outfile:
                fieldnames = ['IP', 'Porta', 'Servizio', 'Prodotto']
                writer = csv.DictWriter(outfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(services_data)

            print(f"Elaborazione completata!")
            print(f"Righe estratte: {len(services_data)}")
            print(f"File salvato in: {output_file}")
        else:
            print("ATTENZIONE: Nessun dato estratto dal file")

    except FileNotFoundError:
        print(f"ERRORE: File '{input_file}' non trovato")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERRORE: Il file non è un JSON valido - {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"ERRORE durante l'elaborazione: {str(e)}")
        sys.exit(1)


def main():
    """Funzione principale"""

    # Parametri di default
    default_input = "output/results/master_data.json"
    default_output = "output/report/services_export.csv"

    # Se sono forniti argomenti da linea di comando
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("Uso: python extract_services.py [file_input.json] [file_output.csv]")
            print("\nSe non specificati, usa i valori di default:")
            print(f"  Input:  {default_input}")
            print(f"  Output: {default_output}")
            print("\nEsempi:")
            print("  python extract_services.py")
            print("  python extract_services.py results/master_data.json output/services.csv")
            sys.exit(0)

        input_file = sys.argv[1] if len(sys.argv) > 1 else default_input
        output_file = sys.argv[2] if len(sys.argv) > 2 else default_output
    else:
        input_file = default_input
        output_file = default_output

    print("=" * 70)
    print("Estrattore Servizi e Porte - master_data.json")
    print("=" * 70)
    print(f"Input:  {input_file}")
    print(f"Output: {output_file}")
    print("=" * 70 + "\n")

    # Crea directory output se non esiste
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Directory creata: {output_dir}\n")

    extract_services_data(input_file, output_file)


if __name__ == "__main__":
    main()
