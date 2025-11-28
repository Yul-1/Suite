#!/usr/bin/env python3
"""
Chart Generator - Task 4.3
Genera grafici professionali PNG per il report PDF.
"""

import csv
import json
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from pathlib import Path

# Paths - Suite structure
BASE_DIR = Path(__file__).parent.parent.parent  # Suite/
DATA_OUTPUT_DIR = BASE_DIR / "output" / "report" / "CSVs"
ASSETS_CHARTS_DIR = BASE_DIR / "output" / "report" / "charts"
CONFIG_DIR = BASE_DIR / "config"

# Load color configuration
with open(CONFIG_DIR / "colors.json", 'r') as f:
    COLORS = json.load(f)

SEVERITY_COLORS = COLORS['severity_colors']
CHART_DPI = 300
FIGSIZE = (10, 6)

def load_csv(filepath):
    """Carica CSV e ritorna lista di dict."""
    with open(filepath, 'r', encoding='utf-8') as f:
        return list(csv.DictReader(f))

def create_vuln_heatmap(severity_data):
    """
    Genera heatmap mosaico vulnerabilità (griglia 20x20).
    Ogni quadratino = una vulnerabilità.
    """
    print("  → Creating vulnerability heatmap...")

    # Calculate total vulnerabilities
    total_vulns = sum(int(row['count']) for row in severity_data if row['severity'] != 'Info')

    # Create grid (20x20 = 400 cells)
    grid_size = 20
    grid = np.zeros((grid_size, grid_size, 3))  # RGB

    # Fill grid with vulnerability colors
    vulns_placed = 0
    severity_order = ['Critical', 'High', 'Medium', 'Low']

    for severity in severity_order:
        count = int(next((row['count'] for row in severity_data if row['severity'] == severity), 0))
        color_hex = SEVERITY_COLORS.get(severity, '#808080')
        color_rgb = tuple(int(color_hex.lstrip('#')[i:i+2], 16)/255 for i in (0, 2, 4))

        for _ in range(min(count, 400 - vulns_placed)):
            if vulns_placed >= 400:
                break
            row = vulns_placed // grid_size
            col = vulns_placed % grid_size
            grid[row, col] = color_rgb
            vulns_placed += 1

    # Create figure
    fig, ax = plt.subplots(figsize=(8, 8), dpi=CHART_DPI)
    ax.imshow(grid, interpolation='nearest')
    ax.set_title('Vulnerability Heatmap', fontsize=16, fontweight='bold', pad=20)
    ax.axis('off')

    # Add legend
    legend_elements = [
        mpatches.Patch(color=SEVERITY_COLORS['Critical'], label='Critical'),
        mpatches.Patch(color=SEVERITY_COLORS['High'], label='High'),
        mpatches.Patch(color=SEVERITY_COLORS['Medium'], label='Medium'),
        mpatches.Patch(color=SEVERITY_COLORS['Low'], label='Low')
    ]
    ax.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))

    plt.tight_layout()
    output_path = ASSETS_CHARTS_DIR / 'vuln_heatmap.png'
    plt.savefig(output_path, dpi=CHART_DPI, bbox_inches='tight')
    plt.close()
    print(f"    ✓ {output_path}")

def create_top_vulns_occurrence(top_vulns_data):
    """
    Bar chart orizzontale: Top vulnerabilities by occurrence.
    """
    print("  → Creating top vulnerabilities by occurrence chart...")

    # Extract data (take top 10)
    vulns = top_vulns_data[:10]
    names = [row['vuln_name'][:50] + '...' if len(row['vuln_name']) > 50 else row['vuln_name']
             for row in vulns]
    counts = [int(row['occurrences']) for row in vulns]
    colors = [SEVERITY_COLORS.get(row['severity'], '#808080') for row in vulns]

    # Create chart
    fig, ax = plt.subplots(figsize=(12, 6), dpi=CHART_DPI)
    y_pos = np.arange(len(names))

    bars = ax.barh(y_pos, counts, color=colors, height=0.7)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel('Occurrences', fontsize=11, fontweight='bold')
    ax.set_title('Top Vulnerabilities by Occurrence', fontsize=14, fontweight='bold', pad=15)
    ax.grid(axis='x', alpha=0.3)

    # Add value labels
    for i, (bar, count) in enumerate(zip(bars, counts)):
        width = bar.get_width()
        ax.text(width + max(counts)*0.01, bar.get_y() + bar.get_height()/2,
                f'{count}', ha='left', va='center', fontsize=10, fontweight='bold')

    plt.tight_layout()
    output_path = ASSETS_CHARTS_DIR / 'top_vulns_occurrence.png'
    plt.savefig(output_path, dpi=CHART_DPI, bbox_inches='tight')
    plt.close()
    print(f"    ✓ {output_path}")

def create_top_risk_hosts(top_hosts_data):
    """
    Stacked horizontal bar chart: Top high-risk hosts.
    """
    print("  → Creating top high-risk hosts chart...")

    # Extract data
    hosts = top_hosts_data[:10]
    labels = [f"{row['ip']}" for row in hosts]
    critical = [int(row['critical']) for row in hosts]
    high = [int(row['high']) for row in hosts]
    medium = [int(row['medium']) for row in hosts]
    low = [int(row['low']) for row in hosts]

    # Create chart
    fig, ax = plt.subplots(figsize=(12, 6), dpi=CHART_DPI)
    y_pos = np.arange(len(labels))

    # Stacked bars
    ax.barh(y_pos, critical, color=SEVERITY_COLORS['Critical'], label='Critical', height=0.7)
    ax.barh(y_pos, high, left=critical, color=SEVERITY_COLORS['High'], label='High', height=0.7)
    ax.barh(y_pos, medium, left=[c+h for c,h in zip(critical, high)],
            color=SEVERITY_COLORS['Medium'], label='Medium', height=0.7)
    ax.barh(y_pos, low, left=[c+h+m for c,h,m in zip(critical, high, medium)],
            color=SEVERITY_COLORS['Low'], label='Low', height=0.7)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlabel('Vulnerability Count', fontsize=11, fontweight='bold')
    ax.set_title('Top High-Risk Hosts', fontsize=14, fontweight='bold', pad=15)
    ax.legend(loc='upper right', fontsize=9)
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    output_path = ASSETS_CHARTS_DIR / 'top_risk_hosts.png'
    plt.savefig(output_path, dpi=CHART_DPI, bbox_inches='tight')
    plt.close()
    print(f"    ✓ {output_path}")

def create_cvss_histogram(cvss_data):
    """
    Histogram: CVSS score distribution con gradiente colore.
    """
    print("  → Creating CVSS histogram...")

    # Extract data
    bins = [float(row['cvss_bin']) for row in cvss_data]
    counts = [int(row['count']) for row in cvss_data]

    # Color gradient based on CVSS value
    colors = []
    for cvss_val in bins:
        if cvss_val >= 9.0:
            colors.append(SEVERITY_COLORS['Critical'])
        elif cvss_val >= 7.0:
            colors.append(SEVERITY_COLORS['High'])
        elif cvss_val >= 4.0:
            colors.append(SEVERITY_COLORS['Medium'])
        else:
            colors.append(SEVERITY_COLORS['Low'])

    # Create chart
    fig, ax = plt.subplots(figsize=(12, 6), dpi=CHART_DPI)
    ax.bar(bins, counts, width=0.4, color=colors, edgecolor='black', linewidth=0.5)

    ax.set_xlabel('CVSS Score', fontsize=11, fontweight='bold')
    ax.set_ylabel('Active Vulnerabilities', fontsize=11, fontweight='bold')
    ax.set_title('CVSS Score Distribution', fontsize=14, fontweight='bold', pad=15)
    ax.set_xticks(np.arange(0, 10.5, 1.0))
    ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    output_path = ASSETS_CHARTS_DIR / 'cvss_histogram.png'
    plt.savefig(output_path, dpi=CHART_DPI, bbox_inches='tight')
    plt.close()
    print(f"    ✓ {output_path}")

def create_vuln_per_host(vuln_dist_data):
    """
    Bar chart verticale: Vulnerability count per host distribution.
    """
    print("  → Creating vulnerability count per host chart...")

    # Extract data
    categories = [row['category'] for row in vuln_dist_data]
    counts = [int(row['count']) for row in vuln_dist_data]

    # Create chart
    fig, ax = plt.subplots(figsize=(8, 6), dpi=CHART_DPI)
    x_pos = np.arange(len(categories))

    bars = ax.bar(x_pos, counts, color=SEVERITY_COLORS['Low'], width=0.6, edgecolor='black', linewidth=1)
    ax.set_xticks(x_pos)
    ax.set_xticklabels(categories, fontsize=11)
    ax.set_ylabel('Host Count', fontsize=11, fontweight='bold')
    ax.set_title('Vulnerability Count per Host', fontsize=14, fontweight='bold', pad=15)
    ax.grid(axis='y', alpha=0.3)

    # Add value labels on top of bars
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, height + max(counts)*0.02,
                f'{count}', ha='center', va='bottom', fontsize=12, fontweight='bold')

    plt.tight_layout()
    output_path = ASSETS_CHARTS_DIR / 'vuln_per_host.png'
    plt.savefig(output_path, dpi=CHART_DPI, bbox_inches='tight')
    plt.close()
    print(f"    ✓ {output_path}")

def main():
    """Main execution."""
    print("=" * 60)
    print("CHART GENERATOR - Task 4.3")
    print("=" * 60)

    # Create output directory
    ASSETS_CHARTS_DIR.mkdir(parents=True, exist_ok=True)
    print(f"\n✓ Output directory: {ASSETS_CHARTS_DIR}")

    # Load data
    print("\n[1/6] Loading aggregated data...")
    severity_data = load_csv(DATA_OUTPUT_DIR / 'severity_breakdown.csv')
    top_vulns_data = load_csv(DATA_OUTPUT_DIR / 'top_vulns_by_occurrence.csv')
    top_hosts_data = load_csv(DATA_OUTPUT_DIR / 'top_high_risk_hosts.csv')
    cvss_data = load_csv(DATA_OUTPUT_DIR / 'cvss_histogram_data.csv')
    vuln_dist_data = load_csv(DATA_OUTPUT_DIR / 'vuln_count_per_host.csv')
    print("  ✓ Data loaded")

    # Generate charts
    print("\n[2/6] Generating charts...")

    create_vuln_heatmap(severity_data)
    create_top_vulns_occurrence(top_vulns_data)
    create_top_risk_hosts(top_hosts_data)
    create_cvss_histogram(cvss_data)
    create_vuln_per_host(vuln_dist_data)

    # Summary
    print("\n" + "=" * 60)
    print("CHART GENERATION COMPLETE")
    print("=" * 60)
    print(f"\nOutput files in: {ASSETS_CHARTS_DIR}")
    print("  - vuln_heatmap.png")
    print("  - top_vulns_occurrence.png")
    print("  - top_risk_hosts.png")
    print("  - cvss_histogram.png")
    print("  - vuln_per_host.png")
    print(f"\nAll charts generated at {CHART_DPI} DPI")
    print("\n✓ Ready for Task 4.4 (PDF Report Builder)")

if __name__ == '__main__':
    main()
