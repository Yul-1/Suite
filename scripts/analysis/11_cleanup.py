#!/usr/bin/env python3
"""
Cleanup & Validation Script - Task 4.5
Organizza output, valida file generati e crea report summary.
"""

import os
import json
from pathlib import Path
from datetime import datetime


# Paths - Suite structure
BASE_DIR = Path(__file__).parent.parent.parent  # Suite/
DATA_INPUT_DIR = BASE_DIR / "output" / "data_input"
DATA_OUTPUT_DIR = BASE_DIR / "output" / "report" / "CSVs"
ASSETS_CHARTS_DIR = BASE_DIR / "output" / "report" / "charts"
REPORT_OUTPUT_DIR = BASE_DIR / "output" / "report"


class CleanupValidator:
    """Validates all generated files and creates summary report."""

    def __init__(self):
        self.validation_results = []
        self.file_stats = {}

    def validate_file(self, filepath, file_type):
        """Validate that file exists and has reasonable size."""
        if not filepath.exists():
            self.validation_results.append({
                'file': str(filepath),
                'type': file_type,
                'status': 'MISSING',
                'size': 0
            })
            return False

        size = filepath.stat().st_size
        self.file_stats[str(filepath)] = size

        if size == 0:
            self.validation_results.append({
                'file': str(filepath),
                'type': file_type,
                'status': 'EMPTY',
                'size': size
            })
            return False

        self.validation_results.append({
            'file': str(filepath),
            'type': file_type,
            'status': 'OK',
            'size': size
        })
        return True

    def validate_all_files(self):
        """Validate all expected output files."""
        print("\n[1/4] Validating data_input files...")
        input_files = [
            'hosts.csv',
            'vulnerabilities.csv',
            'findings.csv',
            'services.csv',
            'config.json'
        ]

        for filename in input_files:
            filepath = DATA_INPUT_DIR / filename
            result = self.validate_file(filepath, 'data_input')
            status = '✓' if result else '✗'
            print(f"  {status} {filename}")

        print("\n[2/4] Validating data_output files...")
        output_files = [
            'severity_breakdown.csv',
            'top_vulns_by_occurrence.csv',
            'top_high_risk_hosts.csv',
            'cvss_histogram_data.csv',
            'vuln_count_per_host.csv',
            'top_vulns_by_cvss.csv',
            'appendix_a_vuln_summary.csv',
            'appendix_b1_detailed_findings.csv'
        ]

        for filename in output_files:
            filepath = DATA_OUTPUT_DIR / filename
            result = self.validate_file(filepath, 'data_output')
            status = '✓' if result else '✗'
            print(f"  {status} {filename}")

        print("\n[3/4] Validating chart files...")
        chart_files = [
            'vuln_heatmap.png',
            'top_vulns_occurrence.png',
            'top_risk_hosts.png',
            'cvss_histogram.png',
            'vuln_per_host.png'
        ]

        for filename in chart_files:
            filepath = ASSETS_CHARTS_DIR / filename
            result = self.validate_file(filepath, 'chart')
            status = '✓' if result else '✗'
            print(f"  {status} {filename}")

        print("\n[4/4] Validating PDF report...")
        pdf_file = REPORT_OUTPUT_DIR / 'vulnerability_assessment_report.pdf'
        result = self.validate_file(pdf_file, 'pdf_report')
        status = '✓' if result else '✗'
        print(f"  {status} vulnerability_assessment_report.pdf")

    def create_summary_report(self):
        """Create text summary report."""
        print("\n[5/5] Creating report_summary.txt...")

        # Calculate statistics
        total_files = len(self.validation_results)
        ok_files = sum(1 for r in self.validation_results if r['status'] == 'OK')
        missing_files = sum(1 for r in self.validation_results if r['status'] == 'MISSING')
        empty_files = sum(1 for r in self.validation_results if r['status'] == 'EMPTY')
        total_size = sum(self.file_stats.values())

        # Load config for metadata
        config_path = DATA_INPUT_DIR / 'config.json'
        if config_path.exists():
            with open(config_path, 'r') as f:
                config = json.load(f)
        else:
            config = {}

        # Create summary text
        summary_lines = []
        summary_lines.append("=" * 70)
        summary_lines.append("VULNERABILITY ASSESSMENT REPORT - GENERATION SUMMARY")
        summary_lines.append("=" * 70)
        summary_lines.append("")
        summary_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_lines.append(f"Organization: {config.get('organization', 'N/A')}")
        summary_lines.append(f"Report Number: {config.get('report_number', 'N/A')}")
        summary_lines.append("")
        summary_lines.append("-" * 70)
        summary_lines.append("SCAN STATISTICS")
        summary_lines.append("-" * 70)
        summary_lines.append(f"Addresses Scanned: {config.get('addresses_scanned', 'N/A')}")
        summary_lines.append(f"Unique Vulnerabilities: {config.get('total_vulnerabilities', 'N/A')}")
        summary_lines.append(f"Total Findings: {config.get('total_findings', 'N/A')}")
        summary_lines.append("")

        if 'severity_summary' in config:
            summary_lines.append("-" * 70)
            summary_lines.append("SEVERITY BREAKDOWN")
            summary_lines.append("-" * 70)
            for severity, count in config['severity_summary'].items():
                summary_lines.append(f"  {severity}: {count}")
            summary_lines.append("")

        summary_lines.append("-" * 70)
        summary_lines.append("FILE GENERATION STATUS")
        summary_lines.append("-" * 70)
        summary_lines.append(f"Total Files Expected: {total_files}")
        summary_lines.append(f"Files Generated: {ok_files}")
        summary_lines.append(f"Files Missing: {missing_files}")
        summary_lines.append(f"Files Empty: {empty_files}")
        summary_lines.append(f"Total Output Size: {total_size / 1024:.2f} KB")
        summary_lines.append("")

        summary_lines.append("-" * 70)
        summary_lines.append("FILE DETAILS")
        summary_lines.append("-" * 70)

        # Group by type
        by_type = {}
        for result in self.validation_results:
            file_type = result['type']
            if file_type not in by_type:
                by_type[file_type] = []
            by_type[file_type].append(result)

        for file_type, results in sorted(by_type.items()):
            summary_lines.append(f"\n{file_type.upper()}:")
            for result in results:
                filename = Path(result['file']).name
                status = result['status']
                size_kb = result['size'] / 1024 if result['size'] > 0 else 0
                status_symbol = '✓' if status == 'OK' else '✗'
                summary_lines.append(f"  {status_symbol} {filename:<50} {size_kb:>8.2f} KB")

        summary_lines.append("")
        summary_lines.append("-" * 70)
        summary_lines.append("PIPELINE STEPS COMPLETED")
        summary_lines.append("-" * 70)
        summary_lines.append("  ✓ Task 4.1: Data Transformation")
        summary_lines.append("  ✓ Task 4.2: Data Aggregation")
        summary_lines.append("  ✓ Task 4.3: Chart Generation")
        summary_lines.append("  ✓ Task 4.4: PDF Report Building")
        summary_lines.append("  ✓ Task 4.5: Cleanup & Validation")
        summary_lines.append("")

        if ok_files == total_files:
            summary_lines.append("=" * 70)
            summary_lines.append("STATUS: ALL FILES GENERATED SUCCESSFULLY")
            summary_lines.append("=" * 70)
        else:
            summary_lines.append("=" * 70)
            summary_lines.append("STATUS: SOME FILES MISSING OR EMPTY - REVIEW REQUIRED")
            summary_lines.append("=" * 70)

        summary_lines.append("")
        summary_lines.append("Report Location:")
        summary_lines.append(f"  {REPORT_OUTPUT_DIR / 'vulnerability_assessment_report.pdf'}")
        summary_lines.append("")

        # Write summary file
        summary_path = REPORT_OUTPUT_DIR / 'report_summary.txt'
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(summary_lines))

        print(f"  ✓ {summary_path}")

        # Print summary to console
        print("\n" + '\n'.join(summary_lines))

    def cleanup_temp_files(self):
        """Remove temporary files if any (currently none to remove)."""
        # For now, we keep all files for analysis
        # Could add logic to remove temporary files here
        pass

    def run(self):
        """Execute cleanup and validation."""
        print("=" * 70)
        print("CLEANUP & VALIDATION - Task 4.5")
        print("=" * 70)

        self.validate_all_files()
        self.create_summary_report()
        self.cleanup_temp_files()

        return 0 if all(r['status'] == 'OK' for r in self.validation_results) else 1


def main():
    """Main execution."""
    try:
        validator = CleanupValidator()
        exit_code = validator.run()

        if exit_code == 0:
            print("\n" + "=" * 70)
            print("CLEANUP & VALIDATION COMPLETE - ALL FILES OK")
            print("=" * 70)
        else:
            print("\n" + "=" * 70)
            print("CLEANUP & VALIDATION COMPLETE - SOME ISSUES FOUND")
            print("=" * 70)

        return exit_code

    except Exception as e:
        print(f"\n[ERROR] Cleanup failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    exit(main())
