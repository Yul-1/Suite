#!/bin/bash
################################################################################
# Vulnerability Assessment Suite - Orchestration Script
#
# Esegue l'intera pipeline di vulnerability assessment:
#   1. Data Collection (Nmap unifier, Greenbone unifier, Data merger)
#   2. Data Analysis (Vuln analyzer, Service analyzer, Surface mapper, Risk scorer)
#
# Usage:
#   ./run_suite.sh [--skip-collection] [--skip-analysis]
#
# Author: AI Assistant
# Version: 1.0
# Date: 2025-11-04
################################################################################

set -e  # Exit on error
set -u  # Exit on undefined variable

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="${SUITE_DIR}/scripts"
OUTPUT_DIR="${SUITE_DIR}/output"
RESULTS_DIR="${OUTPUT_DIR}/results"
ANALYSIS_DIR="${OUTPUT_DIR}/analysis"
REPORT_DIR="${OUTPUT_DIR}/report"
REPORT_CSV_DIR="${REPORT_DIR}/CSVs"

# Flags
SKIP_COLLECTION=false
SKIP_ANALYSIS=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-collection)
            SKIP_COLLECTION=true
            shift
            ;;
        --skip-analysis)
            SKIP_ANALYSIS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--skip-collection] [--skip-analysis]"
            echo ""
            echo "Options:"
            echo "  --skip-collection    Skip data collection phase (use existing master_data.json)"
            echo "  --skip-analysis      Skip analysis phase (only run collection)"
            echo "  --help               Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

################################################################################
# Helper Functions
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_separator() {
    echo "================================================================================"
}

check_python() {
    if ! command -v python3 &> /dev/null; then
        log_error "python3 not found. Please install Python 3.8+"
        exit 1
    fi

    PYTHON_VERSION=$(python3 --version | awk '{print $2}')
    log_info "Python version: ${PYTHON_VERSION}"
}

check_directories() {
    log_info "Checking/creating output directories..."

    mkdir -p "${RESULTS_DIR}"
    mkdir -p "${ANALYSIS_DIR}"
    mkdir -p "${REPORT_DIR}"
    mkdir -p "${REPORT_CSV_DIR}"

    log_success "Output directories ready"
}

run_script() {
    local script_name=$1
    local script_path=$2
    local description=$3

    print_separator
    log_info "Running: ${script_name}"
    log_info "Description: ${description}"
    echo ""

    if [[ ! -f "${script_path}" ]]; then
        log_error "Script not found: ${script_path}"
        exit 1
    fi

    # Execute script
    if python3 "${script_path}"; then
        log_success "${script_name} completed successfully"
    else
        log_error "${script_name} failed with exit code $?"
        exit 1
    fi

    echo ""
}

################################################################################
# Main Execution
################################################################################

main() {
    print_separator
    echo -e "${GREEN}VULNERABILITY ASSESSMENT SUITE${NC}"
    echo "Version: 1.0"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    print_separator
    echo ""

    # Check prerequisites
    log_info "Checking prerequisites..."
    check_python
    check_directories
    echo ""

    # PHASE 1: DATA COLLECTION
    if [[ "${SKIP_COLLECTION}" == false ]]; then
        print_separator
        echo -e "${GREEN}PHASE 1: DATA COLLECTION${NC}"
        print_separator
        echo ""

        # Step 1.1: Nmap Unifier
        run_script \
            "01_nmap_unifier.py" \
            "${SCRIPTS_DIR}/collection/01_nmap_unifier.py" \
            "Unify Nmap scan results into standardized JSON"

        # Step 1.2: Greenbone Unifier
        run_script \
            "02_greenbone_unifier.py" \
            "${SCRIPTS_DIR}/collection/02_greenbone_unifier.py" \
            "Unify Greenbone/OpenVAS scan results into standardized JSON"

        # Step 1.3: Data Merger
        run_script \
            "03_data_merger.py" \
            "${SCRIPTS_DIR}/collection/03_data_merger.py" \
            "Merge Nmap and Greenbone data into master_data.json"

        # Verify master_data.json exists
        if [[ ! -f "${RESULTS_DIR}/master_data.json" ]]; then
            log_error "master_data.json not created. Cannot proceed."
            exit 1
        fi

        log_success "PHASE 1 COMPLETED - master_data.json created"
        echo ""
    else
        log_warning "Skipping data collection phase (--skip-collection)"

        # Verify master_data.json exists
        if [[ ! -f "${RESULTS_DIR}/master_data.json" ]]; then
            log_error "master_data.json not found in ${RESULTS_DIR}"
            log_error "Cannot skip collection without existing master_data.json"
            exit 1
        fi

        log_info "Using existing master_data.json"
        echo ""
    fi

    # PHASE 2: DATA ANALYSIS
    if [[ "${SKIP_ANALYSIS}" == false ]]; then
        print_separator
        echo -e "${GREEN}PHASE 2: DATA ANALYSIS${NC}"
        print_separator
        echo ""

        # Step 2.1: Vulnerability Analyzer
        run_script \
            "04_vuln_analyzer.py" \
            "${SCRIPTS_DIR}/analysis/04_vuln_analyzer.py" \
            "Analyze vulnerabilities and generate statistics"

        # Step 2.2: Data Transformer
        run_script \
            "12_data_transformer.py" \
            "${SCRIPTS_DIR}/analysis/12_data_transformer.py" \
            "Transform master_data.json and analysis results into structured CSV files"

        # Step 2.3: Service Analyzer
        run_script \
            "05_service_analyzer.py" \
            "${SCRIPTS_DIR}/analysis/05_service_analyzer.py" \
            "Analyze services, ports, OS distribution and generate CSVs"

        # Step 2.4: Surface Mapper
        run_script \
            "06_surface_mapper.py" \
            "${SCRIPTS_DIR}/analysis/06_surface_mapper.py" \
            "Map attack surface and identify exposed hosts"

        # Step 2.5: Risk Scorer
        run_script \
            "07_risk_scorer.py" \
            "${SCRIPTS_DIR}/analysis/07_risk_scorer.py" \
            "Calculate risk scores and identify high-risk hosts"

        # Step 2.6: Extract Services (Optional)
        if [[ -f "${SCRIPTS_DIR}/analysis/08_extract_services.py" ]]; then
            run_script \
                "08_extract_services.py" \
                "${SCRIPTS_DIR}/analysis/08_extract_services.py" \
                "Export complete services table to CSV"
        fi

        # Step 2.7: Data Aggregator
        run_script \
            "09_data_aggregator.py" \
            "${SCRIPTS_DIR}/analysis/09_data_aggregator.py" \
            "Aggregate metrics and generate statistical CSVs"

        # Step 2.8: Chart Generator
        run_script \
            "10_chart_generator.py" \
            "${SCRIPTS_DIR}/analysis/10_chart_generator.py" \
            "Generate professional PNG charts and graphs"

        # Step 2.9: Cleanup
        run_script \
            "11_cleanup.py" \
            "${SCRIPTS_DIR}/analysis/11_cleanup.py" \
            "Organize output and perform cleanup"

        log_success "PHASE 2 COMPLETED - All analyses, charts, and cleanup completed"
        echo ""
    else
        log_warning "Skipping analysis phase (--skip-analysis)"
        echo ""
    fi

    # FINAL SUMMARY
    print_separator
    echo -e "${GREEN}SUITE EXECUTION COMPLETED SUCCESSFULLY${NC}"
    print_separator
    echo ""

    log_info "Output Summary:"
    echo ""

    if [[ "${SKIP_COLLECTION}" == false ]]; then
        echo "  Data Collection (output/results/):"
        if [[ -f "${RESULTS_DIR}/nmap_unified.json" ]]; then
            echo "    ✓ nmap_unified.json ($(du -h "${RESULTS_DIR}/nmap_unified.json" | cut -f1))"
        fi
        if [[ -f "${RESULTS_DIR}/greenbone_unified.json" ]]; then
            echo "    ✓ greenbone_unified.json ($(du -h "${RESULTS_DIR}/greenbone_unified.json" | cut -f1))"
        fi
        if [[ -f "${RESULTS_DIR}/master_data.json" ]]; then
            echo "    ✓ master_data.json ($(du -h "${RESULTS_DIR}/master_data.json" | cut -f1))"
        fi
        echo ""
    fi

    if [[ "${SKIP_ANALYSIS}" == false ]]; then
        echo "  Data Analysis (output/analysis/):"
        ANALYSIS_COUNT=$(find "${ANALYSIS_DIR}" -type f -name "*.json" 2>/dev/null | wc -l)
        echo "    ✓ ${ANALYSIS_COUNT} analysis JSON files"
        echo ""

        echo "  Report CSVs (output/report/CSVs/):"
        CSV_COUNT=$(find "${REPORT_CSV_DIR}" -type f -name "*.csv" 2>/dev/null | wc -l)
        echo "    ✓ ${CSV_COUNT} CSV files generated"
        echo ""
    fi

    echo "  Total output size: $(du -sh "${OUTPUT_DIR}" | cut -f1)"
    echo ""

    print_separator
    log_success "All tasks completed successfully!"
    print_separator
    echo ""

    log_info "Next steps:"
    echo "  1. Review master_data.json: ${RESULTS_DIR}/master_data.json"
    echo "  2. Check analysis results: ${ANALYSIS_DIR}/"
    echo "  3. Export CSVs for reporting: ${REPORT_CSV_DIR}/"
    echo "  4. Copy output/report/ directory to create your final Report folder"
    echo ""
}

# Execute main function
main "$@"
