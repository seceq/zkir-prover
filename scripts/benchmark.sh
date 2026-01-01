#!/bin/bash
# Performance benchmark script for deferred mode (Phase 7b)
#
# Usage:
#   ./scripts/benchmark.sh              # Run all benchmarks
#   ./scripts/benchmark.sh --save       # Save results to file
#   ./scripts/benchmark.sh --compare    # Compare with previous results

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RESULTS_DIR="$PROJECT_ROOT/benchmark_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create results directory
mkdir -p "$RESULTS_DIR"

print_header() {
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

run_benchmarks() {
    print_header "Running Deferred Mode Benchmarks"

    cd "$PROJECT_ROOT"

    # Run the benchmark tests
    if [ "$1" == "--save" ]; then
        OUTPUT_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.txt"
        echo -e "${GREEN}Saving results to: $OUTPUT_FILE${NC}"
        cargo test --release benchmark -- --nocapture | tee "$OUTPUT_FILE"

        # Extract key metrics and save to CSV
        CSV_FILE="$RESULTS_DIR/benchmark_${TIMESTAMP}.csv"
        echo "Benchmark,TraceRows,Normalizations,WitnessTime,AuxTime,ProvingTime,TotalTime,MemoryMB" > "$CSV_FILE"

        # Parse results (this is a simplified version - adjust based on actual output)
        grep "Trace rows:" "$OUTPUT_FILE" | while read -r line; do
            # Extract metrics using awk/sed
            # This is a placeholder - actual implementation would parse the formatted output
            echo "Parsing metrics..." >> "$CSV_FILE"
        done

        echo -e "${GREEN}Results saved to:${NC}"
        echo -e "  - Text: $OUTPUT_FILE"
        echo -e "  - CSV:  $CSV_FILE"

        # Create symlink to latest
        ln -sf "$(basename "$OUTPUT_FILE")" "$RESULTS_DIR/latest.txt"
        ln -sf "$(basename "$CSV_FILE")" "$RESULTS_DIR/latest.csv"

    else
        cargo test --release benchmark -- --nocapture
    fi
}

compare_results() {
    print_header "Comparing with Previous Results"

    LATEST="$RESULTS_DIR/latest.txt"

    if [ ! -f "$LATEST" ]; then
        echo -e "${YELLOW}No previous results found. Run with --save first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}Previous results:${NC}"
    cat "$LATEST"

    echo ""
    print_header "Running New Benchmarks"

    CURRENT="$RESULTS_DIR/current_${TIMESTAMP}.txt"
    cargo test --release benchmark -- --nocapture | tee "$CURRENT"

    echo ""
    print_header "Comparison Summary"

    # Simple comparison (would be more sophisticated in practice)
    echo -e "${YELLOW}Previous:${NC} $(grep "Total:" "$LATEST" | head -1 || echo "N/A")"
    echo -e "${YELLOW}Current:${NC}  $(grep "Total:" "$CURRENT" | head -1 || echo "N/A")"

    rm "$CURRENT"
}

show_help() {
    cat << EOF
Deferred Mode Performance Benchmark Script

Usage:
    $0 [OPTIONS]

Options:
    --save              Run benchmarks and save results to file
    --compare           Compare current run with previous results
    --help              Show this help message

Examples:
    # Run benchmarks and display results
    $0

    # Save results with timestamp
    $0 --save

    # Compare with previous run
    $0 --compare

Results are saved to: $RESULTS_DIR/
EOF
}

# Parse arguments
case "${1:-}" in
    --save)
        run_benchmarks --save
        ;;
    --compare)
        compare_results
        ;;
    --help)
        show_help
        ;;
    "")
        run_benchmarks
        ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        show_help
        exit 1
        ;;
esac
