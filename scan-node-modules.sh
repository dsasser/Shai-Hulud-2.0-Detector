#!/bin/bash

# =============================================================================
# SHAI-HULUD 2.0 NODE_MODULES SCANNER
# =============================================================================
# Recursively scans all node_modules directories for compromised packages
# and malicious indicator files from the Shai-Hulud 2.0 supply chain attack.
#
# Usage: ./scan-node-modules.sh [directory]
# If no directory specified, scans from current directory
# =============================================================================

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_FILE="${SCRIPT_DIR}/compromised-packages.json"

# Counters
TOTAL_NODE_MODULES=0
TOTAL_COMPROMISED=0
TOTAL_MALICIOUS_FILES=0
THREATS_FOUND=0

# =============================================================================
# FUNCTIONS
# =============================================================================

print_header() {
    echo ""
    echo -e "${BOLD}=====================================================================${NC}"
    echo -e "${BOLD}  SHAI-HULUD 2.0 NODE_MODULES SCANNER${NC}"
    echo -e "${BOLD}=====================================================================${NC}"
    echo ""
}

check_dependencies() {
    # Check if compromised-packages.json exists
    if [ ! -f "$DB_FILE" ]; then
        echo -e "${RED}ERROR: compromised-packages.json not found at: ${DB_FILE}${NC}"
        echo "Please ensure the script is in the same directory as compromised-packages.json"
        exit 1
    fi

    # Check for jq (optional but preferred)
    if command -v jq &> /dev/null; then
        echo -e "${GREEN}✓${NC} Using jq for JSON parsing (fast mode)"
        USE_JQ=1
    else
        echo -e "${YELLOW}⚠${NC} jq not found, using grep/sed fallback (slower)"
        echo "  Install jq for better performance: brew install jq (macOS) or apt-get install jq (Linux)"
        USE_JQ=0
    fi
    echo ""
}

extract_malicious_files() {
    if [ "$USE_JQ" -eq 1 ]; then
        jq -r '.indicators.maliciousFiles[]' "$DB_FILE"
    else
        # Fallback: extract maliciousFiles array using grep/sed
        grep -A 20 '"maliciousFiles"' "$DB_FILE" | grep '"' | sed 's/.*"\(.*\)".*/\1/' | grep -v maliciousFiles
    fi
}

extract_package_names() {
    if [ "$USE_JQ" -eq 1 ]; then
        jq -r '.packages[].name' "$DB_FILE"
    else
        # Fallback: extract package names using grep
        grep '"name":' "$DB_FILE" | grep -v '"attackInfo"' | sed 's/.*"name": *"\([^"]*\)".*/\1/'
    fi
}

get_package_severity() {
    local pkg_name="$1"
    if [ "$USE_JQ" -eq 1 ]; then
        jq -r ".packages[] | select(.name == \"$pkg_name\") | .severity" "$DB_FILE" 2>/dev/null || echo "critical"
    else
        # Simple fallback - just return critical for all
        echo "critical"
    fi
}

find_node_modules_dirs() {
    local search_dir="$1"
    # Find all node_modules directories, excluding nested ones (node_modules inside node_modules)
    find "$search_dir" -type d -name "node_modules" -not -path "*/node_modules/*/node_modules/*" 2>/dev/null
}

scan_node_modules_dir() {
    local nm_dir="$1"
    local found_packages=()
    local found_files=()
    local has_issues=0

    echo -e "${BLUE}📁 Scanning:${NC} $nm_dir"

    # Scan for compromised packages
    while IFS= read -r pkg_name; do
        # Handle scoped packages (e.g., @asyncapi/cli)
        local pkg_path="${nm_dir}/${pkg_name}"

        if [ -d "$pkg_path" ]; then
            local severity=$(get_package_severity "$pkg_name")
            found_packages+=("$pkg_name|$severity")
            TOTAL_COMPROMISED=$((TOTAL_COMPROMISED + 1))
            has_issues=1
        fi
    done < <(extract_package_names)

    # Scan for malicious indicator files
    while IFS= read -r malicious_file; do
        while IFS= read -r found_path; do
            found_files+=("$found_path")
            TOTAL_MALICIOUS_FILES=$((TOTAL_MALICIOUS_FILES + 1))
            has_issues=1
        done < <(find "$nm_dir" -type f -name "$malicious_file" 2>/dev/null)
    done < <(extract_malicious_files)

    # Report findings for this directory
    if [ "$has_issues" -eq 0 ]; then
        echo -e "   ${GREEN}✓ CLEAN${NC} - No threats detected"
    else
        THREATS_FOUND=1

        if [ ${#found_packages[@]} -gt 0 ]; then
            echo -e "   ${RED}✗ COMPROMISED PACKAGES FOUND:${NC}"
            for pkg_info in "${found_packages[@]}"; do
                IFS='|' read -r pkg_name severity <<< "$pkg_info"
                echo -e "     ${RED}[${severity^^}]${NC} $pkg_name"
            done
        fi

        if [ ${#found_files[@]} -gt 0 ]; then
            echo -e "   ${RED}✗ MALICIOUS INDICATOR FILES FOUND:${NC}"
            for file_path in "${found_files[@]}"; do
                echo -e "     ${RED}⚠${NC} $file_path"
            done
        fi
    fi

    echo ""
    TOTAL_NODE_MODULES=$((TOTAL_NODE_MODULES + 1))
}

print_summary() {
    echo -e "${BOLD}=====================================================================${NC}"
    echo -e "${BOLD}  SCAN SUMMARY${NC}"
    echo -e "${BOLD}=====================================================================${NC}"
    echo ""
    echo "  node_modules directories scanned: $TOTAL_NODE_MODULES"
    echo "  Compromised packages found:       $TOTAL_COMPROMISED"
    echo "  Malicious indicator files found:  $TOTAL_MALICIOUS_FILES"
    echo ""

    if [ "$THREATS_FOUND" -eq 0 ]; then
        echo -e "${GREEN}${BOLD}  ✓ STATUS: CLEAN${NC}"
        echo -e "${GREEN}  No Shai-Hulud 2.0 threats detected${NC}"
    else
        echo -e "${RED}${BOLD}  ✗ STATUS: THREATS DETECTED${NC}"
        echo ""
        echo -e "${YELLOW}  IMMEDIATE ACTIONS REQUIRED:${NC}"
        echo "  1. Do NOT run npm install until packages are updated"
        echo "  2. Rotate all credentials (npm, GitHub, AWS, etc.)"
        echo "  3. Check for unauthorized GitHub self-hosted runners named 'SHA1HULUD'"
        echo "  4. Audit GitHub repos for 'Shai-Hulud: The Second Coming' description"
        echo "  5. Check for actionsSecrets.json files containing stolen credentials"
        echo "  6. Review package.json scripts for suspicious preinstall/postinstall hooks"
        echo ""
        echo "  For more information:"
        echo "  https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains"
    fi

    echo ""
    echo -e "${BOLD}=====================================================================${NC}"
    echo ""
}

# =============================================================================
# MAIN EXECUTION
# =============================================================================

main() {
    local scan_dir="${1:-.}"

    # Validate scan directory
    if [ ! -d "$scan_dir" ]; then
        echo -e "${RED}ERROR: Directory not found: ${scan_dir}${NC}"
        exit 1
    fi

    # Convert to absolute path
    scan_dir="$(cd "$scan_dir" && pwd)"

    print_header
    check_dependencies

    echo -e "${BLUE}Starting scan from:${NC} $scan_dir"
    echo ""

    # Find and scan all node_modules directories
    local nm_dirs=()
    while IFS= read -r nm_dir; do
        nm_dirs+=("$nm_dir")
    done < <(find_node_modules_dirs "$scan_dir")

    if [ ${#nm_dirs[@]} -eq 0 ]; then
        echo -e "${YELLOW}No node_modules directories found in ${scan_dir}${NC}"
        echo ""
        exit 0
    fi

    echo -e "${BLUE}Found ${#nm_dirs[@]} node_modules director(ies) to scan${NC}"
    echo ""

    # Scan each node_modules directory
    for nm_dir in "${nm_dirs[@]}"; do
        scan_node_modules_dir "$nm_dir"
    done

    print_summary

    # Exit with appropriate code
    if [ "$THREATS_FOUND" -eq 1 ]; then
        exit 1
    else
        exit 0
    fi
}

# Run main function
main "$@"

