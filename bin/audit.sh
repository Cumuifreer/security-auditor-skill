#!/bin/bash

# Security Auditor - Static Security Scanner for Agent Skills
# Scans third-party skills for malicious patterns before installation

set -e

# Colors
RED='\033[0;31m'
ORANGE='\033[0;33m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Add GNU coreutils to PATH if available
if [ -d "/opt/homebrew/opt/coreutils/libexec/gnubin" ]; then
    PATH="/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH"
fi

# Counters
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
WHITELISTED=0

# Paths
WHITELIST_FILE="$HOME/.openclaw/security-whitelist.json"

# Default scan mode
MODE="full"
OUTPUT_JSON=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fast)
            MODE="fast"
            shift
            ;;
        --full)
            MODE="full"
            shift
            ;;
        --json)
            OUTPUT_JSON=true
            shift
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Default target
TARGET="${TARGET:-.}"

if [ ! -d "$TARGET" ] && [ ! -f "$TARGET" ]; then
    echo "Error: $TARGET not found"
    exit 1
fi

# Initialize whitelist
init_whitelist() {
    if [ ! -f "$WHITELIST_FILE" ]; then
        echo '{"whitelist":[],"version":1}' > "$WHITELIST_FILE"
    fi
}

# Check if in whitelist
is_whitelisted() {
    local hash
    hash=$(find "$TARGET" -type f -exec md5sum {} \; 2>/dev/null | md5sum | cut -d' ' -f1)
    if grep -q "$hash" "$WHITELIST_FILE" 2>/dev/null; then
        return 0
    fi
    return 1
}

# Add to whitelist
add_to_whitelist() {
    local hash
    hash=$(find "$TARGET" -type f -exec md5sum {} \; 2>/dev/null | md5sum | cut -d' ' -f1)
    local name
    name=$(basename "$TARGET")
    
    if command -v jq &> /dev/null; then
        jq --arg hash "$hash" --arg name "$name" '.whitelist += [{"name": $name, "hash": $hash, "date": now}]' "$WHITELIST_FILE" > temp.json && mv temp.json "$WHITELIST_FILE"
    fi
}

# Print findings
print_finding() {
    local severity=$1
    local message=$2
    local file=$3
    local line=$4
    
    case $severity in
        CRITICAL)
            CRITICAL=$((CRITICAL + 1))
            echo -e "${RED}[!] CRITICAL:${NC} $message"
            ;;
        HIGH)
            HIGH=$((HIGH + 1))
            echo -e "${ORANGE}[!] HIGH:${NC} $message"
            ;;
        MEDIUM)
            MEDIUM=$((MEDIUM + 1))
            echo -e "${YELLOW}[!] MEDIUM:${NC} $message"
            ;;
        LOW)
            LOW=$((LOW + 1))
            echo -e "${BLUE}[!] LOW:${NC} $message"
            ;;
    esac
    
    [ -n "$file" ] && echo "    File: $file"
    [ -n "$line" ] && echo "    Line: $line"
}

# Scan shell scripts
scan_shell() {
    local file=$1
    
    # curl | bash
    if grep -q 'curl.*|' "$file" 2>/dev/null && grep -q 'bash' "$file" 2>/dev/null; then
        # Check if they're on the same line or piped
        local line
        line=$(grep -n 'curl.*|' "$file" | grep -v '^#' | head -1 | cut -d: -f1)
        if [ -n "$line" ]; then
            print_finding "CRITICAL" "curl | bash detected (remote code execution)" "$file" "$line"
        fi
    fi
    
    # wget | bash
    if grep -q 'wget.*|' "$file" 2>/dev/null && grep -q 'bash' "$file" 2>/dev/null; then
        local line
        line=$(grep -n 'wget.*|' "$file" | grep -v '^#' | head -1 | cut -d: -f1)
        if [ -n "$line" ]; then
            print_finding "CRITICAL" "wget | bash detected (remote code execution)" "$file" "$line"
        fi
    fi
    
    # base64 -d | bash
    if egrep -q 'base64[[:space:]]+-d[[:space:]]*\|[[:space:]]*(bash|sh|zsh)' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'base64[[:space:]]+-d[[:space:]]*\|[[:space:]]*(bash|sh|zsh)' "$file" | head -1 | cut -d: -f1)
        print_finding "CRITICAL" "Obfuscated payload (base64 decode + execute)" "$file" "$line"
    fi
    
    # eval $(curl
    if egrep -q 'eval[[:space:]]*\$\([[:space:]]*curl' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'eval[[:space:]]*\$\([[:space:]]*curl' "$file" | head -1 | cut -d: -f1)
        print_finding "HIGH" "Remote code injection (eval curl)" "$file" "$line"
    fi
    
    # chmod +x
    if egrep -q 'chmod[[:space:]]*\+x' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'chmod[[:space:]]*\+x' "$file" | head -1 | cut -d: -f1)
        print_finding "HIGH" "Setting executable permission" "$file" "$line"
    fi
    
    # Gatekeeper bypass
    if egrep -q 'xattr[[:space:]]+-r.*com.apple.quarantine' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'xattr[[:space:]]+-r.*com.apple.quarantine' "$file" | head -1 | cut -d: -f1)
        print_finding "CRITICAL" "macOS Gatekeeper bypass detected" "$file" "$line"
    fi
    
    # Writing to sensitive paths
    if egrep -q '>\s*~/\.(bashrc|profile|zshrc|ssh|gitconfig)' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n '>\s*~/\.(bashrc|profile|zshrc|ssh|gitconfig)' "$file" | head -1 | cut -d: -f1)
        print_finding "HIGH" "Writing to sensitive path" "$file" "$line"
    fi
    
    # sudo without confirmation
    if egrep -q 'sudo[[:space:]]+.*-S' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'sudo[[:space:]]+.*-S' "$file" | head -1 | cut -d: -f1)
        print_finding "HIGH" "Silent sudo execution" "$file" "$line"
    fi
}

# Scan JavaScript/TypeScript
scan_js() {
    local file=$1
    
    # Hardcoded API keys
    if egrep -q '(api_key|apikey|API_KEY|APIKEY)[[:space:]]*[:=][[:space:]]*["'\''][a-zA-Z0-9_-]{20,}' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n '(api_key|apikey|API_KEY|APIKEY)[[:space:]]*[:=][[:space:]]*["'\''][a-zA-Z0-9_-]{20,}' "$file" | head -1 | cut -d: -f1)
        print_finding "HIGH" "Hardcoded API key detected" "$file" "$line"
    fi
    
    # eval
    if egrep -q 'eval\s*\(' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'eval\s*\(' "$file" | head -1 | cut -d: -f1)
        print_finding "MEDIUM" "eval() usage - potential code injection" "$file" "$line"
    fi
    
    # HTTP URLs
    if egrep -q 'http://' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'http://' "$file" | head -1 | cut -d: -f1)
        print_finding "MEDIUM" "Non-HTTPS URL found" "$file" "$line"
    fi
    
    # child_process exec
    if egrep -q 'child_process.*exec\s*\(' "$file" 2>/dev/null; then
        local line
        line=$(egrep -n 'child_process.*exec\s*\(' "$file" | head -1 | cut -d: -f1)
        print_finding "MEDIUM" "Command execution (exec)" "$file" "$line"
    fi
}

# Scan JSON files
scan_json() {
    local file=$1
    
    # Suspicious URLs
    if egrep -q 'http://(?!localhost|127\.0\.0\.1)' "$file" 2>/dev/null; then
        print_finding "MEDIUM" "Non-HTTPS URL in config" "$file"
    fi
    
    # Credentials
    if egrep -q '(secret|token|password|key)[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{10,}' "$file" 2>/dev/null; then
        print_finding "MEDIUM" "Possible credential in config" "$file"
    fi
}

# Scan for encoded/binary content
scan_encoded() {
    local file=$1
    
    # Check if binary
    if file "$file" | grep -qv "text"; then
        print_finding "MEDIUM" "Binary file in skill directory" "$file"
    fi
    
    # Large base64-like blocks
    if egrep -q '[A-Za-z0-9+/=]{200,}' "$file" 2>/dev/null; then
        local count
        count=$(egrep -c '[A-Za-z0-9+/=]{200,}' "$file" 2>/dev/null || echo 0)
        if [ "$count" -gt 3 ]; then
            print_finding "HIGH" "Large encoded content blocks (possible obfuscation)" "$file"
        fi
    fi
}

# Skip self-scan (don't scan the auditor itself)
if [[ "$TARGET" == *"security-auditor"* ]]; then
    echo -e "${GREEN}✓ Skipping self-scan (security-auditor)${NC}"
    exit 0
fi

# Main scan
main() {
    init_whitelist
    
    echo -e "${BLUE}🔒 Security Audit Report${NC}"
    echo "========================"
    echo "Path: $TARGET"
    echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Mode: $MODE"
    echo ""
    
    # Check if whitelisted
    if is_whitelisted; then
        echo -e "${GREEN}✓ This skill is whitelisted (known safe)${NC}"
        exit 0
    fi
    
    # Find all files
    local files
    files=$(find "$TARGET" -type f \( -name "*.sh" -o -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.py" \) 2>/dev/null)
    
    if [ -z "$files" ]; then
        echo -e "${YELLOW}⚠ No scannable files found${NC}"
        exit 0
    fi
    
    # Scan each file
    while IFS= read -r file; do
        ext="${file##*.}"
        
        case $ext in
            sh)
                scan_shell "$file"
                ;;
            js|ts)
                scan_js "$file"
                ;;
            json)
                scan_json "$file"
                ;;
            py)
                scan_shell "$file"
                ;;
        esac
        
        if [ "$MODE" == "full" ]; then
            scan_encoded "$file"
        fi
    done <<< "$files"
    
    # Summary
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${RED}CRITICAL:${NC} $CRITICAL"
    echo -e "${ORANGE}HIGH:${NC} $HIGH"
    echo -e "${YELLOW}MEDIUM:${NC} $MEDIUM"
    echo -e "${BLUE}LOW:${NC} $LOW"
    echo ""
    
    # Recommendation
    if [ $CRITICAL -gt 0 ]; then
        echo -e "${RED}⚠️  RECOMMENDATION: DO NOT INSTALL${NC}"
        echo "Found $CRITICAL CRITICAL threats. This skill appears malicious."
        exit 2
    elif [ $HIGH -gt 0 ]; then
        echo -e "${ORANGE}⚠️  RECOMMENDATION: REVIEW CAREFULLY${NC}"
        echo "Found $HIGH high-risk issues. Review before installing."
        exit 1
    elif [ $MEDIUM -gt 0 ]; then
        echo -e "${YELLOW}⚠️  RECOMMENDATION: CAUTION${NC}"
        echo "Found $MEDIUM medium-risk issues. Usually safe but verify."
        exit 0
    else
        echo -e "${GREEN}✓ RECOMMENDATION: LIKELY SAFE${NC}"
        echo "No significant threats detected."
        
        # Offer to whitelist
        read -p "Add to whitelist? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            add_to_whitelist
            echo "Added to whitelist."
        fi
        
        exit 0
    fi
}

main
