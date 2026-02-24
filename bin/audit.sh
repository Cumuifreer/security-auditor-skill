#!/bin/bash

# Security Auditor - Static Security Scanner for Agent Skills
# Scans third-party skills for malicious patterns before installation

set -uo pipefail

RED='\033[0;31m'; ORANGE='\033[0;33m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

CRITICAL=0; HIGH=0; MEDIUM=0; LOW=0; WHITELISTED=0
WHITELIST_FILE="$HOME/.openclaw/security-whitelist.json"
MODE="full"; OUTPUT_JSON=false; ASSUME_YES=true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fast) MODE="fast"; shift ;;
    --full) MODE="full"; shift ;;
    --json) OUTPUT_JSON=true; shift ;;
    --yes|-y) ASSUME_YES=true; shift ;;
    *) TARGET="$1"; shift ;;
  esac
done
TARGET="${TARGET:-.}"

if [[ ! -e "$TARGET" ]]; then
  echo "Error: $TARGET not found"; exit 1
fi

init_whitelist() {
  mkdir -p "$(dirname "$WHITELIST_FILE")"
  [[ -f "$WHITELIST_FILE" ]] || echo '{"whitelist":[],"version":1}' > "$WHITELIST_FILE"
}

dir_hash() {
  if command -v shasum >/dev/null 2>&1; then
    find "$TARGET" -type f -print0 2>/dev/null | sort -z | xargs -0 shasum 2>/dev/null | shasum | awk '{print $1}'
  else
    find "$TARGET" -type f -print0 2>/dev/null | sort -z | xargs -0 md5 2>/dev/null | md5
  fi
}

is_whitelisted() {
  local hash
  hash="$(dir_hash || true)"
  [[ -n "$hash" ]] && grep -q "$hash" "$WHITELIST_FILE" 2>/dev/null
}

add_to_whitelist() {
  local hash name
  hash="$(dir_hash || true)"; name="$(basename "$TARGET")"
  if command -v jq >/dev/null 2>&1 && [[ -n "$hash" ]]; then
    jq --arg hash "$hash" --arg name "$name" '.whitelist += [{"name":$name,"hash":$hash,"date":now}]' "$WHITELIST_FILE" > "$WHITELIST_FILE.tmp" && mv "$WHITELIST_FILE.tmp" "$WHITELIST_FILE"
  fi
}

print_finding() {
  local severity="$1" msg="$2" file="${3:-}" line="${4:-}"
  case "$severity" in
    CRITICAL) CRITICAL=$((CRITICAL+1)); echo -e "${RED}[!] CRITICAL:${NC} $msg" ;;
    HIGH) HIGH=$((HIGH+1)); echo -e "${ORANGE}[!] HIGH:${NC} $msg" ;;
    MEDIUM) MEDIUM=$((MEDIUM+1)); echo -e "${YELLOW}[!] MEDIUM:${NC} $msg" ;;
    LOW) LOW=$((LOW+1)); echo -e "${BLUE}[!] LOW:${NC} $msg" ;;
  esac
  [[ -n "$file" ]] && echo "    File: $file"
  [[ -n "$line" ]] && echo "    Line: $line"
}

scan_shell() {
  local file="$1" line
  line=$(grep -nE 'curl[^\n]*\|[[:space:]]*(bash|sh|zsh)([[:space:]]|$)' "$file" | grep -v '^#' | grep -v 'grep -nE' | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "CRITICAL" "curl | shell detected (remote code execution)" "$file" "$line"

  line=$(grep -nE 'wget[^\n]*\|[[:space:]]*(bash|sh|zsh)([[:space:]]|$)' "$file" | grep -v '^#' | grep -v 'grep -nE' | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "CRITICAL" "wget | shell detected (remote code execution)" "$file" "$line"

  line=$(grep -nE 'base64[[:space:]]+-d[[:space:]]*\|[[:space:]]*(bash|sh|zsh)' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "CRITICAL" "Obfuscated payload decode+execute" "$file" "$line"

  line=$(grep -nE 'eval[[:space:]]*\$\([[:space:]]*curl' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "HIGH" "eval(curl) remote code injection" "$file" "$line"

  line=$(grep -nE 'xattr[[:space:]]+-r.*com\.apple\.quarantine' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "CRITICAL" "macOS Gatekeeper bypass detected" "$file" "$line"

  line=$(grep -nE '(^|[[:space:]])sudo[[:space:]].*-S([[:space:]]|$)' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "HIGH" "Silent sudo execution" "$file" "$line"
}

scan_js() {
  local file="$1" line
  line=$(grep -nE '(api_key|apikey|API_KEY|APIKEY)[[:space:]]*[:=][[:space:]]*["\x27][A-Za-z0-9_-]{20,}' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "HIGH" "Hardcoded API key" "$file" "$line"

  line=$(grep -nE '(^|[^A-Za-z0-9_])eval[[:space:]]*\(' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "MEDIUM" "eval() usage" "$file" "$line"

  line=$(grep -nE 'child_process.*exec[[:space:]]*\(' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "MEDIUM" "child_process.exec usage" "$file" "$line"
}

scan_python() {
  local file="$1" line
  line=$(grep -nE 'subprocess\.(Popen|run)\(.*shell[[:space:]]*=[[:space:]]*True' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "HIGH" "Python subprocess shell=True" "$file" "$line"

  line=$(grep -nE '(^|[^A-Za-z0-9_])(eval|exec)\(' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "HIGH" "Python eval/exec usage" "$file" "$line"

  line=$(grep -nE 'requests\.(get|post|put|delete)\(.*verify[[:space:]]*=[[:space:]]*False' "$file" | head -1 | cut -d: -f1 || true)
  [[ -n "$line" ]] && print_finding "MEDIUM" "requests(..., verify=False)" "$file" "$line"
}

scan_json() {
  local file="$1"
  if grep -q 'http://' "$file" 2>/dev/null; then
    if ! grep -Eq 'http://(localhost|127\.0\.0\.1)' "$file" 2>/dev/null; then
      print_finding "MEDIUM" "Non-HTTPS URL in config" "$file"
    fi
  fi
  grep -Eq '(secret|token|password|key)[[:space:]]*[:=][[:space:]]*["\x27][^"\x27]{10,}' "$file" 2>/dev/null && \
    print_finding "MEDIUM" "Possible credential in config" "$file" || true
}

scan_encoded() {
  local file="$1"
  file "$file" | grep -qv "text" && print_finding "MEDIUM" "Binary file in skill directory" "$file" || true
  local count
  count=$(grep -Eoc '[A-Za-z0-9+/=]{200,}' "$file" 2>/dev/null || true)
  [[ "${count:-0}" -gt 3 ]] && print_finding "HIGH" "Large encoded content blocks" "$file"
}

main() {
  init_whitelist
  echo -e "${BLUE}🔒 Security Audit Report${NC}"
  echo "========================"
  echo "Path: $TARGET"
  echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
  echo "Mode: $MODE"
  echo ""

  if is_whitelisted; then
    echo -e "${GREEN}✓ This skill is whitelisted (known safe)${NC}"
    exit 0
  fi

  local files
  files=$(find "$TARGET" -type f \( -name "*.sh" -o -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.py" -o -name "package.json" \) 2>/dev/null)
  [[ -z "$files" ]] && { echo -e "${YELLOW}⚠ No scannable files found${NC}"; exit 0; }

  while IFS= read -r f; do
    case "${f##*.}" in
      sh) scan_shell "$f" ;;
      js|ts) scan_js "$f" ;;
      json) scan_json "$f" ;;
      py) scan_python "$f"; scan_shell "$f" ;;
      *)
        if [[ "$(basename "$f")" == "package.json" ]]; then
          grep -nE '"(preinstall|install|postinstall)"[[:space:]]*:' "$f" >/dev/null 2>&1 && print_finding "HIGH" "package.json install hook present" "$f" || true
        fi
        ;;
    esac
    [[ "$MODE" == "full" ]] && scan_encoded "$f"
  done <<< "$files"

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo -e "${RED}CRITICAL:${NC} $CRITICAL"
  echo -e "${ORANGE}HIGH:${NC} $HIGH"
  echo -e "${YELLOW}MEDIUM:${NC} $MEDIUM"
  echo -e "${BLUE}LOW:${NC} $LOW"
  echo ""

  if [[ $CRITICAL -gt 0 ]]; then
    echo -e "${RED}⚠️  RECOMMENDATION: DO NOT INSTALL${NC}"; exit 2
  elif [[ $HIGH -gt 0 ]]; then
    echo -e "${ORANGE}⚠️  RECOMMENDATION: REVIEW CAREFULLY${NC}"; exit 1
  elif [[ $MEDIUM -gt 0 ]]; then
    echo -e "${YELLOW}⚠️  RECOMMENDATION: CAUTION${NC}"; exit 0
  else
    echo -e "${GREEN}✓ RECOMMENDATION: LIKELY SAFE${NC}"
    if [[ "$ASSUME_YES" == true ]]; then
      add_to_whitelist || true
    fi
    exit 0
  fi
}

main
