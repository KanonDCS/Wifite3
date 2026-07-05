#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
err()  { echo -e "${RED}[!]${RESET} $*"; }
info() { echo -e "${CYAN}[*]${RESET} $*"; }

NO_SUDO=false
CHECK_ONLY=false

for arg in "$@"; do
  case $arg in
    --no-sudo)     NO_SUDO=true ;;
    --check-only)  CHECK_ONLY=true ;;
    --help|-h)
      echo "Usage: $0 [--no-sudo] [--check-only]"
      echo "  --no-sudo      Skip sudo prefix"
      echo "  --check-only   Only verify tools, do not install"
      exit 0
      ;;
  esac
done

SUDO_CMD=""
if [[ "$NO_SUDO" == false ]] && command -v sudo &>/dev/null; then
  SUDO_CMD="sudo"
fi

IS_TERMUX=false
IS_NETHUNTER=false
IS_KALI=false
IS_PARROT=false

if [[ -d /data/data/com.termux ]] || [[ "${PREFIX:-}" == /data/data/com.termux* ]]; then
  IS_TERMUX=true
elif [[ -d /sdcard/nh_files ]] || [[ -f /system/xbin/busybox ]]; then
  IS_NETHUNTER=true
elif [[ -f /etc/os-release ]]; then
  source /etc/os-release 2>/dev/null || true
  case "${ID_LIKE:-}${ID:-}" in
    *kali*)   IS_KALI=true ;;
    *parrot*) IS_PARROT=true ;;
  esac
fi

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════╗${RESET}"
echo -e "${BOLD}║            Wifite 3 Installer            ║${RESET}"
echo -e "${BOLD}╚══════════════════════════════════════════╝${RESET}"
echo ""

if $IS_TERMUX; then
  info "Environment: ${BOLD}Termux (Android)${RESET}"
elif $IS_NETHUNTER; then
  info "Environment: ${BOLD}Kali NetHunter${RESET}"
elif $IS_KALI; then
  info "Environment: ${BOLD}Kali Linux${RESET}"
elif $IS_PARROT; then
  info "Environment: ${BOLD}Parrot OS${RESET}"
else
  info "Environment: ${BOLD}${PRETTY_NAME:-Generic Linux}${RESET}"
fi

APT_REQUIRED=(
  "aircrack-ng"
  "iw"
  "python3-scapy"
)

APT_OPTIONAL=(
  "hcxdumptool"
  "hcxtools"
  "tshark"
  "hashcat"
  "reaver"
  "bully"
  "macchanger"
  "python3-tqdm"
  "python3-colorama"
)

PIP_REQUIRED=(
  "scapy"
)

PIP_OPTIONAL=(
  "tqdm"
  "colorama"
)

TERMUX_REQUIRED=(
  "aircrack-ng"
  "iw"
)

TERMUX_OPTIONAL=(
  "hcxdumptool"
  "hcxtools"
  "tshark"
  "hashcat"
)

check_bin() {
  command -v "$1" &>/dev/null
}

install_apt() {
  local pkg="$1"
  local required="${2:-false}"

  if $CHECK_ONLY; then
    if check_bin "$pkg" || dpkg -l "$pkg" &>/dev/null 2>&1; then
      ok "  ${pkg} — found"
    else
      warn "  ${pkg} — NOT FOUND"
    fi
    return
  fi

  info "Installing ${pkg}..."
  if $SUDO_CMD apt-get install -y "$pkg" &>/dev/null; then
    ok "  ${pkg} installed"
  else
    if [[ "$required" == true ]]; then
      err "  FAILED to install required package: ${pkg}"
    else
      warn "  FAILED to install optional package: ${pkg} (skipping)"
    fi
  fi
}

install_pkg() {
  local pkg="$1"
  local required="${2:-false}"

  if $CHECK_ONLY; then
    if check_bin "$pkg"; then
      ok "  ${pkg} — found"
    else
      warn "  ${pkg} — NOT FOUND"
    fi
    return
  fi

  info "Installing ${pkg} via pkg..."
  if pkg install -y "$pkg" &>/dev/null; then
    ok "  ${pkg} installed"
  else
    if [[ "$required" == true ]]; then
      err "  FAILED to install required package: ${pkg}"
    else
      warn "  FAILED to install optional package: ${pkg} (skipping)"
    fi
  fi
}

install_pip() {
  local pkg="$1"

  if $CHECK_ONLY; then
    if python3 -c "import ${pkg}" &>/dev/null 2>&1; then
      ok "  python: ${pkg} — found"
    else
      warn "  python: ${pkg} — NOT FOUND"
    fi
    return
  fi

  info "Installing Python package: ${pkg}..."
  
  local flags="--quiet"
  if ! python3 -c "import sys" &>/dev/null; then
    flags="$flags --break-system-packages"
  else
    if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
      flags="$flags --break-system-packages"
    fi
  fi

  if pip3 install $flags "$pkg" &>/dev/null; then
    ok "  python: ${pkg} installed"
  else
    warn "  python: ${pkg} install failed (non-fatal)"
  fi
}

check_version() {
  local binary="$1"
  local min_major="$2"
  local min_minor="$3"

  if ! check_bin "$binary"; then
    return
  fi

  local version
  version=$("$binary" --version 2>&1 | grep -oP '\d+\.\d+' | head -1 || true)
  if [[ -z "$version" ]]; then
    warn "Could not determine ${binary} version"
    return
  fi

  local major minor
  major=$(echo "$version" | cut -d. -f1)
  minor=$(echo "$version" | cut -d. -f2)

  if [[ "$major" -lt "$min_major" ]] || \
     { [[ "$major" -eq "$min_major" ]] && [[ "$minor" -lt "$min_minor" ]]; }; then
    warn "${binary} v${version} is below minimum v${min_major}.${min_minor}"
    warn "  Please upgrade: ${SUDO_CMD} apt upgrade ${binary}"
  else
    ok "${binary} v${version} — OK (>= ${min_major}.${min_minor})"
  fi
}

if $IS_TERMUX; then
  echo ""
  info "Updating Termux package lists..."
  $CHECK_ONLY || pkg update -y &>/dev/null

  echo ""
  echo -e "${BOLD}Required packages:${RESET}"
  for pkg in "${TERMUX_REQUIRED[@]}"; do
    install_pkg "$pkg" true
  done

  echo ""
  echo -e "${BOLD}Optional packages:${RESET}"
  for pkg in "${TERMUX_OPTIONAL[@]}"; do
    install_pkg "$pkg" false
  done

else
  echo ""
  info "Updating package lists..."
  $CHECK_ONLY || $SUDO_CMD apt-get update -qq

  echo ""
  echo -e "${BOLD}Required packages:${RESET}"
  for pkg in "${APT_REQUIRED[@]}"; do
    install_apt "$pkg" true
  done

  echo ""
  echo -e "${BOLD}Optional packages:${RESET}"
  for pkg in "${APT_OPTIONAL[@]}"; do
    install_apt "$pkg" false
  done
fi

echo ""
echo -e "${BOLD}Python packages:${RESET}"
if check_bin python3; then
  for pkg in "${PIP_REQUIRED[@]}"; do
    if ! python3 -c "import ${pkg}" &>/dev/null; then
      install_pip "$pkg"
    else
      ok "  python: ${pkg} — found"
    fi
  done
  for pkg in "${PIP_OPTIONAL[@]}"; do
    if ! python3 -c "import ${pkg}" &>/dev/null; then
      install_pip "$pkg"
    else
      ok "  python: ${pkg} — found"
    fi
  done
else
  warn "python3 not found — skipping Python package installation"
fi

echo ""
echo -e "${BOLD}Version checks:${RESET}"
check_version "hcxdumptool"   6 0
check_version "hcxpcapngtool" 6 0
check_version "hashcat"       6 0

if [[ -f setup.py ]] && ! $CHECK_ONLY; then
  echo ""
  info "Installing Wifite 3 Python package..."
  
  local pkg_flags=""
  if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
    pkg_flags="--break-system-packages"
  fi

  if pip3 install --quiet -e . $pkg_flags 2>/dev/null || python3 setup.py install --quiet 2>/dev/null; then
    ok "Wifite 3 installed as Python package"
  else
    warn "Could not install as package — run directly with: sudo python3 -m wifite"
  fi
fi

echo ""
echo -e "${BOLD}────────────────────────────────────────────${RESET}"
ok "Wifite 3 installation complete!"
echo ""
info "To run Wifite 3:"
if check_bin wifite; then
  echo "    sudo wifite"
else
  echo "    sudo python3 -m wifite"
fi
echo ""
if $IS_TERMUX; then
  info "Termux note: Some attacks require a compatible kernel."
  info "  For full support, use Kali NetHunter with the custom kernel."
fi
echo ""
