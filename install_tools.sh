#!/usr/bin/env bash
# =============================================================================
# SaiRecon — install_tools.sh
# Supports: Kali Linux (primary), Ubuntu/Debian, macOS (secondary)
# Usage:    chmod +x install_tools.sh && ./install_tools.sh
# =============================================================================
set -uo pipefail  # -e removed: optional tools may fail without stopping the install

GOVERSION="1.22.5"
GO_LINUX_AMD64="https://go.dev/dl/go${GOVERSION}.linux-amd64.tar.gz"
GO_LINUX_ARM64="https://go.dev/dl/go${GOVERSION}.linux-arm64.tar.gz"
GO_MAC_AMD64="https://go.dev/dl/go${GOVERSION}.darwin-amd64.tar.gz"
GO_MAC_ARM64="https://go.dev/dl/go${GOVERSION}.darwin-arm64.tar.gz"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
GF_PATTERNS_DIR="$HOME/.gf"
ENV_FILE="$SCRIPT_DIR/.env"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✗]${RESET} $*"; exit 1; }

echo -e "${BOLD}"
echo " ====================================================================="
echo "   =====     ===    ====  ======   ======   ====    ======  ==   =="
echo "  ==        == ==    ==   ==   ==  ==      ==  ==  ==    == ===  =="
echo "   ====    ==   ==   ==   ======   =====   ==      ==    == == = =="
echo "      ==   =======   ==   ==  ==   ==      ==  ==  ==    == ==  ==="
echo "  =====    ==   ==  ====  ==   ==  ======   ====    ======  ==   =="
echo " ====================================================================="
echo -e "${RESET}"
echo -e "${BOLD}SaiRecon — Tool Installer${RESET}"
echo "======================================"
echo

# ---------------------------------------------------------------------------
# Detect OS
# ---------------------------------------------------------------------------
OS=""
ARCH=$(uname -m)
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    error "Unsupported OS: $OSTYPE  — use install_tools_windows.ps1 on Windows."
fi
info "Detected OS: $OS ($ARCH)"
echo

# ---------------------------------------------------------------------------
# Step 1 — System packages
# ---------------------------------------------------------------------------
echo -e "${BOLD}[1/6] System packages${RESET}"
if [[ "$OS" == "linux" ]]; then
    sudo apt-get update -y -q
    sudo apt-get install -y -q \
        whois dnsutils nmap jq git curl unzip wget ruby-full build-essential \
        python3 python3-pip python3-venv libpcap-dev
    # whatweb via gem (apt version is often outdated)
    if ! command -v whatweb &>/dev/null; then
        sudo gem install whatweb --quiet
    fi
    success "System packages installed"
elif [[ "$OS" == "macos" ]]; then
    if ! command -v brew &>/dev/null; then
        warn "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install whois bind nmap jq git curl unzip wget ruby python3 libpcap
    gem install whatweb --quiet
    success "macOS packages installed"
fi
echo

# ---------------------------------------------------------------------------
# Step 2 — Go (official tarball, not apt golang-go which gives outdated 1.18)
# ---------------------------------------------------------------------------
echo -e "${BOLD}[2/6] Go ${GOVERSION}${RESET}"
install_go() {
    if [[ "$OS" == "linux" ]]; then
        URL=$( [[ "$ARCH" == "aarch64" ]] && echo "$GO_LINUX_ARM64" || echo "$GO_LINUX_AMD64" )
    else
        URL=$( [[ "$ARCH" == "arm64" ]] && echo "$GO_MAC_ARM64" || echo "$GO_MAC_AMD64" )
    fi
    TMP=$(mktemp -d)
    info "Downloading Go ${GOVERSION}..."
    curl -sL "$URL" -o "$TMP/go.tar.gz"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "$TMP/go.tar.gz"
    rm -rf "$TMP"
    success "Go ${GOVERSION} installed to /usr/local/go"
}

NEED_GO=false
if ! command -v go &>/dev/null; then
    NEED_GO=true
else
    CURRENT_GO=$(go version 2>/dev/null | grep -oP '\d+\.\d+' | head -1 || echo "0.0")
    MAJOR=$(echo "$CURRENT_GO" | cut -d. -f1)
    MINOR=$(echo "$CURRENT_GO" | cut -d. -f2)
    if (( MAJOR < 1 || (MAJOR == 1 && MINOR < 21) )); then
        warn "Go $CURRENT_GO found but need >=1.21. Upgrading..."
        NEED_GO=true
    else
        success "Go $CURRENT_GO already installed"
    fi
fi

[[ "$NEED_GO" == true ]] && install_go

# Ensure Go bin is on PATH for this session
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"
GOPATH_BIN="$(go env GOPATH)/bin"
export PATH="$PATH:$GOPATH_BIN"
echo

# ---------------------------------------------------------------------------
# Step 3 — Go tools (ProjectDiscovery + tomnomnom)
# ---------------------------------------------------------------------------
echo -e "${BOLD}[3/6] Go-based recon tools${RESET}"
GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
    "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
    "github.com/projectdiscovery/uncover/cmd/uncover@latest"
    "github.com/tomnomnom/assetfinder@latest"
    "github.com/tomnomnom/anew@latest"
    "github.com/tomnomnom/unfurl@latest"
    "github.com/tomnomnom/gf@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/sensepost/gowitness@latest"
    "github.com/gwen001/github-subdomains@latest"
    "github.com/ffuf/ffuf/v2@latest"
)
FAILED_GO=()
for tool in "${GO_TOOLS[@]}"; do
    binary=$(basename "${tool%%@*}")
    if command -v "$binary" &>/dev/null; then
        success "$binary already installed"
    else
        info "Installing $binary..."
        if go install -v "$tool" 2>/dev/null; then
            success "$binary installed"
        else
            warn "Failed: $tool (continuing)"
            FAILED_GO+=("$tool")
        fi
    fi
done
if (( ${#FAILED_GO[@]} > 0 )); then
    warn "Some Go tools failed: ${FAILED_GO[*]}"
    warn "Run manually: go install <tool>"
fi
echo

# ---------------------------------------------------------------------------
# Step 4 — findomain (prebuilt binary, no Go compile)
# ---------------------------------------------------------------------------
echo -e "${BOLD}[4/6] findomain${RESET}"
if command -v findomain &>/dev/null; then
    success "findomain already installed"
else
    TMP=$(mktemp -d)
    if [[ "$OS" == "linux" ]]; then
        URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux.zip"
        curl -sL "$URL" -o "$TMP/findomain.zip"
        unzip -o "$TMP/findomain.zip" -d "$TMP" >/dev/null
        chmod +x "$TMP/findomain"
        sudo mv "$TMP/findomain" /usr/local/bin/findomain
    elif [[ "$OS" == "macos" ]]; then
        ARCH_STR=$( [[ "$ARCH" == "arm64" ]] && echo "osx-arm64" || echo "osx-x86_64" )
        URL="https://github.com/Findomain/Findomain/releases/latest/download/findomain-${ARCH_STR}.zip"
        curl -sL "$URL" -o "$TMP/findomain.zip"
        unzip -o "$TMP/findomain.zip" -d "$TMP" >/dev/null
        chmod +x "$TMP/findomain"
        sudo mv "$TMP/findomain" /usr/local/bin/findomain
    fi
    rm -rf "$TMP"
    success "findomain installed"
fi
echo

# ---------------------------------------------------------------------------
# Step 5 — Python virtualenv + pip deps
# ---------------------------------------------------------------------------
echo -e "${BOLD}[5/6] Python dependencies (virtualenv)${RESET}"
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtualenv at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi
source "$VENV_DIR/bin/activate"
pip install --upgrade pip -q
pip install -r "$SCRIPT_DIR/requirements.txt" -q
pip install wafw00f arjun -q
pip install -e "$SCRIPT_DIR" -q   # install sairecon itself into venv
success "Python deps installed in $VENV_DIR"

# gf patterns
if [[ ! -d "$GF_PATTERNS_DIR" ]] || [[ -z "$(ls -A "$GF_PATTERNS_DIR" 2>/dev/null)" ]]; then
    info "Installing gf patterns..."
    mkdir -p "$GF_PATTERNS_DIR"
    TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$TMP/gf-patterns" -q
    cp "$TMP/gf-patterns"/*.json "$GF_PATTERNS_DIR/" 2>/dev/null || true
    rm -rf "$TMP"
    success "gf patterns installed to $GF_PATTERNS_DIR"
fi
echo

# ---------------------------------------------------------------------------
# Step 6 — API keys (interactive + .env file)
# ---------------------------------------------------------------------------
echo -e "${BOLD}[6/6] API keys (optional but highly recommended)${RESET}"
echo "These unlock additional recon sources."
echo "Press ENTER to skip any key."
echo

prompt_key() {
    local var="$1" desc="$2" existing=""
    existing=$(grep "^${var}=" "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
    if [[ -n "$existing" ]]; then
        echo -e "  ${GREEN}✓${RESET} $var already in .env (${desc})"
        return
    fi
    read -r -p "  $var ($desc): " val
    if [[ -n "$val" ]]; then
        echo "${var}=${val}" >> "$ENV_FILE"
        echo -e "  ${GREEN}✓${RESET} Saved to .env"
    else
        echo -e "  ${YELLOW}–${RESET} Skipped"
    fi
}

touch "$ENV_FILE"
echo "# SaiRecon API keys — auto-loaded on scan" >> "$ENV_FILE"
prompt_key "GITHUB_TOKEN"    "github.com → Settings → Developer settings → Personal access tokens"
prompt_key "PDCP_API_KEY"    "app.projectdiscovery.io → API keys  (free tier, for asnmap)"
prompt_key "SHODAN_API_KEY"  "account.shodan.io → My Account (free tier available)"
prompt_key "CENSYS_API_ID"   "search.censys.io → Account → API (for uncover)"
prompt_key "CENSYS_API_SECRET" "search.censys.io → Account → API"

echo

# ---------------------------------------------------------------------------
# PATH reminder + activation wrapper
# ---------------------------------------------------------------------------
ACTIVATE_HINT="source $VENV_DIR/bin/activate"

# Write a thin sairecon wrapper so user can call it without activating venv
WRAPPER="/usr/local/bin/sairecon"
sudo tee "$WRAPPER" > /dev/null << WRAPEOF
#!/usr/bin/env bash
# Auto-generated by install_tools.sh
if [[ -f "$VENV_DIR/bin/activate" ]]; then
    source "$VENV_DIR/bin/activate"
fi
# Load .env if present
if [[ -f "$ENV_FILE" ]]; then
    set -o allexport
    source "$ENV_FILE"
    set +o allexport
fi
exec python3 -m sairecon.cli "\$@"
WRAPEOF
sudo chmod +x "$WRAPPER"
success "sairecon wrapper installed → /usr/local/bin/sairecon"

# Append Go bin to shell rc files if missing
for RC in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [[ -f "$RC" ]] && ! grep -q "/usr/local/go/bin" "$RC"; then
        echo 'export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"' >> "$RC"
        info "Added Go PATH to $RC"
    fi
done

echo
echo -e "${BOLD}${GREEN}=== Installation complete ===${RESET}"
echo
echo -e "  Run:  ${BOLD}sairecon doctor${RESET}       → verify all tools"
echo -e "  Run:  ${BOLD}sairecon scan nasa.gov${RESET} → start scanning"
echo
echo -e "  Reports saved to:  ${CYAN}./sairecon_output/<target>_<timestamp>/${RESET}"
echo -e "    nasa.gov.html"
echo -e "    nasa.gov.json"
echo -e "    nasa.gov.md"
echo
if (( ${#FAILED_GO[@]} > 0 )); then
    warn "Some Go tools failed to install — run 'sairecon doctor' to see which."
fi
