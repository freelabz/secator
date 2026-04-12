#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
BLUE='\033[0;94m'
NC='\033[0m' # No Color

# Print colored messages (to stderr so they don't interfere with command substitution)
info() { echo -e "${BLUE}ℹ${NC} $1" >&2; }
success() { echo -e "${GREEN}✓${NC} $1" >&2; }
warn() { echo -e "${YELLOW}⚠${NC} $1" >&2; }
error() { echo -e "${RED}✗${NC} $1" >&2; exit 1; }

# Detect OS and distribution
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v lsb_release >/dev/null 2>&1; then
            DISTRO=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        elif [[ -f /etc/os-release ]]; then
            . /etc/os-release
            DISTRO=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
        elif [[ -f /etc/arch-release ]]; then
            DISTRO="arch"
        elif [[ -f /etc/debian_version ]]; then
            DISTRO="debian"
        else
            DISTRO="unknown"
        fi
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="darwin"
        DISTRO="macos"
    else
        OS="unknown"
        DISTRO="unknown"
    fi
}

# Detect package manager and install Python/pip
detect_pm() {
    case "$OS" in
        linux)
            case "$DISTRO" in
                ubuntu|debian|linuxmint|popos|kali)
                    PM="apt"
                    PM_UPDATE="apt update"
                    PM_INSTALL="apt install -y"
                    PYTHON_PKG="python3 python3-pip python3-venv"
                    ;;
                arch|manjaro|endeavouros|cachyos)
                    PM="pacman"
                    PM_UPDATE="pacman -Sy"
                    PM_INSTALL="pacman -S --noconfirm --needed"
                    PYTHON_PKG="python python-pip"
                    ;;
                alpine)
                    PM="apk"
                    PM_UPDATE="apk update"
                    PM_INSTALL="apk add --no-cache"
                    PYTHON_PKG="python3 py3-pip"
                    ;;
                fedora)
                    PM="dnf"
                    PM_UPDATE="dnf check-update || true"
                    PM_INSTALL="dnf install -y"
                    PYTHON_PKG="python3 python3-pip"
                    ;;
                centos|rhel|rocky|alma)
                    PM="yum"
                    PM_UPDATE="yum check-update || true"
                    PM_INSTALL="yum install -y"
                    PYTHON_PKG="python3 python3-pip"
                    ;;
                opensuse|sles)
                    PM="zypper"
                    PM_UPDATE="zypper refresh"
                    PM_INSTALL="zypper -n install"
                    PYTHON_PKG="python3 python3-pip"
                    ;;
                *)
                    warn "Unknown Linux distribution: $DISTRO"
                    warn "Attempting to use generic package manager detection..."
                    if command -v apt >/dev/null 2>&1; then
                        PM="apt"
                        PM_UPDATE="apt update"
                        PM_INSTALL="apt install -y"
                        PYTHON_PKG="python3 python3-pip python3-venv"
                    elif command -v pacman >/dev/null 2>&1; then
                        PM="pacman"
                        PM_UPDATE="pacman -Sy"
                        PM_INSTALL="pacman -S --noconfirm --needed"
                        PYTHON_PKG="python python-pip"
                    elif command -v dnf >/dev/null 2>&1; then
                        PM="dnf"
                        PM_UPDATE="dnf check-update || true"
                        PM_INSTALL="dnf install -y"
                        PYTHON_PKG="python3 python3-pip"
                    elif command -v yum >/dev/null 2>&1; then
                        PM="yum"
                        PM_UPDATE="yum check-update || true"
                        PM_INSTALL="yum install -y"
                        PYTHON_PKG="python3 python3-pip"
                    else
                        error "Could not detect package manager. Please install Python 3 and pip manually."
                    fi
                    ;;
            esac
            ;;
        darwin)
            PM="brew"
            PM_UPDATE="brew update || true"
            PM_INSTALL="brew install"
            PYTHON_PKG="python3"
            ;;
        *)
            error "Your OS is not supported for native install. You can run secator with Docker instead: https://docs.freelabz.com/getting-started/installation#docker"
            ;;
    esac
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if we can write to a directory directly (without sudo)
can_write_directly() {
    [[ -w "$1" ]] 2>/dev/null
}

# Check if directory is in PATH
in_path() {
    echo "$PATH" | tr ':' '\n' | grep -Fx "$1" >/dev/null
}

# Install Python and pip if needed
install_python() {
    if command_exists python3 && python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
        success "Python 3 is already installed"
        return 0
    fi

    info "Python 3 not found or version < 3.8. Installing..."
    
    if [[ "$PM" == "brew" ]]; then
        if ! command_exists brew; then
            error "Homebrew is required on macOS. Please install it first: https://brew.sh"
        fi
        $PM_INSTALL $PYTHON_PKG || error "Failed to install Python 3"
    else
        # Check if we need sudo
        if [[ "$EUID" -eq 0 ]]; then
            SUDO=""
        else
            SUDO="sudo"
        fi
        
        info "Updating package manager..."
        $SUDO $PM_UPDATE || warn "Package manager update failed, continuing anyway..."
        
        info "Installing Python 3 and pip..."
        $SUDO $PM_INSTALL $PYTHON_PKG || error "Failed to install Python 3"
    fi
    
    # Verify installation
    if ! command_exists python3; then
        error "Python 3 installation failed or python3 command not found"
    fi
    
    success "Python 3 installed successfully"
}

# Install secator in a virtual environment
install_secator() {
    VENV_DIR="$HOME/.secator"
    
    # Check if venv module is available
    if ! python3 -m venv --help >/dev/null 2>&1; then
        error "Python venv module is not available. Please install python3-venv package."
    fi
    
    info "Creating virtual environment at $VENV_DIR..."
    python3 -m venv "$VENV_DIR" || error "Failed to create virtual environment"
    
    info "Activating virtual environment..."
    source "$VENV_DIR/bin/activate" || error "Failed to activate virtual environment"
    
    info "Upgrading pip..."
    pip install --upgrade pip --quiet || warn "Failed to upgrade pip, continuing..."
    
    info "Installing secator..."
    pip install secator --quiet || error "Failed to install secator"
    
    # Find the secator binary
    SECATOR_BIN="$VENV_DIR/bin/secator"
    if [[ ! -f "$SECATOR_BIN" ]]; then
        error "secator binary not found at $SECATOR_BIN"
    fi
    
    success "secator installed successfully"
    echo "$SECATOR_BIN"
}

# Create symlink to secator
create_symlink() {
    local secator_bin="$1"
    local target_dir=""
    
    # Try /usr/local/bin first only if we can write to it directly (without sudo)
    if [[ -d "/usr/local/bin" ]] && can_write_directly "/usr/local/bin"; then
        target_dir="/usr/local/bin"
        info "Using /usr/local/bin (writable without sudo)"
    else
        # Fall back to ~/.local/bin if /usr/local/bin is not writable
        target_dir="$HOME/.local/bin"
        mkdir -p "$target_dir" || error "Failed to create directory $target_dir"
        if [[ -d "/usr/local/bin" ]]; then
            info "Using ~/.local/bin (since /usr/local/bin is not writable)"
        else
            info "Using ~/.local/bin"
        fi
    fi
    
    local symlink_path="$target_dir/secator"
    
    # Remove existing symlink if it exists
    if [[ -L "$symlink_path" ]] || [[ -f "$symlink_path" ]]; then
        info "Removing existing $symlink_path..."
        rm -f "$symlink_path" || error "Failed to remove existing symlink"
    fi
    
    # Create symlink (no sudo needed since we only use writable directories)
    info "Creating symlink: $symlink_path -> $secator_bin"
    ln -s "$secator_bin" "$symlink_path" || error "Failed to create symlink"
    
    success "Symlink created at $symlink_path"
    
    # Check if target directory is in PATH
    if ! in_path "$target_dir"; then
        warn "The directory $target_dir is not in your PATH!"
        warn "Add it to your PATH by running:"
        echo "  export PATH=\"\$PATH:$target_dir\"" >&2
        echo "" >&2
        warn "To make it permanent, add the above line to your shell configuration file:"
        if [[ -n "${ZSH_VERSION:-}" ]]; then
            echo "  echo 'export PATH=\"\$PATH:$target_dir\"' >> ~/.zshrc" >&2
        else
            echo "  echo 'export PATH=\"\$PATH:$target_dir\"' >> ~/.bashrc" >&2
        fi
    else
        success "$target_dir is in your PATH"
    fi
    
    echo "$symlink_path"
}

# Main installation function
main() {
    echo ""
    info "Starting secator installation..."
    echo ""
    
    detect_os
    info "Detected OS: $OS, Distribution: $DISTRO"
    
    detect_pm
    info "Using package manager: $PM"
    echo ""
    
    install_python
    echo ""
    
    local secator_bin
    secator_bin=$(install_secator)
    echo ""
    
    local symlink_path
    symlink_path=$(create_symlink "$secator_bin")
    echo ""
    
    success "Installation complete!"
    echo ""
    info "You can now run secator with:"
    echo "  $symlink_path --help"
    echo ""
    
    if ! in_path "$(dirname "$symlink_path")"; then
        warn "Note: You may need to restart your shell or run the export command above to use 'secator' directly."
    else
        info "You can run 'secator --help' directly."
    fi
    echo ""
}

# Run main function
main "$@"

