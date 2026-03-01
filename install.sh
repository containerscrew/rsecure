#!/usr/bin/env sh

set -e

# Global vars
INSTALLATION_PATH="/usr/local/bin" # Default installation path for user-level binaries (not dpkg/rpm/apk)
BINARY_NAME="rsecure"
REPO="containerscrew/rsecure"

# Welcome message
echo "Welcome to the $BINARY_NAME installation script! 🚀"
echo "Author: github.com/containerscrew"

happyexit(){
  echo ""
  echo "$BINARY_NAME successfully installed! 🎉"
  echo ""
  echo "Now run: $ $BINARY_NAME --help"
  echo ""
  exit 0
}

# Detect OS and Architecture
OS_RAW=$(uname -s)
ARCH_RAW=$(uname -m)
CLI_ARCH=""
OS=""
PKG_FORMAT="tar.gz" # Default format
INSTALL_METHOD="tar"

case $OS_RAW in
  Linux)
    OS="linux"
    # Smart package manager detection
    if command -v apk >/dev/null 2>&1; then
        PKG_FORMAT="apk"
        INSTALL_METHOD="apk"
    elif command -v rpm >/dev/null 2>&1; then
        PKG_FORMAT="rpm"
        INSTALL_METHOD="rpm"
    elif command -v dpkg >/dev/null 2>&1; then
        PKG_FORMAT="deb"
        INSTALL_METHOD="deb"
    fi
    ;;
  Darwin)
    OS="darwin"
    PKG_FORMAT="tar.gz"
    INSTALL_METHOD="tar"
    ;;
  *)
    echo "❌ Error: There is no $BINARY_NAME support for OS: $OS_RAW"
    exit 1
    ;;
esac

case $ARCH_RAW in
  x86_64)
    CLI_ARCH="amd64"
    ;;
  armv8* | aarch64* | arm64)
    CLI_ARCH="arm64"
    ;;
  *)
    echo "❌ Error: There is no $BINARY_NAME support for architecture: $ARCH_RAW"
    exit 1
    ;;
esac

download_release() {
  # Get latest version using grep/sed to avoid depending on jq
  LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

  if [ -z "$1" ]; then
    TAG_VERSION=$LATEST_TAG
  else
    TAG_VERSION=$1
  fi

  # GoReleaser artifacts usually don't have the 'v' prefix in the filename (e.g., 0.3.2 instead of v0.3.2)
  CLEAN_VERSION=$(echo "$TAG_VERSION" | sed 's/^v//')

  FILENAME="${BINARY_NAME}_${CLEAN_VERSION}_${OS}_${CLI_ARCH}.${PKG_FORMAT}"
  DOWNLOAD_URL="https://github.com/$REPO/releases/download/${TAG_VERSION}/${FILENAME}"

  printf "\033[0;32m[info] - OS: %s | Arch: %s | Format: %s \033[0m\n" "$OS" "$CLI_ARCH" "$PKG_FORMAT"
  printf "\033[0;32m[info] - Downloading %s... \033[0m\n" "$FILENAME"

  # Download to /tmp
  curl -L --fail "$DOWNLOAD_URL" -o "/tmp/$FILENAME"

  # Export filename for the install function
  DOWNLOADED_FILE="/tmp/$FILENAME"
}

execute_with_sudo() {
  if [ "$(id -u)" = 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

install_binary(){
  printf "\033[0;32m[info] - Installing %s... \033[0m\n" "$BINARY_NAME"

  case $INSTALL_METHOD in
    apk)
      # --allow-untrusted is needed for local apks not signed by Alpine's official keys
      execute_with_sudo apk add --allow-untrusted "$DOWNLOADED_FILE"
      ;;
    deb)
      execute_with_sudo dpkg -i "$DOWNLOADED_FILE"
      ;;
    rpm)
      execute_with_sudo rpm -U "$DOWNLOADED_FILE"
      ;;
    tar)
      # Extract tar.gz and move binary
      execute_with_sudo tar -xzf "$DOWNLOADED_FILE" -C /tmp/
      execute_with_sudo mv "/tmp/$BINARY_NAME" "$INSTALLATION_PATH/$BINARY_NAME"
      execute_with_sudo chmod +x "$INSTALLATION_PATH/$BINARY_NAME"
      ;;
  esac

  # Cleanup
  execute_with_sudo rm -f "$DOWNLOADED_FILE" "/tmp/$BINARY_NAME" 2>/dev/null || true
}

# Function to display help text
usage() {
    echo "Usage: $0 [-v <version>] [-h]"
    echo "Options:"
    echo "  -v           Select which version do you want to install (e.g., 0.3.2 or v0.3.2)."
    echo "  -h           Display this help message."
}

# Parse options using getopts
while getopts "v:h" option; do
    case "${option}" in
        v)
            VERSION_ARG=${OPTARG}
            download_release "$VERSION_ARG"
            install_binary
            happyexit
            ;;
        h)
            usage
            exit 0
            ;;
        \?)
            usage
            exit 1
            ;;
    esac
done

# If no flags, install latest version by default
if [ $# -eq 0 ]; then
    download_release
    install_binary
    happyexit
fi