#!/bin/bash

# Define version
VERSION=$1
TEMPLATE="PKGBUILD.template"
OUTPUT="PKGBUILD"
AUR_REPO="ssh://aur@aur.archlinux.org/rsecure.git"
TEMP_DIR="/tmp/rsecure_build"

if [[ -z "$VERSION" ]]; then
    echo "Usage: $0 <version>"
    exit 1
fi

# Check latest tag is the same as version
LATEST_TAG=$(git describe --tags --abbrev=0)
if [[ "$LATEST_TAG" != "$VERSION" ]]; then
    echo "Error: Latest git tag ($LATEST_TAG) does not match version ($VERSION)"
    exit 1
fi

# Fetch source and calculate hash without saving file
echo "Fetching source to calculate checksum..."
SHA256=$(curl -L "https://github.com/containerscrew/rsecure/archive/refs/tags/$VERSION.tar.gz" | sha256sum | awk '{print $1}')

# Replace placeholders
sed -e "s|@version@|$VERSION|g" \
    -e "s|@sha256sums@|$SHA256|g" \
    "$TEMPLATE" > "$OUTPUT"

# Validate PKGBUILD
# namcap "$OUTPUT"

# Generate .SRCINFO
echo "Generating .SRCINFO..."
makepkg --printsrcinfo > .SRCINFO

# Sync with AUR repository
echo "Pushing to AUR repository..."
rm -rf "$TEMP_DIR"
git clone "$AUR_REPO" "$TEMP_DIR"

cp "$OUTPUT" .SRCINFO "$TEMP_DIR/"
cd "$TEMP_DIR" || exit 1 # Exit if directory missing

# Only commit and push if there are changes
if [[ -n $(git status --porcelain) ]]; then
    git config user.name "containerscrew"
    git config user.email "info@containerscrew.com"
    git add PKGBUILD .SRCINFO
    git commit -m "Update to v$VERSION"
    git push origin master
else
    echo "No changes detected, skipping push."
fi

# # Cleanup
# rm -rf "$TEMP_DIR"
# echo "Done! v$VERSION deployed."