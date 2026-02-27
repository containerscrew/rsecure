# Local dev

## Compile using goreleaser

```bash
cargo install cargo-zigbuild
brew install zig # or use apt/pacman/dnf to install zig
# Comment binary_signs in .goreleaser.yaml for local build
goreleaser release --snapshot --clean
```

# Testing the binary in multiple OS

Ubuntu and debian based:

```bash
docker run --rm -it ubuntu:latest bash -c "apt-get update && apt-get install -y curl && curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh && rsecure --version && dpkg -l rsecure"
```

Fedora and rpm based:

```bash
docker run --rm -it fedora:latest bash -c "dnf install -y curl && curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh && rsecure --version && rpm -q rsecure"
```

Alpine and apk based:

```bash
docker run --rm -it alpine:latest sh -c "apk add --no-cache curl && curl --proto '=https' --tlsv1.2 -sSfL https://raw.githubusercontent.com/containerscrew/rsecure/main/install.sh | sh && rsecure --version && apk info rsecure"
```
