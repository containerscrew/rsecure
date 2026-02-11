# Local dev

## Compile using goreleaser

```bash
cargo install cargo-zigbuild
brew install zig # or use apt/pacman/dnf to install zig
# Comment binary_signs in .goreleaser.yaml for local build
goreleaser release --snapshot --clean
```
