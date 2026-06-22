---
name: release
description: Cut the next release of rsecure. Triggers when the user asks to "release", "cut a release", "bump version", "generate the next release", or similar. Reads the latest git tag, verifies it matches Cargo.toml, proposes the next version from conventional commits since the tag, then runs `cog bump --version` which handles Cargo.toml, Cargo.lock, CHANGELOG.md, the bump commit, the tag, and the tag push in one step.
---

# Release process

Use this workflow whenever the user asks to release a new version of `rsecure`.

## How automation works

The heavy lifting is done by `cog bump --version X.Y.Z` (cocogitto), which is wired in `cog.toml` to:

1. **`pre_bump_hooks`**:
   - `cargo set-version {{version}}` — updates `Cargo.toml`
   - `cargo update --workspace --offline` — keeps `Cargo.lock` in sync
   - `cog changelog` — regenerates `CHANGELOG.md`
2. Cocogitto creates the bump commit `chore(version): X.Y.Z` with all of the above.
3. The repo's `post-commit` hook auto-pushes the commit to `origin/main`.
4. Cocogitto creates the tag `X.Y.Z`.
5. **`post_bump_hooks`**: `git push origin {{version}}` — pushes the tag.

Net result: a single `cog bump --version X.Y.Z` produces a fully released and pushed version. The skill exists to pick the right `X.Y.Z` and verify state before/after.

## Conventions

- Tags are plain SemVer with no `v` prefix (e.g. `0.4.1`, not `v0.4.1`).
- The version in `Cargo.toml` MUST match the latest git tag at all times. The automation guarantees this — if you ever see them diverge, something failed mid-way; stop and investigate.
- Required tools: `cog` (cocogitto 7+) and `cargo-set-version` (from `cargo-edit`). If either is missing, stop and ask the user to install — do not try to substitute manual edits.

## Steps

### 1. Pre-flight

Run in parallel:

```bash
git describe --tags --abbrev=0          # latest tag
grep '^version' Cargo.toml              # current Cargo.toml version
git status                              # must be clean
which cog && which cargo-set-version    # tools must be present
```

- Working tree must be clean.
- Latest tag MUST equal the `Cargo.toml` version. If not, STOP and surface to the user.

### 2. Propose the next version

List conventional commits since the latest tag:

```bash
git log <latest-tag>..HEAD --oneline --no-merges
```

Categorize them and suggest a bump:

- Any `feat:` or `feat(scope):` → **minor** bump
- Only `fix:`, `chore:`, `docs:`, `refactor:`, `perf:`, `test:`, `build:`, `ci:` → **patch** bump
- Any `!` breaking marker or `BREAKING CHANGE:` footer → **major** bump

Show the user the commit list and the suggested next version. Wait for confirmation (they may override).

### 3. Run the bump

```bash
cog bump --version X.Y.Z
```

This single command handles everything: Cargo.toml, Cargo.lock, CHANGELOG.md, the bump commit, push of commit, tag, push of tag.

### 4. Verify

```bash
git describe --tags --abbrev=0          # should equal X.Y.Z
grep '^version' Cargo.toml              # should equal X.Y.Z
git status                              # must be clean
git ls-remote --tags origin X.Y.Z       # must show the tag on remote
```

### 5. Report back

Tell the user:
- The new version and tag
- The bump commit SHA
- The CHANGELOG.md additions (a short summary, not the full diff)
- A reminder to check the GitHub release / CI if applicable
