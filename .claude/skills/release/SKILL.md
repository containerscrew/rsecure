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
3. Cocogitto creates the tag `X.Y.Z`.
4. **`post_bump_hooks`**:
   - `git push origin main` — pushes the bump commit (cog creates the commit via git2 directly, bypassing the local `post-commit` hook that would otherwise push it)
   - `git push origin {{version}}` — pushes the tag

Net result: a single `cog bump --version X.Y.Z` produces a fully released and pushed version. The skill exists to pick the right `X.Y.Z` and verify state before/after.

## Conventions

- Tags are plain SemVer with no `v` prefix (e.g. `0.4.1`, not `v0.4.1`).
- The version in `Cargo.toml` MUST match the latest git tag at all times. The automation guarantees this — if you ever see them diverge, something failed mid-way; stop and investigate.
- Required tools: `cog` (cocogitto 7+) and `cargo-set-version` (from `cargo-edit`). If either is missing, stop and ask the user to install — do not try to substitute manual edits.

## Irreversibility warning

Pushing a tag triggers `goreleaser` (GitHub Release + binary artifacts), the
`publish-crate` job (crates.io), and downstream packaging (AUR). Once any of these
fire, the version is effectively immutable — crates.io does not allow republishing
a version, and AUR mirrors the tag. **Get the version right *before* running
`cog bump`.** If you realize the wrong bump is about to happen, stop and ask the
user; do not try to "fix it later" by rewriting history.

In particular, if a `feat:` commit is present since the last tag, the next bump
MUST be **minor**, not patch — never quietly downgrade the bump to avoid a version
jump.

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
- Also `ls` the repo root and glance at `git ls-files` for stray scratch/review/plan
  files that agents may have left behind. If found, remove them in a `chore` commit
  *before* the bump — a bumped tag will ship whatever is in the tree.

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
