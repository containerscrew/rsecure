---
name: release
description: Cut the next release of rsecure. Triggers when the user asks to "release", "cut a release", "bump version", "generate the next release", or similar. Reads the latest git tag, verifies it matches Cargo.toml, proposes the next version from conventional commits since the tag, edits Cargo.toml, commits, then runs `cog bump --version` to update the changelog and tag.
---

# Release process

Use this exact workflow whenever the user asks to release a new version of `rsecure`.

## Conventions

- Tags are plain SemVer with no `v` prefix (e.g. `0.4.0`, not `v0.4.0`). See `git tag --sort=-v:refname`.
- The version in `Cargo.toml` MUST match the latest git tag at all times — when they diverge, stop and surface it to the user before doing anything else.
- Cocogitto runs `pre-commit.sh` on every commit (which auto-pushes), so explicit `git push` calls are usually redundant — but still verify the push landed.
- The `cog bump` commit follows the convention `chore(version): X.Y.Z` (see existing history).

## Steps

### 1. Read current state

Run in parallel:

```bash
git describe --tags --abbrev=0          # latest tag
grep '^version' Cargo.toml              # current Cargo.toml version
git status                              # must be clean
```

If the working tree is dirty, stop and ask the user to commit or stash first.

### 2. Verify tag and Cargo.toml agree

If the latest tag does NOT match the `version = "X.Y.Z"` line in `Cargo.toml`, STOP. Report the mismatch to the user and ask how to proceed — do not guess.

### 3. Propose the next version

List conventional commits since the latest tag:

```bash
git log <latest-tag>..HEAD --oneline
```

Categorize them and suggest a bump:

- Any `feat:` or `feat(scope):` → **minor** bump
- Only `fix:`, `chore:`, `docs:`, `refactor:`, `perf:`, `test:` → **patch** bump
- Any `!` breaking marker or `BREAKING CHANGE:` footer → **major** bump

Show the user the commit list and the suggested next version. Wait for confirmation (they may override patch ↔ minor).

### 4. Edit Cargo.toml

Update the `version` field in `Cargo.toml` to the agreed version. Do not touch anything else.

### 5. Commit the Cargo.toml bump

```bash
git add Cargo.toml
cog commit chore "bump version to X.Y.Z" version
```

That produces `chore(version): bump version to X.Y.Z`. The `pre-commit.sh` hook will push automatically.

### 6. Run `cog bump`

```bash
cog bump --version X.Y.Z
```

This regenerates `CHANGELOG.md` (via the `pre_bump_hooks = ["cog changelog"]` in `cog.toml`), creates the `chore(version): X.Y.Z` bump commit, and tags it `X.Y.Z`.

### 7. Push the tag

The pre-commit hook may not push tags. Verify with:

```bash
git push --tags
git status
```

### 8. Report back

Tell the user:
- The new version
- The new tag
- The commit SHAs created
- A reminder to check the GitHub release / CI if applicable
