# Optional skills

Pack of [Claude Code skills](https://skills.sh/) installed at the **project**
level. The pinned set lives in `skills-lock.json` (committed); the downloaded
skill files under `.agents/` and their `.claude/skills/*` symlinks are generated
and git-ignored.

On a fresh machine, restore everything from the lock file:

```bash
npx skills experimental_install
```

To add or change a skill (updates `skills-lock.json` — commit it afterwards):

```bash
npx skills add apollographql/skills@rust-best-practices -y
npx skills add trailofbits/skills@cargo-fuzz -y
npx skills add openai/skills@security-ownership-map -y
```

Codebase-memory-mcp:

```bash
curl -fsSL https://raw.githubusercontent.com/DeusData/codebase-memory-mcp/main/install.sh | bash
```
