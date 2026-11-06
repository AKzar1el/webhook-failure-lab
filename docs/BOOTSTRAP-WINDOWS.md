# Windows bootstrap and Revenue Shot

The repository is bootstrapped at `C:\Users\Tomi\Desktop\lol\webhook-failure-lab`. It was initialized with a SHA-256-verified source archive and local `npm run verify` pass on November 6, 2026.

## Local verification

```powershell
npm run verify
git status --short --branch
```

Use the existing **shared God v5** connector and bind this exact directory with `createWorktree:false`; never use a dedicated tunnel or linked worktrees.

## Merge integration

Worker branches must start with `revshot/` and have green GitHub CI. Include `MERGER_HANDOFF: AKzar1el/webhook-failure-lab@<exact 40-character head SHA>` in the PR body only after verifying reviewed scope, local tests and permitted side effects. The guarded Windows merger independently checks CI, branch ancestry, workflow fingerprints, the handoff SHA, review decisions and changed-file scope before attempting an ordinary protected GitHub merge. No force merges, admin bypasses, or publishing side effects.

## Credentials

Use the central Windows GitHub credential / encrypted merger credential store. Do **not** copy any credential from `mcp-geo/secrets.txt` into the repository, tracked files, CI variables or logs. `secrets.txt` and `.revenue-shot/` are gitignored. Synthetic webhook signing keys in tests are not production credentials.
