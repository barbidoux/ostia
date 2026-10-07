# Repository settings (owner)

The GitHub settings that make the rails hold on the server side too. Only the owner can change them.
WP-0.9 wrote this page; the "Current" column is what the API reported on 2026-10-07.

## Branch protection of `main`

| Setting | Required | Current | Why |
|---|---|---|---|
| Require a pull request before merging | on, **0** required approvals | off | Every change goes through a PR and its checks. The owner opens the PRs the agent prepares, and GitHub forbids approving one's own PR, hence 0 approvals. |
| Require review from Code Owners | off while the owner is the only maintainer | off | `.github/CODEOWNERS` already names the owner for every path. Turn it on when a second maintainer joins. |
| Required status checks | `ci`, `rails`, `fuzz`, `red-first` | `ci`, `fuzz`, `rails` | `red-first` (WP-0.9) runs on pull requests only, so it can be required without blocking pushes. |
| Require branches to be up to date | off | off | It saves CI minutes. The checks run on the merge commit of the PR as of its last push; a later move of `main` is not retested until the next push. |
| Allow force pushes | off | off | No history rewriting on `main`. |
| Allow deletions | off | off | |
| Include administrators | owner's choice | off | When it is off, the owner can bypass a red check in an emergency, and GitHub shows it. |

## Tag rulesets

| Ruleset | Target | Rule | Current |
|---|---|---|---|
| `lock-*` | tags | Only the owner creates, moves or deletes them. Signed tags. | none |
| `v*` | tags | Only the owner creates them (releases). Signed tags. | none |

`ostia_lock.py verify --require-tags` (rails workflow, on `main`) compares every `LOCK.sha256` with the copy in
its `lock-<dir>` tag. A tag ruleset makes sure nobody else can move that reference.

## Merge methods

| Method | Required | Current | Why |
|---|---|---|---|
| Merge commit | allowed | allowed | It keeps the `test(...)` → `feat(...)` commits that red-first and the review rely on. |
| Rebase and merge | allowed | allowed | Same. |
| Squash and merge | **disallowed** | allowed | A squash merges test and implementation into one commit, which erases the red-first evidence (spec §18 cycle rule 3). |
| Automatically delete head branches | owner's choice | off | |

## Security features (already on)

- Dependabot version and security updates. `.github/dependabot.yml` leaves `rails.yml` to the owner.
- CodeQL default setup, secret scanning and push protection.

## How to check

```bash
gh api repos/barbidoux/ostia/branches/main/protection
gh api repos/barbidoux/ostia --jq '{allow_squash_merge, allow_merge_commit, allow_rebase_merge}'
gh api repos/barbidoux/ostia/rulesets
```
