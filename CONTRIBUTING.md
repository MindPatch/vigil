# Contributing

How work moves from idea → issue → branch → commits → PR → merge in this
repository. Follow it for every change; it keeps history readable and every
commit traceable back to a tracked ticket.

---

## The flow at a glance

```
Issue (VIG-<id>)  ──►  Branch (vig-<id>-<slug>)  ──►  Commits (VIG[<id>] Type: …)  ──►  PR (Closes #<id>)  ──►  Merge
```

Every change starts with an **issue** and ends with a **PR linked to that
issue**. No direct commits to `master`.

---

## 1. Tickets / issues

- Every unit of work has a GitHub issue. The issue number **is** the ticket id.
- We refer to it in prose as **`VIG-<id>`** (e.g. `VIG-2`).
- An issue must have:
  - A clear, action-oriented **title**.
  - A **description**: problem, why it matters, acceptance criteria.
  - **Labels** (see taxonomy below).
  - An **assignee**.

### Label taxonomy
| Label | Use for |
|-------|---------|
| `bug` | Incorrect behaviour (false positives/negatives, crashes). |
| `enhancement` | New capability or feature. |
| `accuracy` | Detection precision/recall — the metrics that sell. |
| `rules` | Detection-rule additions or tuning. |
| `documentation` | Documentation only. |
| `priority: high` / `priority: low` | Triage urgency. |

---

## 2. Branches

One branch per issue, created off the latest `master`:

```
vig-<id>-<short-kebab-slug>
```

Examples:
- `vig-2-scoring-precision-redesign`
- `vig-7-fix-node-gyp-false-positive`
- `vig-12-add-pypi-support`

Rules:
- Lowercase, kebab-case slug; keep it short and descriptive.
- Always branch from an up-to-date `master` (`git pull` first).
- Delete the branch after merge.

---

## 3. Commits

**Every commit message** uses this format:

```
VIG[<id>] <Type>: <imperative summary>
```

- `<id>` — the issue number (e.g. `VIG[2]`).
- `<Type>` — one of: **Feat, Fix, Docs, Refactor, Test, Perf, Chore**.
- `<summary>` — imperative mood, ≤ ~70 chars, no trailing period.

Examples:
```
VIG[2] Fix: score by distinct rule, not occurrence count
VIG[2] Refactor: move correlation window into matcher
VIG[7] Test: cover node-gyp install script as benign
VIG[3] Docs: add contributing guide
```

Guidelines:
- One logical change per commit. Don't mix a refactor with a behaviour change.
- The body (optional, after a blank line) explains **why**, not what.
- Commits are authored by a human committer; do not add tool co-author trailers.
- Don't commit secrets. `vigil.toml` is gitignored — keep tokens out of git.

---

## 4. Pull requests

Open a PR from your branch into `master`:

- **Title:** mirror the work, e.g. `VIG-2: Scoring precision redesign`.
- **Body must link the issue** so they auto-close and cross-reference:
  ```
  Closes #<id>
  ```
- After opening, **cross-link both ways**: mention the PR on the issue and the
  issue on the PR, so the issue and PR are visibly linked in the timeline.
- Include a **Test plan** (commands run + results).
- Be honest about known gaps / WIP in the PR body.

### Definition of done (must pass before requesting review)
- [ ] `cargo build --release` clean (no warnings).
- [ ] `cargo test --release` green (unit + `tests/accuracy.rs`).
- [ ] `bench/real_corpus.sh` run for any change touching rules or scoring —
      report the false-positive rate in the PR.
- [ ] PR body contains `Closes #<id>` and a test plan.

---

## 5. Quick reference

```bash
# 1. start from fresh master
git checkout master && git pull origin master

# 2. branch for the issue (id = 2 here)
git checkout -b vig-2-scoring-precision-redesign

# 3. commit in the required format
git commit -m "VIG[2] Fix: score by distinct rule, not occurrence count"

# 4. push and open the PR (links the issue)
git push -u origin vig-2-scoring-precision-redesign
gh pr create --base master --title "VIG-2: Scoring precision redesign" \
  --body "Closes #2

  ## Summary …
  ## Test plan …"

# 5. cross-link on the issue
gh issue comment 2 --body "PR opened: #<pr-number>"
```
