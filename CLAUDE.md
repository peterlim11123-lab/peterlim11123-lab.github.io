# CLAUDE.md

## 1. Instructions

This is a personal CTF writeup blog (Jekyll + Chirpy theme, deployed to GitHub Pages). Primary tasks:

- Write blog posts for CTF challenges from source files in `CTF/<ctfname>/<challengename>/`
- One post per challenge; one `_posts/` file per post
- No commentary, docs, or summaries beyond what the user asks for

---

## 2. Knowledge

**Stack layout:**

```
_posts/           → published blog posts (YYYY-MM-DD-ctfname-challengename.md)
CTF/              → raw challenge files (binaries, scripts, notes, solvers)
assets/           → images and static files
_tabs/            → about, archives, categories, tags pages
_config.yml       → site title, url, author, theme settings
```

**Post front matter:**

```yaml
---
title: "<CTF Name> — <Challenge> (<Category>)"
date: YYYY-MM-DD HH:MM:SS +0800
categories: [CTF, <Primary>]   # Primary: Pwn, Rev, Crypto, Misc, Web
tags: [ctfname, tag1, tag2]    # lowercase, hyphenated
---
```

**IMPORTANT:** Always use a date **1 day earlier than today** to ensure proper timezone handling. Example: if today is 2026-06-22, use `date: 2026-06-21 HH:MM:SS +0800`.

**Post body structure:**

```
**Category:** ...
**Binary:** `filename`
**Vulnerability:** one-line summary

## Summary
## Vulnerability / Bug
## Exploit Strategy (or numbered steps)
## AI Lessons Learnt   ← include if AI_Lessons_Learnt.md exists in the challenge folder
## Fix / Mitigations
```

If `AI_Lessons_Learnt.md` is present in the challenge folder, add an `## AI Lessons Learnt` section before the mitigations table. Render each lesson as a Chirpy `tip` callout:

```markdown
> Lesson text here.
{: .prompt-tip }
```

---

## 3. Memory

- boroCTF posts written: coming-together, dinner, mania, next-challenge (2026-06-13)
- anti-slop posts written: anchorpoint, paper-lantern (2026-06-15)
- biterra posts written: barbie-core (2026-06-20)
- pwnable-tw posts written: babystack (2026-06-20), secretgarden (2026-06-21)
- Avatar: `peterlim.png` (added to about page)

---

## 4. Presentation Style

**Diagrams are mandatory when applicable.** Chirpy ships Mermaid.js — enable per post with `mermaid: true` in front matter.

| Situation | Diagram type |
|---|---|
| Exploit phases / overall flow | Mermaid `graph LR` flowchart |
| Protocol / oracle interaction (attacker ↔ binary) | Mermaid `sequenceDiagram` |
| Memory layout / stack frame | HTML `<table>` with colored rows (`.bs-tbl` pattern) |
| What gets corrupted / overwritten | Animated HTML cells (`@keyframes` with `animation-delay`) |
| ROP chain or gadget sequence | Mermaid `graph LR` |

**Animation rules:**
- Use CSS `@keyframes` + `animation-delay` on individual `<div>` or `<td>` cells to show memory being written progressively.
- Color convention: green = in-bounds / safe, yellow = stale, orange = libc/address bytes, red = corrupted/overflow.
- All colors use `rgba()` so they work in both light and dark Chirpy themes.
- Embed `<style>` blocks directly in the markdown file (Jekyll passes raw HTML through).
- No JavaScript required; no external dependencies beyond Mermaid (already bundled).

**Canonical post with diagrams:** `_posts/2026-06-20-pwnable-tw-babystack.md`

---

## 5. Examples

**Canonical post:** `_posts/2026-06-20-pwnable-tw-babystack.md`

- Lead with bold metadata block before first `##`
- Use fenced code blocks for C, Python, assembly, shell
- Add diagrams at each phase of the exploit walkthrough — do not skip this
- Mitigations table at the end when relevant
- No trailing summaries or recaps

---

## 6. Tools

```bash
# Preview site locally
bundle exec jekyll serve

# Build
bundle exec jekyll build

# New post (name pattern)
touch _posts/$(date +%Y-%m-%d)-<ctfname>-<chall>.md
```

Source files for a challenge live at `CTF/<ctfname>/<challengename>/`. Read solver scripts and notes there before writing the post.

---

## 7. Workflow — After Writing a Post

1. **Validate Mermaid diagrams** — this site uses Mermaid 10.8.0. Parse or render every `mermaid` fence with that exact version before committing. In sequence diagrams, avoid semicolons in message, note, loop, and branch text because 10.8 treats them as statement separators. A diagram is not valid merely because the Markdown fence renders as code.
2. **Build the site** — run `bundle exec jekyll build`. Resolve all build errors before committing. If Bundler is unavailable, report that the build was not run; do not claim full validation.
3. **Check the diff** — run `git diff --check` and inspect `git diff -- <changed-files>` for whitespace errors and unintended edits.
4. **Clean up big files** — binaries (`.so`, patched ELFs), Ghidra projects, `.gdb_history` are excluded by `.gitignore`. No action needed if `.gitignore` is up to date; verify with `git status` before staging.
5. **Stage selectively** — add the new `_posts/` file, any new `CTF/` text files (scripts, notes, decompiled output), and `.gitignore` if updated. Never `git add -A` in this repo.
6. **Commit and push** — use a concise commit message describing what challenge was added.

```bash
# Validation
bundle exec jekyll build
git diff --check
git diff -- <changed-files>

# Publish
git add _posts/YYYY-MM-DD-ctfname-chall.md CTF/... .gitignore
git commit -m "Add <ctfname> <chall> writeup"
git push
```

---

## 8. Guardrails

- Never publish challenge binaries or flag values that are not already public
- Do not create posts without reading the actual solver/notes in `CTF/`
- One post per challenge — do not merge multiple challenges into one file
- Do not modify `_config.yml`, `Gemfile`, or `_tabs/` without being asked
- Keep tags lowercase and hyphenated; categories use Title Case
