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

**Post body structure:**

```
**Category:** ...
**Binary:** `filename`
**Vulnerability:** one-line summary

## Summary
## Vulnerability / Bug
## Exploit Strategy (or numbered steps)
## Fix / Mitigations
```

---

## 3. Memory

- boroCTF posts written: coming-together, dinner, mania, next-challenge (2026-06-13)
- anti-slop posts written: anchorpoint, paper-lantern (2026-06-15)
- biterra posts written: barbie-core (2026-06-20)
- Avatar: `peterlim.png` (added to about page)

---

## 4. Examples

**Canonical post:** `_posts/2026-06-13-boroctf-dinner.md`

- Lead with bold metadata block before first `##`
- Use fenced code blocks for C, Python, assembly, shell
- Mitigations table at the end when relevant
- No trailing summaries or recaps

---

## 5. Tools

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

## 6. Guardrails

- Never publish challenge binaries or flag values that are not already public
- Do not create posts without reading the actual solver/notes in `CTF/`
- One post per challenge — do not merge multiple challenges into one file
- Do not modify `_config.yml`, `Gemfile`, or `_tabs/` without being asked
- Keep tags lowercase and hyphenated; categories use Title Case
