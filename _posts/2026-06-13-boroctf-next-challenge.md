---
title: "boroCTF — Next Challenge (Misc)"
date: 2026-06-13 14:47:00 +0800
categories: [CTF, Misc]
tags: [boroctf, misc, logic-flaw, netcat]
---

**Category:** Misc  
**Target:** `nc thww9zyp6ygt.boroctf.com 19350`  
**Vulnerability:** Logic flaw — flag command with trivially bypassable confirmation

## Summary

The remote service (VULNBOT) exposes a `flag` command gated only by a misleading confirmation prompt. Replying `y` immediately discloses the flag. No binary, no memory corruption, no authentication required.

## Vulnerability

The service interaction:

```
> flag
Are you SURE you don't want to see what the Cheese option does? (y/n)
y
FINE. I guess if you insist.
boroCTF{0nLinE_C@ts*}
```

The prompt is designed to confuse ("sure you don't want to see Cheese?"), but the branching logic is straightforward: `y` → print flag. The `cheese` command is a trap that terminates the connection.

## Exploit

```bash
python3 solve.py
```

Or manually:

```
nc thww9zyp6ygt.boroctf.com 19350
flag
y
```

## Flag

```
boroCTF{0nLinE_C@ts*}
```
