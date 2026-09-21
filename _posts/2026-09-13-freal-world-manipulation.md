---
title: "Freal World Manipulation (Pwn)"
date: 2026-09-13 21:00:00 +0800
categories: [CTF, Pwn]
tags: [freal-world-manipulation, oob-read, pie-leak, arbitrary-read, arbitrary-write, rop]
---

**Binary:** `freal` (x86-64, PIE, NX)
**Theme:** a decimal calculator with a surprisingly useful external-index bug
**Result:** PIE/libc leaks, then a stack ROP chain and shell

## The bugs

`view()` accepts negative indexes because its validation path passes `param_2 = 0` to `checked_slot()`. Index `-11` points 88 bytes before the decimal table, at the in-binary `__dso_handle` cell. The value is accepted as a coherent pointer and `view()` prints eight bytes from it, giving a stable PIE pointer:

```text
PIE = leak - 0x5008
```

There is also a state bug: `destroy()` clears a slot but does not decrement the allocation counter. After 256 add/destroy cycles the table is empty, yet `add()` permanently reports `full`.

## Turning the leak into memory access

The solver first allocates large values to inflate the table's size metadata. Two `1e308` values multiplied together make the external-index check accept indexes beyond the normal table. A later small allocation lands near the PIE image; filling it with a repeated pointer creates a fake slot table. Scanning indexes until `view()` echoes the PIE leak locates that table.

The fake table gives both directions of access:

- `view(index)` reads up to `0x100` bytes from the pointer stored in the fake slot;
- `load(index, data)` writes up to `0x1000` bytes through it.

Reading `write@GOT` yields libc. Reading `environ` yields a stack pointer, from which the solver derives `main`'s saved return address. It writes a conventional `ret; pop rdi; ret; "/bin/sh"; system` chain there. Finally, a deliberately non-numeric line makes `scanf("%ld")` fail and lets `main` return into the chain.

The complete local/remote solver is [solve_robust.py](https://github.com/peterlim11123-lab/boroctf/blob/master/Freal%20World%20Manipulation/solve_robust.py); the primitive details are in the challenge's [exploit notes](https://github.com/peterlim11123-lab/boroctf/blob/master/Freal%20World%20Manipulation/exploit_notes.md).

## Takeaways

Negative-index validation must be shared by every operation, and a freed slot should be returned to the allocator's free-list rather than counted as a permanent allocation. The challenge combines both mistakes with attacker-controlled arithmetic to turn an information leak into full ROP.
