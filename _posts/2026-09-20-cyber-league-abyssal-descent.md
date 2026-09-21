---
title: "Cyber League — Abyssal Descent (Pwn)"
date: 2026-09-20 21:00:00 +0800
categories: [CTF, Pwn]
tags: [cyber-league, abyssal-descent, realloc-uaf, tcache-poisoning, arbitrary-read, arbitrary-write, orw]
---

**Binary:** `chall` (PIE, canary, NX, glibc 2.39)
**Finish:** ORW ROP because the seccomp policy blocks `execve`, `fork`, and `vfork`

## Heap bug and leaks

`enable_realtime()` caches the sonar pointer array in `realtime_feed`. When the array grows, `realloc()` may move and free that array, but the cached pointer is never refreshed. `correct_echo()` then performs an unchecked eight-byte write through the stale pointer, while `query_echo()` prints stale entries with `%p`.

The first grooming phase leaves the freed array overlapping the pressure object. Its vtable pointer discloses the PIE base. A second heap layout lets the stale write poison a tcache `0x50` entry. The exploit uses glibc 2.39's `PROTECT_PTR` encoding and makes `malloc()` return a controlled target.

## Arbitrary memory access

The controlled chunk is used to redirect the pressure vtable toward the `memcpy@GOT` area. A diagnostic call now dispatches to resolved `memcpy` with attacker-chosen source and destination pointers. Repeating that operation gives arbitrary reads and writes. Reading `memcpy@GOT` yields libc; `environ` provides a stack leak for diagnostics.

## Stack pivot and ORW

The `hw_cal_v1` calibration path copies up to `0x400` bytes into a 64-byte local buffer without a canary. The exploit writes `/flag` and a fake vtable into unused `.bss`, points the pressure object at it, and changes the calibration callback to `hw_cal_v1`. The overflow carries an ORW chain:

```text
open("/flag", 0)
read(3, scratch, 0x100)
write(1, scratch, 0x100)
exit(0)
```

The final implementation is [solve.py](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/Abyssal%20Descent/solve.py); the individual bug proofs and safe-linking notes are in [bug_report.md](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/Abyssal%20Descent/bug_report.md).
