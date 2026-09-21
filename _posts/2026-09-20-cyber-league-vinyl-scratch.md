---
title: "Cyber League — Vinyl Scratch (Pwn)"
date: 2026-09-20 23:00:00 +0800
categories: [CTF, Pwn]
tags: [cyber-league, vinyl-scratch, format-string, pie-leak, hn, function-pointer-overwrite]
---

**Binary:** `chall` (PIE, Full RELRO, NX, canary)
**Objective:** reach the dormant `print_flag()` function

## Format string

`leave_review()` reads a review into a stack buffer and calls `printf(review_buf)` directly. A review of `%25$p` prints a saved return address into `main`, giving:

```text
PIE base = leak - 0x1325
```

## One short write

The exit path calls a writable `.data` function pointer at `base + 0x4010`. Its current value is `normal_exit` (`base + 0x1450`), while `print_flag()` is at `base + 0x1570`. Because both values share the same PIE high bytes, a single positional `%hn` only needs to replace the low 16 bits.

The review payload puts the format directives first and the target pointer at offset 104, which makes it printf argument 19 without putting NUL bytes inside the format string:

```text
%<low16(print_flag)>c%19$hn
<padding to 104 bytes>
p64(base + 0x4010)
```

Finally, menu option 3 calls the overwritten pointer and `print_flag()` opens `/flag`. ASLR occasionally puts a newline byte inside the pointer, so the solver reconnects and retries. See [solve.py](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/Vinyl%20Scratch/solve.py) for the retry loop and parsing.
