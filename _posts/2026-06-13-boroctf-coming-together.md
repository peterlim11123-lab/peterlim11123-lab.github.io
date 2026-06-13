---
title: "boroCTF — Coming Together (Pwn/Rev)"
date: 2026-06-13 14:46:00 +0800
categories: [CTF, Pwn]
tags: [boroctf, integer-overflow, signed-integer, logic-bypass]
---

**Category:** Pwn / Reverse  
**Binary:** `chal`  
**Vulnerability:** Integer Overflow (INT_MIN negation)

## Summary

The program reads a number from stdin, rejects negatives by negating them, then checks whether the result fits a normal range. The flag branch is reached if the post-negation value overflows back into negative territory.

## Vulnerability

`main()` applies this guard to user input:

```c
if (local_7c < 0) {
    local_7c = -local_7c;   // overflows when local_7c == INT_MIN
}
uVar1 = local_7c + 2;
if (-1 < (int)uVar1) {      // normal path
    printf("Our total is %d! ...\n", ...);
} else {                     // flag path
    fopen("flag.txt", "r"); puts(flag);
}
```

Negating `INT_MIN` (`-2147483648`) is undefined/wrap-around behaviour on x86: the result is still `INT_MIN`. Adding 2 produces `0x80000002`, which reinterpreted as a signed int is `-2147483646` — not `> -1` — so execution falls into the flag branch.

## Exploit

Send `INT_MIN` as the input:

```
-2147483648
```

The 11-character value fits exactly within the `fgets(..., 12, ...)` limit. No memory corruption, no shellcode — pure integer logic bypass.

## Solution Script

```bash
python3 poc_1_int_overflow.py
```

## Mitigations

Stack canary, NX, PIE, and full RELRO are all present but irrelevant — the exploit never touches memory beyond the input buffer.
