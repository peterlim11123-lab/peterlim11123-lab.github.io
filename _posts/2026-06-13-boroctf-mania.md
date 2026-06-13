---
title: "boroCTF — Mania (Pwn)"
date: 2026-06-13 14:49:00 +0800
categories: [CTF, Pwn]
tags: [boroctf, heap, use-after-free, double-free, tcache, ret2win]
---

**Category:** Pwn (Heap)  
**Binary:** `chal`  
**Vulnerabilities:** Use-After-Free (function pointer hijack) + Double-Free

## Summary

`chal` manages two heap-allocated objects — an `imaginaryFriend` and a `realPerson` — both exactly 72 bytes. Freeing `realPerson` without nulling the pointer, then allocating a new `imaginaryFriend`, hands the same chunk back to the attacker. Writing into the new object overwrites the `conversate` function pointer in the dangling `realPerson` pointer, redirecting execution to `idealConversation()` which calls `system("/bin/sh")`.

## Vulnerabilities

### Bug 1 — Use-After-Free: Function Pointer Hijack

Both structs are 72 bytes (packed). Their layouts overlap at chunk offset 64:

```
imaginaryFriend:  [0..7] rating | [8..39] title[32] | [40..71] special_ability[32]
realPerson:       [0..31] firstName[32] | [32..63] lastName[32] | [64..71] conversate (fn ptr)
```

After `free(RF)` (option 4), the 72-byte chunk enters tcache. The next `malloc(72)` from `imagine()` (option 1) returns the **same chunk**. Writing 24 bytes of padding then the 8-byte address of `idealConversation` into `special_ability` plants the address at chunk offset 64 — exactly where `RF->conversate` reads from.

Calling option 5 (`RF->conversate()`) then jumps to `idealConversation`:

```c
void idealConversation() {
    puts("Wow! You made a real connection!");
    system("/bin/sh");
}
```

`idealConversation` is at fixed address `0x401731` (PIE disabled) — no leak required.

### Bug 2 — Double-Free

Neither `IF` nor `RF` is nulled after `free()`. Selecting option 2 or 4 a second time frees the same pointer again. glibc 2.35 detects this via the tcache key and aborts. On older libc it would allow tcache poisoning for arbitrary write.

## Exploit Steps (Bug 1)

### Step 1 — Meet (option 3)

Allocate `realPerson` (chunk A, 72 bytes). `RF->conversate` = `realConversation` is written at chunk A+64.

### Step 2 — Ghost (option 4)

`free(RF)` sends chunk A into tcache. `RF` is not nulled — it stays as a dangling pointer to chunk A.

### Step 3 — Imagine (option 1)

`malloc(72)` pulls chunk A back out of tcache, returning the exact same memory as the new `imaginaryFriend`.

Input is sent in three fgets calls. The sizes must be exact to avoid leaving a stale `\n` that poisons the next read:

```
title:           send "A"×30 + "\n"  →  fgets reads 31 bytes (hits count), no leftover
special_ability: send "A"×24 + p64(0x401731)[:7]  (31 bytes, no "\n")
                 fgets hits 31-byte limit, appends null at byte 31 = chunk[71]
                 → 8-byte little-endian value at chunk+64 = 0x0000000000401731
rating:          send "1.0\n"  →  fgets reads cleanly
```

`idealConversation` is at `0x401731` (no PIE — fixed address, no leak needed).

### Step 4 — Interact (option 5)

`RF != NULL` passes (dangling pointer). `RF->conversate()` reads chunk+64 = `0x401731` → `idealConversation()` → `system("/bin/sh")`.

## POC Scripts

| Script | Purpose |
|---|---|
| `poc_1_uaf_rce.py` | Full UAF exploit → shell via `idealConversation` |
| `poc_2_double_free.py` | Confirms double-free aborts the process |

## Mitigations

| Mitigation | Status | Impact on exploit |
|---|---|---|
| PIE | **Disabled** | `idealConversation` at fixed `0x401731`; zero leaks needed |
| Stack canary | Enabled | Not relevant — heap-only exploit |
| NX | Enabled | Blocked shellcode; ret2win path used instead |
| RELRO | Partial | GOT writable but not needed here |
| SHSTK / IBT | Enabled | Does not block call to a legitimate code target |
| Tcache key | Enabled (glibc 2.35) | Makes Bug 2 abort; Bug 1 UAF path unaffected |
