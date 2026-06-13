---
title: "boroCTF — dinner (Pwn)"
date: 2026-06-13 14:49:00 +0800
categories: [CTF, Pwn]
tags: [boroctf, stack-overflow, rop, fork, canary, seccomp, orw]
---

**Category:** Pwn  
**Binary:** `dinner_party`  
**Vulnerabilities:** Stack Buffer Overflow + Fork Crash Oracle

## Summary

`dinner_party` is a menu-driven binary that forks on option 1 and reads unbounded input on option 2. The overflow alone triggers a canary abort, but the fork behaviour turns it into a repeatable crash oracle that enables byte-by-byte canary brute-force.

## Vulnerabilities

### Bug 1 — Stack Buffer Overflow (`make_speech`)

`make_speech()` allocates a 136-byte stack buffer but passes `0x400` to `read()`:

```c
undefined1 local_98[136];
read(0, local_98, 0x400);   // 136-byte buffer, 1024-byte read
```

Any input longer than 136 bytes corrupts the stack canary; input past byte 144 reaches the saved return address. The binary is non-PIE (`0x400000`), so code addresses are fixed.

### Bug 2 — Fork Crash Oracle (`set_table`)

Menu option 1 calls `fork()`. The child is not restricted — it returns to the same main menu. The parent calls `wait()` and resumes after the child exits or crashes:

```c
_Var2 = fork();
if (_Var2 != 0) {
    wait(NULL);   // parent survives a crashing child
}
return;           // child also enters the menu
```

Since `fork()` inherits the canary, a child that crashes in `make_speech()` reveals nothing to the parent — but the parent remains alive with its canary intact for the next attempt.

## Exploit Strategy

### Phase 1 — Canary brute-force via fork oracle

The canary is always `\x00` in the lowest byte. Bytes 1–7 are brute-forced one at a time (up to 7 × 256 = 1792 fork attempts).

For each candidate prefix:
1. Send option `1` (set_table) — forks a child. Record the parent PID from the "My assigned seat is: N" output.
2. In the child, send option `2` (make_speech) with `"A"×136 + candidate_prefix`.
3. Send option `1` again and read the PID.
   - **PID unchanged** → child crashed (wrong byte). Send option `3` to clean up and try the next value.
   - **PID changed** → child survived and forked again (correct byte). Send option `3` twice to unwind the grandchild and child, then continue to the next byte.

### Phase 2 — Libc leak via ROP

With the canary known, build a ROP chain using three binary gadgets (non-PIE, all fixed):

```
0x401569: pop rcx ; xor rax, rax ; ret
0x401572: add rax, rcx ; ret
0x401566: xchg rax, rdi ; ret
```

Chain: zero RAX → add `puts@got` → move to RDI → call `puts@plt` → print the 8-byte GOT pointer → return to `main()` for a second overflow.

Parse the leaked address to compute libc base.

### Phase 3 — Open-Read-Write (ORW) ROP chain

`execve` and `execveat` are blocked by the seccomp filter loaded inside `make_speech()`. The flag is read directly using libc ROP gadgets:

```
read(0, BSS+0x300, 9)              # attacker sends "flag.txt\x00" over stdin
open(BSS+0x300, 0)                 # fd returned in rax
xchg rax, rdi                      # move fd to rdi
read(fd, BSS+0x380, 0x100)         # read flag into BSS
write(1, BSS+0x380, 0x100)         # print flag to stdout
```

BSS is at a fixed address (`0x4040c0`) — no PIE leak needed for any of this.

## POC Scripts

| Script | Purpose |
|---|---|
| `poc_1_stack_bof.py` | Confirms the overflow crashes the process |
| `poc_2_fork_crash_oracle.py` | Confirms the parent survives a crashing child |
| `solver.py` | Full canary brute-force and ROP exploit |

## Mitigations

| Mitigation | Status | Impact on exploit |
|---|---|---|
| Stack canary | Present | Bypassed via fork crash oracle |
| NX | Present | Requires ROP chain |
| PIE | **Disabled** | Gadget addresses are fixed — no leak needed |
| seccomp | Present (in `make_speech`) | Blocks `execve`; ROP must use an allowed syscall |
| SHSTK / IBT | Present | Does not block ROP to legitimate call targets |
