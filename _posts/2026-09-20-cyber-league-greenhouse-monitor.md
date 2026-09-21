---
title: "Cyber League — Greenhouse Monitor (Pwn)"
date: 2026-09-20 22:00:00 +0800
categories: [CTF, Pwn]
tags: [cyber-league, greenhouse-monitor, stack-overflow, canary-leak, pie-leak, rop]
---

**Binary:** `chall` (x86-64, PIE, NX, stack canary)
**Remote:** `cyberleague-shared-nlb-8eebe09f116ebe55.elb.ap-southeast-1.amazonaws.com:30002`

The monitor has three independent mistakes that line up into a short ROP exploit.

## Leaks

`view_sensor_log()` initializes a 72-byte stack buffer but writes `0x50` bytes to stdout. The trailing bytes include the stack canary, so menu option 3 leaks it. Menu option 6 prints `main` with `%p`; subtracting the known `main` offset (`0x1793`) recovers the PIE base.

## Overflow

`set_sensor_name()` reads `0x80` bytes into the same 72-byte buffer. With the leaked canary restored, the payload is:

```text
72 bytes filler
8-byte canary
8-byte saved RBP filler
ret
pop rdi ; ret
flag_global (PIE + 0x4060)
puts@plt
```

The extra `ret` aligns the stack for libc's `puts`. The flag is loaded into the global buffer during setup, so no second memory disclosure is required. The compact exploit is [solve.py](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/Greenhouse%20Monitor/chall/solve.py).
