---
title: "anti-slop CTF — AnchorPoint (Pwn/Crypto)"
date: 2026-06-15 00:00:00 +0800
categories: [CTF, Pwn]
tags: [antislop, vm-escape, ecdsa, gcm-nonce-reuse, key-recovery, schnorr]
---

**Category:** Pwn / Crypto  
**Binary:** `anchorpoint`  
**Vulnerabilities:** VM output buffer overflow → ECDSA LCG key recovery → AES-GCM nonce reuse

## Summary

`anchorpoint` is a forking TCP server that exposes a custom VM, a signing oracle (ECDSA), and an AES-GCM sealing oracle per session. The flag requires passing two independent authentication checks: a shadow credential (BIP340 Schnorr) and a root capsule (AES-GCM). Both are normally impossible for an unauthenticated client — but a single VM output-buffer overflow corrupts adjacent protocol metadata, which cascades into ECDSA key recovery and GCM nonce reuse, breaking both checks.

## Protocol

Frames are structured as:

```
[2B magic "AP"] [1B opcode] [2B LE length] [1B rolling-XOR checksum] [payload]
```

Relevant opcodes:

| Opcode | Name | Purpose |
|--------|------|---------|
| `0x01` | Hello | Returns session pubkey, cipher key, S-box seed |
| `0x10` | UploadProgram | Loads up to 511 bytes of obfuscated VM bytecode |
| `0x11` | RunProgram | Executes bytecode; output lands in `local_7c4` |
| `0x12` | Quote | ECDSA-signs VM output; enforces a 2-use budget |
| `0x13` | Seal | AES-256-GCM encrypts VM output; IV derived from shadow buffer |
| `0x20` | Auth | Shadow credential (`0x34` sub-type) or root capsule |
| `0x21` | GetFlag | Returns `flag.txt` iff both auth checks passed |

The Hello frame returns 84 bytes: `nonce(8) + pubX(32) + pubY(32) + version(2) + cipher_key(2) + sbox_seed(8)`. These seed per-session VM encoding and cookie derivation.

## VM Encoding

Each raw bytecode byte is decoded by `FUN_00103880` with a rolling cipher:

```python
state = k0 ^ 0x5A
for pc, raw in enumerate(bytecode):
    b = ROR(raw, k1 & 7) ^ state ^ k0
    hi, lo = b >> 4, b & 0xF
    b = lo | ((sbox[hi & 7] & 7) << 4)
    if hi & 8: b |= 0x80
    state = ((k1 + pc) ^ (state * 0x21) ^ k0 ^ decoded) & 0xFF
```

The S-box is derived from `sbox_seed`. A low-3-bit stack address constant `C` (0–7) is also mixed in; the correct value is found by brute force: encode a `HLT` (`0x70`) for each candidate, upload and run, and pick whichever returns OK.

Key VM opcodes after decoding:

| Decoded | Mnemonic | Effect |
|---------|----------|--------|
| `0x10` | `MOV r, imm` | Load immediate into register |
| `0x80+r` | `CPUSH r` | Push register to output AND to shadow buffer when conditional flag is on |
| `0x71` | `COND_TOGGLE` | Toggle conditional flag |
| `0x70` | `HLT` | Stop execution |

## Bug: VM Output Buffer Overflow

The VM output area `local_7c4` is 64 bytes. The PUSH bound check is `uVar28 < 0x80` (128), so it allows writing up to 128 bytes. The server only returns the first 64 bytes to the client, but all 128 land on the stack.

Stack layout immediately after `local_7c4`:

```
local_7c4[0..63]   VM output (exposed to client)
local_784          quote_budget  (init = 2)    ← output[0x40]
local_783          VM output length
local_782          run flag
local_781[0]       capsule_budget
local_781[1]       quote_cookie
local_781[2]       capsule_budget2
local_781[3]       shadow_cookie
local_77d          shadow cookie comparison byte
```

A program pushing 72 bytes overwrites `quote_budget` and the seven metadata bytes that follow. Crafting those overwrite bytes inflates the quote budget to 10, sets both cookies to their expected values (derived deterministically from `sbox_seed`), and keeps all other fields consistent so subsequent operations succeed.

Cookie values:

```python
quote_cookie  = sbox_seed[5] ^ sbox_seed[8] ^ 0xA5
shadow_cookie = sbox_seed[3] ^ sbox_seed[9] ^ 0x5C
```

## Step 1 — Inflate Quote Budget and Collect Four Signatures

Upload and run a program that pushes 72 bytes: 64 arbitrary bytes followed by 8 override bytes. After the run, call `Quote` (`0x12`) four times. The inflated budget allows all four.

Each quote response contains an ECDSA signature `(r, s)` over a message whose SHA-256 is the hash `e`. The Quote nonce follows a linear recurrence:

```
k[0]   = H(tag, session_random, 0) mod n
k[i+1] = k_a * k[i] + k_b  mod n
```

## Step 2 — Recover the Private Key

For each signature: `k_i = (e_i + r_i * d) / s_i mod n = α_i + β_i * d`

where `α_i = e_i * s_i⁻¹`, `β_i = r_i * s_i⁻¹`.

Consecutive deltas `Δ_i = k_i - k_{i-1}` satisfy `Δ_{i+1} = k_a * Δ_i`, so `k_a = Δ_{i+1} / Δ_i`. Eliminating `k_a` between two pairs yields a quadratic in `d`:

```
c₂ d² + c₁ d + c₀ ≡ 0 (mod n)

c₂ = β₂² - β₃β₁
c₁ = 2α₂β₂ - (α₃β₁ + β₃α₁)
c₀ = α₂² - α₃α₁
```

Solving via the quadratic formula (Tonelli–Shanks for the square root mod `n`) produces at most two roots. The correct root is the one where `d·G = (pubX, pubY)`.

## Step 3 — Forge Shadow Authentication

With the recovered private key `d`, construct and sign the shadow credential:

```python
epoch      = (4).to_bytes(8, 'little')
quote_chain = sha256(sha256(b'\x00'*32 + quote[0]) + quote[1] + ... + quote[3])
crumb       = tagged_hash("Anchorpoint/shadow-crumb", session_id, epoch, quote_chain)[:16]
shadow_msg  = tagged_hash("Anchorpoint/shadow-msg",   session_id, epoch, quote_chain, crumb)
sig         = bip340_sign(shadow_msg, d)
payload     = b'\xA7\x34' + epoch + crumb + sig
```

Send as opcode `0x20`. The server sets its shadow-auth flag.

## Step 4 — GCM Nonce Reuse

The Seal oracle derives its IV from the shadow buffer (`local_77a`). The shadow buffer is populated by `CPUSH` instructions only when the conditional flag is active.

Wrapping only the first 16 push instructions between `COND_TOGGLE` (opcode `0x71`) instructions writes exactly 16 bytes into the shadow buffer and leaves the rest zeroed. Two consecutive Seal calls with the same 16-byte shadow state produce two ciphertexts under the **same key and IV**.

Given two known plaintext–ciphertext pairs `(P₁, C₁)` and `(P₂, C₂)`:

```
stream   = C₁ ⊕ P₁
H        = sqrt( (T₁ ⊕ T₂) / (C₁ ⊕ C₂) )   in GF(2¹²⁸)
tag_mask = T₁ ⊕ GHASH(H, AAD₁, C₁)
```

With `stream`, `H`, and `tag_mask` known, any 16-byte plaintext can be forged:

```python
root_target  = tagged_hash("Anchorpoint/root-capsule", session_id, quote_chain, pubX_bytes)[:16]
root_ct      = bytes(a ^ b for a, b in zip(root_target, stream))
root_tag     = tag_mask ^ GHASH(H, root_aad, root_ct)
root_capsule = bytes([16]) + iv + bytes([len(root_aad)]) + root_aad + root_ct + root_tag
```

Send as opcode `0x20`. The server decrypts to `root_target`, validates it, and sets the root-capsule auth flag.

## Step 5 — Get Flag

Send opcode `0x21`. Both auth flags are now set and the server returns `flag.txt`.

## Exploit Chain

```
Hello
  └─ brute-force C (8 tries) → VM encoder
       └─ push 72 bytes → inflate quote_budget, set cookies
            ├─ ×4 Quote → 4 ECDSA sigs
            │    └─ quadratic mod n → private key d
            │         └─ BIP340 sign → shadow auth ✓
            └─ ×2 Seal, fixed 16-byte shadow buf → same-IV ciphertexts
                  └─ recover H, keystream, tag_mask → forge root capsule ✓
                       └─ opcode 0x21 → FLAG
```

## Fix

Two independent fixes are needed:

1. **VM output bound**: cap the PUSH destination at 64, not 128.
2. **GCM IV**: derive the seal IV from a server-side monotonic counter, not client-influenced VM output.

The ECDSA nonce LCG is also weak; replace with a CSPRNG-derived nonce per signature.
