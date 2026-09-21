---
title: "Cyber League — Synthesizer Rack (Pwn)"
date: 2026-09-20 23:30:00 +0800
categories: [CTF, Pwn]
tags: [cyber-league, synthesizer-rack, type-confusion, arbitrary-read, arbitrary-write, libc-leak, system]
---

**Binary:** `chall` (PIE, Full RELRO, NX, canary)
**Budget:** 20 module operations

## Type confusion

The menu tracks each slot's type in a separate `module_types` array. `repatch` changes that tag without changing the allocated struct. A filter edit reads 32 bytes into `struct + 0x20`; for an oscillator-shaped struct, the last 16 bytes overwrite `buffer_size` at `+0x30` and `buffer_ptr` at `+0x38`.

The exploit adds one oscillator, repatches it as a filter, and supplies:

```text
16 bytes padding | p64(size) | p64(pointer)
```

Repatching back to oscillator makes `record` read `size` bytes from the controlled pointer and `play` write them. This is an arbitrary read/write primitive. The same confusion can also overflow an adjacent module when `buffer_size` is enlarged.

## Leaks and code execution

Menu option 11 prints `cmd_preprocessor`, a function pointer in `.data` at PIE+`0x5010`; subtracting `noop_preprocess` (PIE+`0x28f0`) gives the PIE base. Pointing the oscillator at the PIE's stdout copy (`PIE+0x5020`) leaks `_IO_2_1_stdout_`, which gives libc. The solver then writes `system` over `cmd_preprocessor` and sends `cat /flag.txt` as the next menu line. The main loop invokes the preprocessor before parsing the choice, so that line becomes a shell command.

The full chain is in [exploit.py](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/synthesizer-rack/exploit.py), with verified struct offsets in [state.md](https://github.com/peterlim11123-lab/boroctf/blob/master/cyber-league/synthesizer-rack/state.md).
