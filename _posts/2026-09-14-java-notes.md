---
title: "K17 CTF 2027 — java-notes (Web)"
date: 2026-09-14 21:00:00 +0800
categories: [CTF, Web]
tags: [k17-ctf-2027, java, deserialization, commons-collections, rce]
---

**Category:** Web / Java deserialization
**Flag:** `K17{i_am_java_ONE_with_java!!!!oashd8aghrdfo8aehFIOEASDJFNLC}`

## Bug

The application presents Base64-encoded serialized `Session` objects as portable note tokens. The restore handler decodes attacker input and feeds it directly to `ObjectInputStream.readObject()`:

```java
try (ObjectInputStream ois = new ObjectInputStream(
        new ByteArrayInputStream(raw))) {
    Object obj = ois.readObject();
}
```

There is no class allow-list or `ObjectInputFilter`. The Maven build also ships `commons-collections:3.2.1`, making the classic CommonsCollections6 gadget chain available.

## Exploit

The generator builds `HashSet -> TiedMapEntry -> LazyMap -> ChainedTransformer`. The real transformer array executes:

```text
Runtime.getRuntime().exec(["/bin/sh", "-c", command])
```

The chain is initially populated with a harmless transformer so construction does not execute the command. After insertion, the backing map's `x` key is removed and reflection swaps in the real transformer array; deserialization then triggers the chain.

The endpoint is blind: it returns only “that token is not a session.” The solver therefore makes the container POST `/flag.txt` to a temporary webhook using the image's `curl`, then polls the webhook for the flag.

```bash
python3 solve.py --target https://<instance>
```

Full generator and delivery code are in [solve.py](https://github.com/peterlim11123-lab/boroctf/blob/master/java-notes/solve.py), with the source-level walkthrough in the repository's [WRITEUP.md](https://github.com/peterlim11123-lab/boroctf/blob/master/java-notes/WRITEUP.md).

## Fix

Never deserialize untrusted Java serialization streams. Replace the token with a signed, typed format, or enforce a strict `ObjectInputFilter` and remove legacy gadget-bearing dependencies.
