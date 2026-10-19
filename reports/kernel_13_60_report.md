# PS5 13.60 Live Kernel Dump — Analysis Report

Subject: `kernel-13.60-live.bin` (103,546,880 bytes; terrafirma2021 live RAM
capture from 2026-10-13; SHA-256 `c3f745e2…cddd` matches the source repo's
metadata). Produced 2026-10-19. ([中文版](kernel_13_60_report.zh.md))

## Layout

- text @ VA `0xffffffff9e3f0000` (rva 0–0xCC0000, 13.4 MB)
- data @ VA `0xffffffff9f0b0000` (rva 0xCC0000 onward, 90 MB);
  file offset == rva (flat image)
- 688 uncaptured pages zero-filled (~2.7 MB); the kernel heap
  (0xffff8e77… / 0xffffffffa0cb…) is **not** in the dump (image regions only)

## Quadruple cross-validation (offset tables ↔ dump ↔ Relapse source ↔ FreeBSD)

| Check | Result |
|---|---|
| data rva 0xCC0000 == offset-table `kernelData` (13.60) | ✓ exact |
| rodata probe `_aio_submit_cmd\0_aio_multi_wait` at predicted rva 0x1379d6c | ✓ exact |
| kaslr `retStatic` 0xAE2DA0 | ✓ structurally consistent (call-return boundary; low16 == retLow16) |
| oid.a.kind @0x028cef7c == originalKind 0x80048002 | ✓ exact |

## Forensic finding: the dump itself was made with Relapse

- **oid.b.kind = 0x7f048002** (not the original 0x80048002). flipOidKind's
  flip path decrements byte 3 by one per cancel (0x80→0x7f→…→0x70); the
  capture caught a **mid-flip state** — the dumper ran the kernel exploit
  itself, and oid.b was not fully restored.
- Empirical `sysctl_oid` layout (from the oid.a node bytes):
  `next@0x00, oid_name@0x08, oid_number@0x10, oid_kind@0x14, oid_arg1@0x18,
  oid_arg2@0x20, desc@0x28, oid_handler@0x30`
- oid.a: dynamic number 0x7FFFFFCB8 (SYSCTL_ADD runtime-created node);
  handler = 0xffffffff9e6609e8; the name pointer lands on one of the 688
  uncaptured pages (zero-filled), hence unreadable
- oid.c: static node, oid_number=8 (== the second element of mib [9,8],
  matching the offset tables), arg1Value=200112
- walkCounter.arg1Value = 0 (reset at capture time)
- allproc head / rootvnode point into the kernel heap (0xffff8e77…), not
  captured — process-list walking is not possible from this dump

## Symbol-table recovery attempt (negative result)

- No long Elf64_Sym sequences (longest 24), no long ddb name/address pairs
  (longest 59) → Sony stripped the symtab and live RAM does not materialize one.
- rva 16–20 MB holds ~23k C identifiers (dtrace-probe/sysinit name lists)
  with no accompanying address table.

## Ghidra pipeline results

- **25,611 functions** recovered from the text segment (raw binary import,
  gcc cspec; first run found 0 functions — see the gotchas in
  [tools/](../tools/) headers). Inventory:
  [kernel-13.60-text_symbols.tsv](kernel-13.60-text_symbols.tsv)
- Largest functions 40 KB (0xffffffff9f059c40) and several 19 KB+ — VM/driver
  scale.
- **oid.a handler targeted decompilation**: handler = 0xffffffff9e6609e8 is a
  5-byte thunk → real body 0xffffffff9e947540 = **`sysctl_handle_int`**
  (standard int handler): SYSCTL_OUT writes 4 bytes; when oid_arg1 is
  non-NULL, SYSCTL_IN reads 4 bytes; plus the kernel-mode stack canary
  (guard value @ 0xffffffffa1d0c310, fail routine 0xffffffff9eaed6b0).
  The exploit's "read/write window" = corrupting this kind of node's
  oid_arg1 to an arbitrary kernel address, then reading/writing as an int —
  matching Relapse's sysctlReadInt/WriteInt/aimWindow one-to-one.

## Conclusion

A function-level map of the 13.60 kernel now exists. When a 14.10 kernel
image becomes available: same raw import → 25k-function inventory →
structural diff against this table → new-offset extraction becomes mechanical.
