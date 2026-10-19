# PS5 Firmware Research Notes

Independent reverse-engineering research notes and tooling for PS5 firmware/kernel analysis, produced with byte-level verification against live data. Everything here studies **public artifacts** (open-source exploit repositories, Sony's public CDN, community-released memory captures) — no copyrighted firmware binaries or keys are included in this repo.

> **Languages:** English is primary. Full Chinese research log: [docs/PROGRESS.zh.md](docs/PROGRESS.zh.md); each report has a `*.zh.md` Chinese twin next to it.

## Key Findings

### 1. Cross-firmware offset study (FW 7.00–13.60, 35 firmwares)

From the offset tables shipped in [ps5-webkit-remote-loader](https://github.com/itsPLK/ps5-webkit-autoloader) (GPL):

- **`ucred` / `filedesc` layouts never changed across all 33 main-chain firmwares** (7.00–13.60). Six years, zero structural drift. Only absolute addresses (ASLR) moved.
- The **only** evolving structure is `proc.aioInfo`: 3128 (7.00–9.60) → 3136 (10.00–11.60) → 3144 (12.00–13.60) — two 8-byte insertions.
- KASLR defeat is the same `rtmsg2` mode across every firmware; Sony never fixed the mechanism, only reshuffled addresses per rebuild.
- Full per-version change matrix and machine-readable data: [reports/offsets_report.md](reports/offsets_report.md)

**Practical value:** when porting exploits to a new firmware, ucred/privilege targets can be carried over as-is; only addresses need re-derivation.

### 2. FreeBSD 12 as a pseudo-symbol-table for the PS5 kernel

The PS5 kernel derives from FreeBSD 12. Verified field-by-field ([reports/freebsd_mapping.md](reports/freebsd_mapping.md)):

- `struct ucred`: first 0x1C bytes **byte-identical** to FreeBSD 12.0 (`cr_ref`..`cr_svgid`, statically provable — consecutive u32s). From 0x58, Sony replaces the MAC/jail/audit machinery with `sceAuthId` / `sceCaps` / `sceAttrs` — the HEN privilege-escalation targets.
- `struct filedesc`: first 4 fields byte-identical.
- `struct proc`: `p_ucred`→`p_fd` adjacency preserved; Sony-only fields `dynlib@0x3E8`, `aioInfo@0xC38+`.

**Practical value:** FreeBSD 12 source provides free semantics for kernel RE; only Sony-delta fields need fresh analysis.

### 3. Live 13.60 kernel dump: 25,611 functions + forensics

Analysis of the community-released live RAM capture ([terrafirma2021/ps5-13.60-kernel-dump](https://github.com/terrafirma2021/ps5-13.60-kernel-dump)) — see [reports/kernel_13_60_report.md](reports/kernel_13_60_report.md):

- Ghidra headless (raw binary @ `0xffffffff9e3f0000`, gcc cspec) recovers **25,611 functions**. Inventory: [reports/kernel-13.60-text_symbols.tsv](reports/kernel-13.60-text_symbols.tsv)
- Quadruple cross-validation passed: data-segment RVA `0xCC0000` == offset table `kernelData`; rodata probe string lands exactly at the predicted RVA `0x1379d6c`; kaslr `retStatic 0xAE2DA0` sits at a call-return boundary with matching low-16; `oid.a.kind == 0x80048002` as expected.
- **Forensic finding:** `oid.b.kind = 0x7f048002` — a *mid-flip* state on the `0x80→0x70` decrement path used by Relapse's `flipOidKind`. The dump itself was captured through a Relapse run, leaving exploit residue. Anyone using this dump as "clean" kernel data should know.
- Empirical `sysctl_oid` layout: `next@0x00, oid_name@0x08, oid_number@0x10, oid_kind@0x14, oid_arg1@0x18, oid_arg2@0x20, desc@0x28, oid_handler@0x30`.
- The exploited sysctl nodes route to plain **`sysctl_handle_int`** (4-byte SYSCTL_OUT / SYSCTL_IN window) — confirming the Relapse read/write window mechanism (`aimWindow` corrupts `oid_arg1` to aim the window).
- Kernel-mode stack canary lives at `0xffffffffa1d0c310`.

### 4. Relapse exploit chain — complete mechanism map

Cross-referencing the public [Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) source against the offset tables closed every open question — see [PROGRESS.md](PROGRESS.md) §6:

| Offset-table field | Actual mechanism (source-verified) |
|---|---|
| `kaslr mode "rtmsg2"` | sockaddr length-alignment kernel-base leak |
| `aio{waiterSize 0x38, requestSize 0x28}` | `aio_multi_wait` UAF race heap layouts |
| `oid.a/b/c`, `originalKind 0x80048002` / `writableKind 0x70048002` | `flipOidKind()`: per-cancel byte-decrement flip; nodes a/c form the low/high 32-bit read-write window |
| rodata probe `_aio_submit_cmd\0_aio_multi_wait` | in-kernel function locator |

### 5. PUP container & CDN facts (FW 14.10, verified live)

- Outer container is **SLB2**; only the 64-byte plaintext header is parseable offline. Everything else — including the entry table — is encrypted (uniform ~7.997 bits/byte entropy across the whole 1.17 GB; zero structural leakage).
- Sony embeds the **SHA-256 of the PUP in its download URL** (`sys_<sha256>/PS5UPDATE.PUP`) — free tamper-checking for mirrors.
- CN-region node `dcn01.ps5.update.playstation.net` serves the file directly; `fus01` serves the updatelist over plain HTTP. Tool: [tools/pup_probe.py](tools/pup_probe.py)

### 6. elfldr (itsPLK build) internals

From the stripped ELF ([reports/elfldr_symbols.tsv](reports/elfldr_symbols.tsv), decompileable with our scripts):

- It **does not listen**: dynamic imports contain `recv` only — no socket/bind/listen/accept. The listener is built exploit-side (raw syscalls under ROP, bound to 127.0.0.1:9021); the "localhost-only" security is just the loopback bind.
- Protocol: fixed 64-byte header + variable body framing; `kqueue`/`rfork_thread` event model.
- On completion it `execve`s `/system/vsh/app/NPXS40112/eboot.bin` — restarting the User's Guide/browser app so the console returns cleanly to stock UI.

## Tools

| Tool | Purpose |
|---|---|
| [tools/analyze_offsets.mjs](tools/analyze_offsets.mjs) | Cross-firmware offset-table analyzer (35 FWs, epochs, change matrix) |
| [tools/pup_probe.py](tools/pup_probe.py) | Sony CDN updatelist → PUP URL → ranged header fetch → SLB2 parse |
| [tools/entropy_map.py](tools/entropy_map.py) | Whole-file Shannon entropy mapping |
| [tools/ghidra_dump_decomp.java](tools/ghidra_dump_decomp.java) | Ghidra headless: full-function decompilation export (works on Apple Silicon — see notes in the script header) |
| [tools/ghidra_symbols_only.java](tools/ghidra_symbols_only.java) | Function inventory only (for large kernels) |
| [tools/ghidra_decompile_targets.java](tools/ghidra_decompile_targets.java) | Targeted decompilation by address list |

Reproduce the kernel analysis: `analyzeHeadless <proj> k -import kernel-text.bin -processor x86:LE:64:default -cspec gcc -loader BinaryLoader -loader-baseAddr 0xffffffff9e3f0000 -scriptPath tools -postScript ghidra_symbols_only.java` (Ghidra with mac_arm_64 natives; official macOS zips lack the decompiler binary).

## Methodology Note

Every claim above is backed by a verifiable artifact — exact hashes, byte offsets, or decompiled evidence — and cross-checked across ≥2 independent sources (offset tables ↔ memory dump ↔ exploit source ↔ FreeBSD source). If you find an error, please open an issue with evidence; corrections with byte-level proof are always welcome.

## Credits & Sources

- [itsPLK/ps5-webkit-autoloader](https://github.com/itsPLK/ps5-webkit-autoloader) & ps5-webkit-remote-loader (offset tables, GPL)
- [ntfargo/Relapse-Exploit](https://github.com/ntfargo/Relapse-Exploit) and the Relapse/Poops authors
- [terrafirma2021/ps5-13.60-kernel-dump](https://github.com/terrafirma2021/ps5-13.60-kernel-dump)
- [zecoxao/ps5-pup-decrypt](https://github.com/zecoxao/ps5-pup-decrypt), [deepkicks/TitaniaPy](https://github.com/deepkicks/TitaniaPy), [seregonwar/PFU-PupFileUnpacker](https://github.com/seregonwar/PFU-PupFileUnpacker)
- [psdevwiki](https://www.psdevwiki.com/ps5/), FreeBSD release/12.0.0 source

## Legal

Research on publicly available artifacts and personally owned hardware, for education and interoperability research. No Sony firmware images, keys, or circumvention material is included. Tool code is MIT licensed (see [LICENSE](LICENSE)); reports are provided as-is.
