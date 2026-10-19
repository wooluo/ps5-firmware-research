# PS5 Firmware RE — Full Research Log

> Workspace: `~/DEV/ps5-fw-research/` · Started: 2026-10-19 · Log by ZCode
> Main thread: ps5-webkit-autoloader → firmware update RE → PUP decryption
> architecture → key-extraction frontier → decompilation pipeline.
> This is the consolidated timeline and findings; details in the topical
> reports under `reports/`. ([中文版](docs/PROGRESS.zh.md))

---

## 0. Starting point: ps5-webkit-autoloader analysis

Repo: `~/DEV/ps5-webkit-autoloader` (itsPLK, v0.6.1, GPL-3.0, submodules
initialized, `make test` all green).

- Purpose: "offline-ize" the PS5 WebKit exploit — AppCache-cached exploit
  page + homescreen shortcut (WKAL00001); fully offline after install, no
  third-party DNS. FW 7.00–13.60, dual chains Poops/Relapse.
- Core mechanisms:
  - Native C installer ELF (libmicrohttpd, 127.0.0.1:18181 only): kills
    stale instances (sysctl KERN_PROC_ALL scan, ki_tdname@447) → HTTP →
    launches browser → installs shortcut only after caching completes;
  - **Manifest-attribute gating**: until an exploit is chosen, the server
    overwrites `manifest="/cache.appcache"` in the HTML with same-length
    spaces — AppCache starts on the attribute and JS runs too late to stop it;
  - Two-key localStorage two-phase commit (wkal_pending/wkal_exploit);
    failed installs never pollute the previous one;
  - Three-stage payload queue: elfldr-check.js (probe 9021 to avoid re-running
    the kernel exploit) → poops/relapse.js → autoload.js (mmap-staged ELF →
    socket to elfldr).
- Layering: this repo is a shell; the exploit runner/ROP/offset tables/PC
  host live in third_party/ps5-webkit-remote-loader (one-way dependency).

## 1. Scene landscape (the "permanent CFW / emuMMC" question)

- **No true permanent jailbreak exists**: the boot chain
  (ROM→SE→bl2/3→HV→kernel) is unbroken publicly; internal SSD is
  per-console-key encrypted with anti-rollback → no emuNAND. Contrast: PS3
  got real CFW via the lv0 key leak; Switch via the Fusée Gelée boot-ROM bug.
- **BootROM key leak (2025-12-31)**: symmetric decryption keys (not signing
  keys), unpatchable, ~95M consoles. Theoretically enables a custom boot
  chain → permanent CFW; as of 2026-10 no public build — its practical effect
  so far is accelerating offset RE (exploits now cover up to 13.60).
- **ps5-linux = the closest thing to Atmosphère-style "mirror system"**: HV
  escape + kexec boots a full Linux from USB/M.2, stock system untouched;
  official window FW 3.00–7.61 (pLinux5-NG claims up to 13.60); soft-mod,
  each Linux boot requires re-running the exploit.
- Daily closest-to-permanent: Rest Mode keeps the exploited kernel in RAM +
  the homescreen autoloader icon.

## 2. Round 1: offset tables + live PUP container analysis

### Cross-firmware offset study (35 firmwares, 7.00–13.60)

Tool `tools/analyze_offsets.mjs` → `reports/offsets_report.md` + JSON.

- The `window.KRW` blocks expose the kernel-exploit primitives: sysctl OID
  corruption (read primitive mib=[9,8]), KASLR bypass, proc/ucred offsets,
  and the rodata probe fingerprint (`_aio_submit_cmd\0_aio_multi_wait`).
- KASLR defeat is the same `rtmsg2` mode across the whole series — never
  fixed at the mechanism level.
- 9.05/11.40 are "candidate" files (no KRW block; a different AIO +
  sched_yield path).
- **Correction (round 2)**: "5 ucred epochs" was an artifact of candidate
  files splitting the run. Truth: ucred/filedesc layouts are **unchanged
  7.00–13.60**; the only evolving field is proc.aioInfo
  3128→3136 (FW 10.00)→3144 (FW 12.00).

### PUP container (live, from Sony's CDN)

Tool `tools/pup_probe.py` → updatelist → PUP URL → ranged header fetch →
SLB2 parse.

- **Latest firmware is 14.10.00.00** (built 2026-09-28, repushed 10-14) —
  beyond the scene's offset tables (13.60): the offset race window is open.
- SLB2 outer container (empirical): 64-byte plaintext header + 32-byte
  entropy blob @0x200 + ciphertext from 0x3E0/0x400;
  block_count×512 == exact file size.
- CDN facts: fus01 serves the updatelist over plain HTTP; PUPs on Akamai
  with Range support; CN region direct via dcn01; **Sony embeds the file's
  SHA-256 in the download URL**.

## 3. PUP decryption architecture ("decrypt on Linux?")

- **zecoxao/ps5-pup-decrypt source verdict**: zero lines of crypto — a pure
  ioctl driver for `/dev/pup_update0` (6 commands, 0xC0104401–0xC0284406);
  keys live in the AMD CCP ("Titania") security processor. Porting to Linux
  = reimplementing that hardware service = requires the keys.
- Headers ship the BLS/PUP formats; byte-for-byte consistent with our 14.10
  live parse (inner PUP magic 0xEEF51454 plaintext; header 0x5B0 / hash
  table 0xDE0).
- **GBAtemp frontier (thread/685380, 2026-10-15)**: Deepkicks' TitaniaPy —
  a PC-side Python tool; layer model L0 solved (PBKDF2-HMAC-SHA256), L3
  solved (static keys), **L1 missing one "forever key"** (universal since
  FW 1.0; extract once = decrypt everything, forever).

## 4. Round 2: frontier tracking + five first-hand verifications + FreeBSD

### Scene breakthrough

- GBAtemp thread/686235 (2026-10-18): Deepkicks announces **successful
  extraction of the EncryptService keys on his own 13.60 console** using the
  V4 payload; will not publish raw key bytes — plans "obfuscated constant +
  prebuilt binaries" in TitaniaPy v2. Single-source claim, tracked with care.

### Independent verification (all first-hand)

1. TitaniaPy's parser output matches ours field-for-field on the 14.10 sample;
2. **Full 14.10 PUP downloaded**: 1,261,408,256 bytes; SHA-256 == the URL-
   embedded hash;
3. L0 derivation reproduced locally: PBKDF2-HMAC-SHA256 output == Titania
   Rev 2 master key, exact;
4. "Key not in public set" independently confirmed: extracted the encrypted
   header, ran bruteforce — all 6 available known keys fail (HIGH_ENTROPY);
5. Whole-file entropy map: uniform ~7.997 bits/byte across 1.17 GB, zero
   low-entropy regions — no structural side channel.

### FreeBSD 12 mapping (`reports/freebsd_mapping.md`)

Sparse-cloned FreeBSD release/12.0.0 `sys/sys` against the offset tables:
ucred first 0x1C byte-identical; 0x58+ Sony's sce* privilege model;
filedesc identical; proc.aioInfo the only evolved field. FreeBSD 12 =
a free pseudo-symbol-table for PS5 kernel RE.

## 5. Round 3: decompilation pipeline + two RE targets

### Pipeline

Official Ghidra 12.1.4 macOS zip **contains no decompiler natives** — used a
source-built 12.1.3 with mac_arm_64 + OpenJDK 21; custom Java headless
scripts (`.py` postScripts need PyGhidra mode). Details:
`reports/re_decomp_report.md`.

### Target 1: ps5_key_extractV4.elf — 200/200 functions

Fidelity-calibrated against the V4 C source (1:1 reconstruction). Mechanism:
`/dev/dmem0` physical mapping; CCP queues at `bar+0x3001000+(q<<12)`;
**Approach 8 = CCP PASSTHROUGH descriptor DMA** — the crypto processor's own
copy engine exfiltrates the key past the private mask (which only blocks
CPU MMIO reads). The release asset (Alpha_V1 tag) is byte-identical to the
repo copy (SHA-256 5b8c58b4…).

### Target 2: elfldr-ps5-v0.26-bb1e117.elf — 379/379 functions

Stripped pure RE: recv-only imports (not the listener); 64-byte-header
framing; kqueue + rfork_thread; finish by exec'ing NPXS40112 (the browser
app) for a clean return to stock UI. Details: `reports/re_decomp_report.md`.

## 6. Round 4: ecosystem tracking

- **Frontier 1 (14.10 WebKit)**: pastawithpesto/PS5-14.10-Jailbreak-Research
  — CVE-2026-64784 (JSC bug 317632, UnlinkedMetadataTable::finalize overflow:
  100KB reserved vs 4.29GB written). Memory corruption confirmed on device
  (p146), **blocked by the 4.29GB sweep**; live leads: FreeType loca-table
  OOB read (device-confirmed, potential ASLR leak), CSSFontFace UAF
  (source-verified), and an "offsetless" runtime-derive loader design.
  Relapse CVEs all patched on 14.10 (explains the 13.60 ceiling).
- **Frontier 2 (Relapse standalone)**: ntfargo/Relapse-Exploit — full chain
  closed: every offset-table field mapped to its mechanism (rtmsg2 leak,
  aio_multi_wait UAF race, flipOidKind decrement flip, sysctl window). See
  the mapping table in §"前沿快报 2" of the Chinese log.
- **Frontier 3 (A53 claim)**: EchoStretch's A53-dump announcement could not
  be fully verified (X-only); the southbridge Cortex-A53 coprocessor and
  cragson/a53-code-exec PoC are real. Tracked.
- **External 1 (community chart)**: confirms HV/Linux window 3.00–7.61,
  UMTX sunset; 13.x marked "private" (lag vs itsPLK's public releases).
  Sweet spot for buying hardware: **FW 5.00–7.61**.
- **External 2 (Vynx JB)**: the modern public-host form of the trust model
  the autoloader exists to eliminate.
- **External 3 (SharpEmu)**: C# PS5 emulator (6.4k stars, very active);
  consumes exactly the kernel-ABI knowledge this research produces.

## 7. Round 5: 13.60 kernel deep dive

Community live RAM dump (terrafirma2021) downloaded, hash-verified, and
analyzed — 25,611 functions recovered, sysctl_oid layout derived
empirically, oid.b caught in a **mid-flip state** (the dump itself was made
with Relapse), the read/write window pinned to `sysctl_handle_int`, and the
kernel stack canary located. Full report:
`reports/kernel_13_60_report.md`.

## Current status / blockers

| Item | Status |
|---|---|
| Offset study / PUP container / entropy / FreeBSD mapping | ✅ done |
| V4 + elfldr + 13.60 kernel decompilation (26k+ functions) | ✅ done |
| PUP content decryption | ⏸ waiting on TitaniaPy v2 |
| 13.60 vs 14.10 kernel diff → new offsets | ⏸ depends on the above |
| Key extraction on hardware | ⏸ needs a ≤13.60 console (sweet spot 5.00–7.61) |
| Permanent CFW (custom bl2) | ⏸ waiting on BootROM digestion |

## Next

1. kexp kernel shellcode (18.9 KB) decompilation — last unanalyzed binary in
   the set;
2. elfldr two-build diff (itsPLK v0.26 vs Relapse build) — isolates the
   itsPLK customization;
3. kernel deep dives: aio function family location, sysent export, static
   sysctl name recovery;
4. when TitaniaPy v2 lands: decrypt 14.10 → raw-import → 25k-function diff →
   extract 14.10 offsets (candidate remote-loader PR);
5. long term: BootROM digestion (custom bootloader / permanent CFW).

## Artifact index

| Path | Content |
|---|---|
| `tools/analyze_offsets.mjs` | cross-firmware offset analyzer |
| `tools/pup_probe.py` | updatelist → PUP → SLB2 header probe |
| `tools/entropy_map.py` | whole-file entropy mapping |
| `tools/ghidra_*.java` | headless decompile/symbols/targets export |
| `reports/offsets_report.md` | 35-firmware analysis (+ .zh.md) |
| `reports/freebsd_mapping.md` | FreeBSD 12 struct mapping (+ .zh.md) |
| `reports/kernel_13_60_report.md` | 13.60 kernel report (+ .zh.md) |
| `reports/re_decomp_report.md` | decompilation report (+ .zh.md) |
| `reports/*.tsv` | function inventories (kernel/V4/elfldr) |
| `docs/PROGRESS.zh.md` | full Chinese research log |
| `docs/WORKSPACE.zh.md` | Chinese workspace notes |

Local-only (not in repo): the full 14.10 PUP, the 13.60 kernel dump,
ranged header samples, and full decompiled pseudocode — all regenerable via
the tools from public sources.

---

*Published as https://github.com/wooluo/ps5-firmware-research (2026-10-19).
Every finding is backed by hashes, byte offsets, or decompiled evidence;
corrections with byte-level proof are welcome via issues.*
