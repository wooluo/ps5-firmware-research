# PS5 Binary Decompilation Report (Ghidra headless, full export)

Produced 2026-10-19. Toolchain: Ghidra 12.1.3 with mac_arm_64 natives +
OpenJDK 21 + custom export scripts (`tools/ghidra_dump_decomp.java`,
`tools/ghidra_symbols_only.java`, `tools/ghidra_decompile_targets.java`).
([中文版](re_decomp_report.zh.md))

## Pipeline notes

- **Official Ghidra macOS zips ship no decompiler natives at all**
  (linux/win_x86_64 only) — on Apple Silicon you need a source-built
  distribution with `mac_arm_64` natives.
- Ghidra 12 `.py` postScripts require PyGhidra mode; plain **Java scripts**
  work headless with zero dependencies.
- Reproduce: `JAVA_HOME=<jdk21> <ghidra>/support/analyzeHeadless <proj> ps5re
  -import <elf> -scriptPath tools -postScript ghidra_dump_decomp.java
  -deleteProject`

## Target 1: ps5_key_extractV4.elf (key-extraction payload) — 200/200 functions

Symbol-bearing ELF, with the V4 C source in the same repo → **decompiler
fidelity calibration**: the dispatch logic (no args = approaches 1/2/3/4/6/7
full scan, `-p` = approach 8, oracle = approach 9), function names, and
summary output were all reconstructed 1:1. The pipeline output is trustworthy
for semantic analysis.

Mechanism (source × decompilation cross-confirmed):
- Physical memory access: `open("/dev/dmem0")` (fallback /dev/mem), mmap
  MAP_SHARED MMIO of the CCP queue registers;
- CCP queue addressing: `bar + 0x3001000 + (queue_id << 12)`, 5 queues;
- **Approach 8 (CCP PASSTHROUGH) — the key-exfiltration core**: build a
  32-byte ccp5 descriptor (engine=PASSTHROUGH(5), src=SB slot MEMTYPE_SB,
  dst=system memory), write it into the queue ring at the current tail, bump
  the TAIL register to submit, poll HEAD, read the key from the output page —
  **using the crypto processor's own copy engine to DMA the key out**;
- Key insight: the private mask only blocks direct CPU MMIO reads of SB
  slots, not copies performed by CCP-internal engines.

## Target 2: elfldr-ps5-v0.26-bb1e117.elf (itsPLK custom loader) — 379/379

Stripped, pure RE. Function inventory:
[elfldr_symbols.tsv](elfldr_symbols.tsv). Core findings:

1. **It is not the listener**: the dynamic import table contains only `recv`
   (no socket/bind/listen/accept). Listening happens exploit-side — raw
   syscalls under ROP inside the WebKit process, bound to 127.0.0.1:9021
   (cross-confirmed by the pure-syscall style of remote-loader's
   autoload.js/elfldr-check.js). The "localhost-only" security is exactly
   that loopback bind.
2. Receive protocol: fixed 64-byte header (recv with MSG_DONTWAIT) +
   variable-length body framing, realloc-grown buffer.
3. Event model: `rfork_thread` workers + `kqueue`/`kevent` loop + `waitpid`
   — orthodox BSD style rather than pthreads.
4. Graceful finish: on completion it `execve`s
   `/system/vsh/app/NPXS40112/eboot.bin` — **restarting the User's
   Guide/browser app so the console returns cleanly to stock UI**; debug
   output via /dev/deci_stdout and /dev/deci_stderr.
5. A "kernel_overlap_sockets" string hints the socket fd hand-off from the
   exploit session uses a kernel-side overlap trick.

## Status

The decompilation pipeline is proven (fidelity-calibrated on a binary with
known source). Ready to consume future targets — starting with the 18.9 KB
kexp kernel shellcode from Relapse-Exploit and the two elfldr builds
(itsPLK v0.26 vs Relapse's, differing by ~2.5 KB — a diff isolates the
itsPLK customization).
