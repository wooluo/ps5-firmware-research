# PS5 Kernel Structures × FreeBSD 12.0 Mapping

Data sources: remote-loader offset tables (35 firmwares) × FreeBSD release/12.0.0
`sys/sys` headers. Generated 2026-10-19. ([中文版](freebsd_mapping.zh.md))

## ucred (credentials) — first 0x1C bytes byte-identical to FreeBSD 12.0

FreeBSD 12.0 definition (`sys/ucred.h`). The first seven fields are consecutive
u32/int with no alignment ambiguity, so their offsets are statically provable:

| Offset | FreeBSD 12.0 | PS5 (offset tables) | Verdict |
|---|---|---|---|
| 0x00 | cr_ref (u_int) | — | identical (not referenced by exploits) |
| 0x04 | cr_uid (uid_t) | uid | **identical** |
| 0x08 | cr_ruid | ruid | **identical** |
| 0x0c | cr_svuid | svuid | **identical** |
| 0x10 | cr_ngroups (int) | ngroups | **identical** |
| 0x14 | cr_rgid | rgid | **identical** |
| 0x18 | cr_svgid | svgid | **identical** |
| 0x1c–0x54 | cr_uidinfo / cr_ruidinfo / cr_prison / cr_loginclass / cr_flags... | (unreferenced) | Sony-modified region |
| 0x58 | cr_label (MAC label ptr) | **sceAuthId** | **Sony replaced MAC → SceAuthId** |
| 0x60 | (cr_audit region) | **sceCaps** | Sony capability bits |
| 0x68 | | **sceCaps1** | Sony capability bits |
| 0x80 | (cr_groups region) | **sceAttrs** | Sony attributes |

Interpretation: Sony kept the FreeBSD POSIX credential header and swapped the
MAC/jail/audit machinery for their own privilege model. HEN privilege
escalation = writing `sysCoreAuthId` (lo=7, hi=0x48000000) into sceAuthId and
manipulating sceCaps/sceAttrs.

**This layout is unchanged across all 33 main-chain firmwares 7.00–13.60** —
six years without a single structural change; only absolute addresses moved.

## filedesc (file descriptors) — byte-identical to FreeBSD 12.0

| Offset | FreeBSD 12.0 | PS5 | Verdict |
|---|---|---|---|
| 0x00 | fd_files (fdescenttbl*) | files | **identical** |
| 0x08 | fd_cdir (vnode*) | cdir | **identical** |
| 0x10 | fd_rdir | rdir | **identical** |
| 0x18 | fd_jdir | jdir | **identical** |

## proc (process) — adjacency preserved, tail is Sony-specific

- FreeBSD 12.0 field order: p_list → p_threads → p_slock → **p_ucred → p_fd**
  (adjacent). PS5 has ucred@0x40, fd@0x48 adjacent — compatible with the
  upstream arrangement (p_list 0x10 + p_threads 0x10 + p_slock ≈0x20 →
  p_ucred@0x40; adjacency is the load-bearing observation, exact value not
  compile-verified).
- Sony-only fields: pid@0xBC, dynlib@0x3E8 (SceDynlib), aioInfo@0xC38+.
- **proc is the only structure that ever evolved**: aioInfo 3128 (7.00–9.60)
  → 3136 (10.00–11.60) → 3144 (12.00–13.60) — two 8-byte insertions ahead of
  the AIO region (one pointer-sized field each, at FW 10.00 and 12.00).

## Why this matters

1. FreeBSD 12 open source works as a **pseudo-symbol-table** for PS5 kernel
   RE: ucred/filedesc semantics come for free; only the Sony delta
   (sce* fields, dynlib, aioInfo) needs fresh analysis.
2. Structural stability = trivial exploit porting: for six years only ASLR
   addresses changed; the ucred privilege-escalation semantics never needed
   rewriting. This is why remote-loader covers 35 firmwares at near-zero
   marginal cost.
3. Correction note: an earlier version of this study reported "5 ucred
   epochs"; that was an artifact of candidate files (9.05/11.40 have no KRW
   block) splitting the run. The analyzer was fixed and the report
   regenerated.
