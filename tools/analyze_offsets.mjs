#!/usr/bin/env node
// PS5 remote-loader offset tables: cross-firmware analysis器
// 用法: node analyze_offsets.mjs <remote-loader-checkout> <输出目录>
// 直接 eval 各固件的 offsets/*.js（window 垫片），拿到 KRW/SYMBOLS/常量后做横向对比。

import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join, basename } from 'node:path';

const [root, outDir] = process.argv.slice(2);
if (!root || !outDir) {
  console.error('usage: node analyze_offsets.mjs <remote-loader-dir> <out-dir>');
  process.exit(1);
}

const offsetsDir = join(root, 'offsets');

// 这些顶层 const 名在 35 个文件里都出现（个别固件缺失的用 typeof 兜底）
const CONST_NAMES = [
  'OFFSET_KERNEL_ALLPROC', 'OFFSET_KERNEL_SECURITY_FLAGS', 'OFFSET_KERNEL_ROOTVNODE',
  'OFFSET_KERNEL_DATA', 'OFFSET_KERNEL_EVF_STR',
  'OFFSET_lk_pthread_create_name_np', 'OFFSET_lk_sceKernelGetCurrentCpu',
  'OFFSET_wk_host_constructor_candidates', 'OFFSET_WORKER_STACK_OFFSET',
];

function parseFw(file) {
  const src = readFileSync(file, 'utf8');
  const getter = new Function('window', `
    ${src};
    const out = { KRW: window.KRW || null, SYMBOLS: window.SYMBOLS || null, consts: {} };
    ${CONST_NAMES.map(n => `try { out.consts[${JSON.stringify(n)}] = ${n}; } catch (e) {}`).join('\n')}
    return out;
  `);
  const window = {};
  const parsed = getter(window);
  const fw = basename(file, '.js');
  parsed.fw = fw;

  // syscall/gadget 数量：全局正则（13.00 等文件是压缩多列格式，行锚定会漏计）
  parsed.syscallCount = (src.match(/(?:^|[,{\s])(0x[0-9A-Fa-f]+)\s*:/g) || []).length;
  parsed.gadgetCount = (src.match(/"[^"]+"\s*:\s*0x/g) || []).length;
  parsed.isCandidate = /^\/\/ .*candidate/im.test(src);
  return parsed;
}

function fwKey(fw) { // 版本排序键: "13.60" -> 13.60
  return parseFloat(fw);
}

const files = readdirSync(offsetsDir).filter(f => f.endsWith('.js')).sort((a, b) => fwKey(a) - fwKey(b));
const rows = files.map(f => parseFw(join(offsetsDir, f)));

// ── 1. 主表：每固件关键kernel addrs ────────────────────────────────
let md = `# PS5 remote-loader offset tables: cross-firmware analysis\n\nSource: ${offsetsDir} (${rows.length} firmware versions)\nGenerated: ${new Date().toISOString()}\n\n`;

md += `## 1. Key kernel addresses\n\n| FW | kernelData | allproc | rootvnode | securityFlags | KASLR mode | rodata probe |\n|---|---|---|---|---|---|---|\n`;
for (const r of rows) {
  const k = r.KRW || {};
  md += `| ${r.fw} | ${hex(k.kernelData)} | ${hex(k.allproc)} | ${hex(k.rootvnode)} | ${hex(r.consts.OFFSET_KERNEL_SECURITY_FLAGS)} | ${k.kaslr?.mode || '?'} | ${(k.rodataProbe?.text || '').replace(/\0.*$/, '').slice(0, 24) || '?'} |\n`;
}

// ── 2. 相邻固件 diff：哪些字段动了 ────────────────────────────
md += `\n## 2. Adjacent-firmware change matrix\n\nWhich offset categories changed between adjacent firmware pairs (indicators of Sony recompiles/hardening):\n\n| pair | kernel addrs | KASLR | proc layout | ucred layout | libkernel syms | libc syms | ROP gadgets | sysctl oids |\n|---|---|---|---|---|---|---|---|---|\n`;
for (let i = 1; i < rows.length; i++) {
  const a = rows[i - 1], b = rows[i];
  const ka = a.KRW || {}, kb = b.KRW || {};
  const kernelAddr = ['kernelData', 'allproc', 'rootvnode'].some(k => ka[k] !== kb[k]);
  const kaslr = JSON.stringify(ka.kaslr) !== JSON.stringify(kb.kaslr);
  const proc = JSON.stringify(ka.proc) !== JSON.stringify(kb.proc);
  const ucred = JSON.stringify(ka.ucred) !== JSON.stringify(kb.ucred);
  const lkSym = JSON.stringify(a.SYMBOLS?.libkernel) !== JSON.stringify(b.SYMBOLS?.libkernel);
  const lcSym = JSON.stringify(a.SYMBOLS?.libc) !== JSON.stringify(b.SYMBOLS?.libc);
  const gadgets = a.gadgetCount !== b.gadgetCount;
  const oid = JSON.stringify(ka.oid) !== JSON.stringify(kb.oid);
  md += `| ${a.fw}→${b.fw} | ${mark(kernelAddr)} | ${mark(kaslr)} | ${mark(proc)} | ${mark(ucred)} | ${mark(lkSym)} | ${mark(lcSym)} | ${mark(gadgets)} | ${mark(oid)} |\n`;
}

// ── 3. 结构体布局纪元（Sony 何时改了内核结构） ─────────────────
function epochs(pick) {
  // candidate 文件(9.05/11.40)无 KRW 块,会以 null 切断连续段造成"假纪元"。
  // 纪元分组只统计有 KRW 的固件,candidate 单独标注。
  const groups = [];
  for (const r of rows) {
    if (r.isCandidate) continue;
    const v = JSON.stringify(pick(r.KRW || {}));
    if (groups.length && groups[groups.length - 1].v === v) groups[groups.length - 1].fws.push(r.fw);
    else groups.push({ v, fws: [r.fw] });
  }
  return groups;
}
md += `\n## 3. Kernel struct layout epochs\n\n布局相同的连续固件归为同一纪元（candidate 文件 9.05/11.40 无 KRW 块，不参与分组）:\n\n`;
for (const [name, pick] of [['proc (进程结构)', k => k.proc], ['ucred (凭证结构)', k => k.ucred], ['filedesc (文件描述符)', k => k.filedesc], ['dynlib (动态库限制)', k => k.dynlib], ['sysCoreAuthId', k => k.sysCoreAuthId]]) {
  const es = epochs(pick);
  md += `**${name}** — ${es.length} epochs: ${es.map(e => e.fws.length > 2 ? `${e.fws[0]}–${e.fws[e.fws.length - 1]}` : e.fws.join(',')).join(' | ')}\n\n`;
}

// ── 4. KASLR bypass evolution ─────────────────────────────────────
md += `## 4. KASLR bypass evolution\n\n| FW | mode | retStatic |\n|---|---|---|\n`;
for (const r of rows) md += `| ${r.fw} | ${r.KRW?.kaslr?.mode || '?'} | ${hex(r.KRW?.kaslr?.retStatic)} |\n`;

// ── 5. 特权提升目标（提权语义速查） ──────────────────────────
const sample = rows.find(r => r.fw === '13.60') || rows[rows.length - 1];
md += `\n## 5. Privilege-escalation targets (${sample.fw}, for example)\n\n\`\`\`json\n`;
md += JSON.stringify({ sysCoreAuthId: sample.KRW.sysCoreAuthId, ucred: sample.KRW.ucred, securityFlagsRelated: { securityFlags: sample.consts.OFFSET_KERNEL_SECURITY_FLAGS, targetId: 'securityFlags+0x09', qaFlags: 'securityFlags+0x24', utokenFlags: 'securityFlags+0x8C' } }, null, 2);
md += `\n\`\`\`\n`;

// ── 6. sysctl OID 腐化原语（内核读写怎么来的） ───────────────
md += `\n## 6. sysctl OID corruption primitive config\n\nPoops/slopkit : the kernel R/W primitive = corrupting sysctl tree OID nodes. Per-firmware node config:\n\n| FW | oid.a | oid.b | oid.c | walkCounter | aio\n|---|---|---|---|---|---|\n`;
for (const r of rows) {
  const o = r.KRW?.oid || {};
  md += `| ${r.fw} | ${o.a ? '√' : '—'} | ${o.b ? '√' : '—'} | ${o.c ? `mib=${JSON.stringify(o.c.mib)}` : '—'} | ${r.KRW?.walkCounter ? `mib=${JSON.stringify(r.KRW.walkCounter.mib)}` : '—'} | ${r.KRW?.aio ? '√' : '—'} |\n`;
}

// ── 7. syscall 覆盖面 ────────────────────────────────────────
md += `\n## 7. Attack-surface coverage\n\nPre-located syscall wrappers and ROP gadgets per firmware:\n\n| FW | syscalls | gadgets |\n|---|---|---|\n`;
for (const r of rows) md += `| ${r.fw} | ${r.syscallCount} | ${r.gadgetCount} |\n`;

// Machine-readable JSON
writeFileSync(join(outDir, 'offsets_analysis.json'), JSON.stringify(rows.map(r => ({
  fw: r.fw, KRW: r.KRW, SYMBOLS: r.SYMBOLS, consts: r.consts,
  syscallCount: r.syscallCount, gadgetCount: r.gadgetCount,
})), null, 2));
writeFileSync(join(outDir, 'offsets_report.md'), md);
console.log(`parsed ${rows.length} firmwares -> ${join(outDir, 'offsets_report.md')} + offsets_analysis.json`);

function hex(v) { return v === undefined || v === null ? '?' : '0x' + v.toString(16); }
function mark(b) { return b ? '**Δ**' : '·'; }
