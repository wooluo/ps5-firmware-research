# PS5 13.60 内核活体 dump 分析报告

对象: out/kernel-13.60-live.bin(103,546,880B, terrafirma2021 2026-10-13 活体捕获,
SHA-256 c3f745e2…cddd 官方互验通过)。生成: 2026-10-19。

## 布局

- text @ VA 0xffffffff9e3f0000(rva 0–0xCC0000, 13.4MB)
- data @ VA 0xffffffff9f0b0000(rva 0xCC0000 起, 90MB); file offset == rva(平坦)
- 688 个未捕获页零填充(约 2.7MB); 内核堆(0xffff8e77…/0xffffffffa0cb…)不在 dump 内

## 四重交叉验证(offset 表 ↔ dump ↔ Relapse 源码 ↔ FreeBSD)

| 验证项 | 结果 |
|---|---|
| data rva 0xCC0000 = offset 表 kernelData(13.60) | ✓ 精确 |
| rodata 探针 _aio_submit_cmd\0_aio_multi_wait = 预测 rva 0x1379d6c | ✓ 精确 |
| kaslr retStatic 0xAE2DA0 | ✓ 结构自洽(call 后返回地址, 低16=0x2DA0=retLow16) |
| oid.a.kind @0x028cef7c = originalKind 0x80048002 | ✓ 精确 |

## 法医发现: dump 是 Relapse 链打出来的

- **oid.b.kind = 0x7f048002**(非原始 0x80048002)——flipOidKind 的翻转路径
  是逐 cancel 减 1(0x80→0x7f→…→0x70), dump 抓拍到了中间态;
  dumper 自己跑了内核利用, 且 oid.b 未完全恢复。
- sysctl_oid 结构布局(自 oid.a 节点实证):
  `next@0x00, oid_name@0x08, oid_number@0x10, oid_kind@0x14, oid_arg1@0x18,
  oid_arg2@0x20, desc@0x28?, oid_handler@0x30`
- oid.a: 动态编号 0x7FFFFCB8(SYSCTL_ADD 运行时创建), **handler=0xffffffff9e6609e8
  (rva 0x2709E8)**; 名字指针落在一个未捕获页(零填充)故不可读
- oid.c: 静态节点 oid_number=8(= mib[9,8] 的第二项, 与 offset 表一致),
  arg1Value=200112
- walkCounter.arg1Value=0(捕获时已复位)
- allproc 头指针/rootvnode 指向内核堆(0xffff8e77…), 不在 dump 内,
  进程表遍历不可行(仅镜像区捕获)

## 符号表恢复尝试(负结果)

- 无 Elf64_Sym 长序列(最长 24), 无 ddb 名字-地址对长序列(最长 59)
  → Sony 剥离了符号表, 活体内存中亦无重建
- rva 16–20MB 有 2.3 万 C 标识符(dtrace 探针/sysinit 名单类), 无配套地址表

## Ghidra 流水线结果

- **25,611 个函数**从 text 段恢复（raw binary @ gcc cspec, 2 分钟级；
  首跑 0 函数是因为没开侵略性分析器/cspec 差异，复跑成功）。
  清单归档 `out/re/kernel-13.60-text_symbols.tsv`。
- 最大函数 40KB（0xffffffff9f059c40）、19KB 级数个——VM/驱动体量。
- **oid.a handler 定点反编译**（tools/ghidra_decompile_targets.java）:
  handler=0xffffffff9e6609e8 是 5 字节 thunk → 真身 0xffffffff9e947540 =
  **sysctl_handle_int**(标准 int 处理器): SYSCTL_OUT 写 4B + oid_arg1 非空时
  SYSCTL_IN 收 4B, 外加内核态 stack canary(守卫值 @0xffffffffa1d0c310,
  失败例程 0xffffffff9eaed6b0)。exploit 的"读写窗口"= 把这种节点的
  oid_arg1 腐蚀成任意内核地址后按 int 读写, 与 Relapse 源码
  sysctlReadInt/WriteInt/aimWindow 逐条对应。
- 产物: `out/re/kernel-13.60-text_targets.c`(oid handler + top5 大函数伪代码)。

## 结论

13.60 内核的函数级地图已建立。未来 14.10 内核镜像到手后:
同法 raw 导入 → 25k 级函数清单 → 与本表按体量/调用结构对齐 diff →
新 offset 提取不再依赖手工。

## 下一步

1. 以本方法处理未来 14.10 内核镜像 → 同法函数清单 → 三方 diff
   (13.60 dump ↔ 14.10 镜像 ↔ FreeBSD 12 源码)
2. 反汇编 oid handler(rva 0x2709E8)确认读写窗口的 sysctl 处理函数类型
3. rodata 探针 xref 定位 _aio_submit_cmd/aio_multi_wait 函数体(在 text 内,
   需要导入含 rodata 的完整镜像或以探针地址手工定位)
