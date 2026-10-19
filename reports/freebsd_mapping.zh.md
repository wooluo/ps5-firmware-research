# PS5 内核结构 × FreeBSD 12.0 对照

数据源: remote-loader offset 表 (35 固件) × FreeBSD release/12.0.0 sys/sys 头文件
(本地 /tmp/fbsd, 稀疏克隆)。生成: 2026-10-19。

## ucred (凭证结构) — 前 0x1C 字节与 FreeBSD 12.0 完全一致

FreeBSD 12.0 定义 (sys/ucred.h), 前 7 个字段全是 u32/int 连续排布、
无对齐歧义, 可静态精确推导:

| 偏移 | FreeBSD 12.0 | PS5 (offset 表) | 判定 |
|---|---|---|---|
| 0x00 | cr_ref (u_int) | — | 一致(exploit 不引用) |
| 0x04 | cr_uid (uid_t) | uid | **一致** |
| 0x08 | cr_ruid | ruid | **一致** |
| 0x0c | cr_svuid | svuid | **一致** |
| 0x10 | cr_ngroups (int) | ngroups | **一致** |
| 0x14 | cr_rgid | rgid | **一致** |
| 0x18 | cr_svgid | svgid | **一致** |
| 0x1c–0x54 | cr_uidinfo/cr_ruidinfo/cr_prison/cr_loginclass/cr_flags... | (未引用) | Sony 改造区 |
| 0x58 | cr_label (MAC 标签指针) | **sceAuthId** | **Sony 替换: MAC → SceAuthId** |
| 0x60 | (cr_audit 区) | **sceCaps** | Sony 能力位 |
| 0x68 | | **sceCaps1** | Sony 能力位 |
| 0x80 | (cr_groups 区) | **sceAttrs** | Sony 属性 |

解读: Sony 保留了 FreeBSD 的 POSIX 凭证头部, 把 MAC/jail/audit 机制
替换为自有权限模型。HEN 提权 = 向 sceAuthId 写 sysCoreAuthId
(lo=7, hi=0x48000000) 并操纵 sceCaps/sceAttrs。

**该布局 7.00–13.60 全部 33 个主链固件零变化**——六年从未改动,
HEN 提权目标只有绝对地址在变。

## filedesc (文件描述符) — 与 FreeBSD 12.0 逐字节一致

| 偏移 | FreeBSD 12.0 | PS5 | 判定 |
|---|---|---|---|
| 0x00 | fd_files (fdescenttbl*) | files | **一致** |
| 0x08 | fd_cdir (vnode*) | cdir | **一致** |
| 0x10 | fd_rdir | rdir | **一致** |
| 0x18 | fd_jdir | jdir | **一致** |

## proc (进程结构) — 头部相邻关系一致, 尾部 Sony 特有

- FreeBSD 12.0 字段序: p_list → p_threads → p_slock → **p_ucred → p_fd** (相邻)。
- PS5: ucred@0x40, fd@0x48 相邻, 与上游排布相容 (p_list 0x10 + p_threads 0x10
  + p_slock ≈0x20 → p_ucred@0x40; 未编译验证, 以相邻关系为准)。
- Sony 特有字段: pid@0xBC, dynlib@0x3E8 (SceDynlib), aioInfo@0xC38+。
- **proc 是唯一演变的结构**: aioInfo 3128 (7.00–9.60) → 3136 (10.00–11.60)
  → 3144 (12.00–13.60), 即 10.00 和 12.00 两次在 AIO 区前插入 8 字节
  (每次一个指针/双字字段)。

## 方法论意义

1. FreeBSD 12 开源代码可直接充当 PS5 内核逆向的"伪符号表":
   ucred/filedesc 的字段语义、排布规则免费获得, 攻击面分析只需
   关注 Sony 增量 (sce* 字段、dynlib、aioInfo)。
2. 结构稳定 = exploit 适配成本极低: 六年只有地址 ASLR 在变,
   ucred 提权语义从未需要重写。这也解释了 remote-loader 能以
   极小代价把 35 个固件全部覆盖。
3. 修正: 本报告早期版本曾报告"ucred 5 个纪元", 系 candidate 文件
   (9.05/11.40 无 KRW 块) 切断连续段造成的假象, 已修正分析器。
