# PS5 固件逆向研究 · 全程进度记录

> 工作台: `~/DEV/ps5-fw-research/` ｜ 起始: 2026-10-19 ｜ 记录: ZCode
> 主线索: 从 ps5-webkit-autoloader 出发 → 固件更新逆向 → PUP 解密架构 → 密钥提取前沿 → 反编译流水线
> 本文档是全程时间线与结论汇总; 细节见各专题报告(文末索引)。

---

## 0. 起点: ps5-webkit-autoloader 分析

**仓库**: `~/DEV/ps5-webkit-autoloader`(itsPLK, v0.6.1, GPL-3.0, 子模块已初始化, `make test` 全绿)

- 定位: PS5 WebKit 漏洞利用"离线化"——AppCache 缓存 exploit 页面 + 主屏快捷方式(WKAL00001),
  装完后完全离线, 摆脱第三方 DNS 服务器依赖。FW 7.00–13.60, 双链 Poops/Relapse。
- 核心机制:
  - 原生 C 安装器 ELF(libmicrohttpd, 仅绑 127.0.0.1:18181): 先杀旧实例(sysctl
    KERN_PROC_ALL 扫 ki_tdname@447) → 起 HTTP → 拉起浏览器 → 缓存完成才装快捷方式;
  - **manifest 属性门控**: 未选 exploit 前服务器把 HTML 里 `manifest="/cache.appcache"`
    原位替换成等长空格, 阻止 AppCache 提前启动(AppCache 见属性即启动, JS 拦不住);
  - 双 localStorage 键两阶段提交(wkal_pending/wkal_exploit), 失败安装不污染旧版;
  - payload 三段队列: elfldr-check.js(探测 9021 防重跑内核利用) → poops/relapse.js →
    autoload.js(mmap 暂存 ELF → socket 送 elfldr)。
- 架构分层: 本仓库是壳, exploit runner/ROP/offset 表/PC host 全在
  third_party/ps5-webkit-remote-loader 子模块, 单向依赖。

## 1. 场景格局调研(固化/CFW/镜像系统问题)

- **真固化不存在**: PS5 安全链(boot ROM→SE→bl2/3→HV→kernel)底层未被公开攻破;
  内置 SSD per-console 密钥加密+防回滚 → emuNAND 不可行。对照: PS3 靠 lv0 密钥泄漏
  刷改固件, Switch 靠 Fusée Gelée boot ROM 漏洞每次注入。
- **2025-12-31 BootROM 密钥泄漏**(对称解密密钥, 非签名私钥, 不可补丁, ~9500 万台):
  理论通向自定义引导链→永久 CFW, 截至 2026-10 无公开成品, 实际效果是加速 offset
  逆向(exploit 已覆盖 13.60)。
- **ps5-linux = 最接近大气层的镜像系统**: HV 漏洞逃逸 + kexec, 从 USB/M.2 启动完整
  Linux, 原系统零改动; 官方 FW 窗口 3.00–7.61(pLinux5-NG 称至 13.60); soft-mod,
  每次进 Linux 需先跑 exploit。
- 日常最接近固化: Rest Mode 保活 + autoloader 主屏图标。

## 2. 第一轮: offset 表逆向 + PUP 容器实证

### offset 表跨固件分析(35 固件, 7.00–13.60)

工具 `tools/analyze_offsets.mjs` → `out/offsets_report.md` + `offsets_analysis.json`。

- `window.KRW` 块暴露内核利用核心原语: sysctl OID 节点腐蚀(读原语 mib=[9,8])、
  KASLR 绕过、proc/ucred 结构偏移、rodata 探针指纹(`_aio_submit_cmd\0_aio_multi_wait`)。
- KASLR 全系列统一 `rtmsg2` 模式, 从未被根治(只靠重编译挪地址)。
- 9.05/11.40 为 candidate 格式文件(无 KRW 块, 走 AIO+sched_yield 另一条路)。
- **重要修正**(第二轮): "ucred 5 纪元"系 candidate 文件切断连续段的假象; 真相:
  ucred/filedesc 布局 7.00–13.60 **六年零变化**, 唯一演变是 proc.aioInfo
  3128→3136(FW 10.00)→3144(FW 12.00)。

### PUP 容器实证(真机固件在线分析)

工具 `tools/pup_probe.py` → updatelist → PUP URL → Range 取头部 → SLB2 解析。

- **最新固件是 14.10.00.00**(2026_0928 构建, 10-14 重推)——remote-loader offset 表
  止于 13.60, 社区正处抢 14.10 offset 的窗口期。
- SLB2 外层容器(实证): 64B 明文头 + 0x200 处 32B 熵块 + 0x3E0/0x400 起全密文。
  block_count×512=文件大小(精确)。
- CDN 知识: fus01 明文 HTTP 发 updatelist; PUP 在 Akamai 支持 Range;
  cn 区域走 dcn01 节点国内直连可用; **索尼把 SHA-256 编进下载 URL**(天然防篡改)。

## 3. PUP 解密架构研究("Linux 上解密"问题)

- **zecoxao/ps5-pup-decrypt 源码结论**(克隆于 /tmp/ps5-pup-decrypt):
  程序本体 0 行密码学, 纯 ioctl 驱动 `/dev/pup_update0`(6 条命令
  0xC0104401~0xC0284406), 密钥全在 AMD CCP/Titania 安全处理器硬件槽。
  "移植到 Linux" = 重实现背后的硬件加密服务 = 需要密钥。
- 头文件自带 BLS/PUP 格式定义, 与 14.10 实证逐字节吻合; 内层 PUP 魔数
  0xEEF51454 明文可见, 头部 0x5B0/哈希表 0xDE0。
- **GBAtemp 前沿**(thread/685380, 2026-10-15): Deepkicks 发布 TitaniaPy(PC 端
  Python 工具), 四层模型 L0 已解(PBKDF2-HMAC-SHA256)/L3 已解(静态密钥)/
  L1 差一把"永久钥匙"(全机通用, FW1.0 至今不变, 提取一次永久解密所有固件)。

## 4. 第二轮: 前沿跟踪 + 五项一手验证 + FreeBSD 对照

### 场景突破

- GBAtemp 新帖 thread/686235(2026-10-18): Deepkicks 宣布**用 V4 提取 payload 在
  自己 13.60 主机上成功提取 EncryptService 密钥**; 不公开原始字节, 以"混淆常量+
  预编译二进制"发 TitaniaPy v0.2(号称 2026-10 那个周末); 单源声明, 审慎跟踪。

### 独立验证(全部一手)

1. TitaniaPy info 输出与本工作台解析器逐字段吻合;
2. **完整 14.10 PUP 下载**: 1,261,408,256B, SHA-256 与 URL 内嵌哈希一致;
3. L0 推导本机复现: PBKDF2-HMAC-SHA256 输出=Titania Rev 2 主密钥(精确匹配);
4. "密钥不在公开集"独立验证: 自提加密头跑 bruteforce, 6 把已知密钥全败;
5. 全文件熵测绘(`tools/entropy_map.py`): 1.17GB 全程 ~7.997, 零低熵区,
   无结构侧信道泄露。

### FreeBSD 12 对照(`out/freebsd_mapping.md`)

稀疏克隆 FreeBSD release/12.0.0 sys/sys 对照 offset 表:

- **ucred 前 0x1C 与 FreeBSD 12.0 逐字节一致**(cr_ref..cr_svgid 连续 u32 静态可证);
  0x58 起 Sony 以 sceAuthId/sceCaps/sceAttrs 替换 MAC/jail/audit——HEN 提权目标区;
- **filedesc 前 4 字段逐字节一致**;
- proc: p_ucred/p_fd 相邻关系一致, aioInfo 唯一演变字段;
- 意义: FreeBSD 12 源码 = PS5 内核逆向的"伪符号表"; 结构六年稳定解释了
  remote-loader 能低成本覆盖 35 个固件。

## 5. 第三轮: 反编译流水线与两个目标的 RE

### 流水线

- Ghidra 官方 12.1.4 zip **不含 mac 反编译器原生件**(仅 linux/win_x86_64)——
  Apple Silicon 官方包无法反编译;
- 改用用户自带 `~/tools/ghidra_12.1.3_PUBLIC`(源码构建, 含 mac_arm_64 natives)
  + openjdk@21(`JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home`);
- 自研 headless 导出脚本 `tools/ghidra_dump_decomp.java`(Java, 零 Python 依赖;
  12.x 的 .py postScript 需 PyGhidra 模式)。

### 目标 1: ps5_key_extractV4.elf(密钥提取 payload) — 200/200 函数

- 带符号 + 同仓库 V4 C 源码 → **保真度校准通过**(dispatch/方案命名/摘要流 1:1 重建);
- 机制: `/dev/dmem0` 物理内存映射; CCP 队列寻址 `bar+0x3001000+(q<<12)`;
- **方案 8 (CCP PASSTHROUGH) = 密钥外提核心**: 32B 描述符(engine=5, src=SB 槽,
  dst=系统内存)写入队列环, 推 TAIL 提交, 轮询 HEAD, 输出页读密钥——
  用密码处理器自己的拷贝引擎绕过私钥掩码(掩码只挡 CPU MMIO 读);
- release 资产(Alpha_V1)与仓库副本哈希相同(5b8c58b4…c910), 即同一文件。

### 目标 2: elfldr-ps5-v0.26-bb1e117.elf(itsPLK 定制 loader) — 379/379 函数

stripped 纯 RE, 核心发现:

1. **它不是监听者**: 动态导入表仅 `recv`(无 socket/bind/listen/accept)。
   监听在 exploit 侧(WebKit 进程 ROP 原始 syscall 绑 127.0.0.1:9021),
   "仅本机"由绑定 loopback 实现; 与 remote-loader 的 autoload.js/elfldr-check.js
   纯 syscall 写法互证;
2. 接收协议: 64B 定长头(recv MSG_DONTWAIT)+变长体分帧, realloc 增长;
3. 事件模型: rfork_thread + kqueue/kevent + waitpid(正统 BSD 风格);
4. 收尾: `execve("/system/vsh/app/NPXS40112/eboot.bin")`——重启浏览器应用,
   主机无痕恢复正常 UI; 调试走 /dev/deci_stdout、/dev/deci_stderr;
5. "kernel_overlap_sockets"字符串: socket fd 经内核侧 overlap 技巧与
   exploit 会话交接。

## 当前状态与阻塞点

### 前沿快报 2: Relapse-Exploit 独立发行版全链路闭环(2026-10-19)

仓库 github.com/ntfargo/Relapse-Exploit(Relapse 联合作者 ntfargo 的独立发行版,
2389 星, 2026-09-17 建, 本地 /tmp/Relapse-Exploit)。**完整 JS 源码 + offsets +
kexp 内核 shellcode + elfldr 构建**, README 首次公开利用链描述。

**offset 表全字段语义闭环**(三轮研究的谜团全部解开):

| offset 表字段 | exploit 源码对应机制 |
|---|---|
| kaslr mode "rtmsg2" | leakKernelBase(): sockaddr 长度对齐算术泄露内核基址 |
| aio{waiterSize 0x38, requestSize 0x28} | aio_multi_wait UAF race 的堆结构 |
| oid.a/b/c + originalKind/writableKind | flipOidKind(): 逐个 cancel waiter 把 sysctl OID kind 从 0x80048002"翻"到可写 0x70048002(含防过冲检查), oid a/c = 内核读写窗口的低/高 32 位 |
| walkCounter mib=[9,7] | 翻转进度计数器 |
| rodataProbe "_aio_submit_cmd\0_aio_multi_wait" | 内核态 aio 函数定位器 |
| allproc/proc.ucred/sceAuthId 等 | 遍历进程链→定位凭证→提权 |

**六步利用链**: WebKit(structured clone 对象池不匹配→typedarray 腐化→userland R/W+ROP) → rtmsg2 泄露内核基址 → AIO 停车场(openSocketPair/submitBlockedRead/parkAioWorkers) → 堆 churn 回收 waiter 数组(UAF) → flipOidKind 建 sysctl 读写窗口(慢速内核 R/W) → allproc 遍历+ucred 提权(kexp shellcode: 18.9KB 内核态代码, 按固件 patch 符号)。

其他: offsets 与 remote-loader 逐字节同源(diff 空); payloads/elfldr-ps5-1360.elf 与 itsPLK v0.26 是不同构建(397024B vs 394480B, md5 异)——可 diff 出 itsPLK 定制内容; 致谢名单=场景全明星(TheFlow/SlidyBat/flatz/Sleirsgoevy/cow...)。

### 前沿快报: 14.10 WebKit 研究(2026-10-19 用户提供推文并验证)

推文称"A major WebKit exploit triggered on PS5 14.10"。验证结论:
**研究真实、标题夸大**——真仓库 github.com/pastawithpesto/PS5-14.10-Jailbreak-Research
(2026-10-18 建, 本地克隆 /tmp/PS5-14.10-Jailbreak-Research)。

- 漏洞真实且已编 CVE-2026-64784: JSC bug 317632, UnlinkedMetadataTable::finalize()
  的 unsigned 累加器溢出(38,348,816 次×112B=4,295,067,392 → uint32 回绕为 100,096,
  分配器只留 100KB, 解释器向前写 4.29GB)。数学自洽。
- p146 真机确证: 14 个 worker 字符串 .length 被写成 81400(推文属实);
  **但利用被"4.29GB 扫写"卡死**(p150g-k 五种存活策略全 OOM/崩)——
  是"内存破坏已证", 不是"userland 执行已得"。当前转入广域面审计
  (17+ WebCore 面, LLM agent 逐面读 WebKit-1200 源码)。
- 平台情报(对我们极有价值): PS5 14.10 WebKit≈WebKit-1200(2023-12)/Safari 17.0/
  605.1.15; JIT 禁用(LLInt only); 无 WASM/SAB/WebGL; **Gigacage 被禁**→
  ArrayBuffer 与 JSC 对象共享 FastMalloc 堆(利于利用); 16KB 页; ~500MB 内存上限。
- **p160 证实: Relapse CVE 全集在 14.10 被补**——解释了 remote-loader 止步 13.60。
- 推文署名 @Arn0Stride7/@Devon8zzh 在 GitHub 无账号(纯 X 手柄), 仓库主人另有其人。
- 对我们研究线的意义: 14.10 的"入口竞赛"已开打(此团队 Phase 4 计划=原语→
  ASLR 泄露→任意读写→代码执行→内核); 我们的反编译/diff 流水线仍是下游关键环节。

**同日深挖更新(progress.json + FINDINGS/PROBE_INDEX, 探针已至 p182/11 会话)**:
1. **FreeType loca 表 OOB 读——真机已确认**(FINDING #5): PS5 FreeType 不校验
   字体内部偏移, loca[0]=0x7FFFFFFF 的字体照常加载渲染且过 Canvas 读回;
   配合 Gigacage 禁用(字体缓冲与 JSC 对象共池), 可经字形渲染读相邻堆内存
   → Canvas getImageData 外提——**潜在 ASLR 泄露/读原语**, p182 部署中;
2. CSSFontFace UAF(源码级验证, CSSFontFaceSet.cpp:381 非所有权引用): p170
   WOFF2 路线失败(PS5 拒 WOFF2), p175 TTF-from-ArrayBuffer 等真机结果;
3. **runtime-derive 无 offset 加载器设计**(tools/remote-loader/runtime-derive/):
   目标=从 ARW 原语运行时推导全部 userland 常量(host ctor/memset GOT/stack
   chk guard/26 gadgets/~400 syscall stub), 摆脱 per-build offset 表——
   正面解决"每固件一张表"的痛点, 成功则任何固件(含 14.10)免表运行;
   设计文档基于 itsPLK remote-loader 源码逐行标注(L/src/main.js:92-127 等);
4. 死胡同清单 5 项已系统排除(yarr/rab/clonedargs/relapse CVE/streams BYOB)。

### 前沿快报 3: A53 南桥声明验证 + 13.60 内核 dump 入库(2026-10-19)

**A53 声明(EchoStretch)**: 无法完全验证(声明只在 X 时间线, 本地不可达)。
可考部分: PS5 南桥确有 ARM Cortex-A53 协处理器(psdevwiki/Devices, 管
syscon I/O 与内存管理, 经内核 ioctl 可达); **cragson/a53-code-exec PoC 已存在**
("可击败 ≤5.00 的 HV, 未实现, 依赖 DECI5S 调试通道")。若 EchoStretch 把 A53
路径推到 14.x, 机制上说得通(A53→DECI5 调试通道→读主内存=硬件级调试后门,
可能不受主核 FW 的用户态/内核补丁影响); 但"14.00/14.10 直接受益"目前是
未证声明, 保持跟踪 @StretchEcho。

**重大入库: terrafirma2021/ps5-13.60-kernel-dump**——13.60 内核活体 RAM 重建
(103,546,880B, out/kernel-13.60-live.bin, SHA-256 与官方 JSON 精确一致)。
- 布局: text @0xffffffff9e3f0000(13.4MB) + data @rva 0xCC0000(90MB),
  file offset == rva(平坦连续); 688 个未映射页零填充;
- **三重交叉验证**: data rva 0xCC0000 = offset 表 kernelData(13.60);
  rodata 探针实测落点 = offset 表预测 rva 0x1379d6c(精确);
  offset 表 ↔ 内核 dump ↔ Relapse 源码三方互锁;
- 意义: **内核 RE 不再需要真机**——Ghidra 流水线可直接吃这份 dump:
  raw binary @0xffffffff9e3f0000 导入 → 13.60 内核符号地图 → 14.10 解密后
  同法 diff。注意 JSON 警告: 活体捕获 ≠ 干净的 PUP kernel.bin(含运行态数据)。

### 外部对照 3: SharpEmu PS5 模拟器(2026-10-19 调研)

github.com/sharpemu/sharpemu: C# 从零写的实验性 PS5 模拟器(2026-03 起,
6.4k 星, GPL-2.0+, v0.0.6-mono, PR 已至 #1111, 极活跃, 当天仍有 push)。
- 架构: Core(Cpu/Memory/Loader/Runtime) + HLE(含 **Aerolib** 函数名库/
  FileSystem/GpuMemory) + Vulkan/Metal 双着色器编译器 + GpuConformance 工具;
  Win/Linux/macOS x64(Apple Silicon 走 Rosetta);
- 状态: 自称"重精度轻兼容", 但已出现游戏级修复(Gt7 fixes, VideoOut mesh
  granularity)——比宣传走得远;
- 与本研究的关系: 生态第七层(硬件逃逸/模拟路线); Aerolib 命名库与我们的
  FreeBSD"伪符号表"方法同构, HLE syscall 实现是内核 ABI 知识的消费端。



### 外部对照 2: Vynx JB 公共托管站(2026-10-19)

vynx.dev/JB (Vynx Jailbreak v2.0, WebKitty 框架 + Relapse 集成, 多语言含中文):
- PS5: umtx2(1.00–5.50) + Poops/Relapse(7.00–13.60), **5.50–7.00 空档**;
  PS4: 6.00–13.52 全家 + GoldHEN v2.4b18.x;
- 链条菜单: PSFree/Lapse Modular/BadHoiSt/CSSFontFace/**Netctrl**/Slopkit/Relapse
  ——社区兼容表里的 "NetControlImpi" 即此处的 Netctrl;
- credits 与 Relapse-Exploit 仓库高度重合(ntfargo/ufm42/Sonic-Iso/Jordy/Dr.Yenyen);
- 定位: 这正是 autoloader README 警告的"第三方 DNS 信任模型"的当代形态——
  自动重试/风扇控制/GoldHEN 版本管理是 UX 层, 链条本体与我们已逆向的同源。
  对研究者: 参考实现 + 各链真机成功率数据的观察窗口; 对日常使用:
  autoloader(离线自托管)在信任模型上严格优于此类公共 host。

### 外部对照: 社区兼容表(2026-10 用户提供, @ps5破解折腾吧)


"PS5 可用利用链总表"(截图)与本研究的对账:
- **吻合**: HV/Linux 窗口=3.00–7.61(=ps5-linux-loader 官方范围, 8.00 起 HV 被修);
  UMTX 于 8.00 前后淘汰(=autoloader v0.6.0 changelog); 越低固件越好。
- **张力**: 该表将 13.00–13.60 标为 "private 🔒"、13.60 WebKit ❌, 与 itsPLK
  remote-loader(v0.6.1, 2026-10-08) 公开声称 Relapse→13.60(WebKit 入口)不符。
  可能原因: 表滞后于 itsPLK 发版 / 表中 "Lapse"=ps5-linux 线的 Relapse 构建
  (止于 7.61)而非 itsPLK 扩展版 / 13.x 公开链确实受限。13.x 可用性以实测为准。
- **决策影响**: 买机做密钥提取的甜点位=**FW 5.00–7.61**(V4 需内核读写,
  Byepervisor+Relapse+etaHEN 在此区间全满足且冗余)。

| 事项 | 状态 |
|---|---|
| offset 表分析 / PUP 容器 / 熵测绘 / FreeBSD 对照 | ✅ 完成 |
| V4 + elfldr 全量反编译 | ✅ 完成(579 函数) |
| PUP 内容解密 | ⏸ 等 TitaniaPy v0.2 发布(声称周末) |
| 13.60 vs 14.10 内核 diff → 提 offset | ⏸ 依赖上项 |
| 密钥提取真机验证 | ⏸ 需 ≤13.60 越狱主机(资深者称或需 ≤3.xx) |
| 永久 CFW(自定义 bl2) | ⏸ 等 BootROM 密钥消化, 无公开成品 |

## 下一步

1. 跟踪 TitaniaPy v0.2 发布 → 解密 14.10 → 反编译流水线吃内核 → diff 出 14.10
   offset(可给 remote-loader 提 PR, 正处窗口期);
2. v4 ELF/源码/伪代码三件套在手, 若入手低固件主机可直接复现密钥提取;
3. 长期: 盯 BootROM 消化(自定义 bootloader/永久 CFW)与 GBAtemp thread/686235。

## 产物索引

| 路径 | 内容 |
|---|---|
| `tools/analyze_offsets.mjs` | offset 表跨固件分析器 |
| `tools/pup_probe.py` | updatelist→PUP→SLB2 头部探针 |
| `tools/entropy_map.py` | 全文件熵测绘 |
| `tools/ghidra_dump_decomp.java` | Ghidra headless 全函数反编译导出 |
| `out/offsets_report.md` + `.json` | 35 固件横向分析 |
| `out/freebsd_mapping.md` | FreeBSD 12 结构对照 |
| `out/re_decomp_report.md` | 反编译报告 |
| `out/re/*_decomp.c` + `_symbols.tsv` | V4(200 fn)/elfldr(379 fn) 全量伪代码 |
| `out/PS5UPDATE_14.10.PUP` | 完整 14.10 固件(哈希已验证) |
| `out/updatelist_*.xml`, `pup_head_*.bin` | CDN 快照与头部样本 |
| `/tmp/TitaniaPy/` | TitaniaPy + V4 源码/ELF |
| `/tmp/ps5-pup-decrypt/` | zecoxao 工具源码 |
| `~/DEV/ps5-webkit-autoloader/` | 起点仓库(含 remote-loader 子模块) |
