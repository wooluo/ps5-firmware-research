# PS5 二进制反编译报告（Ghidra headless 全量导出）

生成: 2026-10-19。工具链: 用户自带 Ghidra 12.1.3 (`~/tools/ghidra_12.1.3_PUBLIC`,
源码构建含 mac_arm_64 natives) + openjdk@21 + 自研导出脚本
`tools/ghidra_dump_decomp.java`（headless postScript，全函数反编译 + 符号清单）。

## 流水线备忘

- Ghidra **官方 12.1.4 zip 不含任何 mac 反编译器原生件**（只有 linux/win_x86_64），
  官方包在 Apple Silicon 上无法反编译；用户 12.1.3 源码构建版可用。
- Ghidra 12 的 .py postScript 需要 PyGhidra 模式，headless 用 **Java 脚本**零依赖。
- 复现: `JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
  ~/tools/ghidra_12.1.3_PUBLIC/support/analyzeHeadless /tmp/ghidra_proj ps5re
  -import <elf> -scriptPath ~/DEV/ps5-fw-research/tools
  -postScript ghidra_dump_decomp.java -deleteProject`

## 目标 1: ps5_key_extractV4.elf（密钥提取 payload，200/200 函数）

带符号 ELF，且有同仓库 V4 C 源码 → **反编译保真度可校准**：
dispatch 逻辑（无参=方案 1/2/3/4/6/7 全扫，`-p`=方案 8，oracle=方案 9）、
函数名、摘要输出流全部 1:1 重建。结论：该流水线产出可直接用于语义分析。

机制确认（源码×反编译互证）:
- 物理内存访问: `open("/dev/dmem0")`（失败回退 /dev/mem），mmap MAP_SHARED 直接
  MMIO 映射 CCP 队列寄存器；
- CCP 队列寻址: `bar + 0x3001000 + (queue_id << 12)`，5 个队列；
- **方案 8 (CCP PASSTHROUGH) = 密钥外提的核心**: 构造 32 字节 ccp5 描述符
  (engine=PASSTHROUGH(5), src=SB 槽 MEMTYPE_SB, dst=系统内存), 写入队列环
  当前 tail, 推 TAIL 寄存器提交, 轮询 HEAD 完成后从输出页读取——
  **用密码处理器自己的拷贝引擎绕过私钥掩码做 DMA 外提**；
- 关键洞察: 私有掩码只挡 CPU 直接 MMIO 读 SB 槽, 挡不住 CCP 内部引擎的
  任意源-目的拷贝。

## 目标 2: elfldr-ps5-v0.26-bb1e117.elf（itsPLK 定制 loader，379/379 函数）

stripped 纯 RE。核心发现:

1. **它根本不是监听者**: 动态导入表只有 `recv`（无 socket/bind/listen/accept）。
   监听发生在 exploit 侧——WebKit 进程内用 ROP 原始 syscall 建 socket 绑
   127.0.0.1:9021（与 remote-loader 的 autoload.js/elfldr-check.js 纯 syscall
   写法互证）。elfldr 只负责"accept 之后"的接收半场。
   "仅本机连接"的安全性由 exploit 侧绑定 loopback 实现。
2. **接收协议**: 定长 64 字节头 (recv flags=MSG_DONTWAIT) + 变长体分帧，
   realloc 增长缓冲，对应字符串 "elfldr_read"/"pt_socket"。
3. **事件模型**: `rfork_thread` 起工作线程 + `kqueue`/`kevent` 事件循环 +
   `waitpid` 回收——BSD 风格而非 pthread。
4. **优雅收尾**: 完成后 `execve("/system/vsh/app/NPXS40112/eboot.bin", ...)`——
   NPXS40112 是 PS5 的 User's Guide/浏览器应用。**加载完成后重启浏览器本体，
   让控制台无痕恢复正常 UI**；调试输出走 /dev/deci_stdout、/dev/deci_stderr。
5. 字符串里另有 "kernel_overlap_sockets failed"——socket fd 与 exploit 会话的
   交接经内核侧 overlap 技巧（exploit 运行时持有 listener, elfldr 接管 fd）。

## 产物

- `re/ps5_key_extractV4_decomp.c` (228KB, 200 函数全量伪代码) + `_symbols.tsv`
- `re/elfldr_decomp.c` (234KB, 379 函数) + `_symbols.tsv`
- 原始 ELF: `/tmp/TitaniaPy/ps5_key_extractV4.elf`, `out/elfldr.elf`

## 下一步（RE 管线已就绪）

- TitaniaPy v0.2 发布 → 解密 14.10 PUP → **本流水线直接反编译 14.10 内核**,
  diff 13.60 提取新 offset（FreeBSD 12 对照表已备好当"伪符号表"）。
