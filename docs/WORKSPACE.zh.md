# PS5 固件逆向研究工作台

> **全程进度记录见 [PROGRESS.md](PROGRESS.md)** —— 时间线、结论汇总、阻塞点、产物索引。

围绕 [ps5-webkit-autoloader](../ps5-webkit-autoloader) 生态做的离线侧固件研究，2026-10-19 由 ZCode 完成。
全部产物只依赖公开数据（索尼公共 CDN + 开源仓库），不涉及泄漏密钥。

## 目录

```
tools/analyze_offsets.mjs  remote-loader offset 表跨固件分析器 (node)
tools/pup_probe.py         updatelist → PUP → SLB2 头部探针 (纯标准库 python)
out/offsets_report.md      35 个固件 offset 横向分析报告
out/offsets_analysis.json  机器可读全量数据
out/updatelist_*.xml       索尼官方更新列表快照 (us/cn)
out/pup_head_*.bin         真实 PUP 头部 64KB 样本 (Range 拉取)
```

## 复现

```sh
node tools/analyze_offsets.mjs ~/DEV/ps5-webkit-autoloader/third_party/ps5-webkit-remote-loader out
python3 tools/pup_probe.py --region cn   # 或 us/eu/jp
```

## 核心发现

### A. offset 层（remote-loader 35 固件，7.00–13.60）

1. **结构体布局纪元**：proc 有 7 个纪元、ucred/filedesc/dynlib/sysCoreAuthId 各 5 个，
   边界齐刷刷落在 9.00→9.05、9.60→10.00、11.20→11.40、11.40→11.60——这些就是
   Sony 改内核结构体的加固时点，也是 exploit 需要重适配的版本。
2. **KASLR 绕过从未被根治**：全系列统一 `rtmsg2` 模式（静态 gadget 地址 + 低 16 位
   slide），Sony 每版只挪地址（重编译 ASLR），不修机制。
3. **内核读写原语**：主链全部用 sysctl OID 节点腐蚀（mib=[9,8] 读 / [9,7] 计数器），
   配置在所有主链固件上一致；9.05/11.40 是 v0.6.1 新加的 candidate 文件，走的是
   AIO + sched_yield 内核路径（不同 bug），无 KRW 块——两条技术路线并存。
4. **固件指纹**：rodata 探针字符串 `_aio_submit_cmd\0_aio_multi_wait` 全系列一致。
5. **提权语义**：ucred 里 PS5 特有字段 sceAuthId@0x58 / sceCaps@0x60 / sceAttrs@0x80；
   securityFlags+0x09=targetID、+0x24=QA flags、+0x8C=utoken——HEN 的开关位。
6. **攻击面**：每固件预定位 ~331 个 syscall wrapper + 26 个 ROP gadget（WebKit 进程）。

### B. PUP 层（实证 FW 14.10.00.00，2026_0928 构建，10-14 重推）

1. **最新固件是 14.10**，而 remote-loader offset 表止于 13.60——**当前正处社区抢
   14.10 offset 的窗口期**，diff 分析最有时值。
2. **SLB2 外层容器**（实证，推翻 PFU 文档的 MYPUP123 布局——那是内层格式）：
   64 字节明文头（见 pup_probe.py docstring）+ 0x200 处 32 字节熵块 + 0x3E0 起全密文。
3. **连 entry 表都是加密的**：0x200/0x3E0/0x2597C8 边界/中段 630MB 处采样全为高熵。
   离线解析到头就是这 64 字节——实证确认"解密必须在已破解主机上跑 payload"
   （zecoxao/ps5-pup-decrypt）。
4. CDN 观察：fus01 明文 HTTP 发 updatelist；PUP 在 AkamaiNetStorage，支持 Range；
   cn 区域走 dcn01 节点，国内直连可用。

## 下一步（需要硬件/更多输入）

- [ ] 搞一台低固件（≤13.60）PS5 → autoloader 越狱 → 主机上跑 pup-decrypt 解密 14.10
- [ ] 解密后 diff 13.60 vs 14.10 内核镜像 → 定位新 offset → 可给 remote-loader 提 PR
- [ ] 对照 FreeBSD 12 源码恢复 14.10 内核结构体（proc/ucred 纪元是否又变了）
- [ ] 长期：跟踪 BootROM 密钥消化进展（自定义 bl2 / 永久 CFW）

## 追加调研: "Linux 上解密 PUP"的可行性 (2026-10-19)

zecoxao/ps5-pup-decrypt 源码分析结论 (已克隆至 /tmp/ps5-pup-decrypt):
- 程序本体 **0 行密码学**——纯 ioctl 驱动: 打开 `/dev/pup_update0`,
  6 条命令 (0xC0104401 verify_bls / 0xC0184402 decrypt_header /
  0xC0184403-04 verify_segment / 0xC0184405 decrypt_segment /
  0xC0284406 decrypt_segment_block), 密钥全在 AMD CCP (Titania 安全处理器) 硬件槽。
- 头文件自带完整格式定义 (bls.h/pup.h), 与我 14.10 实证完全一致:
  BLS(SLB2) v3 单条目 offset 0x400; 内层 PUP 魔数 0xEEF51454 明文,
  header_size=0x5B0 hash_table=0xDE0; block_count×512=文件大小。

GBAtemp 前沿 (2026-10-15, Deepkicks "TitaniaPy", thread 685380):
- PC 端 Python 工具已能: BLS/PUP 解析、Layer3 静态密钥解密、PBKDF2 推导
  (实证 Layer0 = PBKDF2-HMAC-SHA256/16B)
- 8 阶段穷举(17 静态密钥×多种模式×滑动窗口) 证明 **Layer1 PUP 容器密钥
  不在公开密钥集里**——它在 Titania/CCP 内, 全机通用, FW1.0 起不变,
  提取一次 = 永久解密所有固件
- 已有 13.60 志愿者跑了提取 payload; 但资深开发者(TheStonedModder,自称
  手里有钥匙)泼冷水: 密钥提取大概率需要极低固件(≤3.xx), 且警告半盲
  payload 有变砖风险, "4 个月+AI 辅助"才拿到

结论: "Linux 解密"= 差一把钥匙的软件工程, 钥匙提取是真硬件研究。

## 第二轮研究 (2026-10-19 下午): 前沿动态 + 独立验证

### 场景重大进展: Layer 1 密钥已被提取

- GBAtemp 新帖 thread/686235 (2026-10-18): Deepkicks 宣布**在自己的 13.60
  主机上用 V4 提取 payload 成功提取 EncryptService 密钥**，
  `analyze_dump.py` 反汇编 EncryptService ioctl handler 定位密钥来源。
- 发布策略: **不公开原始密钥字节**, 以"混淆常量 + 预编译二进制"形式发
  TitaniaPy v0.2 (号称周末), 声称两位资深开发者独立确认。
  单源新人声明, 审慎跟踪。仓库 github.com/deepkicks/TitaniaPy
  (本地 /tmp/TitaniaPy, 含 ps5_key_extractV4.c 提取 payload 源码)。

### 本轮独立验证 (全部一手完成)

1. **TitaniaPy 交叉验证**: 其 info 输出与本工作台解析器在 14.10 样本上
   逐字段吻合; 内层布局明确: 16B 明文头 + 0x10–0x5B0 加密段表(~44 段)
   + 0x5B0–0x1390 哈希表 + 0x1390 起段数据。
2. **完整 14.10 PUP 下载并哈希自验证**: 1,261,408,256 字节,
   SHA-256 = c1738494…daaf6, 与索尼 URL 内嵌哈希完全一致
   (索尼把文件哈希编进路径, 天然防篡改)。
3. **L0 推导本机复现**: PBKDF2-HMAC-SHA256(OTP_AES_ROOT, KDF_SALT1,
   1000 iters, 16B) 输出与 Titania Rev 2 主密钥精确一致。
4. **"密钥不在公开集"独立验证**: 自提 14.10 加密头跑 bruteforce,
   全部 6 把可用已知密钥 (emc_*/eap_*/titania_rev2) 均 HIGH_ENTROPY 失败。
5. **全文件熵测绘** (tools/entropy_map.py): 1.17GB 全程 ~7.997 bits/byte
   零低熵区 — 除 64B BLS 头+16B 内层魔数外整体均匀密文, 段结构
   完全藏在加密之下, 无侧信道结构泄露。

### FreeBSD 12 对照 (out/freebsd_mapping.md)

- **ucred 前 0x1C 与 FreeBSD 12.0 逐字节一致** (cr_ref..cr_svgid 连续
  u32 可静态证明); 0x58 起 Sony 把 MAC/jail/audit 换成 sceAuthId/
  sceCaps/sceAttrs 自有权限模型; **该布局 7.00–13.60 六年零变化**。
- **filedesc 前 4 字段逐字节一致**。
- **proc 是唯一演变的结构**: aioInfo 3128→3136(10.00)→3144(12.00)。
- 修正了早期报告的"ucred 5 纪元"假象 (candidate 文件切断所致),
  分析器已修复重新生成。

### 新增产出

- out/PS5UPDATE_14.10.PUP (完整固件, 1.17GB)
- out/freebsd_mapping.md, out/inner_hdr_enc.bin (加密头样本)
- tools/entropy_map.py

## 第三轮研究 (2026-10-19 晚): 反编译流水线建立

- Ghidra 官方 12.1.4 zip **无 mac 反编译原生件**(仅 linux/win)——改用用户自带
  `~/tools/ghidra_12.1.3_PUBLIC`(源码构建, 含 mac_arm_64 natives) + openjdk@21。
- 自研 headless 导出脚本 `tools/ghidra_dump_decomp.java`(Java, 零 Python 依赖)。
- **V4 提取器 200/200、elfldr 379/379 函数全量反编译**, 产物在 out/re/,
  报告 out/re_decomp_report.md。
- 关键 RE 发现: ① V4 密钥外提=CCP PASSTHROUGH 描述符 DMA(私钥掩码只挡
  CPU MMIO 读, 挡不住 CCP 内部引擎); ② itsPLK elfldr **不是监听者**(导入表
  仅 recv, 无 socket/bind/accept)——监听在 exploit 侧 ROP syscall 完成,
  "仅本机"由绑定 loopback 实现; ③ 收尾 execve 重启 NPXS40112(浏览器应用)
  实现无痕恢复; ④ 接收协议=64B 定长头+变长体, kqueue+rfork_thread 事件模型。

## 参考

- upstream: https://github.com/itsPLK/ps5-webkit-autoloader / ps5-webkit-remote-loader
- 解密工具(主机侧): https://github.com/zecoxao/ps5-pup-decrypt
- PFU 解包器(解密后): https://github.com/seregonwar/PFU-PupFileUnpacker
- psdevwiki: https://www.psdevwiki.com/ps5/ (Updatelist.xml / System_Software 页)
