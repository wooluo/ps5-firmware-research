#!/usr/bin/env python3
"""PS5 PUP 全文件熵测绘: 分段采样 Shannon 熵, 推断内部结构边界。

对 1.17GB 的加密固件做采样式熵测绘:
- 每 step 字节取 window 字节窗口计算熵
- 高熵(>7.5) = 加密/压缩数据; 低熵(<3) = padding/零区; 中熵 = 可能的元数据/表
输出 markdown 表格 + 低熵区域清单(结构边界的线索)。
"""
import math
import sys

def entropy(data):
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    e = 0.0
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e

def main(path, step=16 * 1024 * 1024, window=64 * 1024, head_extra=None):
    import os
    size = os.path.getsize(path)
    samples = []
    off = 0
    # 头部精细采样 (前 8MB 每 1MB) — 结构边界集中在头部
    while off < min(size, 8 * 1024 * 1024):
        with open(path, 'rb') as f:
            f.seek(off)
            samples.append((off, entropy(f.read(min(window, size - off)))))
        off += 1024 * 1024
    # 主体粗采样
    off = 8 * 1024 * 1024
    while off < size:
        with open(path, 'rb') as f:
            f.seek(off)
            samples.append((off, entropy(f.read(min(window, size - off)))))
        off += step
    print(f'| 偏移 | 熵 (bits/byte) | 判读 |')
    print(f'|---|---|---|')
    low = []
    for off, e in samples:
        verdict = '加密/压缩' if e > 7.5 else '中熵(表/元数据?)' if e > 3 else '**低熵(padding/结构!)**'
        if e <= 3:
            low.append((off, e))
        mb = off / 1024 / 1024
        print(f'| {mb:.1f} MB (0x{off:x}) | {e:.3f} | {verdict} |')
    print(f'\n低熵区域 {len(low)} 处:', ', '.join(f'0x{o:x}({e:.2f})' for o, e in low[:20]))

if __name__ == '__main__':
    main(sys.argv[1])
