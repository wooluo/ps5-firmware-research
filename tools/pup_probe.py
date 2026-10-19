#!/usr/bin/env python3
"""PS5 固件 PUP 探针: updatelist → PUP URL → Range 取头部 → 解析 SLB2 容器头。

只用标准库。默认走明文 HTTP 的 fus01（其 HTTPS 用索尼内部 CA，本机验签会失败）。
用法:
  python3 pup_probe.py [--region us] [--out DIR] [--bytes N]
实证格式 (2026-10-19, FW 14.10.00.00 / 2026_0928):
  0x00 magic[4]      = "SLB2"
  0x04 u32 version   = 3
  0x08 u32           = 0x10000 (含义待定)
  0x0c u32           = 1
  0x10 u64           = 0x2597C8 (约 2.4MB; 疑为加密元数据区大小)
  0x18 u32           = 0
  0x1c u32           = 0
  0x20 u32 entry_cnt = 2
  0x24 u32           = 0x4B2F8A3D (头校验/种子?)
  0x30 name[~20]     = "PS5UPDATE1.PUP"
  0x200 32 字节高熵块(盐/种子?), 0x3E0 起全部为密文 —— entry 表本身加密,
  离线无法解析内容; 解密需在已破解主机上跑 zecoxao/ps5-pup-decrypt。
"""
import argparse
import os
import struct
import sys
import urllib.request
import xml.etree.ElementTree as ET

FUS01 = "http://fus01.ps5.update.playstation.net"
SEGMENT = "tJMRE80IbXnE9YuG0jzTXgKEjIMoabr6"  # 官方公共路径段, 多年未变


def fetch(url, rng=None):
    req = urllib.request.Request(url)
    if rng:
        req.add_header("Range", f"bytes={rng[0]}-{rng[1]}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read(), r.headers


def parse_updatelist(xml_bytes):
    root = ET.fromstring(xml_bytes)
    out = {}
    for pup in root.iter("system_pup"):
        label = pup.get("label")
        upd = pup.get("upd_version")
        for img in pup.iter("image"):
            out.setdefault(upd, {"label": label, "images": []})["images"].append(
                {"size": int(img.get("size", 0)), "url": (img.text or "").strip()})
    return out


def parse_slb2(buf):
    if buf[:4] != b"SLB2":
        return {"error": f"unexpected magic {buf[:4]!r}"}
    return {
        "magic": "SLB2", "version": struct.unpack("<I", buf[4:8])[0],
        "f08": hex(struct.unpack("<I", buf[8:12])[0]),
        "f0c": struct.unpack("<I", buf[12:16])[0],
        "f10_size": struct.unpack("<Q", buf[16:24])[0],
        "entry_count": struct.unpack("<I", buf[32:36])[0],
        "f24": hex(struct.unpack("<I", buf[36:40])[0]),
        "name": buf[48:62].decode("ascii", "replace").rstrip("\x00"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--region", default="us")
    ap.add_argument("--out", default="out")
    ap.add_argument("--bytes", type=int, default=65536, help="拉取的头部字节数")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)

    xml_url = f"{FUS01}/update/ps5/official/{SEGMENT}/list/{a.region}/updatelist.xml"
    print(f"[1/3] updatelist: {xml_url}")
    xml, _ = fetch(xml_url)
    with open(os.path.join(a.out, f"updatelist_{a.region}.xml"), "wb") as f:
        f.write(xml)
    pups = parse_updatelist(xml)
    if not pups:
        sys.exit("updatelist 里没有 system_pup")
    for ver, info in pups.items():
        print(f"  最新固件: {ver}  label={info['label']}")
    ver, info = next(iter(pups.items()))
    img = info["images"][0]
    print(f"  PUP: {img['size']:,} bytes\n      {img['url']}")

    print(f"[2/3] Range 拉取前 {a.bytes} 字节…")
    head, hdrs = fetch(img["url"], (0, a.bytes - 1))
    headfile = os.path.join(a.out, f"pup_head_{ver}.bin")
    with open(headfile, "wb") as f:
        f.write(head)
    print(f"  保存 {headfile} (Last-Modified: {hdrs.get('Last-Modified')})")

    print("[3/3] SLB2 头解析:")
    for k, v in parse_slb2(head).items():
        print(f"  {k:12} = {v}")
    print("\n注意: 头部之外全部为密文(含 entry 表), 完整解析需主机侧解密。")


if __name__ == "__main__":
    main()
