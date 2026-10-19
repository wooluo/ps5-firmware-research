# PS5 remote-loader offset tables: cross-firmware analysis

Source: /Users/wooluo/DEV/ps5-webkit-autoloader/third_party/ps5-webkit-remote-loader/offsets (35 firmware versions)
Generated: 2026-10-19T08:05:20.323Z

## 1. Key kernel addresses

| FW | kernelData | allproc | rootvnode | securityFlags | KASLR mode | rodata probe |
|---|---|---|---|---|---|---|
| 7.00 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 7.01 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 7.20 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 7.40 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 7.60 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 7.61 | 0xc50000 | 0x34a9d50 | 0x3d17510 | 0x1718064 | rtmsg2 | _aio_submit_cmd |
| 8.00 | 0xc70000 | 0x34e5d50 | 0x3d6b510 | 0x1733064 | rtmsg2 | _aio_submit_cmd |
| 8.20 | 0xc70000 | 0x34e5d50 | 0x3d6b510 | 0x1733064 | rtmsg2 | _aio_submit_cmd |
| 8.40 | 0xc70000 | 0x34e5d50 | 0x3d6b510 | 0x1733064 | rtmsg2 | _aio_submit_cmd |
| 8.60 | 0xc70000 | 0x34e5d50 | 0x3d6b510 | 0x1733064 | rtmsg2 | _aio_submit_cmd |
| 9.00 | 0xca0000 | 0x33f5d50 | 0x3c7b510 | 0x1a12064 | rtmsg2 | _aio_submit_cmd |
| 9.05 | ? | ? | ? | 0x1a13064 | ? | ? |
| 9.20 | 0xca0000 | 0x33f5d50 | 0x3c7b510 | 0x1a13064 | rtmsg2 | _aio_submit_cmd |
| 9.40 | 0xca0000 | 0x33f5d50 | 0x3c7b510 | 0x1a13064 | rtmsg2 | _aio_submit_cmd |
| 9.60 | 0xca0000 | 0x33f5d50 | 0x3c7b510 | 0x1a13064 | rtmsg2 | _aio_submit_cmd |
| 10.00 | 0xcc0000 | 0x3425d70 | 0x3c63510 | 0x1a39064 | rtmsg2 | _aio_submit_cmd |
| 10.01 | 0xcc0000 | 0x3425d70 | 0x3c63510 | 0x1a39064 | rtmsg2 | _aio_submit_cmd |
| 10.20 | 0xcc0000 | 0x3425d70 | 0x3c63510 | 0x1a39064 | rtmsg2 | _aio_submit_cmd |
| 10.40 | 0xcc0000 | 0x3425d70 | 0x3c63510 | 0x1a39064 | rtmsg2 | _aio_submit_cmd |
| 10.60 | 0xcc0000 | 0x3425d70 | 0x3c63510 | 0x1a39064 | rtmsg2 | _aio_submit_cmd |
| 11.00 | 0xd30000 | 0x35a5d70 | 0x3de7510 | 0x1abc064 | rtmsg2 | _aio_submit_cmd |
| 11.20 | 0xd30000 | 0x35a5d70 | 0x3de7510 | 0x1abc064 | rtmsg2 | _aio_submit_cmd |
| 11.40 | ? | ? | ? | 0x1abc064 | ? | ? |
| 11.60 | 0xd30000 | 0x35a5d70 | 0x3de7510 | 0x1abc064 | rtmsg2 | _aio_submit_cmd |
| 12.00 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 12.02 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 12.20 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 12.40 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 12.60 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 12.70 | 0xd50000 | 0x35d5e00 | 0x3e27510 | 0x1ad3064 | rtmsg2 | _aio_submit_cmd |
| 13.00 | 0xcb0000 | 0x3575e00 | 0x3de3510 | 0x1a49064 | rtmsg2 | _aio_submit_cmd |
| 13.20 | 0xcb0000 | 0x3575e00 | 0x3de3510 | 0x1a49064 | rtmsg2 | _aio_submit_cmd |
| 13.40 | 0xcb0000 | 0x3579e80 | 0x3de7510 | 0x1a49064 | rtmsg2 | _aio_submit_cmd |
| 13.42 | 0xcb0000 | 0x3579e80 | 0x3de7510 | 0x1a49064 | rtmsg2 | _aio_submit_cmd |
| 13.60 | 0xcc0000 | 0x3589e80 | 0x3e0b510 | 0x1a5c064 | rtmsg2 | _aio_submit_cmd |

## 2. Adjacent-firmware change matrix

Which offset categories changed between adjacent firmware pairs (indicators of Sony recompiles/hardening):

| pair | kernel addrs | KASLR | proc layout | ucred layout | libkernel syms | libc syms | ROP gadgets | sysctl oids |
|---|---|---|---|---|---|---|---|---|
| 7.00→7.01 | · | · | · | · | · | · | · | · |
| 7.01→7.20 | · | **Δ** | · | · | **Δ** | · | · | **Δ** |
| 7.20→7.40 | · | · | · | · | · | · | · | · |
| 7.40→7.60 | · | **Δ** | · | · | · | · | · | **Δ** |
| 7.60→7.61 | · | · | · | · | · | · | · | · |
| 7.61→8.00 | **Δ** | **Δ** | · | · | **Δ** | **Δ** | · | **Δ** |
| 8.00→8.20 | · | **Δ** | · | · | · | · | · | **Δ** |
| 8.20→8.40 | · | **Δ** | · | · | · | · | · | · |
| 8.40→8.60 | · | **Δ** | · | · | · | · | · | · |
| 8.60→9.00 | **Δ** | **Δ** | · | · | **Δ** | **Δ** | · | **Δ** |
| 9.00→9.05 | **Δ** | **Δ** | **Δ** | **Δ** | · | · | · | **Δ** |
| 9.05→9.20 | **Δ** | **Δ** | **Δ** | **Δ** | · | · | · | **Δ** |
| 9.20→9.40 | · | **Δ** | · | · | · | · | · | · |
| 9.40→9.60 | · | **Δ** | · | · | · | · | · | · |
| 9.60→10.00 | **Δ** | **Δ** | **Δ** | · | **Δ** | **Δ** | · | **Δ** |
| 10.00→10.01 | · | · | · | · | · | · | · | · |
| 10.01→10.20 | · | **Δ** | · | · | · | · | · | · |
| 10.20→10.40 | · | · | · | · | · | · | · | · |
| 10.40→10.60 | · | **Δ** | · | · | · | · | · | · |
| 10.60→11.00 | **Δ** | **Δ** | · | · | **Δ** | **Δ** | · | **Δ** |
| 11.00→11.20 | · | · | · | · | · | · | · | · |
| 11.20→11.40 | **Δ** | **Δ** | **Δ** | **Δ** | · | · | · | **Δ** |
| 11.40→11.60 | **Δ** | **Δ** | **Δ** | **Δ** | · | · | · | **Δ** |
| 11.60→12.00 | **Δ** | **Δ** | **Δ** | · | **Δ** | **Δ** | · | **Δ** |
| 12.00→12.02 | · | · | · | · | **Δ** | · | · | · |
| 12.02→12.20 | · | **Δ** | · | · | · | · | · | · |
| 12.20→12.40 | · | · | · | · | **Δ** | · | · | · |
| 12.40→12.60 | · | **Δ** | · | · | · | · | · | · |
| 12.60→12.70 | · | · | · | · | · | · | · | · |
| 12.70→13.00 | **Δ** | **Δ** | · | · | **Δ** | **Δ** | · | **Δ** |
| 13.00→13.20 | · | **Δ** | · | · | · | · | · | · |
| 13.20→13.40 | **Δ** | **Δ** | · | · | · | · | · | **Δ** |
| 13.40→13.42 | · | · | · | · | · | · | · | · |
| 13.42→13.60 | **Δ** | **Δ** | · | · | · | · | · | **Δ** |

## 3. Kernel struct layout epochs

布局相同的连续固件归为同一纪元（candidate 文件 9.05/11.40 无 KRW 块，不参与分组）:

**proc (进程结构)** — 3 epochs: 7.00–9.60 | 10.00–11.60 | 12.00–13.60

**ucred (凭证结构)** — 1 epochs: 7.00–13.60

**filedesc (文件描述符)** — 1 epochs: 7.00–13.60

**dynlib (动态库限制)** — 1 epochs: 7.00–13.60

**sysCoreAuthId** — 1 epochs: 7.00–13.60

## 4. KASLR bypass evolution

| FW | mode | retStatic |
|---|---|---|
| 7.00 | rtmsg2 | 0xa83731 |
| 7.01 | rtmsg2 | 0xa83731 |
| 7.20 | rtmsg2 | 0xa83b81 |
| 7.40 | rtmsg2 | 0xa83b81 |
| 7.60 | rtmsg2 | 0xa84191 |
| 7.61 | rtmsg2 | 0xa84191 |
| 8.00 | rtmsg2 | 0xa9cac5 |
| 8.20 | rtmsg2 | 0xa9dec5 |
| 8.40 | rtmsg2 | 0xa9e155 |
| 8.60 | rtmsg2 | 0xa9e3d5 |
| 9.00 | rtmsg2 | 0xac1451 |
| 9.05 | ? | ? |
| 9.20 | rtmsg2 | 0xac1471 |
| 9.40 | rtmsg2 | 0xac19e1 |
| 9.60 | rtmsg2 | 0xac1bc1 |
| 10.00 | rtmsg2 | 0xadf87f |
| 10.01 | rtmsg2 | 0xadf87f |
| 10.20 | rtmsg2 | 0xadfa9f |
| 10.40 | rtmsg2 | 0xadfa9f |
| 10.60 | rtmsg2 | 0xadfa7f |
| 11.00 | rtmsg2 | 0xb52b61 |
| 11.20 | rtmsg2 | 0xb52b61 |
| 11.40 | ? | ? |
| 11.60 | rtmsg2 | 0xb53301 |
| 12.00 | rtmsg2 | 0xb6ec71 |
| 12.02 | rtmsg2 | 0xb6ec71 |
| 12.20 | rtmsg2 | 0xb6eaf1 |
| 12.40 | rtmsg2 | 0xb6eaf1 |
| 12.60 | rtmsg2 | 0xb6eb51 |
| 12.70 | rtmsg2 | 0xb6eb51 |
| 13.00 | rtmsg2 | 0xad8582 |
| 13.20 | rtmsg2 | 0xad8790 |
| 13.40 | rtmsg2 | 0xad8aa0 |
| 13.42 | rtmsg2 | 0xad8aa0 |
| 13.60 | rtmsg2 | 0xae2da0 |

## 5. Privilege-escalation targets (13.60, for example)

```json
{
  "sysCoreAuthId": {
    "lo": 7,
    "hi": 1207959552
  },
  "ucred": {
    "uid": 4,
    "ruid": 8,
    "svuid": 12,
    "ngroups": 16,
    "rgid": 20,
    "svgid": 24,
    "sceAuthId": 88,
    "sceCaps": 96,
    "sceCaps1": 104,
    "sceAttrs": 128
  },
  "securityFlagsRelated": {
    "securityFlags": 27639908,
    "targetId": "securityFlags+0x09",
    "qaFlags": "securityFlags+0x24",
    "utokenFlags": "securityFlags+0x8C"
  }
}
```

## 6. sysctl OID corruption primitive config

Poops/slopkit : the kernel R/W primitive = corrupting sysctl tree OID nodes. Per-firmware node config:

| FW | oid.a | oid.b | oid.c | walkCounter | aio
|---|---|---|---|---|---|
| 7.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 7.01 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 7.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 7.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 7.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 7.61 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 8.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 8.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 8.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 8.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 9.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 9.05 | — | — | — | — | — |
| 9.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 9.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 9.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 10.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 10.01 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 10.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 10.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 10.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 11.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 11.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 11.40 | — | — | — | — | — |
| 11.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.02 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 12.70 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 13.00 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 13.20 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 13.40 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 13.42 | √ | √ | mib=[9,8] | mib=[9,7] | √ |
| 13.60 | √ | √ | mib=[9,8] | mib=[9,7] | √ |

## 7. Attack-surface coverage

Pre-located syscall wrappers and ROP gadgets per firmware:

| FW | syscalls | gadgets |
|---|---|---|
| 7.00 | 328 | 26 |
| 7.01 | 328 | 26 |
| 7.20 | 329 | 26 |
| 7.40 | 329 | 26 |
| 7.60 | 329 | 26 |
| 7.61 | 329 | 26 |
| 8.00 | 330 | 26 |
| 8.20 | 330 | 26 |
| 8.40 | 330 | 26 |
| 8.60 | 330 | 26 |
| 9.00 | 331 | 26 |
| 9.05 | 331 | 26 |
| 9.20 | 331 | 26 |
| 9.40 | 331 | 26 |
| 9.60 | 331 | 26 |
| 10.00 | 331 | 26 |
| 10.01 | 331 | 26 |
| 10.20 | 331 | 26 |
| 10.40 | 331 | 26 |
| 10.60 | 331 | 26 |
| 11.00 | 331 | 26 |
| 11.20 | 331 | 26 |
| 11.40 | 331 | 26 |
| 11.60 | 331 | 26 |
| 12.00 | 332 | 26 |
| 12.02 | 331 | 26 |
| 12.20 | 331 | 26 |
| 12.40 | 331 | 26 |
| 12.60 | 331 | 26 |
| 12.70 | 331 | 26 |
| 13.00 | 331 | 26 |
| 13.20 | 331 | 26 |
| 13.40 | 331 | 26 |
| 13.42 | 331 | 26 |
| 13.60 | 331 | 26 |
