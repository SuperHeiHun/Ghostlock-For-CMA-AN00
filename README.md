# GhostLock (CVE-2026-43499) — 荣耀畅玩30 Plus (CMA-AN00) 适配研究

> **仅供安全研究与教育目的。仅在你拥有的设备上使用。作者不对任何损坏或滥用承担责任。**

## 概要

将 GhostLock (CVE-2026-43499) 内核漏洞研究适配到荣耀畅玩30 Plus
(CMA-AN00, 联发科天玑700 / MT6833, Magic UI 5.0, 内核 `4.14.186+` aarch64)。

**状态: 触发已复现 (DoS → 内核 panic)，LPE 链开发中。**

## 设备信息

| | |
|---|---|
| 型号 | 荣耀畅玩30 Plus (CMA-AN00) |
| SoC | 联发科天玑700 (MT6833) |
| 系统 | Magic UI 5.0, Android 11, 版本 5.0.0.224(C00) |
| 内核 | `4.14.186+ #1 SMP PREEMPT Tue Mar 5 18:50:01 CST 2024` aarch64 |
| Bootloader | 锁定 |
| SELinux | Enforcing (`CONFIG_SECURITY_SELINUX_DEVELOP` 未启用) |

## 漏洞

CVE-2026-43499 ("GhostLock"): Linux 内核 rtmutex/futex-PI 代码中的
use-after-free (`kernel/locking/rtmutex.c` 中的 `remove_waiter()`)。
在 requeue-PI 代理路径上，`remove_waiter()` 清除了错误任务的 `pi_blocked_on`，
留下指向已释放的 `rt_mutex_waiter` 内核栈帧的悬空指针。

- **引入**: Linux 2.6.39 (2011)
- **修复**: Linux 7.1 (2026-04)
- **影响**: 2.6.39 – 7.1 且 `CONFIG_FUTEX_PI=y`
- **CVSS**: 7.8 (AV:L/AC:L/PR:L/UI:N)
- **前置条件**: 无需 capability、无需 user namespace、无需特殊内核配置

### 本机暴露面

| 条件 | 状态 |
|---|---|
| 内核版本在影响范围内 | ✅ 4.14.186 |
| `CONFIG_FUTEX_PI=y` | ✅ |
| `CONFIG_PREEMPT=y` | ✅ (竞态窗口大) |
| `CONFIG_CFI_CLANG=y` | ⚠️ 阻断控制流劫持，需走数据无关路线 |
| `CONFIG_SHADOW_CALL_STACK` | ✅ 未启用 (栈 UAF 有效) |
| `CONFIG_PAGE_TABLE_ISOLATION` | ✅ 未启用 (arm64 4.14 无 KPTI) |
| `CONFIG_RANDOMIZE_BASE=y` | ⚠️ KASLR 开启 |
| `CONFIG_HUAWEI_HIDESYMS=y` | ⚠️ 阻断静态符号提取 |
| Bootloader | 锁定 |
| `ro.debuggable` | 0 |

## 已完成

- ✅ 漏洞触发: 三 futex PI 死锁环 → `remove_waiter()` UAF →
  `rt_mutex_adjust_prio_chain` 内核 panic (~3 秒, 100% 复现)
- ✅ 完整 OTA 固件下载管线 (CDN 防盗链绕过)
- ✅ A/B payload.bin 的 boot 分区提取 (从零实现 protobuf 解析)
- ✅ 内核解压缩 (gzip → 裸 ARM64 Image)
- ✅ 内嵌内核配置提取 (IKCONFIG)

## 未完成

- ❌ 静态 kallsyms 提取: `CONFIG_HUAWEI_HIDESYMS=y` 移除/加密了地址表。
  明文符号名存在于 .rodata 中但对应地址被加密 (45KB 高熵块，无代码引用)
- ❌ 完整 LPE: 需要 init_task/init_cred/selinux_enforcing 的地址
- ❌ mtkclient BROM 进入: preloader 握手失败 (疑 SLA 锁定)

## 仓库结构

```
├── src/
│   └── poc.c                 # 三 futex PI 死锁触发器 (适配自 NebuSec)
├── tools/
│   ├── extract_kernel.py     # boot.img → 裸内核 (gzip/lz4/xz)
│   ├── payload_extract.py    # A/B payload.bin → 分区镜像 (纯 Python protobuf)
│   ├── kallsyms_scan.py      # kallsyms 符号表扫描器 (绝对 + base-relative)
│   ├── crack_addrtable.py    # 加密地址表分析
│   ├── entropy_scan.py       # 高熵区域搜索
│   ├── find_rela2.py         # RELA 重定位表扫描
│   └── dump_triples_full.py  # CFI 函数表 dump
├── docs/
│   └── MEMORY.md             # 完整研究笔记、地址映射、发现记录
└── README.md
```

## 触发方法

```bash
# 交叉编译 (Android NDK r26+)
$NDK/toolchains/llvm/prebuilt/*/bin/clang \
  --target=aarch64-linux-android21 -O2 -o poc src/poc.c

# 推送并运行 (会导致设备重启 — 这是预期行为)
adb push poc /data/local/tmp/ghostlock
adb shell chmod 755 /data/local/tmp/ghostlock
adb shell /data/local/tmp/ghostlock
# 设备约 3 秒后重启 (内核 panic, boot reason: kernel_panic)
```

## 固件提取

完整 OTA 包 (5.0.0.237, 4.4GB) 可通过在系统更新检查时使用端上 HTTPS 代理
(Reqable) 捕获下载 URL 获取:

```
http://update-mobile.hihonorcdn.com:18080/TDS/data/files/.../full/update_full_combine.zip
```

CDN 要求 `User-Agent: HwOUCDownloadManager` 且 `Host` 头不含端口号。
需要中国大陆 IP (海外 IP 返回 403)。

```bash
# 从 A/B payload 提取 boot 分区
python tools/payload_extract.py boot

# 解压内核
python tools/extract_kernel.py boot.img kernel_raw.bin
```

## 关键发现

### HIDESYMS 架构 (CONFIG_HUAWEI_HIDESYMS=y)

- 明文符号名 (未压缩、null 分隔、按地址序) 存在于 `.rodata`
  文件偏移 `0x1fda000-0x2051000` 附近 (11,258 个符号)
- 对应地址表被**加密**: 45,056 字节位于文件 `0x200e000`
  (11,264 × u32, 熵 7.98/8.0)，无 ADRP 引用、无 RELA 条目、
  无重复密钥 XOR 模式 — 疑似 AES 或自定义分组加密
- 白名单/位图检查函数位于虚拟地址 `0xffffff80081a9218`
- CFI 函数表 (242,390 项) 在文件 `0x21869e8`，与 kallsyms 分离
- 区域验证: 指向 `0xa060000-0xa0fdd08` 的指针由 `0x198544` 处代码检查

### vaddr ↔ 文件偏移映射

```
vaddr = file_offset + 0xffffff8008080000
file_offset = vaddr - 0xffffff8008080000
```

`_text` 位于文件偏移 `0x80000` (ARM64 头部的 `text_offset=0x80000`)。

## 缓解

将内核更新到同时包含 `3bfdc63936dd` 和 `40a25d59e85b` 的版本。
没有干净的站点级缓解方案。`RANDOMIZE_KSTACK_OFFSET` 可提高利用门槛
但不能消除漏洞。

## 致谢

- 原始研究: [NebuSec](https://nebusec.ai/research/ionstack-part-2/)
- 原始 PoC: [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)
- ARM64 4.14 参考: [NothingFumo/ghostlock-aresin](https://github.com/NothingFumo/ghostlock-aresin)
- 本适配: CMA-AN00 (MT6833) 设备研究

## 许可

仅供研究和教育目的。使用风险自担。
