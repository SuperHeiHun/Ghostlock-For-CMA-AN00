# GhostLock (CVE-2026-43499) CMA-AN00 项目记忆文件

> 更新: 2026-11-04 | 状态: 触发已复现, LPE 卡在华为 HIDESYMS 符号提取

## 目标设备

- HONOR 荣耀畅玩30 Plus (CMA-AN00), 联发科 MT6833 (天玑700)
- Magic UI 5.0, 系统 5.0.0.224(C00), 构建日期 2024-03-07
- 内核 `4.14.186+ #1 SMP PREEMPT Tue Mar 5 18:50:01 CST 2024` aarch64
- bootloader locked, ro.debuggable=0, SELinux Enforcing (DEVELOP/DISABLE 关)
- WiFi ADB 192.168.10.12:5555 (shell uid 2000, 密钥已授权); USB adb 序列号 AKMP9K2217902880
- PC: Windows, E:\Test\Temp\cve-2026-43499 为工作目录; adb 在 E:\Test\ADB\adb_tool\adb.exe
- PC 出口 IP 是香港 (FlClash TUN/系统代理 127.0.0.1:7890) — 国内 CDN 会 403

## 漏洞与触发

- CVE-2026-43499 GhostLock: rtmutex remove_waiter() 栈 UAF, 2.6.39~7.1, 需 CONFIG_FUTEX_PI
- 官方 PoC: NebuSec/CyberMeowfia IonStack/CVE-2026-43499/poc/poc.c
- ARM64 4.14.186 完整移植参考: NothingFumo/ghostlock-aresin (POCO F3 GT MT6893, 已克隆到
  E:\Test\Temp\cve-2026-43499\ghostlock-aresin)
- 另有社区一键 App: YuKongA/ghostlock-app (含 tools/extract_rs 偏移提取器, 已克隆到
  E:\Test\Temp\cve-2026-43499\ghostlock-app)
- 触发已复现: /data/local/tmp/ghostlock 运行 ~3 秒后 kernel panic 自动重启
  (boot reason: kernel_panic / AP_S_PANIC); PANIC_ON_OOPS=y → 每次失败=重启
- 本机配置: CONFIG_CFI_CLANG=y(严格), 无 SHADOW_CALL_STACK, 无 KPTI(arm64 4.14),
  RANDOMIZE_BASE=y, IKCONFIG_PROC=y(可读 /proc/config.gz), HUAWEI_HIDESYMS=y,
  USER_NS 无, PANIC_ON_OOPS=y; /proc/kallsyms、dmesg、全部 /proc/sys 对 shell 拒绝

## 关键产出文件 (E:\Test\Temp\cve-2026-43499\)

| 文件 | 说明 |
|---|---|
| poc.c / poc | 触发 PoC (NDK r26 编译, aarch64, 已推送 /data/local/tmp/ghostlock) |
| update_full_combine.zip | 4.4GB 全量 OTA 包 (5.0.0.237) 已下载完成 |
| payload.bin | 从 zip 解出的 A/B payload (4.7GB) |
| boot.img | 从 payload 提取的 boot 分区 (30MB, 15 操作 sha256 全过) |
| kernel_raw.bin | 解压后内核 43.4MB, _text 在文件偏移 0x80000 |
| new_config.gz.txt | 237 内核内嵌 config 已提取 (FUTEX_PI=y, CFI=y, VA39, BASE_RELATIVE=n) |
| extract_kernel.py | boot.img → gzip 解压内核 (已验证) |
| kallsyms_scan.py | kallsyms 符号扫描器 (合成数据验证过, 真机失败见下) |
| payload_extract.py | A/B payload protobuf 手工解析器 (已成功提取 boot) |
| parse_triples.py / find_*.py / dbg_*.py | 三元组表解析与诊断脚本 |
| ghostlock-extract.exe | YuKongA/ghostlock-app extract_rs 编译产物 (MSVC 环境已配好) |
| monitor.ps1 | 触发后 ADB 存活监控脚本 |

## 地址映射 (237 内核, 已实证)

- vaddr = file_off + 0xffffff8008080000; file_off = vaddr - 0xffffff8008080000
- _text vaddr = 0xffffff8008080000, _text 文件偏移 = 0x80000 (text_offset=0x80000)
- KASLR slide = 运行时基址 - 上述链接基址

## 固件包下载方法 (可复用)

- Reqable 手机抓包 (更新中心触发下载) 抓到直链:
  `http://update-mobile.hihonorcdn.com:18080/TDS/data/files/p1/s15/G268/g141/v720093/f1/full/update_full_combine.zip`
- 下载必须: `-4 -A 'HwOUCDownloadManager' -H 'Host: update-mobile.hihonorcdn.com'`
  (CDN 按 UA+Host 防盗链, Host 不能带 :18080 端口; 且需国内 IP — PC 需退出 FlClash)
- 包结构: A/B OTA → payload.bin (protobuf 头 24B + manifest 226799B + sig 267B + blob@227090)
- 5.0.0.237(C00E227R4P5), changelog: 系统优化/浏览器 AI 换新

## 卡点: HUAWEI_HIDESYMS 符号表 (路线1进行中, 已深挖)

- 237 内核无标准 kallsyms: 无绝对 u64 地址表、无有效 token_table/index 对、
  vmlinux-to-elf 和 ghostlock-app extract_rs 均失败 (0 token tables)
- 三元组表已完整解析 (triples_dump.txt, 242,390 项): 16B 表头(流指针+默认标志0x403)
  + 24B/项 (A=符号地址, B=编码名指针, C=标志 0x401/0x403)
- A 范围 0xffffff8008000000..0xb386000 = 整个镜像地址域 (含 image base 本身)
- B 指向 19.4MB 区域 = 混合大 blob: 编码段 + 明文片段 + 其他 rodata 字符串
- 编码名长度分布: len=1: 11350, len=2: 11997, len=256(无null): 57846, 其余数千
- 明文全名 blob 已确认 (file 0x1fda000..0x20fd000 混合区): init_task@0x2018bea,
  zlib_deflate/system_state/kernel_neon_* 按地址序 = kallsyms_names 明文变体
- blob 前有引号函数原型字符串区与 MODALIAS= 等 uevent 串 (rodata 字符串区, 非符号表)
- 三元组 B 不直接指向明文名 (init_task name vaddr 0xa018bea 无 B 命中) =
  B 指向编码条目, 明文名区是另一份(运行时副本/解码源?)
- 反汇编发现 sub/ror2/cmp/blr 模式 = CFI_CLANG 类型检查 (242k 三元组疑似 CFI 函数表,
  但 C=0x401/0x403 含义未明, 也可能是华为自定义符号数据库, 未定论)
- capstone 5.0.7 已装; ADRP 交叉引用扫描脚本就绪 (find_xref/find_stream_refs/disasm_refs)

### 路线1扫描结果汇总 (2026-11-05, 静态分析已至墙沿)

- 全镜像 ADRP 扫描 (含后 23MB): 仅 2 处引用加密表附近
  (file 0x1e1b510 = udf#0 陷阱后假阳性; 0x1e1c9d8 = eor x0,x24,#0xf1f1f1f1f1f1f1f1 附近)
- F1 掩码假设 4 项测试全败: 无 _text^F1 存储; 45KB 表 F1 解密=随机;
  无掩码内核指针; 全镜像 F1 解码后内核 u64 = 0 (原本 487,902)
- 45KB 加密表确认强加密 (AES 类), 非简单 XOR/代换
- 结论: 地址表被 HIDESYMS 强加密, 静态提取需先逆向 HIDESYMS 子系统的
  解密例程 (file 0x198000-0x19c000 区域检查代码 + 0x1a9000-0x1ab400 函数簇
  + 0x1e0c00-0x1e1100 函数), 估计数天级 RE 工作
- 白名单检查函数 (file 0x1a9218): x24=0xa057000 位图区, [x0+0x100] 描述符,
  asr x25,x8,#3 = 位图字节数; 40+ 处全内核引用 0xa057000 = 位图全局变量

### 路线1下一层: 定位解码函数 (最新扫描结果 2026-11-04 深夜)

- 加密表 (file 0x200e000..0x2019000, vaddr 0xa08e000..0xa099000, 45KB/11264 u32):
  ADRP 引用 = 0, u64 全局指针 = 0, 无重复密钥特征, 无已知明文对齐
  = 强加密(AES类)或非内核消费(Bootloader/TrustZone), 静态破解成本极高
- 同类高熵块: 0x1d84000(36KB@7.98), 0x1e44000(28KB@7.98), 0x1e3e000(12KB@7.97)
  = 多个加密 blob (疑似密钥/证书/DRM 数据)
- CFI 表实锤: file 0x1e0c80 处 sub/ror2/cmp#0x16/blr = CFI 函数表引用,
  242k 三元组 = CFI 相关 (非符号表) — 此前怀疑证实
- HIDESYMS 白名单检查函数已定位: file 0x1a9218 (vaddr 0x81a9218):
  x24=0xa057000(位图区), x9=0xa05b430, [x0+0x100] 加载, asr x25,x8,#3 = 位图大小
- 白名单/位图/名字区 全部在 file 0x1fe0000..0x209dd08 (vaddr 0xa060000..0xa0fdd08)
  = HIDESYMS 保护的 kallsyms 数据区 (检查代码 0x198544 校验指针落入此区)
- 明文名字区 (init_task 等 11,258 名) 是白名单/部分表, 非全量 kallsyms
- 全量 kallsyms 地址表: 疑似被 HIDESYMS 完全移除或强加密, 静态提取需先逆
  HIDESYMS 子系统代码 (file 0x198000-0x19b000 附近 + 0x1a9000-0x1ab400 函数簇)

### 备选路线(若继续)

- 逆向 HIDESYMS 子系统 (file 0x198000-0x19c000 + 0x1a9-0x1ab4 函数簇, ~几十个函数)
- 手机升级 237 后用 panic trace 逐个泄露符号 (慢)
- 放弃 LPE, 保持 DoS 结论 (触发已 100% 复现)

### 路线1下一层: 定位解码函数

- 流基址页 ADRP 引用 = 0: 消费者经全局指针间接访问
- u64 常量搜索: 流基址 0xffffff8009769310 仅在三元组表头出现一次 (0x21869f0, 即首项 B)
- 待试1: 反汇编引用 0x96e6000-0x9700000 页的低密度代码引用 (disasm_refs.py 已写)
  — 这些页是编码 blob 前部, 引用它们的函数可能是解码器
- 待试2: 已知明文攻击 — 收集 (编码段, 明文后缀) 对, 用明文全名 blob 作字典破解代换

## 已排除路线

- mtkclient BROM: 端口能枚举 (MT65xx Preloader 0E8D:2000) 但握手无响应
  (usblib.py 已打 3 个补丁: bDeviceClass 过滤/set_option/重试+if1), 疑 SLA 锁;
  按键进不了 BROM (直接跑 preloader); mtk crash 命令也依赖握手 → 死路
- zadig 驱动替换: 端口只在线 2-3 秒来不及; 后来证明驱动本来就没问题 (WinUSB 已绑)
- 华为官方固件站/HiSuite Proxy/Firm Finder: CMA-AN00 5.0.0.224/237 无公开直链
- OTA 仅推送 40KB 小补丁 (无 boot.img), 已确认对目标无影响

## 下一步 (用户已选: 走逆向路线 1)

1. 找内核中消费编码表的解码函数: ADRP 扫描流基址页 0x9769000 = 0 引用 →
   改为本地搜 u64 常量 0xffffff8009769310 (find_globals.py 已写好未跑) 或
   ADRP 到 0x9769310 所在 4KB
2. capstone 已装 (5.0.7); 反汇编引用函数 → 复现解码算法 → Python 解码 242k 名字
3. 解码后: 与 A 配对得全符号表 → 填 ghostlock-aresin/src/targets/cma-an00/target.h
4. 编译 exploit (NDK r26 冒烟已过: 93KB aarch64) → 上机 (失败=重启属预期)
5. LPE 链: slide(boot_id 技巧) → stack reclaim(pselect) → 受限写 → fops 劫持
   (同签名函数防 CFI) → pipe physrw → 补丁 cred(uid/caps)+selinux sid → su 守护进程
6. 之后才是 LSposed (锁 BL 无 Magisk, 需内核 root 手工模拟挂载)

## 备忘

- ghostlock-app 的 AGENTS.md 是该仓库贡献者规范, 与我们"使用工具"的场景无关, 不采纳
- 真机每次 exploit 失败 = panic 重启, ADB 需重连; WiFi ADB 重启后仍在 (5555 常开)
- 用户手机可正常升级 OTA (Reqable 抓包流程已打通, 用户已会用)
- GitHub API 未认证限流 (60/h, HK IP), 网页抓取或 git clone 可绕


## 2026-11-05 补充: 逆向进展与最终状态

### 已完成的逆向

- 确认 0x1fda000 全局结构 = HIDESYMS 字符分类/名字校验表 (+0x848 = 256B 字符表,
  151 处代码引用 ldrb [x8, x10] + tbz #5 = 字符有效性检查)
- 确认 242k 三元组 = CFI 函数表 (sub/ror2/cmp/blr 模式), 非符号表
- 确认 白名单检查函数 @vaddr 0x81a9218: x24=0xa057000(位图17KB), [x0+0x100] 描述符
- 确认 HIDESYMS 保护区域 = vaddr 0xa060000..0xa0fdd08 (file 0x2000000..0x209dd08)
- 确认 45KB 加密表 (file 0x200e000) 无任何代码引用 (ADRP/全局/RELA 全查)
- 确认 F1 XOR 掩码假设失败 (4 项测试)
- 确认 RELA 重定位表 @file 0x17363d0 (34,444 项) 但无指向加密表的条目
- 确认明文名字区 = __ksymtab_strings 类 (导出符号 11,204 个, 含 init_task)
  但 __ksymtab 数组中的 name 指针 = 0 命中 (指针可能运行时重定位或不同编码)

### 未解决

- 45KB 加密地址表的解密密钥与算法 (AES 类, 密钥可能在 TrustZone/引导链)
- HIDESYMS 子系统完整逆向 (file 0x198000-0x19c000 + 0x1a9000-0x1ab400, 数十函数)
- init_task/init_cred/selinux_enforcing 的 237 内核运行时地址

### 建议下一步 (需要新会话/更多时间)

1. 用 Ghidra/IDA 加载 kernel_raw.bin (基址 0xffffff8008080000) 做 full RE
2. 逆向 HIDESYMS 初始化函数 (file 0x198000 附近, 找 AES key schedule 或 XOR 流)
3. 或: 手机升级 237 后, 用 panic trace 逐次泄露 (每次重启泄露 1-2 个符号)
4. 或: 等 ghostlock-app 社区出 CMA-AN00 profile (issue 区活跃)
