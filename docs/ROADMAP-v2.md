# linux-driver-backup 优化改进设计文档（基线 v0.1.2）

**Optimization & Improvement Design Document — baseline v0.1.2**

> 文档定位 / Scope：以 **v0.1.2 的实际实现**为基线，横向对标同类软件，给出分级优化建议、关键设计草案与路线图。
> 本文只提"方案与决策"，不含未验证的性能断言；所有对标结论均标注来源（见各节"参考"）。
> Status: 提案 / proposal（待评审后再进入 §14 路线图的排期）
> 撰写日期 / Date：2026-09-27

---

## 摘要 / Abstract

**中文**：v0.1.2 已实现"发行版自适应 + 可校验归档 + 三级备份模式 + GUI/CLI 双模 + 多架构发行包"，在**正确性**上仍有三处会被真实用户踩到的高危缺口：① 还原时跳过符号链接，会破坏 RHEL/SUSE 的 `weak-updates/` 兼容链；② 不感知 **Secure Boot**，在开启 SB 的机器上还原未签名模块会加载失败；③ 不感知**不可变发行版**（Silverblue/Bazzite/MicroOS），对只读 `/usr` 的写入必然失败。此外，**"重建优于拷贝"**这一行业内共识（DKMS / akmods / weak-modules）尚未落地，**固件**仍是全量而非按模块精确发现，**还原没有事务与回滚**。本文据此给出 P0–P3 四级优化项、归档格式 v2 草案、还原事务模型、安全启动签名流程、不可变系统策略、重建决策树，以及容器矩阵 + QEMU 真机验证计划。

**English**: v0.1.2 ships distro-adaptive backup/restore with checksummed archives and multi-arch packages, yet three high-severity correctness gaps remain: skipped symlinks break RHEL/SUSE `weak-updates/` chains; Secure Boot is not detected (restored unsigned modules will not load); immutable distros with read-only `/usr` are not handled. The ecosystem consensus "rebuild beats copy" (DKMS/akmods/weak-modules) is also not implemented, firmware is still captured wholesale, and restore has no transaction/rollback. This document proposes P0–P3 improvements, an archive format v2, a transactional restore model, a Secure Boot signing flow, an immutable-distro strategy, a rebuild decision tree, and a container-matrix plus QEMU verification plan.

---

## 1. 同类/相邻软件横向盘点 / Related Work

> 分七类。每类给出：**它们的长处** → **我们的差距** → **可借鉴点**。

### 1.1 内核模块生命周期管理 / Kernel module lifecycle

| 软件 | 领域 | 长处 | 我们可借鉴 |
|---|---|---|---|
| **DKMS** | 在每次内核升级时**重新编译并安装** OOT 模块 | 版本无关：源码 + 内核头文件 → 新内核自动重建；源码保存在 `/usr/src`，状态在 `/var/lib/dkms` | **还原首选"重建"而非"拷 .ko"**：`dkms install -m <mod> -v <ver> -k <kver>` / `dkms autoinstall -k <kver>`。v0.1.2 只存了 DKMS 源码，却仍以拷贝 `.ko` 为主路径 |
| **akmods**（Fedora/RHEL） | DKMS 的替代实现，构建后**自动签名** | 与 kernel 升级、`/etc/pki/akmods` 签名密钥、Secure Boot 流程打通 | 还原后对 Fedora 系调用 `akmods --force --kernels <kver>`；采用其密钥路径约定 |
| **weak-modules**（RHEL/SUSE 系统自带，路径 `/sbin/weak-modules`；Debian 系不提供） | 为**kABI 兼容**的其它内核建立 `weak-updates/` **符号链接** | 不用重复拷贝即可让模块对多个内核生效；`--add-modules` / `--add-kernel` / `--dry-run` | RHEL 系还原后应执行 `weak-modules --add-modules`（stdin 传模块路径）而不是仅拷贝；**同时暴露了我们跳过符号链接的缺陷（见 §2.3 D1）** |
| **SUSE KMP**（Kernel Module Package） | 发行版打包约定 | `weak-updates/` 优先级规则（`updates/` > `weak-updates/` > 其余）、安装时自动重建 initrd | 优先级模型可用于我们的"还原决策表"；印证"模块放置位置影响加载优先级" |

参考 / Sources：Red Hat 文章 *What is the purpose of weak-modules*（access.redhat.com/articles/9749）；SUSE *Kernel Module Packages Manual*（weak-updates 优先级与 initrd 自动重建）；Oracle Linux 文档 *Removing Weak Update Modules*（`weak-modules --dry-run/--verbose` 用法）。

### 1.2 系统状态与快照 / System state & snapshots

| 软件 | 长处 | 可借鉴 |
|---|---|---|
| **Timeshift** | GUI 优先、计划任务、还原前自动快照 | 还原前的**预快照钩子**；向导式 UI |
| **Snapper / Btrfs 快照** | 文件系统级原子回滚 | 把"还原前快照 + 一键回滚"作为可选集成（见 §5） |
| **etckeeper** | 用 Git 管理 `/etc`，可 diff/审计 | 备份 `/etc` 配置时给出**可读 diff**（"本次备份将改变哪些 modprobe 配置"） |
| **Clonezilla / Rescuezilla** | 离线（Live USB）整机镜像与还原 | **离线还原到指定根**：`--root /mnt/target`（救援场景，见 §3 P1-1） |

参考：各项目官方文档；etckeeper 的 VCS 化 `/etc` 模式。

### 1.3 包与应用备份 / Package & app backup

| 软件 | 长处 | 可借鉴 |
|---|---|---|
| **Aptik** | 面向"重装系统后恢复"：备份 PPA、已装包清单、应用设置 | 区分"**来自包管理器的文件**"与"手工安装的文件"，前者用重装包解决而非拷贝 |
| **apt-clone / `dnf list installed`** | 清单式恢复（重装而非复制） | 记录每个模块的**来源包**并在还原时优先 `--reinstall`（见 §3 P0-5） |

### 1.4 驱动与固件 / Drivers & firmware

| 软件 | 长处 | 可借鉴 |
|---|---|---|
| **fwupd + LVFS** | 固件**清单化 + 来源可追溯 + 签名校验** | 固件不应只是"拷文件"：记录**提供者包/来源**，并做完整性校验 |
| **`modinfo -F firmware`**（kmod） | 精确列出模块所需固件（如 iwlwifi 的 `iwlwifi-*.ucode`） | 用 `.modinfo` 节的 `firmware=` 标签**按需收集固件**，替代 v0.1.2 的 "full 模式整目录拷贝" |
| **Debian/Ubuntu `ubuntu-drivers`、厂商 `.run` 安装器** | 驱动与内核版本的匹配检查 | 还原前做 **vermagic 校验**与"是否签名"检查（见 §3 P0-2、P0-3） |

参考：Intel 社区帖展示 `modinfo iwlwifi | grep -E "filename|bz-"` 的固件清单用法；SUSE/Alpine 讨论均采用"按模块收集固件"以避免全量 `linux-firmware`。

### 1.5 Windows 对照（概念借鉴）/ Windows analogues

| 工具 | 长处 | 可借鉴 |
|---|---|---|
| **DISM `/Export-Driver` + `pnputil /add-driver`** | 导出到**每驱动一个目录**，离线批量导入，驱动仓库概念清晰 | 归档内按"驱动包"而非"目录树"组织，便于**按驱动选择/迁移单卡** |
| **Snappy Driver Installer / DriverStore Explorer** | 驱动索引数据库、离线包、重复驱动清理 | 建立**本地驱动索引**（模块 → 硬件 alias → 元数据），支持 `--list-drivers` 与按设备筛选 |

### 1.6 备份引擎（数据层借鉴）/ Backup engines

| 软件 | 长处 | 可借鉴 |
|---|---|---|
| **Borg / Restic / Kopia** | 内容寻址去重、增量、加密、可恢复传输、保留策略 | 归档 v3 引入**内容寻址块存储 + 增量 + 加密**；`--keep N` 保留策略；断点续传 |

### 1.7 不可变 / 镜像化系统 / Immutable & image-based

| 系统 | 模型 | 对我们的影响 |
|---|---|---|
| **Fedora Silverblue/Kinoite、Bazzite、openSUSE MicroOS/Aeon、Oracle 的 OSTree 镜像** | `/usr` 只读，更新经 `rpm-ostree` 原子切换，`/etc` 与 `/var` 可写 | **直接写 `/usr/lib/modules` 必然失败**；正确路径是 `rpm-ostree` 分层安装 kmod 包；`rpm-ostree usroverlay` 仅临时（重启即失效）。社区已记录 DKMS 在 rpm-ostree 沙箱内 `%posttrans` 写 `/var/lib/dkms` 失败的案例（Bazzite issue #5084） |
| **systemd-sysext** | 只读 `usr` 的可挂载扩展镜像 | 长期可选：把"模块扩展"打成 sysext 镜像 |
| **NixOS** | 声明式、`/run/current-system` | 首版**检测并明确不支持**，给出手工指引 |

参考：Fedora Discussion（`rpm-ostree usroverlay` 行为与重启失效）；Oracle 博客（OSTree 只读 `/usr`，`/var`、`/etc` 可写）；ublue-os/bazzite#5084（DKMS posttrans 在只读沙箱内失败）。

### 1.8 引导与签名 / Boot, initramfs & signing

| 工具 | 长处 | 可借鉴 |
|---|---|---|
| **dracut / mkinitcpio / update-initramfs / mkinitrd(SUSE) / mkinitfs(Alpine)** | 发行版各自的 initrd 体系，含"新增模块后自动重建"的钩子 | 扩展 §6 的 initramfs 命令矩阵；参考 KMP 模板"装模块即重建 initrd" |
| **kernel-install / ukify / systemd-boot** | UKI（统一内核镜像）把 initrd 与内核合并，**模块在 UKI 内** | 若目标机使用 UKI，必须先重建并**重签名 UKI**，否则还原无效 |
| **sbctl / sbsign / mokutil / sign-file / kmodsign** | Secure Boot 签名与密钥登记 | 形成 §6 的签名流程（key 发现 → 签名 → MOK 导入指引 → 校验 `modinfo -F sig_id`） |

参考：RHEL 9 Secure Boot 排障文（`mokutil --list-enrolled`、`sign-file`、`modinfo | grep sig`）；Linux Mint 论坛（`mokutil --sb-state`；Ubuntu 系用 `/var/lib/shim-signed/mok/`）；Arch 论坛（SB 需与内核同密钥签名）；内核文档 *Kernel module signing facility*（`CONFIG_MODULE_SIG_FORCE` / `module.sig_enforce=1` 时未签名模块被拒）。

---

## 2. v0.1.2 现状与差距 / Current state & gaps

### 2.1 现状（实现事实，非设想）/ Current implementation facts

- **扫描**：`/lib/modules` + `/usr/lib/modules` 去重遍历；`kernel/**` 视为 in-tree 排除；`updates|extra|extramodules|weak-updates|其它顶层目录` 收为 OOT；识别 `.ko{,.xz,.zst,.gz,.bz2,.lzo,.lz4}`
- **三种模式**：`minimal`（OOT + `/etc` 配置）、`standard`（+ DKMS 源码）、`full`（+ 整个 `/lib/firmware`）
- **归档**：`tar.gz` + 顶层 `manifest.json`（format_version=1、逐文件 sha256、内核/架构/发行版/模式、warnings）
- **还原**：`inspect` → 架构/内核一致性校验（`allow_kernel_mismatch`）→ 需要则 `pkexec` 自进程重入 → 解压（路径穿越防护、0644、同名先备份 `.ldbak`）→ `depmod -a` → RHEL 补 `restorecon` → 发行版 initramfs 命令
- **提权**：备份免 root；还原经 `pkexec` 单次提权，行协议 `PROGRESS/NOTE/RESULT`
- **测试**：62 单测；CLI 冒烟；本机真实扫描/备份/预演；CI 双架构构建 + 双架构 deb/rpm/tar + AppImage

### 2.2 能力矩阵 / Capability matrix

| 能力 | v0.1.2 | DKMS | akmods | weak-modules | Timeshift | fwupd | DISM(对照) |
|---|---|---|---|---|---|---|---|
| OOT 模块备份 | ✅ | —（保源码） | — | — | 快照式 | — | ✅ |
| **重建优先（跨内核）** | ❌ | ✅ | ✅ | ⚠️（kABI 链接） | ❌ | — | — |
| 固件处理 | ⚠️ 全量/可选 | — | — | — | ❌ | ✅ 清单化 | ❌ |
| 签名/Secure Boot | ❌ | ⚠️（需配置） | ✅ | — | ❌ | ✅ | — |
| 回滚 | ⚠️ `.ldbak` 手工 | — | — | — | ✅ 快照 | — | — |
| 事务性 | ❌ | ⚠️ | ⚠️ | ⚠️ | ✅ | — | — |
| 不可变系统 | ❌ | ❌（社区已知失败） | ❌ | ❌ | ⚠️ | ✅ | — |
| 离线/救援还原 | ❌ | ❌ | ❌ | ❌ | ⚠️ | — | ✅ |
| 归档可校验 | ✅ SHA-256 | — | — | — | — | ✅ 签名 | — |

### 2.3 已识别的缺口（按严重度）/ Identified gaps

| ID | 缺口 | 影响 | 证据/根因 |
|---|---|---|---|
| **D1** | 还原**跳过 symlink/hardlink**；备份时又**跟随叶子符号链接**把内容实体化 | RHEL/SUSE 的 `weak-updates/<mod>.ko -> ../../<oldkver>/extra/<mod>.ko` 还原后**断链**，模块对其它内核不可见；且备份体积虚增 | `src/restore.rs::plan_entry` 将 symlink/hardlink 一律 `SkipLink`；`src/scan.rs` 叶子链接跟随 |
| **D2** | 无 **Secure Boot** 感知 | 开启 SB 的机器上，还原的未签名模块加载失败（`Key was rejected by service`），用户以为"还原成功"却无效 | 内核文档 `CONFIG_MODULE_SIG_FORCE`；`mokutil --sb-state` |
| **D3** | 无**不可变发行版**感知 | Silverblue/Bazzite/MicroOS 上 `/usr` 只读，写入 `/usr/lib/modules` 直接失败，报错不友好 | OSTree 只读 `/usr`；DKMS 在 rpm-ostree 沙箱内失败的既有案例 |
| **D4** | 跨内核还原只做"提示"，**没有 DKMS 重建路径** | 备份 6.8 → 还原到 6.11 时 .ko ABI 不兼容，成功率低；明明存了 DKMS 源码却不用 | §1.1 行业实践 |
| **D5** | 固件"整目录"或"不备份"，未按模块精确发现 | `full` 模式动辄数百 MB；`standard` 模式又可能缺固件导致设备不可用 | `modinfo -F firmware` 可精确列出 |
| **D6** | 归档**未记录文件来源包** | 无法判断"该文件其实来自 `kmod-v4l2loopback` 包"，本可 `dnf reinstall` 一键解决，却只能拷贝 | RHEL/SUSE KMP 与 Debian DKMS 打包惯例 |
| **D7** | 还原前**未校验 vermagic**、未校验签名状态 | 跨内核/跨架构种子的坏归档要到 `modprobe` 时才发现 | `.modinfo` 节的 `vermagic=` |
| **D8** | 提权**无 polkit policy**，SSH/无桌面环境不可用 | `pkexec` 需要认证 agent；headless 只能 `sudo`（v0.1.2 已给出提示，但体验割裂） | polkit 机制 |
| **D9** | 无**回滚**与**事务** | 还原一半失败/还原后启动异常，只能手工从 `.ldbak` 恢复；无"撤销上一次还原" | — |
| **D10** | 归档**仅 SHA-256，无签名/来源认证** | 归档被替换后 SHA-256 可被同步篡改；企业/救援介质场景不满足 | fwupd 的签名模型 |
| **D11** | initramfs 命令矩阵**仅 4 家**（Debian/RHEL/Arch/Unknown） | SUSE(`mkinitrd`)、Alpine(`mkinitfs`)、Void、Gentoo、Slackware、UKI 系统覆盖不到 | §1.8 |
| **D12** | 无**离线还原到指定根** | 救援场景（Live USB 修复无法启动的系统）无法使用 | Clonezilla/Rescuezilla 的离线模型 |
| **D13** | 归档未保留 **xattr / 属主 / mtime 精度**，未做 SELinux 之外的属性处理 | 极端情况下（capability、自定义 label）不完整 | tar PAX 扩展 |

---

## 3. 分级优化建议 / Prioritized improvements

> 每项给出：**问题 → 方案 → 接口变更 → 风险 → 验证**。P0=正确性/安全，P1=兼容性/易用性，P2=性能/分发，P3=生态/长期。

### P0（0.2.0 必做）/ Correctness & security

#### P0-1 符号链接语义正确化（修 D1）/ Correct symlink semantics
- **方案**：
  1. **备份**：`scan` 不再跟随叶子符号链接，把 `kind=symlink` 与 `link_target` 记入 manifest；tar 中以 symlink 条目存储。
  2. **还原**：允许符号链接，但**只允许相对且解析后仍落在受管根**（`/lib/modules/<kver>`、`/usr/lib/modules/<kver>`、`/etc/...`）之内的目标；拒绝绝对路径与越界目标；`weak-updates/` 的典型形态（指向其它 kver 的模块）在受管根内 → **放行**，并额外校验目标在归档中被恢复或本机已存在；目标缺失时给 `NOTE` 提示（可 `--strict-links` 升级为错误）。
- **接口**：`model::EntryKind` 增加 `Symlink`；`ManifestEntry` 增加 `link_target: Option<String>`；新增 CLI `--strict-links`。
- **风险**：放宽链接后需严防通过链接逃逸写入（解析后用 `canonicalize` 校验前缀）。
- **验证**：单测覆盖"越界链接拒绝""weak-updates 链接接受""目标缺失提示"；容器内构造 RHEL 风格 `weak-updates` 夹具做端到端。

#### P0-2 Secure Boot 感知与模块签名（修 D2、D7）
- **方案**：
  1. **探测**：`/sys/firmware/efi` 存在 → 读 `mokutil --sb-state`（优先）或 `/sys/kernel/security/lockdown`；读内核 config（`/proc/config.gz` 或 `/boot/config-<kver>`）判断 `CONFIG_MODULE_SIG_FORCE`。
  2. **归档记录**（备份侧）：对每个模块记录 `signed`/`sig_id`/`sig_key`/`vermagic`（`modinfo -F` 或自解析 `.modinfo` 节）。
  3. **还原前**：比对 `vermagic` 与目标内核（用任一 in-tree 模块的 vermagic 作为基准）；不匹配 → 强提示并建议改走 **DKMS 重建**（P0-4）。
  4. **还原后**：若 SB 开启且模块未签名 → 寻找签名密钥（Ubuntu/Debian 系 `/var/lib/shim-signed/mok/`，Fedora 系 `/etc/pki/akmods/`），用 `sign-file`（RHEL/Ubuntu 补丁版 `kmodsign`）签名；密钥缺失时**不假称成功**，输出"需生成并登记 MOK"的分步指引（`mokutil --import`）。
- **接口**：`distro::secure_boot_state() -> SecureBootState`；`restore::RestoreReport` 增加 `signed: usize`、`unsigned_left: usize`；CLI `--sign-key <priv> --sign-cert <der>`、`--no-sign`。
- **风险**：私钥处理必须仅 root 可读；签名失败不得静默；MOK 登记需重启，属用户动作。
- **验证**：OVMF + `sbctl`/自签 MOK 的 QEMU 场景；断言 `modinfo -F sig_id` 非空且 `modprobe` 成功。

#### P0-3 不可变发行版策略（修 D3）/ Immutable distro strategy
- **方案**：启动时探测（`/run/ostree-booted` 存在、`rpm-ostree` 可用、`/usr` 只读挂载）→
  - **备份**：完全支持（只读不影响读）。
  - **还原**：**默认拒绝直写**，改为三条受支持路径，按可用性排序：
    1. `rpm-ostree install <对应 kmod 包>`（若 manifest 记录了来源包，见 P0-5）；
    2. `rpm-ostree override replace`（本地 rpm）；
    3. `rpm-ostree usroverlay` + 写入（**标注"重启后失效，仅临时排障"**）。
  - 目标为 NixOS（存在 `/run/current-system`）→ 明确不支持并给出声明式改法指引。
- **接口**：`distro::immutability() -> Immutability{ Nix, Ostree, ReadOnlyUsr, Mutable }`；`restore` 增加 `--on-immutable <refuse|usroverlay|ostree-install>`（默认 `refuse`）。
- **风险**：`usroverlay` 会误导用户以为"永久生效"，输出必须显式警告。
- **验证**：容器无法模拟 OSTree，改在 QEMU 里用 Fedora Atomic 镜像做一次真实还原演练（见 §13）。

#### P0-4 "重建优先"还原策略（修 D4）/ Rebuild-first restore
- **方案**：还原决策树（详见 §8）
  ```
  归档含该模块的 DKMS 源码？ ── 是 ─→ dkms install / dkms autoinstall（Fedora: akmods --force）
        │否                                   │失败
        ▼                                     ▼
  来源包已知？ ── 是 ─→ apt --reinstall / dnf reinstall ──→ 仍失败 → 拷贝 .ko（当前行为）
        │否
        ▼
  直接拷贝 .ko + depmod（当前行为）；RHEL/SUSE 追加 weak-modules --add-modules
  ```
- **接口**：`restore::RestoreStrategy { Rebuild, Reinstall, CopyTo }`；CLI `--strategy auto|rebuild|reinstall|copy`；`RestoreReport` 记录每个模块实际采用的策略。
- **风险**：重建需要内核头文件/编译工具链，缺失时应**降级并说明**，而不是失败。
- **验证**：容器内用 `dkms` 真包（如 `v4l2loopback-dkms`）做"备份 → 安装新内核 → 还原 → `modprobe` 成功"的流水线。

#### P0-5 来源包记录与"清单式还原"（修 D6）/ Package provenance
- **方案**：备份时对每个文件执行 `dpkg-query -S` / `rpm -qf`（失败则记 `owner: null`），写入 manifest v2 的 `owner` 字段；还原时若 `owner` 已知且仓库可用，**优先建议/执行重装**（`--strategy reinstall`），并把"文件已被更新版本覆盖"的情况识别出来（包版本差异）。
- **接口**：`ManifestEntry.owner: Option<Provenance{manager, package, version}>`。
- **验证**：本机 Mint（dpkg）与 Fedora 容器（rpm）各跑一次，断言 `owner.package` 正确（如 `linux-image-...`、`kmod-...`）。

#### P0-6 还原事务与回滚（修 D9）/ Transactional restore & rollback
- **方案**：
  1. **staging + 原子替换**：先解压到受管根内的临时目录（`.ldb-staging-<ts>`），全部校验通过后再逐文件 `rename` 替换；替换前把原文件**移入回滚区**（保留时间戳，不再只是同名 `.ldbak` 覆盖）。
  2. **还原日志**：`/var/lib/linux-driver-backup/restore-<ts>.json` 记录每个路径的"原状态（不存在/回滚区路径）/ 新 sha256 / 策略"。
  3. **回滚命令**：`linux-driver-backup --rollback last|<ts>` 逆序还原，并重新 `depmod` + initramfs。
  4. **可选预快照**：若检测到 `timeshift`/`snapper` 且用户开启 `--snapshot-before-restore`，先触发一次快照。
- **接口**：`restore::Transaction`；CLI `--rollback`、`--keep-rollback N`（默认保留 3 次）。
- **风险**：`rename` 跨文件系统会失败 → 回退为 copy+fsync；回滚区需容量检查（预估字节数）。
- **验证**：单测模拟"第 3 个文件写入失败"，断言已写入文件全部回滚；容器内做 `--rollback` 往返。

### P1（0.3.0）/ Compatibility & usability

| ID | 建议 | 要点 |
|---|---|---|
| P1-1 | **离线还原到指定根**（修 D12） | `--root /mnt/target`：在 Live USB 中还原到未启动的系统；`depmod`/initramfs 命令改为 `chroot` 或直接指定 `-r <root>`；这对救援场景价值极高 |
| P1-2 | **initramfs 命令矩阵扩展**（修 D11） | SUSE `mkinitrd`（dracut 包装）/`dracut -f`、**Alpine `mkinitfs <kver>`**（工具为 `mkinitfs`，非 `mkinitramfs`；亦可用 `update-kernel` 脚本）、Void `dracut -f`、Gentoo `dracut -f`/`genkernel --initramfs`、Slackware 无统一标准（`mkinitrd_command_generator.sh`，检测不到则提示）、**UKI 系统**改用 `ukify build`/`kernel-install` 并重签名（`sbctl sign`/`sbsign`） |
| P1-3 | **固件按需收集**（修 D5） | 备份：解析每个 OOT 模块的 `firmware=` 标签 → 只收集命中的 `/lib/firmware/**`（含 `.zst`/`.xz` 变体与同目录版本族）；还原：`firmware` 条目单独开关，并记录"包提供者"（来自 `linux-firmware` 的文件只记名不存内容） |
| P1-4 | **polkit 策略 + headless 路径**（修 D8） | 安装 `/usr/share/polkit-1/actions/io.github.ltbkq.linux-driver-backup.policy`（`auth_admin_keep`，减少重复弹窗、提示品牌化）；headless 明确引导 `sudo`，并支持 `--root` 离线模式 |
| P1-5 | **per-module 选择与依赖闭包** | GUI 列表加复选框；按 `.modinfo` 的 `depends=` 计算闭包，避免"选了 nvidia 却没选 nvidia-uvm" |
| P1-6 | **诊断与可观测性** | 结构化日志文件（`/var/log/linux-driver-backup.log`，轮转）+ GUI 日志面板 + `--diagnose` 一键收集（内核/发行版/SB 状态/模块列表/命令输出），便于报 issue |
| P1-7 | **`--verify` 归档体检** | 校验 sha256、manifest 一致性、vermagic、签名状态，输出报告；可在还原前强制 |
| P1-8 | **配置文件与保留策略** | `/etc/linux-driver-backup.toml` + `~/.config/...`：默认模式、输出目录、`--keep N` 轮转、签名密钥路径 |

### P2（0.4.0）/ Performance & distribution

| ID | 建议 | 要点 |
|---|---|---|
| P2-1 | **压缩算法可选 + 并行** | 现为 gzip 单线程；改为 `--compress zstd|gzip|none`，zstd 多线程（`zstd` crate 的 `zstdmt`）。模块压缩率高、体积/耗时双收益；`.ko.zst` 原样存储不二次压缩 |
| P2-2 | **单遍读取** | 现在"哈希"与"打包"两阶段各读一次文件；改为哈希阶段把数据块经有界通道交给打包阶段（大文件分块流式，内存上限可配），I/O 减半 |
| P2-3 | **归档 v3：增量 + 去重 + 加密** | 内容寻址块存储（借鉴 Borg/Restic/Kopia）：二次备份只传变化块；`--encrypt age|gpg`；可选 `--remote sftp|s3`（复用 `rclone` 或自带） |
| P2-4 | **供应链与分发渠道** | **COPR**（Fedora/RHEL）、**OBS**（openSUSE/SLE 及跨发行版）、**Launchpad PPA**（Ubuntu）、**AUR** 正式提交、**Flathub**（需改用 portal 文件对话框）、**winget 式一行安装脚本**；产物 **minisign/GPG 签名** + `SHA256SUMS` 的签名版；生成 **SBOM**（syft）与构建来源证明 |
| P2-5 | **可复现构建** | `--locked`、固定 Rust 版本、记录构建镜像 digest，产出可复验哈希（便于第三方复核二进制与源码一致） |
| P2-6 | **AppImage aarch64** | 补齐 arm64 AppImage（现仅 x86_64） |

### P3（1.0+）/ Ecosystem & long-term

| ID | 建议 | 要点 |
|---|---|---|
| P3-1 | **驱动索引与硬件别名** | 借鉴 Snipped Driver Installer：`--list-drivers`、按 `alias=` 反查设备（配合 `lspci`/`lsusb` 映射），支持"按设备导出/迁移" |
| P3-2 | **归档签名与信任链**（修 D10） | `--sign`（minisign/GPG）→ `manifest.sig`；`--require-signature`；企业内可固定公钥指纹 |
| P3-3 | **systemd-sysext 扩展镜像** | 把模块集打成 sysext，天然适配只读 `/usr` 的发行版 |
| P3-4 | **TUI 与自动化** | 无 GUI 环境的交互式 TUI（`ratatui`）；systemd timer 定期备份；`--json-progress`（NDJSON）便于外部编排 |
| P3-5 | **i18n 与可访问性** | Slint `gettext` 特性 + `@tr()`、随系统主题、`accessibility` 特性（屏幕阅读器）、键盘全操作 |
| P3-6 | **xattr/属主保真**（修 D13） | tar PAX 扩展写入 xattr、保留 mtime 精度与属主；评估 `tar` crate 的 PAX 支持或自写扩展头 |
| P3-7 | **架构重构** | 拆出 `lib.rs`（核心库）+ 薄 `main.rs`，便于集成测试、fuzz、TUI 与第三方调用 |

---

## 4. 归档格式 v2 规格草案 / Archive format v2 (draft)

**兼容策略**：`format_version` 升为 `2`；v2 读取器必须能读 v1（缺失字段按默认值）；v1 读取器遇到 v2 → 明确报错并提示升级。tar 布局不变（`manifest.json` + `data/`），新增可选 `manifest.sig`。

```json
{
  "format_version": 2,
  "tool_version": "0.2.0",
  "created_at": "2026-09-27T12:00:00Z",
  "kernel_release": "6.8.0-45-generic",
  "kernel_vermagic": "6.8.0-45-generic SMP preempt mod_unload modversions",
  "arch": "x86_64",
  "distro": { "id": "linuxmint", "version_id": "22.3", "pretty_name": "Linux Mint 22.3", "family": "debian" },
  "immutability": "mutable",
  "secure_boot": { "enabled": false, "sig_enforce": false },
  "mode": "standard",
  "compression": { "archive": "zstd-3", "modules": "as-is" },
  "entries": [
    {
      "path": "lib/modules/6.8.0-45-generic/updates/dkms/nvidia.ko",
      "size": 123456, "sha256": "…", "kind": "module",
      "strategy_hint": "rebuild",
      "owner": { "manager": "dpkg", "package": "nvidia-dkms-550", "version": "550.107.02-1" },
      "modinfo": { "vermagic": "6.8.0-45-generic SMP …", "depends": ["nvidia"], "alias": ["pci:v000010DEd…"], "firmware": ["nvidia/…bin"], "sig_id": "…", "sig_key": "…" }
    },
    { "path": "lib/modules/6.8.0-45-generic/weak-updates/foo.ko", "kind": "symlink", "link_target": "../../6.8.0-40-generic/extra/foo.ko" },
    { "path": "lib/firmware/iwlwifi-bz-a0-gm-b0-95.ucode.zst", "kind": "firmware", "owner": { "manager": "dpkg", "package": "linux-firmware", "version": "20240318.git3b128b60" }, "content_stored": false }
  ],
  "dkms": [ { "package": "nvidia", "version": "550.107.02", "kernels": ["6.8.0-45-generic"] } ],
  "warnings": []
}
```

**要点**：`owner`（来源包）、`modinfo`（vermagic/depends/alias/firmware/签名）、`link_target`（符号链接语义）、`content_stored=false`（包提供的固件不重复存储）、`strategy_hint`（重建/重装/拷贝的提示）、`compression` 与 `secure_boot` 上下文。

---

## 5. 还原事务模型 / Transactional restore

```
                         ┌──────────────────────────────┐
  1. inspect + verify ──▶│ 前置检查                     │
                         │ · sha256 全量校验            │
                         │ · 架构/内核/vermagic         │
                         │ · SB 状态 + 签名可用性       │
                         │ · 不可变系统 → 切换策略      │
                         └───────────┬──────────────────┘
                                     ▼
  2. stage            解压到受管根内 .ldb-staging-<ts>/（同文件系统，保证 rename 原子）
                                     ▼
  3. journal          写 restore-<ts>.json（每个路径的原状态与回滚区位置）
                                     ▼
  4. commit           逐文件：原文件 → 回滚区（.ldb-rollback-<ts>/），新文件 rename 就位
                     中途任一失败 → 立即按 journal 逆序回滚，返回 AppError::Cancelled/失败
                                     ▼
  5. rebuild/refresh  策略执行（§8）→ depmod → restorecon(RHEL) → initramfs/UKI → 签名校验
                                     ▼
  6. report           输出每文件策略、签名结果、需重启提示；写入"最近一次成功还原"标记
```

回滚：`linux-driver-backup --rollback last`（或 `--rollback <ts>`）→ 逆序恢复 → 重跑 `depmod` + initramfs。回滚区默认保留最近 3 次，超出按时间清理。

---

## 6. Secure Boot 签名流程 / Secure Boot signing flow

```
备份侧                              还原侧
─────                              ─────
modinfo -F sig_id/sig_key  ──▶     读取 manifest 的签名元数据
modinfo -F vermagic          ──▶   与目标内核 vermagic 比对
                                   │
                     SB 关闭 ──────┴────── SB 开启
                       │                    │
                    直接安装          模块已签名？─是─▶ 直接安装
                                           │否
                                           ▼
                                  找密钥：/var/lib/shim-signed/mok/*（Debian 系，已实测存在 MOK.priv/MOK.der）
                                          /etc/pki/akmods/*（Fedora 系）
                                          --sign-key/--sign-cert 显式指定
                                           │
                                     无密钥 ─▶ 不假称成功，输出 MOK 生成与登记步骤：
                                               openssl req -new -x509 -nodes -newkey rsa:2048 \
                                                 -keyout MOK.priv -outform DER -out MOK.der -days 36500 -subj "/CN=…/"
                                               mokutil --import MOK.der    # 重启时完成登记
                                           │有密钥
                                           ▼
                                  sign-file sha256 MOK.priv MOK.der <module.ko>
                                           ▼
                                  校验 modinfo -F sig_id 非空 + 尝试 modprobe -n（dry）
```

补充：若内核 `CONFIG_MODULE_SIG_FORCE` 或 `module.sig_enforce=1`，未签名模块**必然被拒**，此时未签名即视为**失败**而非警告。UKI 系统还需 `ukify`/`kernel-install` 重建并重签 UKI。

---

## 7. 不可变发行版策略 / Immutable distro strategy

| 探测信号 | 判定 | 备份 | 还原默认行为 | 可选覆盖 |
|---|---|---|---|---|
| `/run/ostree-booted` 存在 | OSTree（Silverblue/Bazzite/MicroOS） | ✅ 支持 | **拒绝直写**，指引 `rpm-ostree install/override`；`--on-immutable usroverlay` 时用 `rpm-ostree usroverlay` 并**警告重启失效** | `rpm-ostree install <kmod 包>` / `override replace <rpm>` / `usroverlay` |
| `/run/current-system` 存在 | NixOS | ✅ 支持 | 明确不支持，给声明式配置指引 | — |
| `/usr` 只读挂载（`/proc/mounts` 含 `ro`） | 通用只读 | ✅ | 切到 `--root` 离线模式或提示解除只读 | `--root` |
| 以上皆无 | 可变系统 | ✅ | 现有流程 | — |

---

## 8. 重建优先决策树 / Rebuild-first decision tree

```
对归档内每个 OOT 模块 M：
 1) manifest.dkms 含 M 的源码？ ──▶ Debian 系: dkms install -m <pkg> -v <ver> -k <kver>
                                     Fedora 系: akmods --force --kernels <kver>
                                     依赖：内核头/kernel-devel + gcc + make；缺失则降级并记录
 2) owner 已知且仓库可用？    ──▶ apt-get install --reinstall <pkg> / dnf reinstall <pkg>
                                 （能同时修复"文件被升级覆盖"的情况）
 3) RHEL/SUSE 且模块 kABI 兼容？ ──▶ 写入 extra/ 后 weak-modules --add-modules（stdin 列表），
                                     为其它已装内核建立 weak-updates 符号链接
 4) 兜底：拷贝 .ko（+ .zst 原样） → depmod -a <kver> → restorecon(RHEL) → initramfs
失败处理：逐级降级并写 NOTE；最终失败则保持 P0-6 的事务回滚。
```

---

## 9. 固件精确发现 / Firmware discovery

1. 对每个 OOT 模块取 `firmware=` 列表：优先 `modinfo -F firmware <module>`（**已实测**：kmod 31 的 `modinfo -F firmware iwlwifi` → `iwlwifi-100-5.ucode …`，`r8169` → `rtl_nic/rtl8126a-3.fw …`）；兼容回退为 `modinfo <module> | grep '^firmware:'`；完全没有 `kmod` 时自解析 ELF 的 `.modinfo` 节。
2. 在 `/lib/firmware` 内做**前缀目录 + 版本族**匹配（如 `iwlwifi-bz-a0-*-86.ucode`），并同时纳入 `.zst`/`.xz` 压缩变体。
3. **包来源判定**：`dpkg -S` / `rpm -qf` → 若来自 `linux-firmware` 等系统包，则只记 `content_stored:false`（还原时校验存在性并提示 `apt/dnf reinstall linux-firmware`），显著缩小归档。
4. 还原：`firmware` 条目独立开关（`--with-firmware` 保留），并对**已存在的同名文件做版本比对**，避免降级覆盖更新的固件。

---

## 10. 性能优化 / Performance

| 项 | 现状 | 目标 | 手段 |
|---|---|---|---|
| 压缩 | gzip 单线程 | zstd 多线程，体积/速度双优 | `--compress zstd`（`zstdmt`），`.ko.zst` 不二次压缩 |
| I/O | 哈希、打包各读一遍 | 单遍 | 哈希阶段经有界通道把块交给打包阶段，内存上限可配（默认 64 MiB） |
| 并行度 | Hasher ≤ 4 线程 | 可配 `--jobs N`，按设备类型（SSD/HDD）给默认值 | 线程池 + 背压；进度按字节加权（保持 §4.4 分段） |
| 大目录 | `full` 模式固件上万文件 | 由 §9 精确化后条目数降 1–2 个数量级 | 固件按需收集 |
| 冷启动 | GUI 启动即建窗口 | 不变 | — |

> 原则：所有性能项**不得**牺牲 §5 的事务性与 §6 的签名校验顺序。

---

## 11. 易用性 / Usability

- **文件对话框**：引入 XDG portal（`ashpd` 或 `rfd --features xdg-portal`），避免依赖 GTK；同时满足 Flathub 沙箱要求。
- **进度与 ETA**：显示已处理字节/总量、剩余时间、当前文件；失败时保留**可复制的诊断摘要**。
- **列表交互**：搜索/过滤（按 kind、名称）、排序（体积/名称）、按模块勾选 + 依赖闭包提示。
- **主题与可访问性**：跟随系统深浅色；开启 Slint `accessibility` 特性；全键盘可达。
- **i18n**：Slint `gettext` 特性 + `@tr()`；先提供 zh_CN / en_US。
- **CLI**：`--json-progress`（NDJSON）、`--quiet`、`--dry-run` 输出人类可读计划、`--list-archives`、shell 补全脚本、man page。
- **首次运行引导**：检测 SB / 不可变系统 / 缺失工具链，一次性给出"你的机器需要什么"的清单。

---

## 12. 分发与供应链 / Distribution & supply chain

| 渠道 | 目标发行版 | 说明 |
|---|---|---|
| COPR | Fedora / RHEL / 衍生 | 直接 `dnf copr enable` + 自动跟随版本 |
| OBS | openSUSE / SLE / 跨发行版 | 可同时产出 deb/rpm/AppImage |
| Launchpad PPA | Ubuntu / Mint | apt 源体验 |
| AUR | Arch | `makepkg -si` / `yay -S` |
| Flathub | 通用 | 沙箱内需 portal 文件对话框 + `--root` 等能力受限，需权限说明 |
| GitHub Releases | 通用兜底 | 现有渠道，保留 |

**供应链加固**：minisign/GPG 签名发布产物（`SHA256SUMS` + `SHA256SUMS.sig`）、公钥固定说明、SBOM（syft）、构建来源证明（SLSA）、可复现构建参数记录。归档侧引入 `--sign/--require-signature`（P3-2）。

---

## 13. 测试与验证计划 / Verification plan

| 层级 | 手段 | 覆盖 |
|---|---|---|
| 单元 | 现有 62 项 + 新增：symlink 越界/合法、vermagic 比对、签名探测、事务回滚逆序、固件族匹配 | 纯函数与状态机 |
| 夹具 | 构造"伪内核树"（含 kernel/、updates/dkms、weak-updates 链接、/etc 配置、固件） | 扫描/备份/预演无需真机 |
| 容器矩阵 | `ubuntu:22.04` / `debian:12` / `fedora:40` / `archlinux` 内跑 `--scan/--backup/--restore --dry-run`，并真实执行 deb/rpm 安装 | 发行版差异、包元数据正确性 |
| QEMU 真机 | ① 可变系统：还原 → 重启 → `lsmod` 验证；② **Secure Boot**（OVMF + sbctl/自签 MOK）：还原 → 签名 → `modprobe` 成功；③ **Fedora Atomic**：验证不可变路径的拒绝/`usroverlay` 警告 | 端到端与内核真实行为 |
| 模糊测试 | `cargo-fuzz` 对归档解析（tar/manifest/link_target） | 路径穿越与 panic |
| 回归守门 | CI 增加"依赖名断言"（已有）、"Requires 解析样例"、"manpage/desktop 校验" | 防止 v0.1.1 的 Fedora 类事故复现 |

---

## 14. 路线图 / Roadmap

| 版本 | 主题 | 包含项 | 验收标准 |
|---|---|---|---|
| **0.2.0** | 正确性与安全 | P0-1…P0-6（符号链接、Secure Boot、不可变系统、重建优先、来源包、事务回滚） + 归档 v2 | QEMU 三场景（可变/SB/Atomic）全通过；容器矩阵全绿；v1 归档仍可读 |
| **0.3.0** | 兼容性与体验 | P1-1…P1-8（离线 `--root`、initramfs 矩阵、按需固件、polkit、模块勾选、诊断、`--verify`、配置与保留） | Live USB 场景实测；SUSE/Alpine 容器扫描正确；GUI 新增交互通过人工验收 |
| **0.4.0** | 性能与分发 | P2-1…P2-6（zstd 并行、单遍 I/O、增量/加密、COPR/OBS/PPA/AUR/Flathub、签名与 SBOM、AppImage arm64） | 相比 v0.1.2：full 模式体积/耗时显著下降；渠道安装命令可用 |
| **1.0** | 生态 | P3-1…P3-7（驱动索引、归档签名、sysext、TUI/自动化、i18n/无障碍、xattr、lib 化） | 归档签名可校验；i18n 完整；库 API 稳定 |

---

## 15. 风险与取舍 / Risks & trade-offs

| 风险 | 影响 | 缓解 |
|---|---|---|
| Secure Boot 签名涉及用户私钥与 MOK 登记（需重启） | 体验中断、误操作 | 默认"检测 + 指引"，仅在显式 `--sign-key` 时自动签名；绝不静默失败 |
| 不可变系统的 `usroverlay` 是临时方案 | 用户误以为永久生效 | 输出层强警告 + `RestoreReport.notes` 永久记录 |
| DKMS/akmods 重建需要编译工具链与内核头 | 服务器最小化系统常缺失 | 决策树逐级降级；缺失时明确说明"已回退到拷贝，可能 ABI 不兼容" |
| 归档 v2 增加元数据收集（modinfo/dpkg -S/rpm -qf） | 备份变慢 | 元数据命令并行/批量（`dpkg-query -S` 支持一次多路径），并设 `--fast` 跳过 |
| 事务回滚区占磁盘 | 空间不足 | 还原前预估空间并检查；默认保留 3 次 |
| 引入 portal/签名等依赖 | 二进制体积与构建复杂度上升 | 依赖设为可选特性；核心仍保持"无 tokio、无重量级运行时" |
| 与包管理器语义竞争（重装 vs 拷贝） | 用户困惑 | 在 GUI/CLI 明确展示"该文件的正确修复方式是重装包 X" |

---

## 16. 验证记录 / Verification log

> 本节的目的是让文档**可被复核**：每条关键断言都标注验证方法与结果。
> 验证日期 2026-09-27；环境：Linux Mint 22.3（Ubuntu 20.04+ 系）/ 内核 7.3.0-070300rc3 / kmod 31 / dkms 3.0.11 / rustc 1.98.1。
> 方法代号：**S**=源码逐条核对（file:line）、**E**=本机实验、**U**=上游文档/包页面。

### 16.1 对 v0.1.2 实现的断言（全部与源码一致）/ Claims about the v0.1.2 implementation

| # | 断言 | 方法 | 证据 | 结论 |
|---|---|---|---|---|
| 1 | 还原跳过符号链接/硬链接 | S | `src/restore.rs:168,181,398,645`（`EntryAction::SkipLink`，含 `is_symlink() \|\| is_hard_link()` 判定） | ✅ 证实 |
| 2 | 备份跟随**叶子**符号链接（目录链接不跟随） | S | `src/scan.rs:319` 注释 + `:328` `file_type.is_symlink()` 处理 | ✅ 证实 |
| 3 | 无 Secure Boot / vermagic / 签名相关实现 | S | `grep -rn "vermagic\|sig_id\|secure_boot\|mokutil" src/` → 无命中 | ✅ 证实 |
| 4 | 无 `modinfo`/`firmware=` 解析（固件非按需） | S | `grep -rn "modinfo\|firmware=" src/` → 仅 `restore.rs:537` 注释提及 | ✅ 证实 |
| 5 | 无来源包查询（dpkg/rpm 归属） | S | `grep -rn "dpkg-query\|rpm -qf\|dpkg -S" src/ packaging/` → 无命中 | ✅ 证实 |
| 6 | 未安装 polkit policy | S | `find . -name '*.policy'` → 无 | ✅ 证实 |
| 7 | `.ldbak` 是覆盖式（非时间戳回滚区） | S | `src/restore.rs:31`（后缀定义）、`:317`（已存在则覆盖） | ✅ 证实 |
| 8 | 归档仅有 SHA-256、无签名 | S | 源码无 minisign/GPG 校验路径 | ✅ 证实 |
| 9 | initramfs 命令矩阵仅 3 族 + Unknown→None | S | `src/distro.rs::initramfs_cmd` 仅 `Debian/Rhel/Arch` 分支 | ✅ 证实 |
| 10 | CLI 无 `--root`（离线还原） | S | `src/main.rs::parse_args` 无该选项 | ✅ 证实 |
| 11 | tar 仅写 mode/mtime/uid/gid，无 xattr/PAX | S | `src/backup.rs:716-719`、`:764-768` | ✅ 证实 |
| 12 | 哈希与打包各读文件一遍（双读） | S | `src/backup.rs:555-556`（`hash_file` → `File::open`）与 `:758`（`write_entry` → `File::open`） | ✅ 证实 |
| 13 | `.ko` 压缩变体识别清单 | S | `src/scan.rs:310`：`.xz .zst .zstd .gz .bz2 .lzo .lz4` | ✅ 与 §2.1 一致 |
| 14 | 项数声明（P0=6 / P1=8 / P2=6 / P3=7 / D=13） | S | 脚本统计文档编号 | ✅ 一致 |
| 15 | 13 项缺口均有对应的优化项 | S | 脚本映射：D1→P0-1 … D13→P3-6，无孤立项 | ✅ 一致 |

### 16.2 外部技术断言 / External technical claims

| # | 断言 | 方法 | 证据 | 结论 |
|---|---|---|---|---|
| 16 | `weak-modules` 建立 `weak-updates/` 符号链接，支持 `--add-modules/--add-kernel/--dry-run` | U | Red Hat 文章 *What is the purpose of weak-modules*（access.redhat.com/articles/9749）；SUSE *KMP Manual*（优先级 `updates`>`weak-updates`>其余）；Oracle Linux 文档（`--dry-run --verbose`） | ✅ 证实 |
| 17 | `weak-modules` **由哪个包提供** | U | kmod 类 spec/scriptlet 以 `[ -x /sbin/weak-modules ]` 检测调用；Debian 系不提供（**本机实测不存在**） | ⚠️ 原稿写"由 kmod 包提供"**过宽** → 已改为"RHEL/SUSE 系统自带，Debian 系不提供" |
| 18 | `dkms autoinstall -k <kernel/arch>` 可用 | U | Ubuntu noble `dkms(8)` man page：`autoinstall [-k kernel/arch]` | ✅ 证实 |
| 19 | `modinfo -F firmware` 可列模块所需固件 | **E**+U | 本机 kmod 31 实测：`modinfo -F firmware iwlwifi` → `iwlwifi-100-5.ucode …`；`r8169` → `rtl_nic/rtl8126a-3.fw …`；回退形式 `modinfo <m> \| grep '^firmware:'` 同样有效 | ✅ 证实（已把实测证据写入 §9） |
| 20 | Debian/Ubuntu 系 MOK 位于 `/var/lib/shim-signed/mok/` | **E** | 本机实测存在 `MOK.priv`(0600) 与 `MOK.der` | ✅ 证实 |
| 21 | Secure Boot 下未签名模块被拒；`CONFIG_MODULE_SIG_FORCE`/`module.sig_enforce=1` 时强制 | U | 内核文档 *Kernel module signing facility*；RHEL 9 排障文（`mokutil --list-enrolled`、`sign-file`、`modinfo \| grep sig`）；Mint 论坛（`mokutil --sb-state`） | ✅ 证实 |
| 22 | 不可变系统 `/usr` 只读；`rpm-ostree usroverlay` 为临时覆盖 | U | Fedora Discussion（usroverlay 重启失效）；Oracle OSTree 博客（`/usr` 只读，`/etc`、`/var` 可写）；ublue-os/bazzite#5084（DKMS 在 rpm-ostree 沙箱内写 `/var/lib/dkms` 失败） | ✅ 证实 |
| 23 | **Alpine 的 initramfs 工具名** | U | Alpine Wiki *Initramfs init*：`mkinitfs -c /etc/mkinitfs/mkinitfs.conf -b / <kernelvers>`（`mkinitramfs` 是 Debian `initramfs-tools` 的低层内部脚本，非 Alpine 工具） | ❌ **原稿误写 `mkinitramfs -k <kver>`** → 已在 §1.1/§1.8/D11/P1-2 全部修正为 `mkinitfs <kver>` |
| 24 | 归档签名的路线图版本归属 | S | 一致性检查发现附录 A 写 `0.2.0(v2)`，与 §3 P3-2、§14 的 `1.0` 冲突 | ❌ **自相矛盾** → 已统一为 `1.0（v2 预留 manifest.sig 字段）` |

### 16.3 文档质量检查 / Document quality checks

| 项 | 方法 | 结果 | 处置 |
|---|---|---|---|
| 中文占比（"以中文为主"） | E（脚本统计，去代码块） | 汉字 5418 / 英文词 1492 → **78.4%** | ✅ 达标 |
| 二级/三级标题双语对照 | E | 发现 1 处缺英文（§2.1） | ⚠️ 已补 `/ Current implementation facts` |
| 缺口↔对策映射完整性 | E | D1–D13 全部有归属优化项 | ✅ |
| 路线图与分级项一致性 | E | 0.2.0=P0(6)、0.3.0=P1(8)、0.4.0=P2(6)、1.0=P3(7) | ✅ |

### 16.4 验证结论 / Conclusion

- **证实 21 项**（13 项代码行为 + 8 项外部事实），其中 2 项由**本机实验**直接证明（`modinfo -F firmware`、MOK 密钥路径）。
- **修正 2 项表述**：`weak-modules` 的包归属（过宽 → 精确）、附录 A 的归档签名版本（自相矛盾 → 统一）。
- **纠正 1 项技术错误**：Alpine 的 initramfs 工具应为 `mkinitfs`，原稿 `mkinitramfs -k` 有误（涉及 §1.1 / §1.8 / D11 / P1-2 共 4 处）。
- **文档质量**：中文占比 78.4%、标题双语、无孤立缺口、路线图与分级项一致。
- 未验证项（需落地时用 QEMU/真机确认，已列入 §13）：Secure Boot 签名后 `modprobe` 成功率、OSTree 系统上三条还原路径的实际可用性、`weak-modules` 在 RHEL 上对还原模块的接受度、UKI 重建流程。

---

| 功能 | v0.1.2 | 0.2.0(计划) | DKMS | akmods | weak-modules | Timeshift | fwupd | Clonezilla | DISM |
|---|---|---|---|---|---|---|---|---|---|
| OOT 模块备份 | ✅ | ✅ | 源码 ✅ | 源码 ✅ | — | 快照 ⚠️ | — | 镜像 ✅ | ✅ |
| 跨内核重建 | ❌ | ✅ | ✅ | ✅ | ⚠️ kABI | ❌ | — | ❌ | — |
| 符号链接语义 | ❌ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ | — |
| 固件按需 | ❌ | ✅ | — | — | — | ❌ | ✅ 清单 | ✅ 整机 | ✅ |
| Secure Boot 签名 | ❌ | ✅ | ⚠️ | ✅ | — | ❌ | ✅ | ❌ | ❌ |
| 事务/回滚 | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ | ✅ | — | ✅ 镜像级 | — |
| 不可变系统 | ❌ | ✅（指引/临时） | ❌ | ❌ | ❌ | ⚠️ | ✅ | ✅ | — |
| 离线 `--root` 还原 | ❌ | 0.3.0 | ❌ | ❌ | ❌ | ⚠️ | — | ✅ | ✅ |
| 归档签名 | ❌ | 1.0（v2 预留 `manifest.sig` 字段） | — | — | — | — | ✅ | ⚠️ | — |
| 增量/去重 | ❌ | 0.4.0 | — | — | — | ⚠️ | — | ⚠️ | — |
| GUI | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | CLI | ✅ | ✅ |

## 附录 B：术语表 / Glossary

| 中文 | English | 说明 |
|---|---|---|
| 外置模块 | out-of-tree module (OOT) | 不在内核源码树内、非发行版内核包自带的模块 |
| kABI | kernel ABI | 内核导出符号版本校验，决定模块能否跨内核加载 |
| 弱更新 | weak-updates | RHEL/SUSE 用符号链接让 kABI 兼容模块对多个内核生效 |
| 统一内核镜像 | UKI (Unified Kernel Image) | 内核+initrd+cmdline 合并的 EFI 可执行文件，模块在其中时需重建并重签 |
| 机器所有者密钥 | MOK (Machine Owner Key) | Secure Boot 下用户自签名模块的信任链 |
| 不可变系统 | immutable / image-based OS | `/usr` 只读、更新原子化的发行版（Silverblue / MicroOS 类） |
| 内容寻址 | content-addressed storage | 以哈希寻址的块存储，天然去重，供增量备份使用 |

---

> **说明**：本文档为提案。落地前建议先评审 P0 范围（是否有必要在 0.2.0 一次做满 6 项），并确认是否引入 `ashpd`/`zstd`/`minisign` 等新依赖（当前项目刻意保持"无 tokio、无重量级运行时"的依赖纪律）。
