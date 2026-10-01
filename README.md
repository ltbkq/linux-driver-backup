# Linux 驱动备份与还原工具

**Linux Driver Backup & Restore Tool — a Rust + Slint desktop application**

一行简介 / One-line intro:
**中文**：一个发行版自适应的 Linux 外置（out-of-tree）驱动备份与还原工具，提供 GUI 与 CLI 双模式，产出可校验、可跨机还原的 `tar.gz` 归档。
**English**: A distro-adaptive backup & restore tool for Linux out-of-tree drivers, with both GUI and CLI front-ends, producing checksummed `tar.gz` archives that can be restored across machines.

<!-- 徽章 / Badges -->
[![CI](https://github.com/ltbkq/linux-driver-backup/actions/workflows/build/badge.svg)](https://github.com/ltbkq/linux-driver-backup/actions/workflows/build.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Rust: 1.92+](https://img.shields.io/badge/rust-1.92%2B-orange.svg)](https://www.rust-lang.org/tools/install)

---

## 目录 / Table of Contents

- [功能特性 / Features](#功能特性--features)
- [界面预览 / Screenshots](#界面预览--screenshots)
- [安装 / Installation](#安装--installation)
- [快速开始 / Quick Start](#快速开始--quick-start)
- [使用方法 / Usage](#使用方法--usage)
- [备份内容与归档格式 / What is Backed Up](#备份内容与归档格式--what-is-backed-up)
- [权限说明 / Privileges](#权限说明--privileges)
- [备份范围限制与风险 / Limitations](#备份范围限制与风险--limitations)
- [开发 / Development](#开发--development)
- [许可 / License](#许可--license)
- [贡献 / Contributing](#贡献--contributing)

---

## 功能特性 / Features

- **发行版自适应 / Distro-adaptive**：自动探测 Debian 系（Ubuntu、Linux Mint、Debian…）、RHEL 系（Fedora、Rocky、AlmaLinux、CentOS…）、Arch 系（Arch、Manjaro、EndeavourOS…）与未知发行版；按发行版选择 `depmod` 之后的 initramfs 更新命令（`update-initramfs` / `dracut` / `mkinitcpio`），未知发行版则明确跳过而不谎报成功。*Detects the distro family and picks the right initramfs tool.*
- **三级备份模式 / Three-tier backup modes**：外置（out-of-tree）模块 + DKMS 源码 + 配置文件 + 可选固件，分为 `minimal` / `standard`（默认）/ `full` 三档，按需在体积与完整性之间取舍。*Choose between minimal, standard and full scope.*
- **可校验归档 / Verifiable archive**：`tar.gz` 内含 `manifest.json`，记录格式版本、工具版本、内核版本、架构、发行版、备份模式，以及**逐文件 SHA-256**；还原前先读清单校验，支持跨机还原。*Every file is hashed with SHA-256 and listed in `manifest.json`.*
- **GUI + CLI 双模 / Dual front-ends**：桌面环境用 Slint 图形界面；无显示环境、自动化脚本与 CI 冒烟测试用同一二进制的命令行参数完成扫描、备份与还原。*One binary, both a Slint GUI and a scriptable CLI.*
- **单文件分发 / Single-file delivery**：`cargo build --release` 产出一个可执行文件，无需 Python / Qt / C++ 运行时；Slint 采用 `default-features = false` 裁剪特性并使用软件渲染，避免 OpenGL/EGL 依赖。*One stripped binary, no runtime toolchain required.*
- **非破坏性还原 / Non-destructive restore**：还原前可先 `--dry-run` 预演（只打印计划、不写盘）；目标位置已存在同名文件时先备份为 `*.ldbak` 再覆盖；写入完成后强制执行 `depmod -a <kver>`（RHEL 系并补 `restorecon`），最后按发行版自适应更新 initramfs——没有 `depmod` 就不会有 `modules.dep`/`modules.alias`，还原等于无效。*Dry-run preview, `.ldbak` safety copies, mandatory `depmod`, then distro-adaptive initramfs update.*
- **多线程流水作业 / Pipelined workers**：扫描 → 打包两段式流水线（哈希并入打包，单遍读，C-38），`std::thread` + 有界通道背压，进度实时回传、可随时取消，全程不阻塞 UI。*A two-stage pipeline keeps the UI responsive.*

## v0.3.0 新增 / What's new in v0.3.0

> 对应 [docs/ITERATION-v0.3.0.md](docs/ITERATION-v0.3.0.md) 的 W1–W9：还原事务完备化、扫描/元数据修复、离线还原收尾、
> 固件按需收集、GUI 强化、CLI/配置、打包与 CI 加固。**归档格式仍为 v2**（仅语义收紧，字段只增不删）。
> The W1–W9 work of the iteration document: transactional restore, scan/metadata fixes, offline restore,
> on-demand firmware, GUI enhancements, CLI/config, packaging & CI. **Archive format stays v2.**

- **还原事务完备化（W1）**：目录创建入 WAL、系统阶段失败默认自动回滚（`--no-auto-rollback-on-post` 可保留事务）、外部命令（`dkms install`/`akmods`/重装/`weak-modules`）逆序补偿、回滚文件名 URL 转义单射化、`run_id` 秒内唯一 + 孤儿清理 + 状态排他锁、`RestorePlan` 让 dry-run 与实跑统计同源、`inspect` 进程内缓存。
- **离线还原（W4）**：`--root <目录>` 下发行版/vermagic/Secure Boot/不可变状态全部改为读取**目标根**；`--chroot-exec` 增加提前 root 预检。
- **扫描修复（W3）**：`rpm -qf`/`modinfo` 批量化（消除数万次进程）、`kernel/` 子树链接不再误判、配置目录扩至 11 条、`/usr/lib/firmware` 回退、`dkms.conf` 的 `PACKAGE_NAME` 识别、告警去重封顶。
- **备份单遍哈希（C-38）**：哈希与打包合并为一次读取，`manifest.sha256` 恒等于归档内实际字节；输出改为**同目录临时文件 + 成功后才原子替换**，失败不再毁掉旧备份（C-37）。
- **固件按需收集（W5）**：新增 `--firmware all|needed|none`，按模块 `modinfo.firmware` 标签精选固件并写入 manifest。
- **GUI 强化（W6）**：原生文件对话框（rfd）、勾选还原（含 `modinfo.depends` 依赖闭包）、策略与 `--strict-links`/`--no-sign`/`--on-immutable` 开关、扫描告警常驻面板、一键诊断包与回滚入口、行内显示 path/owner/vermagic。
- **CLI 与配置（W7）**：新增 `--verify [ARCHIVE] [--json]`（逐条 SHA-256 体检）、`--require-verify`、`--diagnose [OUT]`（脱敏诊断包）、`--keep-rollback <n>`、`--config <f>`；零依赖配置文件 `/etc/linux-driver-backup.toml` 与 `~/.config/linux-driver-backup/config.toml`（6 键，CLI 旗标优先）。
- **打包与 CI（W8/W9）**：版本/架构解析统一到 `packaging/lib/common.sh`；PKGBUILD 渲染 + `.SRCINFO`；RPM `--rpm-target fedora|suse|both`；polkit policy 随包安装；CI 新增 `fmt`/`clippy`/`shellcheck`/`desktop-file-validate`/`cargo audit`/MSRV/安装冒烟与 aarch64 qemu，action 全部 pin 到 commit SHA。

## v0.2.1 修复 / What's fixed in v0.2.1

> 对应 [docs/ITERATION-v0.3.0.md](docs/ITERATION-v0.3.0.md) §2.1 的 **14 项安全与正确性热修**；无新功能、归档格式不变。
> The 14 security & correctness hotfixes of §2.1: no new features, archive format unchanged.

| 修复 / Fix | 说明 / Details |
|---|---|
| **符号链接禁闭** / symlink jail | `etc/` 链接目标归一化校验（拒绝指向 `/`、`..` 逃逸、白名单前缀外的绝对目标）；提取时逐路径组件 `symlink_metadata` 检查，杜绝穿链接任意写。/ Link targets are normalized and contained; each path component is checked before writing. |
| **写前日志（WAL）** / write-ahead log | 每条目先 `fsync` 落日志再变更；崩溃/断电后 `--rollback` 可从 JSONL 日志恢复。/ Every entry is journaled and fsynced before mutation; `--rollback` recovers from the JSONL log after a crash. |
| **manifest 权威化** / manifest is authoritative | 非法路径与归档内未登记条目一律硬错误，不再静默丢弃。/ Illegal manifest paths and unregistered archive entries are hard errors instead of silent drops. |
| **归属查询修复** / provenance queries | 读取 stdout 不看退出码（`dpkg-query -S` 批内部分失败不再丢弃整批）；usr-merge 归一化让 `/lib/…` 也查得到来源包。/ stdout is read regardless of exit code, with usr-merge path normalization. |
| **提权前校验** / elevation trust check | pkexec 前要求自身二进制 `uid==0` 且组/其他不可写，dev 构建与 AppImage 不再以 root 执行用户可写文件。/ The binary handed to pkexec must be root-owned and not group/world-writable. |
| **架构检查解耦** / independent arch check | 架构不符需独立的 `--allow-arch-mismatch`（或交互/确认框确认），`--allow-kernel-mismatch` 不再顺带放行。/ Arch mismatch now requires its own consent. |
| **默认目标内核** / default target kernel | 还原默认以**当前内核**为目标（联网），跨内核差异降级为提示并按 DKMS 重建；删除 GUI 死逻辑传参。/ Online restores default to the running kernel with rebuild-first; dead code removed. |
| **退出码契约** / exit codes | `0` 成功或用户主动取消、`1` 运行失败（含 JSON 输出失败）、`2` 用法错误；`tests/exit_codes.rs` 集成测试守护。 |
| **GUI 二次确认** / GUI confirmation | 真实还原前弹出确认框，列出归档、内核/架构差异与"将写入系统目录"警告，取消零副作用。/ A confirmation dialog lists the archive, kernel/arch delta and the root-write warning before any change. |
| **dry-run 严格只读** / strictly read-only dry-run | 不可变系统闸门移到预演返回之后，预演永不执行 `rpm-ostree` 等变更命令。/ The immutable gate runs after dry-run returns; previews never execute mutating commands. |
| **staging 清理** / staging cleanup | 失败路径（含 `?` 提前返回）清理 `.ldb-staging-*`，并提供启动时清扫。/ Staging leftovers are removed on every exit path. |

## v0.2.0 新增能力 / What's new in v0.2.0

> 对应 [docs/ROADMAP-v2.md](docs/ROADMAP-v2.md) 的 **P0（正确性与安全）** 计划，归档格式升级为 **v2**（v1 归档仍可读）。
> Implements the P0 (correctness & security) items of the roadmap; archive format is now **v2** while v1 stays readable.

| 能力 / Capability | 说明 / Details |
|---|---|
| **符号链接语义** / correct symlink semantics | 备份不再"实体化"链接；RHEL/SUSE 的 `weak-updates/<m>.ko -> ../../<kver>/extra/…` 与 `/etc` 下的配置别名（含绝对目标）都能原样还原。/ `weak-updates` chains and `/etc` config aliases (including absolute targets) are restored as real symlinks. |
| **重建优先** / rebuild-first | 还原策略决策树：DKMS 重建（`dkms install` / `akmods --force`）→ 重装来源包（`apt --reinstall` / `dnf reinstall`）→ `weak-modules --add-modules`（RHEL/SUSE）→ 拷贝兜底；失败自动降级为拷贝并提示。/ Automatic strategy selection with transparent fallback to copying. |
| **Secure Boot 感知与签名** / Secure Boot aware | 记录模块 `vermagic`/`sig_id`；还原前比对 vermagic，SB 开启时用 MOK 密钥（`/var/lib/shim-signed/mok`、`/etc/pki/akmods`）自动签名（`sign-file`/`kmodsign`）；未签名且内核强制签名时报错而非谎报成功。/ Records and verifies vermagic, signs restored modules with the MOK key, refuses to pretend success when signing is enforced. |
| **不可变系统防护** / immutable distros | 探测 OSTree（Silverblue/Bazzite/MicroOS）与 NixOS：默认**拒绝**直写 `/usr/lib/modules` 并给出替代路径；`--on-immutable usroverlay` 可用临时覆盖层（重启失效，明确警告）。/ Detects immutable distros and refuses unsafe writes by default. |
| **事务化还原与回滚** / transactional restore | 每条目先写同目录暂存再原子 `rename`，覆盖前把原文件移入回滚区，全程记录 JSON 事务日志；失败自动逆序回滚；`--rollback last` 可撤销上一次还原。/ Atomic per-entry commit, automatic rollback on failure, and `--rollback last`. |
| **来源包记录** / provenance | 备份时用 `dpkg-query -S` / `rpm -qf` 记录文件来源包，还原时可优先重装包而不是覆盖文件。/ Records package provenance to prefer reinstalling packages. |
| **离线/救援还原** / offline restore | `--root <目录>` 把归档还原到未启动的系统（Live USB 修复场景），可选 `--chroot-exec` 在目标根内执行 depmod/initramfs。/ Restore into an offline root, optionally executing depmod/initramfs inside it. |

**归档格式 v2 新增字段** / new manifest v2 fields：`kernel_vermagic`、`immutability`、`secure_boot`、`compression`、`dkms[]`、每条目的 `link_target` / `owner` / `modinfo` / `content_stored` / `strategy_hint`。

### 新增命令行参数 / New CLI options

```bash
# 跨内核按 DKMS 重建（推荐），而不是拷贝 .ko
linux-driver-backup --restore --archive b.tar.gz --strategy rebuild

# 离线还原到未启动的系统（救援模式，无需 root，按目标目录权限判定）
linux-driver-backup --restore --archive b.tar.gz --root /mnt/target --yes --no-sign

# 撤销上一次还原
sudo linux-driver-backup --rollback last
```

| 参数 / Option | 说明 / Description |
|---|---|
| `--strategy auto\|rebuild\|reinstall\|weak-modules\|copy` | 覆盖自动策略选择 / override strategy selection |
| `--root <dir>` | 离线还原到指定根（救援场景）/ restore into an offline root |
| `--on-immutable refuse\|usroverlay` | 不可变系统的处置方式 / policy on immutable distros |
| `--strict-links` | 符号链接目标缺失即报错（默认仅提示）/ fail when a link target is missing |
| `--no-sign` | 跳过 Secure Boot 签名 / skip module signing |
| `--chroot-exec` | 在 `--root` 内执行 depmod/initramfs / run depmod/initramfs inside `--root` |
| `--rollback [last\|<id>]` | 回滚上一次（或指定）还原 / undo a restore |

> ⚠️ Secure Boot 签名需要 MOK 私钥（root-only）。若系统尚未有密钥，请先生成并登记：
> `openssl req -new -x509 -nodes -newkey rsa:2048 -keyout MOK.priv -outform DER -out MOK.der -days 36500 -subj "/CN=Driver Backup Module Signing/"`，
> 然后 `sudo mokutil --import MOK.der` 并在重启时完成登记。

## 界面预览 / Screenshots

GUI 主窗口（扫描 → 选择模式与输出路径 → 备份 / 还原，含 dry-run 开关）：

![screenshot](docs/screenshot.png)

## 安装 / Installation

> **分发方式 / Distribution**：当前以 **GitHub Releases 附件形式分发**——
> 本仓库**尚未**接入 apt 源、PPA、Snap Store 或 Flathub（这些需要外部仓库审核，已列入路线图，
> 见 DESIGN.md §11.4）。因此所有安装方式都是「到 [Releases](../../releases) 页面下载附件 → 本地安装」。
>
> 附件由 CI 的 `package` 作业在推送 `v*` 标签时自动产出，**同时覆盖 x86_64/amd64 与 aarch64/arm64 两个架构**的
> `.deb`、`.rpm`、`tar.gz`，外加 x86_64 的 `AppImage` 与两个架构的单文件二进制（均附 `.sha256` 校验清单），
> 构建脚本入口为 [`packaging/build-packages.sh`](packaging/build-packages.sh)。

### 各发行版安装命令 / Install commands by distro

| 发行版 / Distro | 格式 / Format | 安装命令 / Install command |
|---|---|---|
| Debian / Ubuntu / Linux Mint / Kali / deepin（x86_64） | `.deb` | `sudo dpkg -i linux-driver-backup_<版本>_amd64.deb`<br>或 `sudo apt install ./linux-driver-backup_<版本>_amd64.deb`（自动补齐依赖） |
| Debian / Ubuntu / Linux Mint 等（arm64） | `.deb` | `sudo apt install ./linux-driver-backup_<版本>_arm64.deb`（树莓派 / ARM 服务器 / Apple Silicon 虚拟机） |
| Fedora / RHEL / Rocky / AlmaLinux / openEuler（x86_64） | `.rpm` | `sudo dnf install ./linux-driver-backup-<版本>-1.x86_64.rpm` |
| Fedora / RHEL / Rocky / AlmaLinux 等（aarch64） | `.rpm` | `sudo dnf install ./linux-driver-backup-<版本>-1.aarch64.rpm` |
| Arch / Manjaro / EndeavourOS | 源码包（PKGBUILD，AUR 用） | 渲染并构建：`bash packaging/build-packages.sh arch --tarball <tarball> --sha256 <sha256>` 产出填充好的 `PKGBUILD` 与 `.SRCINFO`（版本取自 `Cargo.toml`，无需手工替换），再执行 `makepkg -si`；若已提交 AUR，可用 `yay -S linux-driver-backup` |
| 任意发行版 / Any distro | AppImage（免安装，可放 U 盘，仅 x86_64） | `chmod +x linux-driver-backup-<版本>-linux-x86_64.AppImage`<br>`./linux-driver-backup-<版本>-linux-x86_64.AppImage` |
| 任意发行版 / Any distro | `tar.gz`（通用兜底，x86_64 + aarch64） | 解压后执行 `./install.sh`（默认装入 `/usr/local`，可用 `--prefix` 改前缀） |
| 从源码构建 / Build from source | — | 见下方 [快速开始 / Quick Start](#快速开始--quick-start) 的「从源码构建 / Build from source」 |

说明 / Notes：

- **v0.1.1 的 RPM 在 Fedora 上的已知问题**：该版本把 `wayland` 写成了 RPM 依赖名，而
  Fedora 并无此包（提供 `libwayland-client.so.0` 的是 `libwayland-client`），因此
  `sudo rpm -ivh …x86_64.rpm` 会报「wayland 被 linux-driver-backup 需要」。
  **v0.1.2 起已修正**（硬链接依赖交由 rpmbuild 自动生成 soname 依赖，只显式声明
  dlopen 的 `libwayland-client` / `libxkbcommon` / `libxkbcommon-x11`）；
  在修复前如需应急安装，可用 `sudo rpm -ivh --nodeps <包>`（依赖库在桌面版 Fedora 上均已存在）。

- 无需 root 的方式：**AppImage** 与 **`tar.gz` + `install.sh`（装到自己的前缀）**；`.deb` / `.rpm` 装进 `/usr` 需要 sudo。
- 卸载 / Uninstall：
  - Debian 系：`sudo apt remove linux-driver-backup`（或 `sudo dpkg -r linux-driver-backup`）
  - RHEL 系：`sudo dnf remove linux-driver-backup`
  - Arch：`sudo pacman -R linux-driver-backup`
  - AppImage：直接删除 `.AppImage` 文件即可
  - `install.sh`：`sudo ./install.sh --uninstall --prefix=/usr/local`
- 运行时依赖（`libxkbcommon`、`libxkbcommon-x11`、`libwayland-client`、`libfontconfig1`、`libfreetype6`）由 `.deb` / `.rpm` 的依赖字段自动带上；
  AppImage 自带入口但仍需系统提供上述运行库，极简环境请参考 [运行时系统依赖 / Runtime dependencies](#2-运行时系统依赖--runtime-dependencies)。

### 验证安装 / Verify the installation

```bash
# 1) 版本号应与 Cargo.toml 的 version 一致
linux-driver-backup --version

# 2) 扫描并输出合法 JSON（无需 root），应包含 entries 与 kernel_release 两个字段
linux-driver-backup --scan --json

# 3) 不带任何参数应能启动图形界面（需在 X11 或 Wayland 会话内）
linux-driver-backup
```

安装落点 / Install layout（`install.sh` 与各发行版一致的相对布局）：

| 内容 / Item | `.deb` / `.rpm` / AUR | `install.sh`（默认前缀） |
|---|---|---|
| 可执行文件 | `/usr/bin/linux-driver-backup` | `/usr/local/bin/linux-driver-backup` |
| 桌面入口 | `/usr/share/applications/linux-driver-backup.desktop`（`Exec`/`TryExec` 为绝对路径） | `/usr/local/share/applications/…` |
| 图标 | `/usr/share/icons/hicolor/scalable/apps/linux-driver-backup.svg` | `/usr/local/share/icons/hicolor/scalable/apps/…` |
| polkit 策略 | `/usr/share/polkit-1/actions/io.github.ltbkq.linux-driver-backup.policy`（GUI 提权） | `/usr/local/share/polkit-1/actions/…`（可用 `--no-polkit` 关闭） |
| 许可全文 | `/usr/share/doc/linux-driver-backup/copyright`（deb）/ `%{_docdir}`（rpm） | `/usr/local/share/doc/linux-driver-backup/LICENSE` |

> 维护者提示 / Maintainer tip：本机可用 `bash packaging/build-packages.sh deb tar` 产出 `.deb` 与
> `tar.gz`；`.rpm` 与 AppImage 需要 `rpmbuild` / `appimagetool`，本机缺失时脚本会打印「[跳过]」，
> 由 CI 的 `package` 作业补齐。版本与架构解析统一在 [`packaging/lib/common.sh`](packaging/lib/common.sh)
> （唯一事实源）；RPM 目标默认 `auto`，可用 `--rpm-target fedora|suse|both` 指定。

## 快速开始 / Quick Start

### 1) 从源码构建 / Build from source

前置条件：

- **Rust 工具链**：`rustup` 安装的**稳定版 ≥ 1.92**（`Cargo.toml` 中 `rust-version = "1.92"`，edition 2021；slint 1.18 要求 1.92）。

  ```bash
  rustup update stable
  rustc --version   # 应 >= 1.92
  ```

- **编译期系统依赖**（Slint 使用 winit X11/Wayland 后端 + 软件渲染，编译需要 pkg-config 与窗口系统头文件）：

  ```bash
  # Debian / Ubuntu / Linux Mint
  sudo apt-get install -y pkg-config libxkbcommon-dev libwayland-dev libx11-dev
  ```

构建：

```bash
cargo build --release
```

产物路径 / Output:

```
target/release/linux-driver-backup
```

> CI 中会额外加 `--target <triple>`，此时产物位于 `target/<triple>/release/linux-driver-backup`，详见 [.github/workflows/build.yml](.github/workflows/build.yml)。

### 2) 运行时系统依赖 / Runtime dependencies

本程序是单文件二进制，但**不是零依赖**（winit 后端在运行时 `dlopen` 下列库）：

| 依赖 / Dependency | 用途 / Purpose |
|---|---|
| `libxkbcommon.so.0` | 键盘布局与按键映射 / keyboard mapping |
| `libxkbcommon-x11.so.0` | X11 会话下的键盘映射扩展（dlopen，Wayland 不需要） / X11 keymap extension |
| Wayland 客户端库（`libwayland-client.so.0`） | Wayland 会话下的窗口与输入 / Wayland windowing |
| `libfontconfig.so.1` + `libfreetype.so.6` | **硬链接依赖**：系统字体发现与字形栅格化（`ldd` 可查） / hard-linked: font discovery & glyph rasterization |
| 系统字体 | 界面文字渲染 / UI text rendering |
| 显示服务器 | GUI 需要 X11 或 Wayland 会话 / GUI needs X11 or Wayland |
| `pkexec`（polkit） | 还原时的单次提权；无显示环境（SSH）可改用 `sudo` 跑 CLI / single elevation for restore |

> 桌面发行版通常已自带以上库；极简容器或无桌面的服务器可能需要手动安装。

## 使用方法 / Usage

### 图形界面 / GUI

直接运行且**不带任何参数**即启动 GUI：

```bash
./target/release/linux-driver-backup
```

基本流程 / Typical workflow：

1. **扫描 / Scan**：点击「扫描」列出当前内核下的外置模块、DKMS 源码与配置文件，界面显示系统信息与条目列表。
2. **选择模式与输出路径 / Choose mode & output path**：在下拉框选择 `minimal` / `standard` / `full`，并填写备份输出路径（默认预填 `~/driver-backup-<kver>-<时间戳>.tar.gz`）。
3. **备份 / Backup**：点击「备份」，进度条按字节加权显示（扫描 0–10%、哈希 10–70%、压缩 70–95%、清单 95–100%），随时可「取消」，取消时清理 `.part` 半成品。
4. **还原 / Restore**：填入归档路径，可先勾选 **dry-run 预演**（只输出计划、不写盘），确认无误后再执行真正的还原；写入系统目录需要 root，程序会通过 `pkexec` 弹出系统密码框完成**单次提权**。

### 命令行 / CLI

命令行参数与 GUI 共用同一套核心逻辑，适合无显示环境、脚本与 CI 冒烟测试。完整参数（依据 DESIGN.md §5.7）：

| 参数 / Option | 说明 / Description |
|---|---|
| *(无参数 / no args)* | 启动 GUI / launch the GUI |
| `--scan [--mode <m>] [--json]` | 扫描并打印结果；`--json` 输出机器可读 JSON（便于测试），`<m>` 为 `minimal`/`standard`/`full` |
| `--backup --out <f> [--mode <m>] [--kver <k>]` | 备份到指定归档文件 `<f>`；模式默认 `standard`，内核版本默认取当前运行内核 |
| `--restore --archive <f> [--dry-run] [--yes] [--with-firmware] [--allow-kernel-mismatch] [--allow-arch-mismatch] [--root <dir>] [--strategy …]` | 从归档 `<f>` 还原；`--dry-run` 只预演不写盘，`--yes` 跳过交互确认，`--with-firmware` 允许还原固件；备份内核与当前不符用 `--allow-kernel-mismatch`（或交互确认），**架构不符**需独立的 `--allow-arch-mismatch`（或交互确认） |
| `--helper-restore --archive <f> …` | **仅供内部使用**：由 `pkexec <自身> --helper-restore …` 以 root 重入时解析的内部标志，用户不应手动调用 |

退出码 / Exit codes：`0` 成功或用户主动取消；`1` 运行失败；`2` 用法/参数错误（JSON 输出失败也返回 1）。*0 = success or user cancellation; 1 = runtime failure; 2 = usage error.*

可复制的三个示例 / Three copy-pasteable examples：

```bash
# 1) 扫描外置驱动并以 JSON 输出（无需 root）
./target/release/linux-driver-backup --scan --mode standard --json

# 2) 以 standard 模式备份到指定文件（无需 root）
./target/release/linux-driver-backup --backup --out ~/driver-backup.tar.gz --mode standard

# 3) 还原前先 dry-run 预演（只打印计划，不写盘）
./target/release/linux-driver-backup --restore --archive ~/driver-backup.tar.gz --dry-run --yes
```

> 真正写入系统的还原需要 root：桌面下由程序内部 `pkexec` 提权；SSH / 无显示环境请改用 `sudo` 运行 CLI（`pkexec` 在无显示环境可能不可用）。

## 备份内容与归档格式 / What is Backed Up

### 备份范围与三级模式 / Backup scope & modes（DESIGN.md §4.2）

扫描 `/lib/modules/<kver>/` 与 `/usr/lib/modules/<kver>/`（usr-merge 自动去重），采用**全树遍历 + in-tree 基线排除**：

| 子树 / Subtree | 归类 / Category | 是否备份 / Backed up |
|---|---|---|
| `kernel/**`（vmlinuz 自带基线） | in-tree 模块 | ❌ 不备份（内核包升级即恢复） |
| `updates/**`、`extra/**`、`extramodules/**`、`weak-updates/**` | out-of-tree 模块 | ✅ |
| `kernel/` 之外的其它顶层目录（如 `nvidia/`） | out-of-tree 模块 | ✅ |
| `/etc/modprobe.d`、`/etc/udev/rules.d`、`/etc/depmod.d`、`/etc/modules-load.d` | 配置文件 | ✅（`minimal` 起包含） |
| `/usr/src/<pkg>-*/`、`/var/lib/dkms/<pkg>/<ver>` | DKMS 源码 | ✅（`standard` 起包含；可在新内核上重建，比 `.ko` 二进制更可靠） |
| `/lib/firmware/**` | 固件 | 仅 `full`（默认关闭） |

三级模式 / The three modes：

| 模式 / Mode | 包含内容 / Contents |
|---|---|
| `minimal` | 外置（out-of-tree）模块 + `/etc` 配置文件 |
| `standard`（默认 / default） | `minimal` + DKMS 源码 |
| `full` | `standard` + `/lib/firmware`（会先估算体积并在 UI 上提示，`linux-firmware` 常达数百 MB） |

### 归档格式 / Archive format（DESIGN.md §4.3）

```
driver-backup-<kver>-<YYYYMMDD-HHMMSS>.tar.gz
├── manifest.json        # 元数据 + 逐文件 sha256（还原时先读它）/ metadata + per-file SHA-256
└── data/
    ├── lib/modules/<kver>/...      # 相对路径原样保存（去除前导 /）
    ├── etc/modprobe.d/...
    └── var/lib/dkms/...            # standard 模式 / standard mode
```

`manifest.json` 字段要点：`format_version`（供未来演进，当前为 `1`）、`tool_version`、`created_at`（RFC3339）、`kernel_release`、`arch`、`distro`（`id` / `version_id` / `pretty_name` / `family`）、`mode`、`entries`（每项含 `path`、`size`、`sha256`、`kind`，`kind` 取值 `module` / `dkms` / `config` / `firmware`）、`warnings`。

还原时先读取 `manifest.json`，逐条校验 SHA-256 后再解压写盘。

## 权限说明 / Privileges

| 操作 / Action | 所需权限 / Privilege | 实现 / How |
|---|---|---|
| 扫描 / 备份 backup | **普通用户即可 / no root needed**（`/lib/modules`、`/lib/firmware` 默认 0755/0644，只读访问） | 直接执行 |
| 还原 restore（写 `/lib/modules`、`depmod`、initramfs） | **root** | 程序内部通过 `pkexec <当前可执行文件> --helper-restore …` **单次提权**，由同一个二进制以 root 身份重入，无需外部 `tar`/`sh` 命令 |

说明：

- 提权后 helper 的 stdout 使用行协议（`PROGRESS` / `NOTE` / `RESULT`）回传，GUI/CLI 据此驱动进度显示。
- `pkexec` 会在图形会话中弹出 polkit 原生密码框；**无显示或 SSH 环境**下可能不可用，此时改用 `sudo` 运行 CLI 模式。
- 安全约束：内核版本串须匹配 `^[0-9A-Za-z][0-9A-Za-z._+-]*$` 才能进入任何命令参数；归档内路径会剥离 `..` 与绝对路径前缀，拒绝越界写入（路径穿越防护）。

## 备份范围限制与风险 / Limitations

- **不备份 in-tree 模块 / In-tree modules are excluded**：`kernel/**` 下由内核包自带的基线模块不在备份范围内——它们随内核包升级即恢复，备份它们既冗余又容易过期。
- **跨内核还原需确认 ABI / Cross-kernel restore requires ABI confirmation**：从 `6.8` 备份的 `.ko` 还原到 `6.11` 可能因模块 ABI 不兼容而无法加载；程序会比对 `manifest.kernel_release` 并要求二次确认（`allow_kernel_mismatch`），但**是否兼容需自行判断**。
- **固件体积大 / Firmware can be huge**：`full` 模式包含 `/lib/firmware`，`linux-firmware` 常达数百 MB，备份耗时长、归档体积大；程序会先估算体积并提示，也支持随时取消。
- **Secure Boot 需自备 MOK 密钥 / Secure Boot requires a MOK key**：本工具不会自动生成私钥；未配置密钥时只给出指引（若内核 `CONFIG_MODULE_SIG_FORCE` 生效则拒绝"假成功"）。
- **不可变系统仅提供指引 / immutable distros are guidance-only**：OSTree 系统默认拒绝直写，`usroverlay` 为临时手段（重启失效）；NixOS 明确不支持。
- **离线还原默认不重建 initramfs / offline restore skips depmod by default**：`--root` 模式下需显式 `--chroot-exec` 才会在目标根内执行。
- **musl 静态版为实验性 / musl static build is experimental**：主线交付 glibc 版（`x86_64` / `aarch64`，在 ubuntu-22.04 上编译以获得更广的 glibc 兼容面）；Slint 软件渲染 + winit 在 musl 上未充分验证，静态版仅作实验用途。
- **暂无增量与加密 / No incremental or encrypted archives**：首版不做增量备份、不做加密归档，大归档会重复占用磁盘空间（已列入路线图）。
- **不替代包管理器 / Not a package manager replacement**：不做 DKMS 之外的内核源码编译，不管理内核包升级。

## 开发 / Development

### 目录结构 / Directory layout

```
linux-driver-backup-rust/
├── .github/workflows/build.yml     # CI：多目标编译 + 打包（package）+ Release 发布
├── packaging/                      # 打包资产（DESIGN.md §11）
│   ├── linux-driver-backup.desktop # 桌面入口（freedesktop 桌面入口规范 v1.5）
│   ├── icon.svg                    # 可缩放图标（256×256，随 GPL-3.0 分发）
│   ├── deb/control                 # .deb 控制字段模板（@VERSION@ / @SIZE_KB@ 占位）
│   ├── linux-driver-backup.spec    # RPM spec 模板（%build 留空，CI 拷入二进制）
│   ├── arch/PKGBUILD               # Arch/AUR 源码包模板（见 arch/README.md）
│   ├── appimage/                   # AppDir 结构说明
│   ├── lib/common.sh               # 版本/架构/校验/占位符唯一解析（各脚本 source）
│   ├── polkit/                     # pkexec 提权 policy（io.github.ltbkq.linux-driver-backup）
│   ├── build-appimage.sh           # 组 AppDir 并用 appimagetool（固定版本+SHA-256）产 AppImage
│   ├── build-packages.sh           # 统一打包入口：deb / tar / rpm / arch / appimage / all
│   └── install.sh                  # 通用安装脚本（--prefix / --uninstall / --polkit-dir / --help）
├── ui/
│   └── app_window.slint            # 声明式 GUI（含 struct 模型）
├── src/
│   ├── main.rs                     # 入口：GUI 装配 + CLI 分发 + 回调绑定
│   ├── model.rs                    # 共享类型与错误（所有模块的依赖根）
│   ├── distro.rs                   # 发行版探测 / 内核版本 / 系统命令适配
│   ├── scan.rs                     # 驱动扫描（全树遍历 + in-tree 基线排除）
│   ├── backup.rs                   # 流水作业打包：扫描→哈希→压缩→manifest
│   ├── restore.rs                  # 校验→解压→depmod→initramfs
│   └── privilege.rs                # pkexec 提权、helper 行协议解析
├── build.rs                        # slint_build::compile("ui/app_window.slint")
├── Cargo.toml
├── LICENSE                         # GPL-3.0 全文（deb/rpm 的 copyright 来源）
├── DESIGN.md                       # 设计文档（唯一事实源 / single source of truth）
└── README.md
```

### 设计文档 / Design document

完整的技术选型、模块接口冻结契约（§5）、测试与验收标准（§6）、CI 与分发（§7）见 **[DESIGN.md](DESIGN.md)**。并行开发时**只允许依赖 §5 的冻结契约**，不得臆造其它模块的 API。

面向**下一版的优化改进方案**（对标 DKMS/akmods/weak-modules/Timeshift/fwupd/DISM 等同类软件，含 P0–P3 分级建议、归档格式 v2 草案、事务化还原与 Secure Boot 签名流程）见 **[docs/ROADMAP-v2.md](docs/ROADMAP-v2.md)**。

### 常用开发命令 / Common commands

```bash
cargo build            # 调试构建
cargo build --release  # 发布构建
cargo test --no-fail-fast   # 运行全部单元测试（与 CI 一致）
cargo clippy -- -D warnings # lint（尽量保持零警告）
```

### 文档规范 / Documentation policy（DESIGN.md 附录 A）

- 项目所有文档（`DESIGN.md`、`README.md`、源码模块注释）采用**中英文双语，以中文为主**；章节标题、摘要与表格关键列提供英文对照，正文论述以中文为主。
- 公共 API 的 doc comment 首句为英文一句话说明，其后可用中文展开细节。
- All project documents are **bilingual: Chinese-primary, English-secondary**; section titles, abstracts and key table columns carry English equivalents, and every public API doc comment starts with a one-line English summary.

## 许可 / License

本项目采用 **GPL-3.0-only** 授权（见 `Cargo.toml` 的 `license = "GPL-3.0-only"`）。

This project is licensed under **GPL-3.0-only**.

**关于 GUI 框 Slint 的授权 / About the Slint GUI framework**：
Slint 采用三重授权 `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`。本项目选择并声明 **GPL-3.0-only**，与 Slint 的 `GPL-3.0-only` 分支兼容，因此可以合法地依赖并分发 Slint。若你 fork 本项目并改为其它授权（例如闭源商用），必须先取得 Slint 的免版税授权或软件授权，否则与 Slint 的授权条款不兼容。

> Slint is triple-licensed `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0`; this project picks **GPL-3.0-only**, which is compatible with Slint's GPL branch. Any relicensing (e.g. closed-source commercial use) requires a Slint royalty-free or software license.

## 贡献 / Contributing

欢迎提交 Issue 与 Pull Request：

1. 修改前请先阅读 [DESIGN.md](DESIGN.md)，接口变更须同步更新 §5 冻结契约；
2. 保持代码与文档的**中英双语、中文为主**风格，遵循附录 A 的文档规范；
3. 提交前运行 `cargo build`、`cargo test --no-fail-fast` 与 `cargo clippy -- -D warnings`，确保与 CI 行为一致；
4. PR 描述请说明动机、影响范围（是否触及备份/还原格式或权限模型）以及测试方式。

Contributions are welcome. Please read [DESIGN.md](DESIGN.md) first, keep the bilingual (Chinese-primary) documentation style, and make sure `cargo build`, `cargo test --no-fail-fast` and `cargo clippy -- -D warnings` all pass before submitting.
