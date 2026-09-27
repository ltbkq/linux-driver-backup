# Linux 驱动备份与还原工具

**Linux Driver Backup & Restore Tool — a Rust + Slint desktop application**

一行简介 / One-line intro:
**中文**：一个发行版自适应的 Linux 外置（out-of-tree）驱动备份与还原工具，提供 GUI 与 CLI 双模式，产出可校验、可跨机还原的 `tar.gz` 归档。
**English**: A distro-adaptive backup & restore tool for Linux out-of-tree drivers, with both GUI and CLI front-ends, producing checksummed `tar.gz` archives that can be restored across machines.

<!-- 徽章 / Badges -->
[![CI](https://github.com/ltbkq/linux-driver-backup/actions/workflows/build/badge.svg)](https://github.com/ltbkq/linux-driver-backup/actions/workflows/build.yml)
[![License: GPL-3.0-only](https://img.shields.io/badge/license-GPL--3.0--only-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Rust: 1.83+](https://img.shields.io/badge/rust-1.83%2B-orange.svg)](https://www.rust-lang.org/tools/install)

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
- **多线程流水作业 / Pipelined workers**：扫描 → 哈希 → 压缩三段式流水线（`std::thread` + 有界通道背压），进度实时回传、可随时取消，全程不阻塞 UI。*A three-stage pipeline keeps the UI responsive.*

## 界面预览 / Screenshots

GUI 主窗口（扫描 → 选择模式与输出路径 → 备份 / 还原，含 dry-run 开关）：

![screenshot](docs/screenshot.png)

## 安装 / Installation

> **分发方式 / Distribution**：当前以 **GitHub Releases 附件形式分发**——
> 本仓库**尚未**接入 apt 源、PPA、Snap Store 或 Flathub（这些需要外部仓库审核，已列入路线图，
> 见 DESIGN.md §11.4）。因此所有安装方式都是「到 [Releases](../../releases) 页面下载附件 → 本地安装」。
>
> 附件由 CI 的 `package` 作业在推送 `v*` 标签时自动产出（`.deb`、`.rpm`、`tar.gz`、`AppImage`），
> 构建脚本入口为 [`packaging/build-packages.sh`](packaging/build-packages.sh)。

### 各发行版安装命令 / Install commands by distro

| 发行版 / Distro | 格式 / Format | 安装命令 / Install command |
|---|---|---|
| Debian / Ubuntu / Linux Mint / Kali / deepin | `.deb` | `sudo dpkg -i linux-driver-backup_<版本>_amd64.deb`<br>或 `sudo apt install ./linux-driver-backup_<版本>_amd64.deb`（自动补齐依赖） |
| Fedora / RHEL / Rocky / AlmaLinux / openEuler | `.rpm` | `sudo dnf install ./linux-driver-backup-<版本>-1.x86_64.rpm` |
| Arch / Manjaro / EndeavourOS | 源码包（PKGBUILD，AUR 用） | 本地构建安装：`cd packaging/arch`，先按 [packaging/arch/README.md](packaging/arch/README.md) 渲染模板中的 `@VERSION@`，再执行 `makepkg -si`；若已提交 AUR，可用 `yay -S linux-driver-backup` |
| 任意发行版 / Any distro | AppImage（免安装，可放 U 盘） | `chmod +x linux-driver-backup-<版本>-linux-x86_64.AppImage`<br>`./linux-driver-backup-<版本>-linux-x86_64.AppImage` |
| 任意发行版 / Any distro | `tar.gz`（通用兜底） | 解压后执行 `./install.sh`（默认装入 `/usr/local`，可用 `--prefix` 改前缀） |
| 从源码构建 / Build from source | — | 见下方 [快速开始 / Quick Start](#快速开始--quick-start) 的「从源码构建 / Build from source」 |

说明 / Notes：

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
| 桌面入口 | `/usr/share/applications/linux-driver-backup.desktop` | `/usr/local/share/applications/…` |
| 图标 | `/usr/share/icons/hicolor/scalable/apps/linux-driver-backup.svg` | `/usr/local/share/icons/hicolor/scalable/apps/…` |
| 许可全文 | `/usr/share/doc/linux-driver-backup/copyright`（deb）/ `%{_docdir}`（rpm） | `/usr/local/share/doc/linux-driver-backup/LICENSE` |

> 维护者提示 / Maintainer tip：本机可用 `bash packaging/build-packages.sh deb tar` 产出 `.deb` 与
> `tar.gz`；`.rpm` 与 AppImage 需要 `rpmbuild` / `appimagetool`，本机缺失时脚本会打印「[跳过]」，
> 由 CI 的 `package` 作业补齐。

## 快速开始 / Quick Start

### 1) 从源码构建 / Build from source

前置条件：

- **Rust 工具链**：`rustup` 安装的**稳定版 ≥ 1.83**（`Cargo.toml` 中 `rust-version = "1.83"`，edition 2021）。

  ```bash
  rustup update stable
  rustc --version   # 应 >= 1.83
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
| `--restore --archive <f> [--dry-run] [--yes] [--with-firmware]` | 从归档 `<f>` 还原；`--dry-run` 只预演不写盘，`--yes` 跳过交互确认，`--with-firmware` 允许还原固件 |
| `--helper-restore --archive <f> …` | **仅供内部使用**：由 `pkexec <自身> --helper-restore …` 以 root 重入时解析的内部标志，用户不应手动调用 |

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
│   ├── build-appimage.sh           # 组 AppDir 并用 appimagetool 产 AppImage
│   ├── build-packages.sh           # 统一打包入口：deb / tar / rpm / appimage / all
│   └── install.sh                  # 通用安装脚本（--prefix / --uninstall / --help）
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
