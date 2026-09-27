# Linux 驱动备份与还原工具 —— 设计文档 v2.0（验证与优化版）

**Linux Driver Backup & Restore Tool — Design Document v2.0 (Verified & Optimized)**

> 项目代号 / Project: `linux-driver-backup`
> 语言/框架 / Stack: Rust 2021 + Slint 1.18 GUI
> 状态 / Status: **已通过事实核查并重构 / Fact-checked and restructured**（本文档替代初版设计 / supersedes the initial draft）
> 核查日期 / Reviewed: 2026-09-27，环境 / Host: Linux Mint 22.3 (Ubuntu-based), rustc 1.98.1

## 摘要 / Abstract

**中文（主）**：本文档对初版 Rust + Slint 驱动备份工具设计做了 12 项逐条事实核查，发现 3 项致命问题（Slint 与 tokio 官方不兼容、两处 API 命名不匹配导致编译失败、还原流程缺失 `depmod` 导致还原无效）、2 项高危问题（强引用泄漏窗口、备份范围不完整），并纠正了"无依赖单文件"的过度承诺。文档给出验证后的技术选型与版本、三层多线程流水作业运行时架构、自进程 `pkexec` 提权模型、可校验的 `tar.gz + manifest.json` 归档格式，以及用于并行开发的**冻结接口契约**（§5）。全部声明均标注证据来源。

**English (secondary)**: This document fact-checks the initial Rust + Slint design in 12 items and finds three fatal issues (officially unsupported Slint+tokio combination, two API naming mismatches that break compilation, and a missing `depmod` step that makes restore a no-op) plus two high-severity issues (strong-reference leak, incomplete backup scope), and corrects the overstated "dependency-free single file" claim. It then specifies the verified dependency set, a three-stage multi-threaded pipeline runtime, a self re-exec `pkexec` privilege model, a checksummed `tar.gz + manifest.json` archive format, and **frozen interface contracts** (§5) used as the single source of truth for parallel development. Every claim is annotated with its evidence.

---

## 0. 对初版设计的事实核查结果 / Fact-Check of the Initial Design

初版文档中 12 项关键声明，逐条验证（证据来源：docs.rs / crates.io API / Slint 官方文档与 CHANGELOG）：

| # | 初版声明/代码 | 核查结果 | 严重度 | 处置 |
|---|---|---|---|---|
| 1 | `slint = "1.3"` | **过时**。最新为 **1.18.1**（2026-09-21 发布），1.3 为 2023 年版本，API 与特性开关已变更 | 高 | 改为 `1.18` + `compat-1-18` |
| 2 | `#[tokio::main]` + `tokio::spawn` 驱动 UI 后台任务 | **Slint 官方文档明确不推荐**：`The use of #[tokio::main] is not recommended`；tokio future 在 Slint 事件循环中"可能永远不被驱动"、"current-thread 调度器不能在 Slint 主线程使用"。tokio 还会引入大量编译产物，与"轻量单文件"目标冲突 | **致命** | **移除 tokio**，改用 `std::thread` 工作线程 + `slint::invoke_from_event_loop` 回传 UI |
| 3 | `sys-info = "0.9"` | **已停止维护**：crates.io 显示 `sys-info 0.9.1` 最后更新 **2021-10-21**（5 年未动），且为 C 绑定（链接 libc）。内核版本读 `/proc/sys/kernel/osrelease` 即可，零依赖 | 中 | **移除 sys-info**，改读 procfs |
| 4 | `.slint` 声明 `callback start_restore()`，Rust 绑定 `app.on_restore_with_initramfs(...)` | **名称不匹配 → 编译失败**（`AppWindow` 上不存在 `on_restore_with_initramfs`） | 致命 | 统一为 `start-restore` / `on_start_restore` |
| 5 | `distro.get_initramfs_command()` vs 定义 `get_initramfs_cmd()` | **名称不匹配 → 编译失败** | 致命 | 统一为 `initramfs_cmd()` |
| 6 | 回调闭包 `move` 捕获 `app` 强引用 | 官方文档警告：*"Strong reference should not be captured by the closures… would produce a reference loop and leak the component"*，会导致窗口关闭时挂死 | 高 | 全部改用 `app.as_weak()`，回调内 `upgrade()` 失败即返回 |
| 7 | `slint::invoke_from_event_loop(...).unwrap()` | 事件循环退出后返回 `Err`，`unwrap` 直接 panic | 中 | 改 `let _ = ...` |
| 8 | `ProgressIndicator` 控件及 `progress` 属性 | **属实**。`std-widgets.slint` 的 Basic Widgets 含 `ProgressIndicator`，`progress: float` 取值 0..1（超出范围自动截断），另有 `indeterminate: bool` | — | 保留 |
| 9 | 备份范围 = 3 个目录下的 `.ko` | **不完整**。遗漏：`/lib/firmware`（固件 blob，无它网卡/GPU/RAID 卡不工作）、`/etc/modprobe.d`、`/etc/udev/rules.d`、`/etc/depmod.d`、DKMS 源码（`/usr/src`+`/var/lib/dkms`）。另 Arch 用 `/usr/lib/modules`（usr-merge），且遗漏 NVIDIA 可能所在的 `kernel/` 子树外的目录 | 高 | 见 §4.2 扫描策略：全树遍历 + in-tree 基线排除 |
| 10 | 还原后仅执行 initramfs 更新 | **缺失 `depmod -a <kver>`**：新放入的 `.ko` 不写入 `modules.dep`/`modules.alias`，**模块根本不会被识别**，还原等于无效 | **致命** | 还原流程强制插入 depmod，RHEL 系补 `restorecon` |
| 11 | "下载即可运行、无依赖单文件" | **需限定**：winit 后端运行时会 `dlopen` `libxkbcommon.so.0`（键盘映射）、Wayland 需 `libwayland-client`，字体发现依赖系统字体；Slint 二进制 strip 后典型 **6–15 MB**，并非"非常小"。默认特性还含 `system-tray`（拉入 `ksni`/D-Bus）与 `renderer-femtovg`（需 OpenGL/EGL） | 中 | 用 `default-features = false` 精确裁剪，改用软件渲染器，声明真实运行时依赖 |
| 12 | "备份需要复杂依赖/需 root" | **部分错误**：`/lib/modules`、`/lib/firmware` 默认 0755/0644，**备份可普通用户执行**；只有**还原**（写 `/lib/modules`、depmod、initramfs）需要 root | 中 | 备份免密、还原单次 `pkexec` 提权（§5.2） |

**额外发现的初版遗漏**：
- **许可证合规**：Slint 采用 `GPL-3.0-only OR LicenseRef-Slint-Royalty-free-2.0 OR LicenseRef-Slint-Software-3.0` 三重授权。若本项目声称"开源"，须显式选择 **GPL-3.0** 并在 README 标注，否则与 Slint 授权不兼容（商业闭源分发则需 Slint 免费授权条款允许的范围）。
- **无文件选择能力**：`std-widgets.slint` **没有**文件对话框控件（已核对控件清单），初版界面无法让用户选备份路径。
- **Slint 默认特性过重**：`default = [std, backend-default, renderer-femtovg, renderer-software, accessibility, compat-1-2, system-tray]`，必须 `default-features = false` 才能兑现"轻量无依赖"。

---

## 1. 目标与非目标 / Goals and Non-Goals

**目标**
1. 单二进制分发：`cargo build --release` 产出一个可执行文件，用户无需 Python/Qt/C++ 运行时。
2. 发行版自适应：Debian 系 / RHEL 系 / Arch 系 / 未知，自动探测，自动选择 `depmod` + initramfs 更新命令。
3. GUI + CLI 双模：GUI（Slint）用于桌面；CLI（`--scan/--backup/--restore`）用于无显示环境、自动化与 **CI 冒烟测试**。
4. 备份格式可校验、可跨机还原：`tar.gz` + `manifest.json`（逐文件 SHA-256）。
5. 全程不卡 UI：多线程流水作业（§4.4），进度实时回传。

**非目标**
- 不做 DKMS 之外的内核源码编译；不管理内核包升级；不替代发行版包管理器。
- 首版不做增量备份、不做加密归档（列入 §9 风险）。

---

## 2. 技术选型（验证后） / Verified Technology Choices

| 组件 | 选型 | 版本 | 验证依据 |
|---|---|---|---|
| GUI | Slint（`backend-winit-x11` + `backend-winit-wayland` + `renderer-winit-software`） | **1.18** | crates.io 最新 1.18.1；软件渲染避免 OpenGL/EGL 依赖 |
| 打包 | `tar` | 0.4.x（最新 0.4.46, 2026-05） | 活跃维护 |
| 压缩 | `flate2`（gzip） | 1.x（最新 1.1.10, 2026-08） | 活跃维护 |
| 哈希 | `sha2` | 0.10 | 0.11 已发布但生态兼容性未稳，先锁 0.10 |
| 序列化 | `serde` + `serde_json` | 1.x | manifest 与 `--json` 输出 |
| 目录遍历 | `walkdir` | 2.x | 扫描 `/lib/modules` 全树 |
| 线程 | `std::thread` + `std::sync::mpsc` | std | **替代 tokio**（见核查 #2） |
| 提权 | `pkexec`（polkit 原生密码框） | 系统自带 | 见 §5.2 |

**明确移除的依赖**：`tokio`、`sys-info`（理由见核查 #2/#3）。

### 2.1 `Cargo.toml`（最终形态） / Final Form

```toml
[package]
name = "linux-driver-backup"
version = "0.1.0"
edition = "2021"
rust-version = "1.83"
description = "Linux out-of-tree driver (kernel module) backup & restore tool with adaptive distro support"
license = "GPL-3.0-only"
build = "build.rs"

[dependencies]
slint = { version = "1.18", default-features = false, features = [
    "compat-1-18",   # 强制项：Slint 1.18 语义兼容
    "compat-1-2",
    "std",
    "backend-winit-x11",
    "backend-winit-wayland",
    "renderer-winit-software",   # 软件渲染：无需 OpenGL/EGL
    "renderer-software",
] }
tar = "0.4"
flate2 = "1.1"
sha2 = "0.10"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
walkdir = "2"

[build-dependencies]
slint-build = "1.18"

[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = true
panic = "abort"
```

> 说明：`system-tray`、`accessibility`、`renderer-femtovg`、`backend-qt` 均被默认特性关闭，直接消除 Qt/OpenGL/D-Bus 依赖。

---

## 3. 目录结构 / Directory Layout

```
linux-driver-backup-rust/
├── .github/workflows/build.yml     # CI：多目标编译 + Release 发布
├── ui/
│   └── app_window.slint            # 声明式 GUI（含 struct 模型）
├── src/
│   ├── main.rs                     # 入口：GUI 装配 + CLI 分发 + 回调绑定
│   ├── model.rs                    # ★ 共享类型与错误（所有模块的依赖根）
│   ├── distro.rs                   # 发行版探测 / 内核版本 / 系统命令适配
│   ├── scan.rs                     # 驱动扫描（全树遍历 + in-tree 基线排除）
│   ├── backup.rs                   # 流水作业打包：扫描→哈希→压缩→manifest
│   ├── restore.rs                  # 校验→解压→depmod→initramfs
│   └── privilege.rs                # pkexec 提权、helper 行协议解析
├── build.rs                        # slint_build::compile("ui/app_window.slint")
├── Cargo.toml
├── DESIGN.md                       # 本文档
└── README.md
```

依赖方向（无环）：`model ← distro ← scan ← backup`，`model ← distro ← restore ← privilege`，全部 → `main`。

---

## 4. 核心设计 / Core Design

### 4.1 发行版自适应（`distro.rs`） / Distro Adaptation

```rust
pub enum Family { Debian, Rhel, Arch, Unknown }

pub struct DistroInfo {
    pub id: String,            // "ubuntu"
    pub id_like: Vec<String>,  // ["debian"]  —— ID 未识别时的回退依据
    pub version_id: String,    // "24.04"
    pub pretty_name: String,   // "Ubuntu 24.04.1 LTS"
    pub family: Family,
}
```
- 探测顺序：`ID` 精确匹配 → `ID_LIKE` 逐项匹配 → `Unknown`（保留 pretty_name 展示）。
- 映射表：`ubuntu|debian|linuxmint|pop|elementary|kali|raspbian → Debian`；`rhel|centos|fedora|rocky|alma|ol|amzn → Rhel`；`arch|manjaro|endeavouros|artix|garuda → Arch`。
- `initramfs_cmd(family, kver)`：
  - Debian → `update-initramfs -u -k <kver>`
  - Rhel → `dracut --force --kver <kver>`
  - Arch → `mkinitcpio -P`
  - Unknown → `None`（跳过，不谎报成功）
- 所有系统命令统一走 `depmod -a <kver>`（initramfs 之前，见核查 #10）。
- `kernel_release()` 读 `/proc/sys/kernel/osrelease`；`is_root()` 解析 `/proc/self/status` 的 `Uid:` 行 —— 均为零依赖实现。

### 4.2 扫描策略（`scan.rs`） / Scan Strategy

`/lib/modules/<kver>/` 下的分类规则（同时检查 `/lib/modules` 与 `/usr/lib/modules`，usr-merge 自动去重）：

| 子树 | 归类 | 备份？ |
|---|---|---|
| `kernel/**`（vmlinuz 自带基线） | in-tree | ❌ 不备份（内核包升级即恢复） |
| `updates/**`、`extra/**`、`extramodules/**`、`weak-updates/**` | out-of-tree 模块 | ✅ |
| `kernel/` 之外的其它顶层目录（如 `nvidia/`） | out-of-tree 模块 | ✅ |
| `/etc/modprobe.d`、`/etc/udev/rules.d`、`/etc/depmod.d`、`/etc/modules-load.d` | 配置 | ✅（Minimal 起） |
| `/usr/src/<pkg>-*/`、`/var/lib/dkms/<pkg>/<ver>` | DKMS 源码 | ✅（Standard；**优先策略：可在新内核上重建，比 `.ko` 二进制更可靠**） |
| `/lib/firmware/**` | 固件 | 仅 Full（默认关闭，见下） |

**三级备份模式**（UI ComboBox / CLI `--mode`）：
- `minimal`：OOT 模块 + `/etc` 配置
- `standard`（默认）：minimal + DKMS 源码
- `full`：standard + `/lib/firmware`（会先估算体积并在 UI 上提示，linux-firmware 常达数百 MB）

### 4.3 备份归档格式 / Archive Format

```
driver-backup-<kver>-<YYYYMMDD-HHMMSS>.tar.gz
├── manifest.json        # 元数据 + 逐文件 sha256（还原时先读它）
└── data/
    ├── lib/modules/<kver>/...      # 相对路径原样保存（去除前导 /）
    ├── etc/modprobe.d/...
    └── var/lib/dkms/...            # standard 模式
```

`manifest.json` 字段（`format_version` 供未来演进）：

```json
{
  "format_version": 1,
  "tool_version": "0.1.0",
  "created_at": "2026-09-27T12:00:00Z",
  "kernel_release": "6.8.0-45-generic",
  "arch": "x86_64",
  "distro": { "id": "linuxmint", "version_id": "22.3",
              "pretty_name": "Linux Mint 22.3", "family": "debian" },
  "mode": "standard",
  "entries": [
    { "path": "lib/modules/6.8.0-45-generic/updates/dkms/foo.ko",
      "size": 123456, "sha256": "…", "kind": "module" }
  ],
  "warnings": ["…"]
}
```

### 4.4 运行时线程模型：多线程流水作业 / Runtime Threading Model

```
┌─ UI 线程（Slint 事件循环，永阻塞）────────────────────────┐
│  on_start_backup → as_weak().upgrade() → 启动 worker      │
└───────────────┬──────────────────────────────────────────┘
                │ std::thread::spawn
┌───────────────▼─── 备份流水线（3 级，sync_channel 限流背压）──┐
│ Stage 1  Walker    ：walkdir 遍历 + 分类，产 ScanEntry       │
│                      └─sync_channel(64)─┐                   │
│ Stage 2  Hasher×N  ：读文件 + SHA-256（N= min(4, 可用核数)） │
│                      └─sync_channel(64)─┐                   │
│ Stage 3  Packer    ：单写者 GzEncoder<tar::Builder>，        │
│                      末尾追加 manifest.json                  │
└───────┬─────────────────────────────────────────────────────┘
        │ mpsc::progress(f32, String)  +  Arc<AtomicBool> cancel
┌───────▼──────────────┐
│ UI 回传：slint::invoke_from_event_loop（`let _ =` 不 panic） │
└──────────────────────┘
```

要点：
- **背压**：`sync_channel` 有界，避免大目录（full 模式 /lib/firmware）把内存吃光。
- **取消**：`Arc<AtomicBool>` 三阶段共享，取消时清理半成品 `.part` 文件。
- **进度**：按字节数加权（扫描阶段 0–10%，哈希 10–70%，压缩 70–95%，manifest 95–100%）。
- **禁止 tokio**：一切异步回传走 `invoke_from_event_loop`，一切并发走 `std::thread`。

### 4.5 权限模型 / Privilege Model

| 操作 | 权限 | 实现 |
|---|---|---|
| 扫描 / 备份 | 普通用户即可（0755/0644 可读） | 直接执行 |
| 还原写入 `/lib/modules`、depmod、initramfs | root | **单次提权** |

提权策略 —— **自进程 re-exec**（保持"单文件"，不依赖外部 `tar`/`sh` 命令）：

```
GUI 普通进程
  └─ 需要 root 时 → pkexec <当前可执行文件> --helper-restore --archive <f> [--kver <k>] [--mode <m>]
        └─ helper 以 root 运行：解压(路径穿越防护/0644/uid 0；同名文件先备份为 <path>.ldbak)
              → depmod -a <kver>        （致命失败即中止，否则模块不被索引，见核查 #10）
              → restorecon -R（仅 RHEL 系且命令存在；失败仅记录 notes，非致命）
              → initramfs 命令（发行版自适应；Unknown 跳过）
              → 按行协议回传结果
```

> 实现顺序说明 / Ordering note：本文档初稿为 `restorecon → depmod → initramfs`，实现（`src/restore.rs`）采用 `depmod → restorecon → initramfs`。二者功能等价（restorecon 只改 SELinux 标签、depmod 只读 ELF 元数据，互不依赖），以实现顺序为准。/ The implementation order is functionally equivalent; the implemented order is authoritative.

**helper 行协议**（stdout，GUI 逐行解析驱动进度条）：
```
PROGRESS\t<float>\t<utf-8 消息>
NOTE\t<消息>
RESULT\tOK|FAIL\t<消息>
```
安全约束：`kver` 必须通过 `^[0-9A-Za-z][0-9A-Za-z._+-]*$` 校验后才能进入任何命令参数；归档内路径必须 strip 掉 `..` 与绝对路径前缀，拒绝越界写入。

### 4.6 GUI 界面（`ui/app_window.slint`） / GUI Layout

```slint
export struct ModuleItem {
    name: string,      // "nvidia.ko"
    path: string,      // 相对路径
    size: string,      // "1.2 MiB"（预格式化，避免 UI 里做运算）
    kind: string,      // "module" | "dkms" | "config" | "firmware"
}

export component AppWindow inherits Window {
    title: "Linux 驱动备份与还原";
    min-width: 640px;  min-height: 480px;

    in property <string> system-info: "系统信息加载中…";
    in property <string> status-text: "准备就绪";
    in property <float>  progress: 0.0;          // 0..1
    in property <bool>   busy: false;            // 控制按钮 enabled
    in property <[ModuleItem]> modules: [];      // 由 VecModel 提供
    in property <string> out-path;               // 备份输出路径（LineEdit 绑定）
    in property <string> archive-path;           // 待还原归档（LineEdit 绑定）
    in property <int>    mode-index: 1;          // 0 minimal / 1 standard / 2 full
    in property <bool>   dry-run: true;          // 还原预演开关

    callback start-backup();
    callback start-restore();
    callback refresh-scan();
    callback cancel();
    // …布局：system-info / 模块 ListView / ProgressIndicator / 状态行 /
    //       mode ComboBox + out-path LineEdit / 还原归档 LineEdit + dry-run CheckBox /
    //       按钮组（扫描·备份·还原·取消）
}
```

Rust 侧生成 API（**命名以此为准**）：`set_system_info`、`set_status_text`、`set_progress`、`set_busy`、`set_modules(ModelRc<ModuleItem>)`、`set_out_path`、`get_out_path`、`set_archive_path`、`get_archive_path`、`set_mode_index`、`get_mode_index`、`set_dry_run`、`get_dry_run`、`on_start_backup`、`on_start_restore`、`on_refresh_scan`、`on_cancel`。

> 注意：`.slint` 中的短横线命名在 Rust 中转为下划线（`start-backup` → `on_start_backup`）。

---

## 5. 模块接口契约（并行开发的唯一事实源） / Frozen Interface Contracts

> 以下签名是并行开发的**冻结契约**，任何模块只能依赖本节，不得臆造对方 API。

### 5.1 `src/model.rs`（共享类型 + 错误） / Shared Types & Errors

```rust
use std::path::PathBuf;
use std::sync::Arc;
use crate::distro::{DistroInfo, Family};

/// UI/CLI 共用进度回调
pub type ProgressFn = Arc<dyn Fn(f32, String) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupMode { Minimal, Standard, Full }
impl BackupMode {
    pub fn from_index(i: i32) -> Self;           // 0/1/2 → Minimal/Standard/Full
    pub fn index(&self) -> i32;
    pub fn label(&self) -> &'static str;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind { Module, Dkms, Config, Firmware }

#[derive(Debug, Clone)]
pub struct ScanEntry { pub abs_path: PathBuf, pub rel_path: String, pub size: u64, pub kind: EntryKind }

#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    pub entries: Vec<ScanEntry>,
    pub skipped_in_tree: usize,
    pub firmware_bytes: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry { pub path: String, pub size: u64, pub sha256: String, pub kind: EntryKind }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestDistro { pub id: String, pub version_id: String, pub pretty_name: String, pub family: Family }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub format_version: u32,     // 恒为 1
    pub tool_version: String,
    pub created_at: String,      // RFC3339
    pub kernel_release: String,
    pub arch: String,
    pub distro: ManifestDistro,
    pub mode: BackupMode,
    pub entries: Vec<ManifestEntry>,
    #[serde(default)] pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum AppError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Format(String),        // 归档/manifest 不合法
    Validation(String),    // 输入不合法（如 kver 含非法字符）
    Cancelled,
    Command { program: String, status: i32, stderr: String },
    Privilege(String),     // 提权失败 / 未获 root
}
impl std::fmt::Display for AppError { … }
impl std::error::Error for AppError { … }
impl From<std::io::Error> for AppError { … }
impl From<serde_json::Error> for AppError { … }
pub type AppResult<T> = Result<T, AppError>;

/// 人类可读体积："1.2 MiB"
pub fn human_size(bytes: u64) -> String;
/// 校验内核版本串是否可安全进入命令行参数
pub fn is_safe_kernel_version(s: &str) -> bool;
```

### 5.2 `src/distro.rs` / Distro Detection

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Family { #[serde(rename = "debian")] Debian, #[serde(rename = "rhel")] Rhel,
                  #[serde(rename = "arch")] Arch, #[serde(rename = "unknown")] Unknown }

#[derive(Debug, Clone)]
pub struct DistroInfo { pub id: String, pub id_like: Vec<String>, pub version_id: String,
                        pub pretty_name: String, pub family: Family }
impl DistroInfo {
    pub fn detect() -> Self;                 // /etc/os-release：ID → ID_LIKE → Unknown
    pub fn family_label(&self) -> &'static str;  // "Debian 系" / "RHEL 系" / …
}
impl std::fmt::Display for DistroInfo { … }  // 一行摘要，用于 system-info

pub fn kernel_release() -> String;           // /proc/sys/kernel/osrelease
pub fn arch() -> &'static str;               // std::env::consts::ARCH
pub fn is_root() -> bool;                    // 解析 /proc/self/status Uid
pub fn module_roots() -> Vec<std::path::PathBuf>;   // /lib/modules + /usr/lib/modules 去重

#[derive(Debug, Clone)]
pub struct SystemCmd { pub program: String, pub args: Vec<String> }
pub fn depmod_cmd(kver: &str) -> SystemCmd;                     // depmod -a <kver>
pub fn initramfs_cmd(family: Family, kver: &str) -> Option<SystemCmd>;
pub fn has_cmd(name: &str) -> bool;                             // PATH 查找
```

### 5.3 `src/scan.rs` / Scanning

```rust
use crate::distro::DistroInfo;
use crate::model::{AppResult, BackupMode, ScanReport};

pub struct ScanOptions<'a> {
    pub kver: &'a str,
    pub distro: &'a DistroInfo,
    pub mode: BackupMode,
    pub cancel: Option<&'a std::sync::atomic::AtomicBool>,
}
/// 全树扫描 + in-tree 基线排除；不依赖 root
pub fn scan(opt: &ScanOptions<'_>) -> AppResult<ScanReport>;
```

### 5.4 `src/backup.rs` / Backup Pipeline

```rust
use crate::model::{AppResult, BackupMode, Manifest, ProgressFn, ScanReport};
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub struct BackupRequest {
    pub out_file: PathBuf,          // 目标 .tar.gz
    pub kver: String,
    pub distro: crate::distro::DistroInfo,
    pub mode: BackupMode,
    pub progress: ProgressFn,
    pub cancel: Arc<AtomicBool>,
}

pub struct BackupReport {
    pub out_file: PathBuf,
    pub bytes_written: u64,
    pub entry_count: usize,
    pub duration_ms: u128,
    pub manifest: Manifest,
}

/// 三段流水：Walker → Hasher×N → Packer；内部自建线程
pub fn run_backup(req: BackupRequest) -> AppResult<BackupReport>;
/// 供 GUI 预填输出路径：~/driver-backup-<kver>-<ts>.tar.gz
pub fn default_out_path(kver: &str) -> PathBuf;
```

### 5.5 `src/restore.rs` / Restore Pipeline

```rust
pub struct ArchiveInfo { pub manifest: Manifest, pub total_bytes: u64 }
/// 只读：解出 manifest 并统计体积（GUI 还原前预览 / dry-run 依据）
pub fn inspect(archive: &std::path::Path) -> AppResult<ArchiveInfo>;

pub struct RestoreRequest {
    pub archive: std::path::PathBuf,
    pub kver: Option<String>,            // None → 用 manifest.kernel_release
    pub dry_run: bool,
    pub allow_kernel_mismatch: bool,
    pub with_firmware: bool,
    pub progress: ProgressFn,
    pub cancel: Arc<std::sync::atomic::AtomicBool>,
}
pub struct RestoreReport {
    pub dry_run: bool,
    pub written: usize,
    pub skipped: usize,
    pub depmod_done: bool,
    pub initramfs_done: Option<bool>,    // None = 未知发行版跳过
    pub notes: Vec<String>,
}
/// 需要 root 时返回 AppError::Privilege，由 main 决定是否 pkexec 重入
pub fn run_restore(req: RestoreRequest) -> AppResult<RestoreReport>;
```

### 5.6 `src/privilege.rs` / Privilege Elevation

```rust
pub const HELPER_FLAG: &str = "--helper-restore";
/// 当前可执行文件绝对路径（pkexec 重入用）
pub fn self_exe() -> crate::model::AppResult<std::path::PathBuf>;
/// 启动 `pkexec <self> --helper-restore --archive <f> …`，逐行解析行协议，
/// 通过 progress 回调驱动 UI；返回 RESULT 行的成败
pub fn run_helper_via_pkexec(args: &[String], progress: crate::model::ProgressFn,
                             cancel: std::sync::Arc<std::sync::atomic::AtomicBool>)
    -> crate::model::AppResult<String>;
/// helper 模式下的 stdout 行协议输出（root 进程内使用）
pub struct HelperSink;
impl HelperSink {
    pub fn progress(&self, v: f32, msg: &str);
    pub fn note(&self, msg: &str);
    pub fn result(&self, ok: bool, msg: &str);
}
```

### 5.7 `src/main.rs`（CLI 子集） / CLI Subset

```
linux-driver-backup                          # 无参数 → 启动 GUI
linux-driver-backup --scan [--mode m] [--json]           # 扫描并打印（JSON 便于测试）
linux-driver-backup --backup --out <f> [--mode m] [--kver k]
linux-driver-backup --restore --archive <f> [--dry-run] [--yes] [--with-firmware]
linux-driver-backup --helper-restore --archive <f> …     # 仅由 pkexec 调用
```

---

### 5.8 v0.2.0 增补契约 / v0.2.0 contract addendum

> 依 ROADMAP-v2 §3 的 P0 计划实现；**归档格式 v2**，并保证 v1 归档仍可读（serde 默认值补齐）。

**`model.rs`（新增/变更）**

```rust
pub enum EntryKind { Module, Dkms, Config, Firmware, Symlink }      // +Symlink
pub struct Provenance { pub manager: String, pub package: String, pub version: String }
pub struct ModInfo { pub vermagic: Option<String>, pub depends: Vec<String>,
                     pub firmware: Vec<String>, pub sig_id: Option<String>, pub sig_key: Option<String> }
impl ModInfo { pub fn is_signed(&self) -> bool; }
pub enum RestoreStrategy { Rebuild, Reinstall, WeakModules, Copy, Skip }
impl RestoreStrategy { pub fn label_zh(&self) -> &'static str; }
pub struct SecureBootInfo { pub enabled: bool, pub sig_enforce: bool }
pub struct DkmsPackage { pub name: String, pub version: String }

pub struct ScanEntry  { /* 既 4 字段 */ pub link_target: Option<String>, pub owner: Option<Provenance>,
                        pub modinfo: Option<ModInfo>, pub content_stored: bool }
pub struct ScanReport { /* 既 4 字段 */ pub dkms: Vec<DkmsPackage> }
pub struct ManifestEntry { /* 既 4 字段 */ pub link_target: Option<String>, pub owner: Option<Provenance>,
                            pub modinfo: Option<ModInfo>, pub content_stored: bool,
                            pub strategy_hint: Option<RestoreStrategy> }
pub struct Manifest { /* 既字段 */ pub kernel_vermagic: Option<String>, pub immutability: Option<String>,
                       pub secure_boot: Option<SecureBootInfo>, pub compression: Option<String>,
                       pub dkms: Vec<DkmsPackage> }
impl Manifest { pub fn format_supported(&self) -> bool; pub fn is_legacy_v1(&self) -> bool; }
pub const MANIFEST_FORMAT_VERSION: u32 = 2;      // v2
pub const MIN_MANIFEST_FORMAT_VERSION: u32 = 1;  // 仍可读 v1
```

**`distro.rs`（新增）**

```rust
pub enum Immutability { Mutable, Ostree, Nix, ReadOnlyUsr }
impl Immutability { pub fn tag(&self) -> &'static str; pub fn label_zh(&self) -> &'static str; }
pub struct SecureBootState { pub enabled: bool, pub sig_enforce: bool }
impl SecureBootState { pub fn to_info(&self) -> crate::model::SecureBootInfo; }
pub struct MokKeyPair { pub private: PathBuf, pub certificate: PathBuf }

pub fn immutability() -> Immutability;                 // /run/ostree-booted、/run/current-system、/usr ro
pub fn secure_boot_state() -> SecureBootState;         // mokutil --sb-state + sig_enforce
pub fn mok_keys() -> Vec<MokKeyPair>;                  // /var/lib/shim-signed/mok、/etc/pki/akmods
pub fn sign_tool(kver: &str) -> Option<(String, Vec<String>)>;   // kmodsign / sign-file
pub fn reference_vermagic(kver: &str) -> Option<String>;
pub fn is_module_path(path: &Path) -> bool;
pub const MODULE_COMPRESSION_SUFFIXES: [&str; 7];
pub fn dkms_install_cmd(name: &str, version: &str, kver: &str) -> Option<SystemCmd>;
pub fn akmods_cmd(kver: &str) -> Option<SystemCmd>;
pub fn reinstall_cmd(manager: &str, package: &str) -> Option<SystemCmd>;
pub fn weak_modules_cmd() -> Option<SystemCmd>;
```

**`restore.rs`（新增/变更）**

```rust
pub enum ImmutablePolicy { Refuse, Usroverlay }
pub struct RestoreJournal { pub created_at: String, pub target_kver: String,
                            pub root: String, pub entries: Vec<JournalEntry> }
impl RestoreJournal { pub fn save(&self, path: &Path) -> AppResult<()>;
                      pub fn load(path: &Path) -> AppResult<Self>; }
pub struct RollbackReport { pub restored: usize, pub removed: usize, pub notes: Vec<String> }
pub const DEFAULT_KEEP_ROLLBACK: usize = 3;

pub struct RestoreRequest { /* 既字段 */ pub root: Option<PathBuf>,
    pub strategy: Option<RestoreStrategy>, pub on_immutable: ImmutablePolicy,
    pub strict_links: bool, pub no_sign: bool, pub chroot_exec: bool,
    pub keep_rollback: usize }
// 注意：RestoreRequest 现在实现 Default（便于 `..Default::default()` 构造）

pub struct RestoreReport { /* 既字段 */ pub links_written: usize, pub rebuilt: usize,
    pub reinstalled: usize, pub signed: usize, pub unsigned_left: usize,
    pub rollback_journal: Option<PathBuf>, pub strategy_counts: Vec<(String, usize)> }

pub fn run_rollback(root: &Path, journal: Option<&Path>, progress: ProgressFn) -> AppResult<RollbackReport>;
pub fn latest_journal(root: &Path) -> Option<PathBuf>;
```

**`main.rs`（CLI 增补）**

```
--restore … [--root <dir>] [--strategy auto|rebuild|reinstall|weak-modules|copy]
            [--on-immutable refuse|usroverlay] [--strict-links] [--no-sign] [--chroot-exec]
--rollback [last|<id>] [--root <dir>]
```

> 还原顺序（v0.2.0）：**inspect → 内核/架构/vermagic 校验 → 权限 → 不可变系统闸门 →
> 事务化解压（符号链接 / 来源包 / 回滚日志）→ 重建(DKMS/akmods) → 重装包 → weak-modules →
> depmod → restorecon → Secure Boot 签名 → initramfs → 汇总**。

---

## 6. 测试与验收 / Testing & Acceptance

1. `cargo build --release` 无 error；`cargo clippy -- -D warnings` 尽量通过。
2. CLI 冒烟（CI 与本机 Mint 均可跑，无需 root）：
   - `--scan --json` → 合法 JSON，含 `entries`、`kernel_release`
   - `--backup --out /tmp/x.tar.gz --mode minimal` → 产物存在且 `tar -tzf` 含 `manifest.json`
   - `--restore --archive /tmp/x.tar.gz --dry-run --yes` → 输出计划不写盘
3. 单元测试（各模块 `#[cfg(test)]`）：os-release 解析、kver 校验、路径穿越拒绝、manifest 往返序列化。
4. 手工验收：GUI 扫描/备份/取消/进度；还原走 pkexec 弹密码框。

## 7. CI 与分发（`.github/workflows/build.yml`） / CI & Distribution

- 触发：push / tag `v*`。
- 矩阵：`x86_64-unknown-linux-gnu`（在 `ubuntu-22.04` 容器内编译，保证 glibc ≥ 2.35 之前的兼容性）、`aarch64-unknown-linux-gnu`（cross）。
- 必装系统包：`pkg-config libxkbcommon-dev libwayland-dev libx11-dev`（winit/xkbcommon 头文件）。
- 产物：`strip` 后单文件 + `sha256sum` 清单，tag 时自动创建 GitHub Release。
- musl 静态版列为**实验性**（Slint 软件渲染 + winit 在 musl 上未充分验证，见 §9）。

## 8. 许可 / License

选择 **GPL-3.0-only**，与 Slint 的 `GPL-3.0-only OR …` 授权兼容；README 必须注明 Slint 授权来源。

## 9. 已知风险与待验证项 / Known Risks

| 风险 | 影响 | 缓解 |
|---|---|---|
| 软件渲染性能 | 大窗口低端机可能掉帧 | UI 尺寸小（640×480），实测后再决定是否加 femtovg |
| winit 运行时 `dlopen` `libxkbcommon.so.0`/`libwayland-client` | 极简容器/服务器无这些库 | 文档声明运行时依赖；CI 产物 README 列明 |
| musl 静态链接未经验证 | 静态版可能无法启动 | 列为实验性，主线交付 glibc 版 |
| `/lib/firmware` 体积（可达数百 MB） | full 模式耗时长 | 体积预估 + 进度 + 可取消 |
| 跨内核还原（备份 6.8 → 还原到 6.11） | 模块 ABI 不兼容 | manifest 比对 + UI 二次确认 + `allow_kernel_mismatch` |
| `pkexec` 在无显示/SSH 环境不可用 | 还原失败 | 检测失败后提示改用 `sudo` CLI 模式 |
| 未做增量/加密归档 | 大归档重复占用 | 列入路线图 |

---

## 10. 开发期流水作业计划（本次执行） / Development Pipeline Plan

| 波次 | 并行单元 | 产出 | 依赖 |
|---|---|---|---|
| W1 | A：工程骨架 | `Cargo.toml`、`build.rs`、`ui/app_window.slint`、`.gitignore` | — |
| W1 | B：系统适配 | `src/distro.rs`、`src/scan.rs` | §5.2/§5.3 |
| W1 | C：备份流水线 | `src/model.rs`、`src/backup.rs` | §5.1/§5.4 |
| W1 | D：还原与提权 | `src/restore.rs`、`src/privilege.rs` | §5.5/§5.6 |
| W1 | E：CI 与文档 | `.github/workflows/build.yml`、`README.md` | — |
| W2 | F：集成 | `src/main.rs`（GUI 绑定 + CLI 分发） | A–D 全部就位 |
| W3 | G：验证 | `cargo build` / `clippy` / CLI 冒烟 / 修复 | W2 |
| W4 | H：打包分发 | `packaging/**`、`LICENSE`、CI package job、README 安装章节 | W3 |

W1 各单元**只写文件、不并行执行 cargo**（避免 target/ 锁竞争），W3 统一编译验证。

---

## 11. 打包与分发 / Packaging & Distribution

**目标 / Goal**：各主流发行版「下载即装、装完即跑」，不需要用户手动编译。

### 11.1 交付物矩阵 / Deliverables

| 格式 | 适用发行版 | 构建工具 | 依赖声明 |
|---|---|---|---|
| `.deb` | Debian / Ubuntu / Linux Mint / Kali / Deepin / elementary | `dpkg-deb --build`（本机与 CI 均已具备） | `Depends: libc6, libxkbcommon0, libwayland-client0`（按实际链接动态补全） |
| `.rpm` | Fedora / RHEL / Rocky / AlmaLinux / openEuler | `rpmbuild -bb`（CI 上 `apt-get install rpm`；本机无 rpmbuild，交由 CI 产出） | `Requires: glibc, libxkbcommon, wayland` |
| AppImage | **任意发行版**（免安装、可放 U 盘） | `appimagetool`（CI 下载官方产物，`APPIMAGE_EXTRACT_AND_RUN=1` 免 FUSE） | 无，自包含 |
| `PKGBUILD` | Arch / Manjaro / EndeavourOS / AUR | `makepkg -si`（源码包，供 AUR 提交） | `depends=(glibc wayland libxkbcommon)` |
| `tar.gz` + `install.sh` | 无包管理器 / 嵌入式 / 通用兜底 | `tar` + 安装脚本（装入 `/usr/local/bin`） | 无 |
| Flatpak manifest | 沙箱化分发（**路线图，首版不产出**） | `flatpak-builder` + `packaging/flatpak/*.yml` | runtime `org.freedesktop.Platform//24.08` |

**架构范围 / Arch scope**：`build-packages.sh` 支持 `--arch <amd64|arm64> --bin <路径>`，可在 x86_64 runner 上**直接为 aarch64 二进制出包**（`dpkg-deb` 与 `rpmbuild --target aarch64` 只做「元数据 + 文件」组装，不校验机器码，故无需 QEMU 或原生 runner）。因此 CI 的 `package` job 现在同时产出：

| 架构 | deb | rpm | tar.gz | AppImage | 单文件二进制 |
|---|---|---|---|---|---|
| x86_64 / amd64 | ✅ | ✅ | ✅ | ✅ | ✅ |
| aarch64 / arm64 | ✅ | ✅ | ✅ | ⚠️ 暂不产出（appimagetool 交叉组装意义有限） | ✅ |

脚本另带**架构一致性提示**：若 `--arch` 与二进制 `file` 描述不符，只打印提示（不失败），避免误发。

### 11.2 桌面集成资产 / Desktop integration

```
packaging/
├── linux-driver-backup.desktop   # Type=Application; Exec=linux-driver-backup;
│                                 # Icon=linux-driver-backup; Categories=System;Utility;Terminal=false
├── icon.svg                      # 可缩放图标（安装到 /usr/share/icons/hicolor/scalable/apps/）
├── linux-driver-backup.spec      # RPM spec 模板
├── arch/PKGBUILD                 # Arch 源码包（pkgname/pkgver/pkgrel/source/checksums）
├── deb/                          # .deb 组装（DEBIAN/control + data 树）
├── appimage/AppDir/              # AppRun + .desktop + usr/bin
├── flatpak/io.github.ltbkq.LinuxDriverBackup.yml
├── install.sh                    # 通用安装：cp → /usr/local/bin、desktop、icon；--uninstall 对应卸载
└── build-packages.sh             # 统一入口：探测本机可用工具，生成全部可生成的格式
```

安装路径规范 / Install layout：
- 二进制 → `/usr/bin/`（deb/rpm）或 `/usr/local/bin/`（install.sh）
- `.desktop` → `/usr/share/applications/linux-driver-backup.desktop`
- 图标 → `/usr/share/icons/hicolor/scalable/apps/linux-driver-backup.svg`（安装后 `update-icon-caches` 可选）
- `LICENSE`（GPL-3.0 全文，取自系统 `/usr/share/common-licenses/GPL-3`）→ `/usr/share/doc/linux-driver-backup/copyright`（deb）/ `%{_docdir}`（rpm）

### 11.3 构建与验证流程 / Build & verify

1. **本机 W4 验证**（Mint，已具备 `dpkg-deb` 与 `desktop-file-install`）：
   - `./packaging/build-packages.sh deb tar` → 产出 `.deb` 与 `tar.gz`
   - 验证：`dpkg-deb -I` 检查控制字段、`dpkg-deb -c` 检查路径；`lintian`（若可用）；**在临时 root 目录解包后用 `dpkg --root=` 或直接 `dpkg -x` 抽取并运行 `--scan --json` 冒烟**
   - `tar.gz` 用 `install.sh --prefix=/tmp/xxx` 装完执行 `linux-driver-backup --version`
2. **CI `package` job**（`needs: build`，仅 x86_64，tag 时额外产出 rpm/AppImage）：
   - deb：复用 CI 已编译二进制 + `packaging/deb` 组装
   - rpm：`apt-get install rpm` → `rpmbuild -bb`
   - AppImage：下载 appimagetool → 组 AppDir → 打包
   - 全部产物与 `.sha256` 一并挂到 GitHub Release

### 11.4 风险与约束 / Constraints

- `.rpm` 与 AppImage **本机无工具**（无 `rpmbuild`/`appimagetool`），只在 CI 构建并验证，避免本机 sudo 安装工具链。
- deb/rpm 的 `Depends/Requires` 首版按运行时实际 `dlopen` 需求手写（`libxkbcommon0` 等），CI 中用 `ldd` 复核，避免声明过宽（安装冲突）或过窄（运行缺库）。
- AppImage 在 CI 需网络下载 appimagetool；失败则降级为只发 deb/rpm/tar（Release 不因此失败，标记 warning）。
- Flatpak/Snap 首版**只提供 manifest 不做自动发布**（需外部仓库审核，列入路线图）；`packaging/flatpak/*.yml` 待补（§11.1 已标注路线图）。
- **W3 实测结论（2026-09-27，Linux Mint 22.3 / glibc 2.39）**：`ldd` 显示的**硬链接**依赖为 `libc6` + `libfontconfig1` + `libfreetype6`；`LD_DEBUG=libs` 实测的**运行期 dlopen** 依赖为 `libxkbcommon.so.0`、`libxkbcommon-x11.so.0`（X11 会话）与 `libwayland-client`（Wayland 会话）。deb/rpm 的依赖字段与 README 运行时依赖表均已按实测更新（首版手写清单漏了 fontconfig/freetype 与 xkbcommon-x11，已补齐）。
- **RPM 依赖包名（v0.1.2 修复）**：初版 spec 把 `wayland` 当作 Requires 包名，Fedora 上不存在该包（提供 `libwayland-client.so.0` 的包名为 `libwayland-client`），导致 `rpm -ivh` 报「wayland 被 linux-driver-backup 需要」而拒绝安装。现策略：**硬链接依赖由 `AutoReqProv` 自动生成 soname 依赖**（`libfontconfig.so.1()(64bit)` 等），只手写运行期 dlopen 的库，并按 `%if 0%{?fedora} || 0%{?rhel} || 0%{?ldb_target_fedora}` 使用 Fedora/RHEL 真实包名；其它 RPM 发行版退化为 SoName 文件依赖。CI 增加回归断言：Requires 中不得出现裸 `wayland`，且必须含自动生成的 `libfontconfig.so.1`。
- **lintian 全绿待办**（W4-H 实测本机 lintian 报 3E1W：`copyright-contains-full-gpl-license`、`copyright-not-using-common-license-for-gpl`、`no-changelog`、`no-manual-page`）：首版以「LICENSE 全文即 copyright」为准，不影响安装；路线图为改用 DEP-5 短 copyright + 单列 `LICENSE`、补 `changelog.Debian.gz`（版本加 `-1` 修订位）、补 man page。
- `AppDir/usr/bin` 为构建产物不入库，`packaging/appimage/AppDir/` 只入库 `AppRun` 骨架。
- RPM `Source0` 首版不声明（声明后 rpmbuild 强制校验 `_sourcedir` 同名源码包），CI 走 `%build` 留空 + 拷入二进制；将来发 SRPM 时再启用。

---

## 附录 A：文档规范 / Appendix A: Documentation Policy

- 项目所有文档（`DESIGN.md`、`README.md`、源码模块注释）采用**中英文双语，以中文为主**。
- All project documents (`DESIGN.md`, `README.md`, module-level source comments) are **bilingual: Chinese-primary, English-secondary**.
- 约定 / Convention：章节标题、摘要、表格关键列提供英文对照；正文论述以中文为主；公共 API 的 doc comment 首句提供英文一句话说明，其后可用中文展开细节。
- Section titles, abstracts and key table columns carry English equivalents; prose stays Chinese; every public API doc comment starts with a one-line English summary, optionally followed by Chinese details.

## 附录 B：English Summary（英文摘要）

**What was verified (12 checks)**
1. Slint `1.3` → outdated; current is **1.18.1** (2026-09-21). 2. Slint officially states `#[tokio::main]` is **not recommended**: tokio futures may never be driven by Slint's event loop → tokio removed. 3. `sys-info` last updated **2021-10-21**, unmaintained → replaced by reading `/proc/sys/kernel/osrelease`. 4/5. Two API naming mismatches (`start_restore` vs `on_restore_with_initramfs`, `get_initramfs_command` vs `get_initramfs_cmd`) → compile errors, fixed by contract §5. 6. Strong component reference captured in callbacks → reference loop/leak; use `as_weak()`. 7. `invoke_from_event_loop(..).unwrap()` panics after loop exit → ignore error. 8. `ProgressIndicator { progress: 0..1 }` confirmed to exist. 9. Backup scope widened: full `/lib/modules` walk with in-tree baseline exclusion, `/etc/{modprobe.d,udev/rules.d,depmod.d,modules-load.d}`, DKMS sources, optional `/lib/firmware`. 10. **`depmod -a <kver>` was missing** — without it restored modules are invisible; now mandatory before initramfs, plus `restorecon` on RHEL. 11. "No-dependency single file" qualified: runtime `dlopen`s `libxkbcommon`/`libwayland-client`, needs system fonts, binary ≈ 6–15 MB stripped; default features trimmed via `default-features = false`. 12. Backup is **unprivileged** (read-only on 0755/0644 trees); only restore needs root.

**Architecture**
- Runtime: UI thread (Slint) ⇄ worker threads via `std::thread` + `mpsc` progress + `Arc<AtomicBool>` cancel; a **3-stage bounded pipeline** (Walker → Hashers → Packer) with `sync_channel` backpressure.
- Privilege: single elevation via `pkexec <self> --helper-restore …`, a line protocol (`PROGRESS/NOTE/RESULT`) drives the UI; no external `tar`/`sh` needed.
- Archive: `tar.gz` + `manifest.json` (per-file SHA-256, kernel/distro/arch metadata) for verified cross-machine restore.
- Delivery: one stripped binary; glibc x86_64/aarch64 as primary targets, musl static experimental; license **GPL-3.0-only** to match Slint.

**Development pipeline**: W1 five parallel units (skeleton / distro+scan / backup / restore+privilege / CI+README) written against frozen contracts §5 with no concurrent `cargo` runs; W2 integration (`main.rs`); W3 build, clippy, CLI smoke tests.
