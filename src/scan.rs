//! 驱动扫描：全树遍历 + in-tree 基线排除 + 三级模式（Minimal/Standard/Full）。
//! Driver scanning: full-tree walk with in-tree baseline exclusion and the three backup modes.
//!
//! 对应 DESIGN.md §4.2 扫描策略与 ROADMAP-v2 §3（P0-1/P0-2/P0-5），要点：
//!
//! - 同时考虑 `/lib/modules` 与 `/usr/lib/modules`（由 [`crate::distro::module_roots`] 去重）；
//! - `module_root/<kver>/` 下位于 `kernel/` 子树的 `.ko*` 属于内核自带基线（in-tree），
//!   只计数进 [`ScanReport::skipped_in_tree`]，**不备份**（内核包升级即恢复）；
//! - `kernel/` 之外的全部 `.ko*`（`updates/`、`extra/`、`extramodules/`、`weak-updates/`、
//!   `nvidia/` 等任意顶层目录以及根下的散文件）都是 out-of-tree 模块，全部收录；
//! - `/etc/{modprobe.d,udev/rules.d,depmod.d,modules-load.d}` 的常规文件从 Minimal 起就收录；
//! - DKMS 源码（`/var/lib/dkms/<pkg>/<ver>` + `/usr/src` 同名/`*-dkms` 目录）在 Standard 起收录；
//! - `/lib/firmware` 整棵树仅 Full 收录，并把体积累加进 [`ScanReport::firmware_bytes`]；
//! - 不存在的目录、读不了的子树等非致命问题一律记入 [`ScanReport::warnings`]，不整体失败；
//! - 每处理一个条目都会检查 `cancel`，命中即返回 [`AppError::Cancelled`]。
//!
//! ## v0.2.0 新增（归档格式 v2）
//! v0.2.0 additions (archive format v2):
//!
//! - **P0-1 符号链接语义**：叶子符号链接**不再被跟随/实体化**，而是产出
//!   [`EntryKind::Symlink`] + [`ScanEntry::link_target`]（`readlink` 原文），`size = 0`；
//!   仅当链接名或链接目标形如模块，或链接位于受管配置目录时收录，其余只记 warning。
//!   目录符号链接保持"不跟随"并记 warning；
//! - **P0-2 模块元数据**：对每个 [`EntryKind::Module`] 调用一次 `modinfo`，解析为
//!   [`ModInfo`]（`vermagic` / `depends` / `firmware` / `sig_id` / `sig_key`）；
//! - **P0-5 来源包**：批量 `dpkg-query -S`（回退 `rpm -qf`）把结果填入
//!   [`ScanEntry::owner`]；查询失败/工具缺失**绝不报错**，只保持 `None`；
//! - **DKMS 清单**：Standard/Full 模式遍历 `/var/lib/dkms/<name>/<version>` 收集
//!   [`ScanReport::dkms`]；
//! - **固件内容标记**：Full 模式下若固件文件属于系统包（由 `owner` 判断），
//!   标记 [`ScanEntry::content_stored`]`= false`（由包提供，不重复存内容）。
//!
//! ## v0.3.0 W3（扫描正确性/性能）
//! v0.3.0 W3 scan fixes:
//!
//! - **C-24**：`rpm -qf` 改为批量（每 [`QUERY_CHUNK`] 路径一次 fork，30s 超时，
//!   只取包名+版本，不再输出 `%{FILENAMES}`）；
//! - **C-25**：先判 in-tree 再处理符号链接，`kernel/` 内的链接不再被当成外置模块；
//! - **C-26**：静默跳过 `build`/`source` 头文件链接；[`push_warning`] 全局去重 +
//!   [`MAX_WARNINGS`] 上限 + 溢出计数；
//! - **C-27**：配置路径扩展覆盖 initramfs 控制文件/目录（[`CONFIG_PATHS`]）；
//! - **C-28**：固件目录在真实目录间回退（usr-merge 下 `/lib/firmware` 是链接）；
//!   [`ScanReport::firmware_bytes`] 只累计 `content_stored` 的固件；
//! - **C-29**：`/usr/src` 匹配读取 `dkms.conf` 的 `PACKAGE_NAME`，并与 manifest
//!   复用同一次 `/var/lib/dkms` 枚举；
//! - **C-43**：`modinfo` 批量调用，第 5 阶段（元数据+归属）接入取消检查；
//! - **C-37**：单文件不可读只记 warning，不中止扫描。
//!
//! 路径约定：[`ScanEntry::rel_path`] 是"去掉前导 `/` 的相对路径"
//! （如 `lib/modules/6.8.0-45-generic/updates/dkms/foo.ko`），归档直接按它落盘（DESIGN.md §4.3）。

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use walkdir::WalkDir;

use crate::distro::{has_cmd, is_module_path, module_roots, DistroInfo, Family};
use crate::model::{
    AppError, AppResult, BackupMode, DkmsPackage, EntryKind, ModInfo, Provenance, ScanEntry,
    ScanReport,
};

/// 所有模式都会扫描的配置路径（C-27：补齐控制还原期 initramfs 行为的文件/目录）。
/// Configuration paths scanned in every mode (C-27). The `bool` says whether an
/// absent path is worth a warning: the four core dirs are, the distro-specific
/// extras are not (avoids warning spam on systems that do not have them).
///
/// `/etc/modules`、`/etc/dracut.conf`、`/etc/mkinitcpio.conf` 是**文件**，
/// 其余是**目录**；[`scan`] 按路径实际类型分派（目录走 [`walk_files`]，文件走
/// [`push_file`]，符号链接走 [`handle_symlink`]）。
const CONFIG_PATHS: &[(&str, bool)] = &[
    // 核心四目录：缺失时告警（旧行为）
    ("/etc/modprobe.d", true),
    ("/etc/udev/rules.d", true),
    ("/etc/depmod.d", true),
    ("/etc/modules-load.d", true),
    // C-27 扩展：控制还原期 initramfs 行为的配置（缺失静默）
    ("/etc/initramfs-tools", false),
    ("/etc/dracut.conf", false),
    ("/etc/dracut.conf.d", false),
    ("/etc/mkinitcpio.conf", false),
    ("/etc/mkinitcpio.d", false),
    ("/etc/modules", false),
    ("/etc/sysconfig/modules", false),
];

/// DKMS 已注册模块库（`<pkg>/<ver>/`） / Registered DKMS modules.
const DKMS_ROOT: &str = "/var/lib/dkms";

/// DKMS 源码目录（与 `/var/lib/dkms` 的 pkg 同名，或名字含 `-dkms`） / DKMS source trees.
const USR_SRC: &str = "/usr/src";

/// 固件目录候选，仅 Full 模式（C-28：usr-merge 下 `/lib/firmware` 为符号链接，
/// 需要回退到真实目录 `/usr/lib/firmware`）。
/// Firmware directory candidates (C-28: `/lib/firmware` is a symlink on usr-merged systems).
const FIRMWARE_DIRS: &[&str] = &["/lib/firmware", "/usr/lib/firmware"];

/// 批处理外部命令（`dpkg-query` / `rpm`）时每次传入的最大路径/包数，防命令行超长。
/// Max paths/packages per external query invocation, guarding against ARG_MAX.
const QUERY_CHUNK: usize = 256;

/// 依赖外部命令（`rpm` / `modinfo`）的默认超时：超时即放弃该批、降级为 `None`。
/// Default timeout for external queries (C-24/C-43): on timeout the batch is dropped.
const QUERY_TIMEOUT: Duration = Duration::from_secs(30);

/// `modinfo` 失败原因最多写入的 warning 条数（去重后），避免刷屏。
/// Maximum number of distinct `modinfo` failure warnings (after dedup).
const MAX_MODINFO_WARNINGS: usize = 3;

/// `rpm -qf` 的批量查询格式：只取包名与版本，**不取 `%{FILENAMES}`**
/// （C-24：后者对每个包输出全部文件列表，可达数 MB 且只用首行）。
/// Batched `rpm -qf` query format: package name + version only, never `%{FILENAMES}`.
///
/// P-1 待容器复核：若 Fedora 上多路径 `-qf` 并非"每个路径一行"，解析会按键数
/// 校验失败并自动回退到逐路径查询（见 [`collect_owners_rpm_with`]），不影响正确性。
const RPM_BATCH_FORMAT: &str = "%{NAME}\t%{VERSION}-%{RELEASE}\n";

/// `report.warnings` 的全局上限（C-26）：超过后只保留一条溢出计数。
/// Global cap for `report.warnings` (C-26); beyond it only an overflow counter is kept.
const MAX_WARNINGS: usize = 200;

/// 溢出计数的前缀，用于在达到上限后原地累加被省略的条数。
/// Prefix of the overflow counter warning, updated in place once the cap is hit.
const WARNING_OVERFLOW_PREFIX: &str = "（更多告警已省略，共 ";

/// Scan input: kernel version, distro, backup mode and an optional cancellation flag.
///
/// `kver` 会被校验（[`crate::model::is_safe_kernel_version`]），不安全的串直接报
/// [`AppError::Validation`]，防止 `../` 逃逸出模块目录。
pub struct ScanOptions<'a> {
    /// Target kernel release, e.g. `6.8.0-45-generic` / 目标内核版本
    pub kver: &'a str,
    /// Detected distro, used for advisories (never changes scope) / 已探测发行版，仅用于提示
    pub distro: &'a DistroInfo,
    /// Backup mode; decides whether DKMS and firmware are included / 备份模式
    pub mode: BackupMode,
    /// Cancellation flag; `true` makes scanning return [`AppError::Cancelled`] / 取消开关
    pub cancel: Option<&'a AtomicBool>,
}

/// Walk every configured tree and build a [`ScanReport`] (unprivileged, read-only).
///
/// 全树扫描 + in-tree 基线排除；只读系统目录，**不依赖 root**（只读外部命令 `modinfo` /
/// `dpkg-query` / `rpm`，失败一律降级为 `None`/warning，绝不整体失败）。
///
/// # 注意 / Note
///
/// `Full` 模式下 [`ScanReport::entries`] 可能包含**上万条** firmware 条目
/// （`linux-firmware` 常达数百 MB）；调用方（`main.rs`）**只应把 module/dkms/config
/// 的摘要塞进 UI 列表**，firmware 仅用 [`ScanReport::firmware_bytes`] 做体积提示，
/// 避免 GUI 列表爆炸。
pub fn scan(opt: &ScanOptions<'_>) -> AppResult<ScanReport> {
    let mut report = ScanReport::default();
    check_cancel(opt)?;

    // 路径安全：kver 会拼进 module_root，先按统一规则校验
    if !crate::model::is_safe_kernel_version(opt.kver) {
        return Err(AppError::Validation(format!(
            "内核版本串不安全: {:?}",
            opt.kver
        )));
    }
    if opt.distro.family == Family::Unknown {
        let id = if opt.distro.id.is_empty() {
            "?"
        } else {
            opt.distro.id.as_str()
        };
        push_warning(
            &mut report,
            format!("未识别的发行版家族（ID={id}），还原时将跳过 initramfs 更新"),
        );
    }

    // 1) out-of-tree 模块：/lib/modules/<kver> 与 /usr/lib/modules/<kver>
    let roots = module_roots();
    if roots.is_empty() {
        push_warning(
            &mut report,
            "未找到可读的模块目录（/lib/modules、/usr/lib/modules）".to_string(),
        );
    }
    for root in &roots {
        scan_module_root(&root.join(opt.kver), opt, &mut report)?;
    }

    // 2) 配置文件/目录：Minimal 起就包含（C-27：目录与单文件混合，按类型分派）
    for (raw, warn_if_missing) in CONFIG_PATHS {
        let path = Path::new(raw);
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.is_dir() => walk_files(path, EntryKind::Config, opt, &mut report)?,
            Ok(meta) if meta.file_type().is_symlink() => handle_symlink(path, &mut report),
            Ok(meta) if meta.is_file() => push_file(path, EntryKind::Config, &mut report),
            _ if *warn_if_missing => {
                push_warning(&mut report, format!("配置目录不存在或不可读: {raw}"));
            }
            _ => {}
        }
    }

    // 3) DKMS 源码：Standard 起（可在新内核重建，比 .ko 二进制更可靠）
    if matches!(opt.mode, BackupMode::Standard | BackupMode::Full) {
        scan_dkms(opt, &mut report)?;
    }

    // 4) 固件：仅 Full
    //
    // 权衡：backup 流水线必须逐文件读取/哈希，所以 firmware 只能逐文件进 `entries`
    // （不做"只留汇总条目"的取巧——那样归档会缺内容）；代价是 `entries` 可能上万条，
    // 因此额外把总字节累计到 `firmware_bytes` 供体积预估，UI 侧（main.rs）只把
    // module/dkms/config 摘要塞进列表，firmware 不进 UI 列表。
    if opt.mode == BackupMode::Full {
        match firmware_dir() {
            Some(fw) => walk_files(Path::new(fw), EntryKind::Firmware, opt, &mut report)?,
            None => push_warning(
                &mut report,
                format!(
                    "固件目录不存在或不可读: {}",
                    FIRMWARE_DIRS.join("、")
                ),
            ),
        }
    }

    // 5) v2 元数据：模块 modinfo（P0-2）、来源包 owner（P0-5）、固件内容标记、DKMS 清单。
    //    C-43：这一阶段（尤其 full 模式的上万条固件归属查询）同样必须可取消。
    check_cancel(opt)?;
    collect_module_metadata(opt, &mut report)?;

    check_cancel(opt)?;
    let paths: Vec<PathBuf> = report.entries.iter().map(|e| e.abs_path.clone()).collect();
    let owners = collect_owners(&paths, opt.cancel)?;
    if !owners.is_empty() {
        for entry in report.entries.iter_mut() {
            if let Some(prov) = owners.get(&entry.abs_path) {
                entry.owner = Some(prov.clone());
            }
        }
    }
    // 由系统包提供的固件不再重复存内容（ROADMAP §4 的 `content_stored=false`）。
    mark_package_provided_firmware(&mut report.entries);
    // C-28：体积只统计"真正存入内容"的固件（必须在标记之后累计）。
    if opt.mode == BackupMode::Full {
        tally_firmware(&mut report);
    }

    Ok(report)
}

/// Scan one `module_root/<kver>` tree, splitting in-tree and out-of-tree modules.
///
/// `kernel/` 子树下的 `.ko*` 计入 `skipped_in_tree` 并跳过；其余 `.ko*` 收录为
/// [`EntryKind::Module`]。叶子符号链接按 [`EntryKind::Symlink`] 收录（不再跟随），
/// 目录符号链接与无关链接只记 warning。目录不存在只记 warning（例如只装了
/// `/lib/modules` 的系统）。
fn scan_module_root(
    kver_dir: &Path,
    opt: &ScanOptions<'_>,
    report: &mut ScanReport,
) -> AppResult<()> {
    check_cancel(opt)?;
    if !kver_dir.is_dir() {
        report
            .warnings
            .push(format!("模块目录不存在或不可读: {}", kver_dir.display()));
        return Ok(());
    }

    for result in WalkDir::new(kver_dir) {
        check_cancel(opt)?;
        let entry = match result {
            Ok(e) => e,
            // 子树读取失败（权限/竞态删除）→ 记 warning，继续扫其余部分
            Err(err) => {
                report
                    .warnings
                    .push(format!("遍历 {} 时出错: {err}", kver_dir.display()));
                continue;
            }
        };
        let file_type = entry.file_type();
        // 相对 kver 目录的第一段即分类依据；C-25：**先判 in-tree，再处理符号链接**，
        // 否则 `kernel/` 子树内的链接会被当成外置模块收录。
        let rel = match entry.path().strip_prefix(kver_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let in_tree = rel.starts_with("kernel");
        if file_type.is_symlink() {
            if in_tree {
                // 内核基线子树内的链接：既不是外置模块，也不值得告警。
                if is_module_file(&entry.file_name().to_string_lossy()) {
                    report.skipped_in_tree += 1;
                }
                continue;
            }
            // 符号链接：不跟随；链接名/目标形如模块才收录（如 weak-updates/foo.ko）。
            handle_symlink(entry.path(), report);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy();
        if !is_module_file(&name) {
            continue;
        }
        if in_tree {
            // 内核自带基线：不备份，只统计数量
            report.skipped_in_tree += 1;
            continue;
        }
        push_file(entry.path(), EntryKind::Module, report);
    }
    Ok(())
}

/// Recursively collect regular files under `root` as `kind` entries.
///
/// 用于配置目录、DKMS 源码与固件目录：不做 in-tree 分类，整个子树全收。
/// 叶子符号链接同样不跟随：位于受管配置目录或形如模块才按 [`EntryKind::Symlink`]
/// 收录，其余只记 warning。
fn walk_files(
    root: &Path,
    kind: EntryKind,
    opt: &ScanOptions<'_>,
    report: &mut ScanReport,
) -> AppResult<()> {
    check_cancel(opt)?;
    for result in WalkDir::new(root) {
        check_cancel(opt)?;
        let entry = match result {
            Ok(e) => e,
            Err(err) => {
                push_warning(report, format!("遍历 {} 时出错: {err}", root.display()));
                continue;
            }
        };
        let file_type = entry.file_type();
        if file_type.is_symlink() {
            handle_symlink(entry.path(), report);
            continue;
        }
        if file_type.is_file() {
            push_file(entry.path(), kind, report);
        }
    }
    Ok(())
}

/// Record a leaf symlink as [`EntryKind::Symlink`], or warn and skip it (P0-1).
///
/// 符号链接**不被跟随**：目录链接与无关链接只记 warning；仅当链接名/链接目标
/// 形如模块（[`crate::distro::is_module_path`]）或链接位于受管配置目录时，才按链接
/// 语义收录（`size = 0`，保存 `readlink` 的原始字符串）。
fn handle_symlink(abs: &Path, report: &mut ScanReport) {
    // C-26：`/lib/modules/<kver>/build`、`source` 是内核头文件链接，**必然存在**，
    // 既无备份价值也不应每次扫描都告警 —— 静默跳过。
    if is_kernel_header_link(abs) {
        return;
    }
    // 目录符号链接：walkdir 默认不跟随，这里也明确跳过并记 warning。
    if abs.is_dir() {
        push_warning(report, format!("跳过目录符号链接（不跟随）: {}", abs.display()));
        return;
    }
    let target = match fs::read_link(abs) {
        Ok(t) => t,
        Err(err) => {
            push_warning(report, format!("无法读取符号链接 {}: {err}", abs.display()));
            return;
        }
    };
    if !symlink_is_relevant(abs, &target) {
        push_warning(
            report,
            format!(
                "跳过无关符号链接: {} -> {}",
                abs.display(),
                target.display()
            ),
        );
        return;
    }
    report.entries.push(ScanEntry {
        abs_path: abs.to_path_buf(),
        rel_path: rel_path_of(abs),
        size: 0,
        kind: EntryKind::Symlink,
        link_target: Some(target.to_string_lossy().into_owned()),
        owner: None,
        modinfo: None,
        content_stored: true,
    });
}

/// Whether a symlink is worth archiving: module-like name/target, or inside a managed config dir.
///
/// 链接名或链接目标形如模块，或链接位于受管配置路径（[`CONFIG_PATHS`]）时才有意义。
fn symlink_is_relevant(abs: &Path, target: &Path) -> bool {
    is_module_path(abs) || is_module_path(target) || is_managed_config_dir(abs)
}

/// Whether a path sits under one of the managed configuration paths (C-27).
///
/// 用于判断配置目录/文件内的符号链接是否需要收录。
fn is_managed_config_dir(path: &Path) -> bool {
    CONFIG_PATHS.iter().any(|(dir, _)| path.starts_with(dir))
}

/// Whether this symlink is the well-known `build`/`source` header link under a kernel tree.
///
/// `/lib/modules/<kver>/build`、`source` 指向内核头文件，几乎每台机器都有；
/// 扫描时静默跳过，不再产生噪声告警（C-26）。
fn is_kernel_header_link(abs: &Path) -> bool {
    matches!(
        abs.file_name().and_then(|n| n.to_str()),
        Some("build") | Some("source")
    )
}

/// Collect DKMS sources: `/var/lib/dkms/<pkg>/<ver>/**` and matching `/usr/src` trees.
///
/// `/usr/src` 的匹配规则（避免过度设计）：目录名包含 `-dkms`，或与 `/var/lib/dkms` 中出现的
/// `<pkg>` 同名/以 `<pkg>-` 开头（如 pkg `nvidia` → `/usr/src/nvidia-550.129.03`）。
fn scan_dkms(opt: &ScanOptions<'_>, report: &mut ScanReport) -> AppResult<()> {
    scan_dkms_in(Path::new(DKMS_ROOT), Path::new(USR_SRC), opt, report)
}

/// [`scan_dkms`] 的可测试核心：注入 `/var/lib/dkms` 与 `/usr/src` 两个根目录。
/// Testable core of [`scan_dkms`] with injectable roots.
fn scan_dkms_in(
    dkms_root: &Path,
    usr_src: &Path,
    opt: &ScanOptions<'_>,
    report: &mut ScanReport,
) -> AppResult<()> {
    // C-29：只枚举一次 `/var/lib/dkms`，同时得到「包清单」与「待遍历版本目录」，
    // 供 `ScanReport::dkms` 与文件遍历复用（消除旧实现的两遍目录遍历）。
    let enumerated = enumerate_dkms(dkms_root, report);
    report.dkms = enumerated.packages;

    for ver_dir in &enumerated.walk_dirs {
        walk_files(ver_dir, EntryKind::Dkms, opt, report)?;
    }
    if !dkms_root.is_dir() {
        push_warning(
            report,
            format!("DKMS 目录不存在或不可读: {}", dkms_root.display()),
        );
    }

    if usr_src.is_dir() {
        let pkgs = &enumerated.names;
        let prefixes: Vec<String> = pkgs.iter().map(|p| format!("{p}-")).collect();
        for dir in sorted_dirs(usr_src, report) {
            let name = match dir.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            // C-29：优先读目录内 `dkms.conf` 的 `PACKAGE_NAME=`（可识别不带
            // `-dkms` 后缀、命名不一致的包），目录名启发式仅作回退。
            let conf_name = dkms_conf_package_name(&dir);
            let matched = name.contains("-dkms")
                || pkgs.contains(&name)
                || prefixes.iter().any(|pre| name.starts_with(pre.as_str()))
                || conf_name
                    .as_deref()
                    .is_some_and(|pkg| pkgs.iter().any(|p| p == pkg));
            if matched {
                walk_files(&dir, EntryKind::Dkms, opt, report)?;
            }
        }
    } else {
        push_warning(
            report,
            format!("DKMS 源码目录不存在或不可读: {}", usr_src.display()),
        );
    }
    Ok(())
}

/// One-pass enumeration of `/var/lib/dkms` (C-29).
///
/// 「注册包清单」用于 manifest 重建、名字集合用于匹配 `/usr/src`、
/// `walk_dirs` 用于实际遍历（`<pkg>/<ver>` 与按内核的 `kernel-*` 构建目录都收录，
/// 与旧行为一致；只有 `<ver>` 计入包清单）。
struct DkmsEnum {
    /// 去重排序后的注册包（`<pkg>/<ver>`）。
    packages: Vec<DkmsPackage>,
    /// 一级 `<pkg>` 名字（供 `/usr/src` 匹配）。
    names: Vec<String>,
    /// 需要遍历的二级目录（`<pkg>/<ver>` 与 `<pkg>/kernel-*`）。
    walk_dirs: Vec<PathBuf>,
}

/// Enumerate `/var/lib/dkms` once; read errors degrade to warnings.
fn enumerate_dkms(root: &Path, report: &mut ScanReport) -> DkmsEnum {
    let mut packages: Vec<DkmsPackage> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut walk_dirs: Vec<PathBuf> = Vec::new();

    if !root.is_dir() {
        return DkmsEnum {
            packages,
            names,
            walk_dirs,
        };
    }

    for pkg_dir in sorted_dirs(root, report) {
        let name = match pkg_dir.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        names.push(name.clone());
        for ver_dir in sorted_dirs(&pkg_dir, report) {
            let is_kernel_build = ver_dir
                .file_name()
                .map(|n| n.to_string_lossy().starts_with("kernel-"))
                .unwrap_or(false);
            // `/var/lib/dkms/<pkg>/kernel-<kver>-<arch>/` 是按内核的构建目录，
            // 不是模块版本，因此不计入包清单；但仍要遍历其内容。
            if !is_kernel_build {
                if let Some(version) = ver_dir.file_name() {
                    packages.push(DkmsPackage {
                        name: name.clone(),
                        version: version.to_string_lossy().into_owned(),
                    });
                }
            }
            walk_dirs.push(ver_dir);
        }
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    packages.dedup();
    DkmsEnum {
        packages,
        names,
        walk_dirs,
    }
}

/// Read `<dir>/dkms.conf` and return the value of its `PACKAGE_NAME=` directive (C-29).
fn dkms_conf_package_name(dir: &Path) -> Option<String> {
    let text = fs::read_to_string(dir.join("dkms.conf")).ok()?;
    parse_dkms_conf_package_name(&text)
}

/// Parse `PACKAGE_NAME=` out of `dkms.conf` text (pure function).
///
/// 支持 `PACKAGE_NAME=foo`、`PACKAGE_NAME="foo"`、`PACKAGE_NAME='foo'` 以及
/// `export PACKAGE_NAME=foo`；注释行忽略，值为空时继续找下一行。
fn parse_dkms_conf_package_name(text: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.split_whitespace().last().unwrap_or("");
        if key != "PACKAGE_NAME" {
            continue;
        }
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        if !value.is_empty() {
            return Some(value.to_string());
        }
    }
    None
}

/// Fill [`ScanEntry::modinfo`] for every module entry with a **batched** `modinfo`
/// call (P0-2, C-43).
///
/// 先确认存在 `modinfo`（否则记一条 warning 后返回）；之后按 [`QUERY_CHUNK`] 分片，
/// 每次传入多个模块路径（`modinfo a.ko b.ko …` 会按 `filename:` 分块输出）。
/// 失败原因去重后最多记 [`MAX_MODINFO_WARNINGS`] 条，避免刷屏。
fn collect_module_metadata(opt: &ScanOptions<'_>, report: &mut ScanReport) -> AppResult<()> {
    if !report.entries.iter().any(|e| e.kind == EntryKind::Module) {
        return Ok(());
    }
    if !has_cmd("modinfo") {
        push_warning(report, "未找到 modinfo 命令，跳过模块元数据收集".to_string());
        return Ok(());
    }
    collect_module_metadata_with(opt.cancel, report, run_modinfo_batch)
}

/// [`collect_module_metadata`] 的可测试核心：`run` 注入"一批模块 → modinfo 文本"。
/// Testable core of [`collect_module_metadata`] with an injectable batched runner.
///
/// `run` 接收一批模块路径，返回合并后的 `modinfo` 文本（含每个模块的 `filename:`
/// 行）；返回 `Err(原因)` 表示整批失败。找不到块的模块不计入成功。
fn collect_module_metadata_with<F>(
    cancel: Option<&AtomicBool>,
    report: &mut ScanReport,
    run: F,
) -> AppResult<()>
where
    F: Fn(&[PathBuf]) -> Result<String, String>,
{
    let modules: Vec<PathBuf> = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Module)
        .map(|e| e.abs_path.clone())
        .collect();
    if modules.is_empty() {
        return Ok(());
    }

    let mut failures: Vec<String> = Vec::new();
    let mut found: HashMap<PathBuf, ModInfo> = HashMap::new();
    let mut missing = 0usize;

    for chunk in modules.chunks(QUERY_CHUNK) {
        check_cancel_flag(cancel)?;
        match run(chunk) {
            Ok(text) => {
                for (filename, info) in parse_modinfo_blocks(&text) {
                    found.insert(PathBuf::from(filename), info);
                }
                missing += chunk
                    .iter()
                    .filter(|path| !found.contains_key(*path))
                    .count();
            }
            Err(reason) => push_failure(&mut failures, reason),
        }
    }

    if missing > 0 {
        push_failure(
            &mut failures,
            format!("modinfo 未返回 {missing} 个模块的元数据"),
        );
    }
    for entry in report.entries.iter_mut() {
        if entry.kind == EntryKind::Module {
            if let Some(info) = found.remove(&entry.abs_path) {
                entry.modinfo = Some(info);
            }
        }
    }
    for reason in failures {
        push_warning(report, format!("modinfo 收集失败: {reason}"));
    }
    Ok(())
}

/// Record one distinct failure reason, capped at [`MAX_MODINFO_WARNINGS`] (order preserved).
fn push_failure(failures: &mut Vec<String>, reason: String) {
    if failures.len() < MAX_MODINFO_WARNINGS && !failures.contains(&reason) {
        failures.push(reason);
    }
}

/// Run one batched `modinfo` over `modules`, returning combined stdout (C-43).
///
/// 只应 spawn 失败/超时返回 `Err`：`modinfo` 对个别坏模块会非零退出但仍输出有效
/// 模块的信息，按退出码丢弃会连带丢掉整批元数据（与 [`run_command_stdout`] 同理由）。
fn run_modinfo_batch(modules: &[PathBuf]) -> Result<String, String> {
    let args: Vec<OsString> = modules
        .iter()
        .map(|m| m.as_os_str().to_os_string())
        .collect();
    run_command_stdout_timeout("modinfo", &args, QUERY_TIMEOUT)
        .ok_or_else(|| "无法执行 modinfo（缺失或超时）".to_string())
}

/// Split batched `modinfo` output into `(filename, ModInfo)` pairs (pure function).
///
/// `modinfo a.ko b.ko …` 为每个模块输出一段以 `filename:` 开头的块；以新的
/// `filename:` 行为界切块，再交给 [`parse_modinfo`]。首行之前的内容忽略。
fn parse_modinfo_blocks(text: &str) -> Vec<(String, ModInfo)> {
    let mut blocks: Vec<(String, String)> = Vec::new();
    let mut current: Option<(String, String)> = None;
    for line in text.lines() {
        let is_filename = line
            .split_once(':')
            .map(|(k, _)| k.trim() == "filename")
            .unwrap_or(false);
        if is_filename {
            if let Some(done) = current.take() {
                blocks.push(done);
            }
            let filename = line
                .split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default();
            current = Some((filename, format!("{line}\n")));
        } else if let Some((_, body)) = current.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some(done) = current.take() {
        blocks.push(done);
    }
    blocks
        .into_iter()
        .map(|(filename, body)| (filename, parse_modinfo(&body)))
        .collect()
}

/// Parse `modinfo` text into [`ModInfo`] (pure function, unit-test friendly).
///
/// 逐行解析形如 `key: value` 的输出：`vermagic`/`sig_id`/`sig_key` 取首个非空值；
/// `depends` 按 `,` 拆分去空去重；`firmware` 收集**所有**行。其它键与脏行忽略。
fn parse_modinfo(text: &str) -> ModInfo {
    let mut info = ModInfo::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "vermagic" => {
                if info.vermagic.is_none() && !value.is_empty() {
                    info.vermagic = Some(value.to_string());
                }
            }
            "depends" => {
                for dep in value.split(',') {
                    let dep = dep.trim();
                    if !dep.is_empty() && !info.depends.iter().any(|d| d == dep) {
                        info.depends.push(dep.to_string());
                    }
                }
            }
            "firmware" => {
                if !value.is_empty() {
                    info.firmware.push(value.to_string());
                }
            }
            "sig_id" => {
                if info.sig_id.is_none() && !value.is_empty() {
                    info.sig_id = Some(value.to_string());
                }
            }
            "sig_key" if info.sig_key.is_none() && !value.is_empty() => {
                info.sig_key = Some(value.to_string());
            }
            _ => {}
        }
    }
    info
}

/// usr-merge 归一化：把绝对路径根后的首段 `/lib`、`/bin`、`/sbin`、`/lib64` 改写到 `/usr` 下。
///
/// Normalize an absolute path to its usr-merged spelling for provenance lookups (C-23).
///
/// usr-merge 系统（Debian/Ubuntu usrmerge、Fedora `/usr` 布局）的包数据库记录的是
/// `/usr/lib/...`，而扫描走 `/lib/modules` 根 —— 直接查 `/lib/...` 必然无匹配
/// （实测 `dpkg-query -S /lib/x86_64-linux-gnu/libc.so.6` exit=1 无输出，
/// `/usr/lib/x86_64-linux-gnu/libc.so.6` 返回 `libc6:amd64`，
/// 见 docs/ITERATION-v0.3.0.md §3.1-5），连带固件 `content_stored=false` 优化失效。
///
/// 只改写**根之后的第一个组件**，因此 `/usr/lib/...` 自身、`/var/lib/...`（中段的
/// `lib` 不是首段）、`/libfoo/...`（前缀相近但非独立段）、相对路径都原样返回。
/// 归一化只是**查询串**：非 usr-merge 系统（`/lib` 为真实目录）上归一化查询会落空，
/// 由调用方（[`collect_owners_dpkg`] / [`collect_owners_rpm`]）用原始路径重试一次兜底。
fn usr_merge_normalize(p: &Path) -> PathBuf {
    /// usr-merge 会合并进 `/usr` 的根目录段 / Root dirs that usr-merge moves under `/usr`.
    const MERGED_ROOT_DIRS: &[&str] = &["lib", "bin", "sbin", "lib64"];
    let mut comps = p.components();
    if comps.next() != Some(Component::RootDir) {
        return p.to_path_buf();
    }
    let first = match comps.next() {
        Some(Component::Normal(seg)) => seg,
        _ => return p.to_path_buf(),
    };
    if !MERGED_ROOT_DIRS.iter().any(|d| first == OsStr::new(d)) {
        return p.to_path_buf();
    }
    let mut out = PathBuf::from("/usr");
    out.push(first);
    // 余下组件原样追加；`/lib` 这种只剩根段的路径不补尾斜杠。
    let rest = comps.as_path();
    if !rest.as_os_str().is_empty() {
        out.push(rest);
    }
    out
}

/// Resolve package provenance for the given paths (P0-5), `dpkg-query` first, then `rpm`.
///
/// 先尝试 `dpkg-query -S`（按 [`QUERY_CHUNK`] 分片）并对命中的包批量取版本；若无
/// `dpkg-query` 则回退 `rpm -qf`（逐路径）。两者都缺失或查询失败时返回空 map，
/// **绝不报错**（调用方保持 `owner = None`）。
///
/// 入口先对每个路径做 usr-merge 归一化（C-23，见 [`usr_merge_normalize`]），查询用
/// 归一化路径，命中的结果**映射回原始路径键**插入 `owners` —— map 的 key 永远是调用方
/// 传入的 `paths` 中的路径；查询本身走 [`run_command_stdout`]（C-22：不看退出码）。
fn collect_owners(
    paths: &[PathBuf],
    cancel: Option<&AtomicBool>,
) -> AppResult<HashMap<PathBuf, Provenance>> {
    let mut owners: HashMap<PathBuf, Provenance> = HashMap::new();
    if paths.is_empty() {
        return Ok(owners);
    }
    // 归一化只在入口做一次，dpkg 与 rpm 两条查询路径共用（C-23）。
    let queries: Vec<PathBuf> = paths.iter().map(|p| usr_merge_normalize(p)).collect();
    if has_cmd("dpkg-query") {
        collect_owners_dpkg(paths, &queries, &mut owners, cancel)?;
    } else if has_cmd("rpm") {
        collect_owners_rpm(paths, &queries, &mut owners, cancel)?;
    }
    Ok(owners)
}

/// `dpkg-query -S` 批量查来源包，再 `-W` 批量取版本，写入 `owners`。
/// Query provenance in batch with `dpkg-query -S`, then resolve versions with `-W`.
///
/// `queries` 与 `paths` 等长且一一对应（C-23 归一化后的查询串）；分片查询走
/// [`run_command_stdout`]（C-22：无视退出码），命中的包一律以 `paths` 的**原始路径**
/// 为 key 写入 `owners`，归一化只影响发给 dpkg 的查询串。
fn collect_owners_dpkg(
    paths: &[PathBuf],
    queries: &[PathBuf],
    owners: &mut HashMap<PathBuf, Provenance>,
    cancel: Option<&AtomicBool>,
) -> AppResult<()> {
    // 查询串 -> 包名
    let mut package_by_path: HashMap<String, String> = HashMap::new();
    dpkg_query_s(queries, &mut package_by_path, cancel)?;

    // 回退：归一化改变了路径却未命中的条目，用原始路径再查一次。
    // 设计文档 §4-W0 C-23 允许"自然无归属"与"原路径重试"二选一，这里选重试：
    // 非 usr-merge 系统（`/lib` 是真实目录）上归一化查询必然落空，重试避免老系统回归；
    // usr-merge 系统上重试只是一批无命中的空查询（按 QUERY_CHUNK 分片），代价可忽略。
    let mut retry: Vec<PathBuf> = Vec::new();
    for (orig, norm) in paths.iter().zip(queries) {
        if norm == orig {
            continue;
        }
        let norm_key = norm.to_string_lossy();
        if !package_by_path.contains_key(&*norm_key) {
            retry.push(orig.clone());
        }
    }
    dpkg_query_s(&retry, &mut package_by_path, cancel)?;

    if package_by_path.is_empty() {
        return Ok(());
    }

    // 去重后的包名列表
    let mut packages: Vec<String> = package_by_path.values().cloned().collect();
    packages.sort();
    packages.dedup();

    let mut versions: HashMap<String, String> = HashMap::new();
    for chunk in packages.chunks(QUERY_CHUNK) {
        check_cancel_flag(cancel)?;
        let mut args: Vec<OsString> = Vec::with_capacity(chunk.len() + 2);
        args.push(OsString::from("-W"));
        // dpkg-query 会解释格式串里的 `\t` / `\n` 转义。
        args.push(OsString::from("-f=${Package}\\t${Version}\\n"));
        args.extend(chunk.iter().map(|p| OsString::from(p.as_str())));
        // C-22：同样不看退出码 —— 批内包不存在时 exit=1，但已解析的包仍会输出；
        // 完全无输出（包都不存在）时空串自然解析不出版本。
        let Some(text) = run_command_stdout("dpkg-query", &args) else {
            continue;
        };
        for line in text.lines() {
            if let Some((package, version)) = line.split_once('\t') {
                versions.insert(package.trim().to_string(), version.trim().to_string());
            }
        }
    }

    for (path, query) in paths.iter().zip(queries) {
        if let Some(package) = package_for(&package_by_path, path, query) {
            // `-S` 对 multiarch 包可能给出 `pkg:arch`，而 `-W` 的 `${Package}` 只有 `pkg`。
            let base = package.split(':').next().unwrap_or(package.as_str());
            let version = versions
                .get(package)
                .or_else(|| versions.get(base))
                .cloned()
                .unwrap_or_default();
            owners.insert(
                path.clone(),
                Provenance {
                    manager: "dpkg".to_string(),
                    package: package.clone(),
                    version,
                },
            );
        }
    }
    Ok(())
}

/// `rpm -qf` **批量**查来源包（C-24），写入 `owners`。
/// Query provenance in **batch** with `rpm -qf` (C-24).
///
/// 旧实现每路径 fork 一次 `rpm`（full 模式数万固件＝数万进程），且 `%{FILENAMES}`
/// 输出可达数 MB 却只取首行。现在按 [`QUERY_CHUNK`] 分片，一次传入多个路径，格式只取
/// 包名与版本（[`RPM_BATCH_FORMAT`]），并设 [`QUERY_TIMEOUT`] 超时。
///
/// 关联策略：`rpm -qf a b …` 按参数逐个输出（每个归属路径一行）；当输出行数与传入
/// 路径数一致时按序对应，否则整片回退到逐路径查询，保证正确性（P-1 待容器复核）。
/// `queries` 与 `paths` 等长（C-23 归一化查询串）：先用归一化串批量查，未命中且与
/// 原始路径不同者再用原始路径逐条重试；命中一律回填**原始路径键**。
fn collect_owners_rpm(
    paths: &[PathBuf],
    queries: &[PathBuf],
    owners: &mut HashMap<PathBuf, Provenance>,
    cancel: Option<&AtomicBool>,
) -> AppResult<()> {
    collect_owners_rpm_with(paths, queries, owners, cancel, |args| {
        run_command_stdout_timeout("rpm", args, QUERY_TIMEOUT)
    })
}

/// [`collect_owners_rpm`] 的可测试核心：`run` 注入"一批 rpm 参数 → stdout"。
/// Testable core of [`collect_owners_rpm`] with an injectable runner.
fn collect_owners_rpm_with<F>(
    paths: &[PathBuf],
    queries: &[PathBuf],
    owners: &mut HashMap<PathBuf, Provenance>,
    cancel: Option<&AtomicBool>,
    run: F,
) -> AppResult<()>
where
    F: Fn(&[OsString]) -> Option<String>,
{
    let mut resolved = vec![false; paths.len()];
    for (chunk_index, chunk) in queries.chunks(QUERY_CHUNK).enumerate() {
        check_cancel_flag(cancel)?;
        let Some(hits) = rpm_query_batch(chunk, &run) else {
            continue; // 输出对不齐：留给下面的逐路径回退
        };
        for (offset, (name, version)) in hits.into_iter().enumerate() {
            let index = chunk_index * QUERY_CHUNK + offset;
            owners.insert(
                paths[index].clone(),
                Provenance {
                    manager: "rpm".to_string(),
                    package: name,
                    version,
                },
            );
            resolved[index] = true;
        }
    }

    // 回退：归一化查询未命中、且原始拼写不同的（非 usr-merge 系统），逐条再查。
    for (index, (path, query)) in paths.iter().zip(queries).enumerate() {
        if resolved[index] || query == path {
            continue;
        }
        check_cancel_flag(cancel)?;
        let args: Vec<OsString> = vec![
            OsString::from("-qf"),
            OsString::from("--qf"),
            OsString::from(RPM_BATCH_FORMAT),
            path.as_os_str().to_os_string(),
        ];
        let Some(text) = run(&args) else {
            continue;
        };
        if let Some((name, version)) = parse_rpm_batch(&text).into_iter().next() {
            owners.insert(
                path.clone(),
                Provenance {
                    manager: "rpm".to_string(),
                    package: name,
                    version,
                },
            );
        }
    }
    Ok(())
}

/// One batched `rpm -qf` over `query_paths`; `None` when output cannot be aligned.
///
/// 返回与 `query_paths` 等长（且按序对应）的 `(name, version)` 列表；任一无法归属的
/// 路径会让 rpm 少输出一行，此时返回 `None` 触发调用方逐路径回退（顺序关联不可靠）。
fn rpm_query_batch<F>(query_paths: &[PathBuf], run: &F) -> Option<Vec<(String, String)>>
where
    F: Fn(&[OsString]) -> Option<String>,
{
    if query_paths.is_empty() {
        return Some(Vec::new());
    }
    let mut args: Vec<OsString> = Vec::with_capacity(query_paths.len() + 3);
    args.push(OsString::from("-qf"));
    args.push(OsString::from("--qf"));
    args.push(OsString::from(RPM_BATCH_FORMAT));
    args.extend(query_paths.iter().map(|p| p.as_os_str().to_os_string()));
    let text = run(&args)?;
    let hits = parse_rpm_batch(&text);
    if hits.len() != query_paths.len() {
        return None;
    }
    Some(hits)
}

/// Batch `dpkg-query -S` over `query_paths`, merging hits into `package_by_path`.
///
/// 按 [`QUERY_CHUNK`] 分片查来源包；`package_by_path` 的 key 是 dpkg 原样回显的路径串。
/// C-22：查询走 [`run_command_stdout`] —— 批内只要有一个未归属路径 dpkg 就 `exit=1`，
/// 但 stdout 仍包含其余路径的匹配（实测见 docs/ITERATION-v0.3.0.md §3.1-4），按退出码
/// 丢弃会让整批最多 [`QUERY_CHUNK`] 条归属信息全部丢失。
fn dpkg_query_s(
    query_paths: &[PathBuf],
    package_by_path: &mut HashMap<String, String>,
    cancel: Option<&AtomicBool>,
) -> AppResult<()> {
    for chunk in query_paths.chunks(QUERY_CHUNK) {
        check_cancel_flag(cancel)?;
        let mut args: Vec<OsString> = Vec::with_capacity(chunk.len() + 1);
        args.push(OsString::from("-S"));
        args.extend(chunk.iter().map(|p| p.as_os_str().to_os_string()));
        let Some(text) = run_command_stdout("dpkg-query", &args) else {
            continue;
        };
        for (package, path) in parse_dpkg_query_s(&text) {
            package_by_path.entry(path).or_insert(package);
        }
    }
    Ok(())
}

/// Look up one path's owning package, preferring the usr-merged query spelling (C-23).
///
/// `package_by_path` 的 key 是 dpkg 回显的路径串（通常就是归一化查询串 `query`）。
/// 先按 `query` 查；落空且 `query != path` 时回看原始路径 `path`（非 usr-merge 系统的
/// 回退查询结果）。命中与否只决定要不要回填，**调用方一律用原始 `path` 作 owners 的 key**。
fn package_for<'a>(
    package_by_path: &'a HashMap<String, String>,
    path: &Path,
    query: &Path,
) -> Option<&'a String> {
    let norm_key = query.to_string_lossy();
    if let Some(package) = package_by_path.get(&*norm_key) {
        return Some(package);
    }
    if query != path {
        let orig_key = path.to_string_lossy();
        return package_by_path.get(&*orig_key);
    }
    None
}

/// Run a command and return its stdout lossily, ignoring the exit status (C-22).
///
/// 归属查询专用的"尽力而为"执行器：只要子进程成功 spawn 就返回 stdout（lossy UTF-8），
/// **不看退出码**；仅 spawn 失败（命令不存在等）返回 `None`。
///
/// 依据（实测，docs/ITERATION-v0.3.0.md §3.1-4）：`dpkg-query -S` 批内只要有一个
/// 未归属路径就 `exit=1`，而 stdout 仍输出其余匹配（如 `coreutils: /usr/bin/env`）——
/// 按退出码丢弃会把整批归属信息一起扔掉。`-W` 版本查询失败（包不存在）时 stdout 为空，
/// 空输出自然不影响解析。
fn run_command_stdout(program: &str, args: &[OsString]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Like [`run_command_stdout`] but with a wall-clock timeout (C-24/C-43).
///
/// "尽力而为"执行器：忽略退出码，成功 spawn 即读取 stdout（在独立线程里读，避免
/// 管道写满导致子进程阻塞）；仅 spawn 失败或 [`Duration`] 内未退出（随后 `kill`）
/// 返回 `None`。
fn run_command_stdout_timeout(
    program: &str,
    args: &[OsString],
    timeout: Duration,
) -> Option<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = thread::spawn(move || {
        let mut buf = String::new();
        let _ = stdout.read_to_string(&mut buf);
        buf
    });

    let start = Instant::now();
    let finished = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                let _ = child.kill();
                break false;
            }
        }
    };
    let text = reader.join().unwrap_or_default();
    finished.then_some(text)
}

/// Parse `dpkg-query -S` output: `package: path1, path2` (one package per line).
///
/// 返回 `(包名, 路径)` 对；同一包多路径用 `,` 分隔，多包多行。`diversion by …`
/// 之类不含 `": "` 或包名带空白的行被忽略。
fn parse_dpkg_query_s(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }
        let Some((package, rest)) = line.split_once(": ") else {
            continue;
        };
        let package = package.trim();
        if package.is_empty() || package.chars().any(char::is_whitespace) {
            continue;
        }
        for path in rest.split(',') {
            let path = path.trim();
            if !path.is_empty() {
                out.push((package.to_string(), path.to_string()));
            }
        }
    }
    out
}

/// Parse batched `rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'` output (C-24).
///
/// 每行一个 `(name, version)`；字段不足两列、包名为空的脏行忽略。**不再解析
/// `%{FILENAMES}`**，因此输出始终很小。
fn parse_rpm_batch(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let Some((name, version)) = line.split_once('\t') else {
            continue; // 无制表符 = 脏行（例如 rpm 的诊断输出混入）
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.push((name.to_string(), version.trim().to_string()));
    }
    out
}

/// Mark firmware entries provided by a system package as `content_stored = false` (ROADMAP §4).
///
/// 仅影响 [`EntryKind::Firmware`]：`owner` 已知即表示该文件本可由包管理器修复，
/// 归档只记路径不重复存内容；`kind` 保持不变。
fn mark_package_provided_firmware(entries: &mut [ScanEntry]) {
    for entry in entries.iter_mut() {
        if entry.kind == EntryKind::Firmware && entry.owner.is_some() {
            entry.content_stored = false;
        }
    }
}

/// Sum the sizes of firmware entries that actually store content (C-28, W5).
///
/// 只累计 `content_stored == true` 的固件：由系统包提供的固件只记路径、不进归档，
/// 计入体积会让 UI 虚高。必须在 [`mark_package_provided_firmware`] **之后**调用。
fn tally_firmware(report: &mut ScanReport) {
    report.firmware_bytes = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Firmware && e.content_stored)
        .map(|e| e.size)
        .sum();
}

/// Locate the firmware tree, preferring a real directory (C-28).
///
/// usr-merge 系统上 `/lib/firmware` 是符号链接；`WalkDir` 默认不跟随链接，直接遍历会
/// 得到空结果。因此优先选**非符号链接的目录**（`/lib/firmware` → `/usr/lib/firmware`），
/// 两者都不是真实目录时，退而取任一个 `is_dir()` 跟随链接成立的候选。
fn firmware_dir() -> Option<&'static str> {
    for dir in FIRMWARE_DIRS {
        if let Ok(meta) = fs::symlink_metadata(dir) {
            if meta.is_dir() && !meta.file_type().is_symlink() {
                return Some(dir);
            }
        }
    }
    FIRMWARE_DIRS
        .iter()
        .copied()
        .find(|dir| Path::new(dir).is_dir())
}

/// Append one regular-file entry; unreadable files degrade to a warning, never an error.
///
/// 常规文件默认 `content_stored = true`；`owner`/`modinfo` 留待后续批量填充。
/// C-37 的"单文件不可读不中止"在本模块即体现为这里只记 warning（备份流水线另有处理）。
fn push_file(abs: &Path, kind: EntryKind, report: &mut ScanReport) {
    match fs::metadata(abs) {
        Ok(meta) => report.entries.push(ScanEntry {
            abs_path: abs.to_path_buf(),
            rel_path: rel_path_of(abs),
            size: meta.len(),
            kind,
            link_target: None,
            owner: None,
            modinfo: None,
            content_stored: true,
        }),
        Err(err) => push_warning(report, format!("无法读取 {}: {err}", abs.display())),
    }
}

/// Archive-relative path: drop the leading `/` (`/lib/modules/x` → `lib/modules/x`).
///
/// 以扫描时使用的字面路径为准：来自 `/usr/lib/modules` 就产出 `usr/lib/modules/...`。
fn rel_path_of(abs: &Path) -> String {
    abs.to_string_lossy().trim_start_matches('/').to_string()
}

/// Whether a file name looks like a kernel module, delegating to [`crate::distro::is_module_path`].
///
/// `*.ko` 与压缩变体（`.ko.xz` / `.ko.zst` / `.ko.gz` …）统一由
/// [`crate::distro::MODULE_COMPRESSION_SUFFIXES`] 判定，本模块不再维护重复后缀表。
fn is_module_file(name: &str) -> bool {
    is_module_path(Path::new(name))
}

/// Sorted immediate subdirectories, or `[]` plus a warning when unreadable.
fn sorted_dirs(dir: &Path, report: &mut ScanReport) -> Vec<PathBuf> {
    let read_dir = match fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(err) => {
            push_warning(report, format!("无法读取目录 {}: {err}", dir.display()));
            return Vec::new();
        }
    };
    let mut out: Vec<PathBuf> = read_dir
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

/// Bail out as soon as the shared cancel flag is set.
fn check_cancel(opt: &ScanOptions<'_>) -> AppResult<()> {
    check_cancel_flag(opt.cancel)
}

/// [`check_cancel`] 的裸旗标版本：供不持有 [`ScanOptions`] 的第 5 阶段辅助函数复用（C-43）。
/// Bare-flag variant of [`check_cancel`] reused by the stage-5 helpers (C-43).
fn check_cancel_flag(flag: Option<&AtomicBool>) -> AppResult<()> {
    match flag {
        Some(flag) if flag.load(Ordering::Relaxed) => Err(AppError::Cancelled),
        _ => Ok(()),
    }
}

/// Append a warning with global dedup and a hard cap (C-26).
///
/// 同一条消息只保留一次；总数达 [`MAX_WARNINGS`] 后不再追加具体消息，而是把
/// "省略计数"标记原地累加（`（更多告警已省略，共 N 条）`）。
fn push_warning(report: &mut ScanReport, message: String) {
    if message.is_empty() {
        return;
    }
    if report.warnings.contains(&message) {
        return;
    }
    if report.warnings.len() < MAX_WARNINGS {
        report.warnings.push(message);
        return;
    }
    if let Some(last) = report.warnings.last_mut() {
        if let Some(count) = parse_overflow_count(last) {
            *last = format!("{WARNING_OVERFLOW_PREFIX}{} 条）", count + 1);
            return;
        }
    }
    report
        .warnings
        .push(format!("{WARNING_OVERFLOW_PREFIX}1 条）"));
}

/// Parse the omitted-warning count out of an overflow marker (see [`push_warning`]).
fn parse_overflow_count(marker: &str) -> Option<usize> {
    marker
        .strip_prefix(WARNING_OVERFLOW_PREFIX)?
        .strip_suffix(" 条）")?
        .parse()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ldb-scan-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    fn write_file(path: &Path) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, b"ko").expect("write file");
    }

    fn dummy_distro() -> DistroInfo {
        DistroInfo {
            id: "testos".to_string(),
            id_like: vec!["debian".to_string()],
            version_id: "1".to_string(),
            pretty_name: "Test OS 1".to_string(),
            family: Family::Debian,
        }
    }

    /// 构造一个完整的 [`ScanEntry`]（v2 字段齐全），供排序/标记类测试使用。
    fn entry(abs: &str, size: u64, kind: EntryKind, owner: Option<Provenance>) -> ScanEntry {
        ScanEntry {
            abs_path: PathBuf::from(abs),
            rel_path: abs.trim_start_matches('/').to_string(),
            size,
            kind,
            link_target: None,
            owner,
            modinfo: None,
            content_stored: true,
        }
    }

    #[test]
    fn rel_path_drops_leading_slash() {
        let abs = Path::new("/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko");
        assert_eq!(
            rel_path_of(abs),
            "lib/modules/6.8.0-45-generic/updates/dkms/foo.ko"
        );
        // 来自 /usr/lib/modules 时按字面路径保留 usr/lib 前缀
        assert_eq!(
            rel_path_of(Path::new("/usr/lib/modules/6.8.0/extra/bar.ko")),
            "usr/lib/modules/6.8.0/extra/bar.ko"
        );
        // 本来就相对的路径原样保留
        assert_eq!(rel_path_of(Path::new("etc/depmod.d/x.conf")), "etc/depmod.d/x.conf");
        for p in [
            "/a/b.ko",
            "/etc/modprobe.d/z.conf",
            "/var/lib/dkms/nvidia/1.0/x.c",
        ] {
            assert!(!rel_path_of(Path::new(p)).starts_with('/'), "{p}");
        }
    }

    #[test]
    fn module_file_detection_covers_compression_suffixes() {
        for name in [
            "foo.ko",
            "foo.ko.xz",
            "foo.ko.zst",
            "foo.ko.zstd",
            "foo.ko.gz",
            "foo.ko.bz2",
            "foo.ko.lzo",
            "foo.ko.lz4",
        ] {
            assert!(is_module_file(name), "{name}");
        }
        for name in ["foo.o", "vmlinux", "modules.dep", "foo.kot", "notes.txt"] {
            assert!(!is_module_file(name), "{name}");
        }
    }

    /// (c) in-tree vs out-of-tree 分类：kernel/ 子树只计数不备份，其余 .ko* 全收。
    #[test]
    fn classifies_in_tree_vs_out_of_tree() {
        let base = temp_dir("classify");
        let kver_dir = base.join("modules").join("6.0.0-test");

        // in-tree：内核包自带基线
        write_file(&kver_dir.join("kernel/drivers/net/foo.ko"));
        write_file(&kver_dir.join("kernel/drivers/bar.ko.zst"));
        write_file(&kver_dir.join("kernel/notes.txt")); // 非模块文件 → 忽略

        // out-of-tree：约定目录 + 任意顶层目录 + 根下散文件
        write_file(&kver_dir.join("updates/dkms/nv.ko"));
        write_file(&kver_dir.join("extra/extra.ko.xz"));
        write_file(&kver_dir.join("weak-updates/a.ko"));
        write_file(&kver_dir.join("extramodules/b.ko"));
        write_file(&kver_dir.join("nvidia/nvidia.ko"));
        write_file(&kver_dir.join("top-level.ko"));

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&kver_dir, &opt, &mut report).expect("scan module root");

        assert_eq!(report.skipped_in_tree, 2, "kernel/ 下两个 .ko 计为 in-tree");
        assert_eq!(report.entries.len(), 6, "kernel/ 之外的 .ko* 全部收录");
        assert!(
            report
                .entries
                .iter()
                .all(|e| e.kind == EntryKind::Module && e.size == 2)
        );
        assert!(
            !report
                .entries
                .iter()
                .any(|e| e.rel_path.contains("/kernel/")),
            "in-tree 模块不得进入 entries"
        );
        // (b)(c) rel_path 去前导 /，且与 abs_path 一致
        for e in &report.entries {
            assert!(!e.rel_path.starts_with('/'));
            assert_eq!(e.rel_path, e.abs_path.to_string_lossy().trim_start_matches('/'));
        }
        assert!(
            report
                .entries
                .iter()
                .any(|e| e.rel_path.ends_with("updates/dkms/nv.ko"))
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_module_dir_only_warns() {
        let base = temp_dir("missing");
        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "9.9.9-none",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&base.join("no-such-kver"), &opt, &mut report).expect("non-fatal");
        assert!(report.entries.is_empty());
        assert_eq!(report.warnings.len(), 1, "目录不存在 → warning 而非整体失败");
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn cancel_flag_aborts_with_cancelled() {
        let base = temp_dir("cancel");
        write_file(&base.join("updates/a.ko"));
        let cancel = AtomicBool::new(true);
        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: Some(&cancel),
        };
        let mut report = ScanReport::default();
        match scan_module_root(&base, &opt, &mut report) {
            Err(AppError::Cancelled) => {}
            other => panic!("expected AppError::Cancelled, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn walk_files_collects_configs_recursively() {
        let base = temp_dir("config");
        write_file(&base.join("foo.conf"));
        write_file(&base.join("sub/bar.conf"));

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        walk_files(&base, EntryKind::Config, &opt, &mut report).expect("walk configs");

        assert_eq!(report.entries.len(), 2);
        assert!(report.entries.iter().all(|e| e.kind == EntryKind::Config));
        assert!(report.entries.iter().all(|e| !e.rel_path.starts_with('/')));
        assert!(report.entries.iter().any(|e| e.rel_path.ends_with("sub/bar.conf")));
        let _ = fs::remove_dir_all(&base);
    }

    /// Standard/Full 模式收录的 DKMS 源码：`/var/lib/dkms/<pkg>/<ver>` + `/usr/src` 匹配目录。
    #[test]
    fn dkms_scan_picks_registered_and_usr_src_trees() {
        let base = temp_dir("dkms");
        let dkms_root = base.join("var").join("lib").join("dkms");
        let usr_src = base.join("usr").join("src");

        // /var/lib/dkms/<pkg>/<ver> 整棵树纳入
        write_file(&dkms_root.join("nvidia/550.129.03/module.c"));
        write_file(&dkms_root.join("nvidia/550.129.03/modules/nvidia.ko"));
        write_file(&dkms_root.join("vbox/7.0.14/source/vbox.c"));
        // 只有 pkg、没有版本目录 → 不产出条目
        fs::create_dir_all(dkms_root.join("ghostpkg")).unwrap();

        // /usr/src：pkg 前缀 / 精确同名 / 名字含 `-dkms` / 无关目录
        write_file(&usr_src.join("nvidia-550.129.03/dkms.conf"));
        write_file(&usr_src.join("vbox/dkms.conf"));
        write_file(&usr_src.join("virtualbox-guest-dkms/dkms.conf"));
        write_file(&usr_src.join("unrelated-1.0/x.c"));

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Standard,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_dkms_in(&dkms_root, &usr_src, &opt, &mut report).expect("scan dkms");

        assert_eq!(report.entries.len(), 6, "3 个 dkms 树文件 + 3 个匹配的 usr/src 文件");
        assert!(report.entries.iter().all(|e| e.kind == EntryKind::Dkms));
        assert!(report.entries.iter().all(|e| !e.rel_path.starts_with('/')));
        assert!(
            !report
                .entries
                .iter()
                .any(|e| e.rel_path.contains("unrelated-1.0")),
            "无关的 /usr/src 目录不得收录"
        );
        assert!(report.entries.iter().any(|e| e
            .rel_path
            .ends_with("var/lib/dkms/nvidia/550.129.03/modules/nvidia.ko")));
        assert!(report
            .entries
            .iter()
            .any(|e| e.rel_path.ends_with("usr/src/virtualbox-guest-dkms/dkms.conf")));
        let _ = fs::remove_dir_all(&base);
    }

    /// C-28：`firmware_bytes` 只累计 `content_stored == true` 的固件（包提供的跳过）。
    #[test]
    fn tally_firmware_sums_only_content_stored_firmware() {
        let mut report = ScanReport::default();
        report
            .entries
            .push(entry("/lib/firmware/a.bin", 100, EntryKind::Firmware, None));
        let mut provided = entry("/lib/firmware/b.bin", 250, EntryKind::Firmware, None);
        provided.content_stored = false; // 由系统包提供，不进归档
        report.entries.push(provided);
        report.entries.push(entry(
            "/lib/modules/x/updates/m.ko",
            7,
            EntryKind::Module,
            None,
        ));
        tally_firmware(&mut report);
        assert_eq!(report.firmware_bytes, 100, "包提供固件不得计入体积");
    }

    // -----------------------------------------------------------------------
    // v0.2.0 新增：P0-1 符号链接 / P0-2 modinfo / P0-5 来源包 / DKMS / 固件标记
    // -----------------------------------------------------------------------

    /// P0-1：叶子符号链接按 Symlink 收录，不再跟随、不再把目标内容当普通文件备份。
    #[test]
    fn leaf_symlink_is_recorded_as_symlink_not_followed() {
        let base = temp_dir("symlink");
        let kver_dir = base.join("6.0.0-test");
        write_file(&kver_dir.join("weak-updates/a.ko"));
        std::os::unix::fs::symlink("a.ko", kver_dir.join("weak-updates/b.ko"))
            .expect("create symlink");

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&kver_dir, &opt, &mut report).expect("scan");

        let modules: Vec<&ScanEntry> = report
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::Module)
            .collect();
        let links: Vec<&ScanEntry> = report
            .entries
            .iter()
            .filter(|e| e.kind == EntryKind::Symlink)
            .collect();
        assert_eq!(modules.len(), 1, "目标 a.ko 只收录一次，不因链接而重复");
        assert!(modules[0].rel_path.ends_with("weak-updates/a.ko"));
        assert_eq!(links.len(), 1, "b.ko 必须按符号链接语义收录");
        let link = links[0];
        assert!(link.rel_path.ends_with("weak-updates/b.ko"));
        assert_eq!(link.link_target.as_deref(), Some("a.ko"), "readlink 原样保存");
        assert_eq!(link.size, 0, "符号链接大小记为 0");
        assert!(link.content_stored);
        assert!(link.owner.is_none() && link.modinfo.is_none());
        let _ = fs::remove_dir_all(&base);
    }

    /// P0-1：目录符号链接保持不跟随，且记一条 warning（不绕出扫描树）。
    #[test]
    fn directory_symlink_is_skipped_with_warning() {
        let base = temp_dir("dirlink");
        write_file(&base.join("realdir/real.ko"));
        std::os::unix::fs::symlink("realdir", base.join("linkdir")).expect("symlink dir");

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&base, &opt, &mut report).expect("scan");

        assert_eq!(
            report
                .entries
                .iter()
                .filter(|e| e.kind == EntryKind::Module)
                .count(),
            1,
            "只收录真实目录里的 real.ko"
        );
        assert!(report.entries.iter().all(|e| e.kind != EntryKind::Symlink));
        assert!(
            report.warnings.iter().any(|w| w.contains("目录符号链接")),
            "目录链接应记 warning: {:?}",
            report.warnings
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// P0-1：既不形如模块、也不在受管配置目录的链接被跳过并记 warning。
    #[test]
    fn irrelevant_symlink_is_skipped() {
        let base = temp_dir("irrelevant");
        write_file(&base.join("target.txt"));
        std::os::unix::fs::symlink("target.txt", base.join("alias.dat")).expect("symlink");

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&base, &opt, &mut report).expect("scan");

        assert!(report.entries.is_empty(), "平凡 .txt 与无关链接都不收录");
        assert!(
            report.warnings.iter().any(|w| w.contains("无关符号链接")),
            "应记 warning: {:?}",
            report.warnings
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// P0-2：解析已签名模块的 modinfo 文本。
    #[test]
    fn parse_modinfo_reads_signed_module_fields() {
        let text = "\
filename:       /lib/modules/6.8.0-45-generic/updates/dkms/nvidia.ko
vermagic:       6.8.0-45-generic SMP preempt mod_unload modversions
depends:        nvidia
firmware:       nvidia/ga102/gsp.bin
sig_id:         PKCS#7
sig_key:        AB:CD:EF
signer:         Build time autogenerated kernel key
";
        let info = parse_modinfo(text);
        assert_eq!(
            info.vermagic.as_deref(),
            Some("6.8.0-45-generic SMP preempt mod_unload modversions")
        );
        assert_eq!(info.depends, vec!["nvidia".to_string()]);
        assert_eq!(info.firmware, vec!["nvidia/ga102/gsp.bin".to_string()]);
        assert!(info.is_signed());
        assert_eq!(info.sig_id.as_deref(), Some("PKCS#7"));
        assert_eq!(info.sig_key.as_deref(), Some("AB:CD:EF"));
    }

    /// P0-2：未签名模块没有 `sig_id`/`sig_key` 行。
    #[test]
    fn parse_modinfo_unsigned_module_has_no_signature() {
        let info = parse_modinfo("vermagic: 6.8.0 SMP\ndepends: \n");
        assert!(!info.is_signed());
        assert!(info.sig_id.is_none() && info.sig_key.is_none());
        assert!(info.depends.is_empty(), "空 depends 行不产出依赖");
    }

    /// P0-2：depends 按逗号拆分去空去重，firmware 收集所有行。
    #[test]
    fn parse_modinfo_splits_depends_and_collects_all_firmware() {
        let text = "\
depends: nvidia, nvidia-uvm ,  nvidia
firmware: nvidia/1.bin
firmware: nvidia/2.bin
";
        let info = parse_modinfo(text);
        assert_eq!(
            info.depends,
            vec!["nvidia".to_string(), "nvidia-uvm".to_string()]
        );
        assert_eq!(
            info.firmware,
            vec!["nvidia/1.bin".to_string(), "nvidia/2.bin".to_string()]
        );
    }

    /// P0-2：空输入 / 无关键字段 → 默认值，不 panic。
    #[test]
    fn parse_modinfo_empty_input_is_default() {
        assert_eq!(parse_modinfo(""), ModInfo::default());
        assert_eq!(parse_modinfo("\n\nno-colon-line\n"), ModInfo::default());
        assert!(!parse_modinfo("").is_signed());
    }

    /// P0-2：注入式收集器把 modinfo 文本填入每个 Module 条目（批处理，按 filename 分块）。
    #[test]
    fn module_metadata_is_filled_from_modinfo() {
        let path = "/lib/modules/6.0.0-test/updates/dkms/a.ko";
        let mut report = ScanReport::default();
        report.entries.push(entry(path, 1, EntryKind::Module, None));
        let canned = format!(
            "filename:       {path}\nvermagic:       6.8.0-45-generic SMP\n\
             firmware:       fw/a.bin\ndepends:        dep1, dep2\nsig_id:         PKCS#7\n"
        );
        collect_module_metadata_with(None, &mut report, |_paths: &[PathBuf]| {
            Ok(canned.clone())
        })
        .expect("collect");

        let info = report.entries[0].modinfo.as_ref().expect("metadata filled");
        assert_eq!(info.vermagic.as_deref(), Some("6.8.0-45-generic SMP"));
        assert_eq!(info.depends, vec!["dep1".to_string(), "dep2".to_string()]);
        assert_eq!(info.firmware, vec!["fw/a.bin".to_string()]);
        assert!(info.is_signed());
        assert!(report.warnings.is_empty());
    }

    /// C-43：批处理下 `modinfo` 文本按 `filename:` 分块，映射回各自的模块条目。
    #[test]
    fn parse_modinfo_blocks_maps_each_module_by_filename() {
        let text = "\
filename:       /lib/modules/6/updates/a.ko
vermagic:       6.8.0 SMP
sig_id:         PKCS#7
filename:       /lib/modules/6/updates/b.ko
depends:        a
";
        let blocks = parse_modinfo_blocks(text);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].0, "/lib/modules/6/updates/a.ko");
        assert_eq!(blocks[0].1.vermagic.as_deref(), Some("6.8.0 SMP"));
        assert!(blocks[0].1.is_signed());
        assert_eq!(blocks[1].0, "/lib/modules/6/updates/b.ko");
        assert_eq!(blocks[1].1.depends, vec!["a".to_string()]);
        assert!(parse_modinfo_blocks("").is_empty());
    }

    /// P0-2：失败原因去重，且最多写 [`MAX_MODINFO_WARNINGS`] 条。
    #[test]
    fn modinfo_failures_are_deduped_and_capped() {
        let mut report = ScanReport::default();
        for i in 0..5 {
            report.entries.push(entry(
                &format!("/lib/modules/6.0.0-test/updates/m{i}.ko"),
                1,
                EntryKind::Module,
                None,
            ));
        }
        collect_module_metadata_with(None, &mut report, |_paths: &[PathBuf]| {
            Err("boom".to_string())
        })
        .expect("collect");
        assert_eq!(report.warnings.len(), 1, "同一失败原因去重后只记一条");
        assert!(report.entries.iter().all(|e| e.modinfo.is_none()));
    }

    /// C-43：`modinfo` 批次内成功与缺失并存时，只对缺失项记一条失败告警。
    #[test]
    fn modinfo_missing_entries_are_reported_once() {
        let mut report = ScanReport::default();
        for i in 0..3 {
            report.entries.push(entry(
                &format!("/lib/modules/6/updates/m{i}.ko"),
                1,
                EntryKind::Module,
                None,
            ));
        }
        // 只返回第一个模块的块，其余两个缺失。
        collect_module_metadata_with(None, &mut report, |paths: &[PathBuf]| {
            Ok(format!("filename:       {}\nvermagic: 6.8.0 SMP\n", paths[0].display()))
        })
        .expect("collect");
        assert_eq!(report.entries[0].modinfo.as_ref().unwrap().vermagic.as_deref(), Some("6.8.0 SMP"));
        assert!(report.entries[1].modinfo.is_none() && report.entries[2].modinfo.is_none());
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("未返回 2 个模块"));
    }

    /// C-43：第 5 阶段元数据收集可取消。
    #[test]
    fn modinfo_collection_respects_cancel() {
        let cancel = AtomicBool::new(true);
        let mut report = ScanReport::default();
        report.entries.push(entry(
            "/lib/modules/6/updates/a.ko",
            1,
            EntryKind::Module,
            None,
        ));
        match collect_module_metadata_with(Some(&cancel), &mut report, |_p: &[PathBuf]| {
            Ok(String::new())
        }) {
            Err(AppError::Cancelled) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    /// P0-5：`pkg: /path1, /path2` 单包多路径。
    #[test]
    fn parse_dpkg_query_s_single_package_many_paths() {
        let text = "v4l2loopback-dkms: /lib/modules/6.8/updates/dkms/v4l2loopback.ko, \
                    /lib/modules/6.8/updates/dkms/other.ko\n";
        let parsed = parse_dpkg_query_s(text);
        assert_eq!(
            parsed,
            vec![
                (
                    "v4l2loopback-dkms".to_string(),
                    "/lib/modules/6.8/updates/dkms/v4l2loopback.ko".to_string()
                ),
                (
                    "v4l2loopback-dkms".to_string(),
                    "/lib/modules/6.8/updates/dkms/other.ko".to_string()
                ),
            ]
        );
    }

    /// P0-5：多包多行 + 忽略 `diversion by …` 脏行。
    #[test]
    fn parse_dpkg_query_s_multiple_packages_and_lines() {
        let text = "\
linux-image-6.8.0-45-generic: /lib/modules/6.8.0-45-generic/kernel/drivers/net/foo.ko
nvidia-dkms-550: /lib/modules/6.8.0-45-generic/updates/dkms/nvidia.ko
diversion by foo from: /usr/lib/old
";
        let parsed = parse_dpkg_query_s(text);
        assert_eq!(parsed.len(), 2, "diversion 行被忽略");
        assert_eq!(parsed[0].0, "linux-image-6.8.0-45-generic");
        assert_eq!(parsed[1].0, "nvidia-dkms-550");
        assert_eq!(parsed[1].1, "/lib/modules/6.8.0-45-generic/updates/dkms/nvidia.ko");
    }

    /// P0-5：空输入与无路径行 → 空结果。
    #[test]
    fn parse_dpkg_query_s_empty_input() {
        assert!(parse_dpkg_query_s("").is_empty());
        assert!(parse_dpkg_query_s("\n  \n").is_empty());
        assert!(parse_dpkg_query_s("no-separator-here").is_empty());
    }

    /// C-24：解析批量 `rpm -qf` 的 `NAME\tVERSION-RELEASE` 行（不再含 FILENAMES）。
    #[test]
    fn parse_rpm_batch_reads_name_and_version() {
        let text = "kmod-nvidia\t550.107.02-1\nkmod-nvidia\t550.107.02-1\n";
        let parsed = parse_rpm_batch(text);
        assert_eq!(
            parsed,
            vec![
                ("kmod-nvidia".to_string(), "550.107.02-1".to_string()),
                ("kmod-nvidia".to_string(), "550.107.02-1".to_string()),
            ]
        );
    }

    /// C-24：包名为空/无分隔符的脏行被忽略。
    #[test]
    fn parse_rpm_batch_skips_malformed_lines() {
        let text = "only-one-field\n\tno-name\nreal\nreal\t1.0\n";
        let parsed = parse_rpm_batch(text);
        assert_eq!(parsed, vec![("real".to_string(), "1.0".to_string())]);
    }

    /// C-24：批量查询按"每路径一行"关联；行数不符时返回 `None` 触发逐路径回退。
    #[test]
    fn rpm_query_batch_aligns_only_on_matching_line_count() {
        let paths = vec![
            PathBuf::from("/usr/lib/modules/6/extra/a.ko"),
            PathBuf::from("/usr/lib/modules/6/extra/b.ko"),
        ];
        let ok = rpm_query_batch(&paths, &|_args: &[OsString]| {
            Some("kmod-a\t1.0-1\nkmod-b\t2.0-1\n".to_string())
        })
        .expect("aligned");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[0].0, "kmod-a");
        assert_eq!(ok[1].0, "kmod-b");

        // 有一路径未归属 → rpm 只输出一行 → 无法按序对应 → None
        assert!(rpm_query_batch(&paths, &|_a: &[OsString]| {
            Some("kmod-a\t1.0-1\n".to_string())
        })
        .is_none());
        // spawn 失败 → None
        assert!(rpm_query_batch(&paths, &|_a: &[OsString]| None).is_none());
    }

    /// C-24：可注入的批量 rpm 收集器按序回填原始路径键，并对未命中项逐路径回退。
    #[test]
    fn collect_owners_rpm_maps_paths_and_falls_back() {
        let paths = vec![
            PathBuf::from("/lib/modules/6/extra/a.ko"),
            PathBuf::from("/lib/modules/6/extra/b.ko"),
        ];
        // 归一化查询；整批因有一路径未归属而无法按序对齐 → 回退到原始路径逐条单查。
        let queries = vec![
            PathBuf::from("/usr/lib/modules/6/extra/a.ko"),
            PathBuf::from("/usr/lib/modules/6/extra/b.ko"),
        ];
        let mut owners = HashMap::new();
        collect_owners_rpm_with(&paths, &queries, &mut owners, None, |args| {
            // 批查询最后一个是归一化后的 b；单查回退最后一个是原始路径。
            let last = args
                .last()
                .map(|a| a.to_string_lossy().into_owned())
                .unwrap_or_default();
            match last.as_str() {
                // 批查询：故意只回一行 → 行数不符 → 无法对齐
                "/usr/lib/modules/6/extra/b.ko" => Some("kmod-a\t1.0-1\n".to_string()),
                // 逐路径回退：非 usr-merge 数据库记录的是 /lib 原始路径
                "/lib/modules/6/extra/a.ko" => Some("kmod-a\t1.0-1\n".to_string()),
                "/lib/modules/6/extra/b.ko" => Some("kmod-b\t2.0-1\n".to_string()),
                _ => None,
            }
        })
        .expect("collect rpm");

        assert_eq!(owners[&paths[0]].package, "kmod-a");
        assert_eq!(owners[&paths[0]].version, "1.0-1");
        assert_eq!(owners[&paths[1]].package, "kmod-b");
        assert!(owners.keys().all(|k| paths.contains(k)), "key 必须是原始路径");
    }

    /// C-24：`rpm -qf` 批量查询优先按"每个归属路径一行"关联，一次填入全部。
    #[test]
    fn collect_owners_rpm_batch_fills_all_aligned_paths() {
        let paths = vec![
            PathBuf::from("/usr/lib/modules/6/extra/a.ko"),
            PathBuf::from("/usr/lib/modules/6/extra/b.ko"),
        ];
        let queries = paths.clone(); // 已归一化，无需回退
        let mut owners = HashMap::new();
        collect_owners_rpm_with(&paths, &queries, &mut owners, None, |_args| {
            Some("kmod-a\t1.0-1\nkmod-b\t2.0-1\n".to_string())
        })
        .expect("collect rpm");
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[&paths[0]].package, "kmod-a");
        assert_eq!(owners[&paths[1]].package, "kmod-b");
    }

    /// C-43：归属查询阶段同样可取消。
    #[test]
    fn collect_owners_rpm_respects_cancel() {
        let cancel = AtomicBool::new(true);
        let paths = vec![PathBuf::from("/usr/lib/modules/6/extra/a.ko")];
        let queries = paths.clone();
        let mut owners = HashMap::new();
        match collect_owners_rpm_with(&paths, &queries, &mut owners, Some(&cancel), |_a| {
            Some(String::new())
        }) {
            Err(AppError::Cancelled) => {}
            other => panic!("expected Cancelled, got {other:?}"),
        }
    }

    /// C-22：`dpkg-query -S` 批内含未归属路径时 exit=1，stdout 里已匹配的部分必须仍被解析。
    ///
    /// 进程级实测证据（docs/ITERATION-v0.3.0.md §3.1-4）：`dpkg-query -S <存在路径>
    /// <不存在路径>` → `exit=1` 且 stdout 输出 `coreutils: /usr/bin/env`（诊断文本走
    /// stderr，归属查询只读 stdout）。这里把"一次批查询的混合 stdout"直接喂给解析函数，
    /// 锁定"部分失败不拖垮整批"；进程级的"非零退出仍返回 stdout"由
    /// [`run_command_stdout_ignores_exit_status`] 覆盖。
    #[test]
    fn parse_dpkg_query_s_keeps_matches_from_partial_batch() {
        // 三个命中路径分属两个包 —— 批内其余未归属路径只体现在退出码上，不在 stdout 里。
        let stdout = "\
coreutils: /usr/bin/env
dash: /bin/sh, /usr/bin/sh
";
        let parsed = parse_dpkg_query_s(stdout);
        assert_eq!(parsed.len(), 3, "exit=1 批次的 stdout 命中必须全部保留");
        assert_eq!(
            parsed[0],
            ("coreutils".to_string(), "/usr/bin/env".to_string())
        );
        assert_eq!(
            parsed[2],
            ("dash".to_string(), "/usr/bin/sh".to_string())
        );
    }

    /// C-22：归属查询读 stdout 而不看退出码 —— exit≠0 仍返回输出，仅 spawn 失败返回 `None`。
    #[test]
    fn run_command_stdout_ignores_exit_status() {
        // 模拟 `dpkg-query -S` 批内含未归属路径：exit=1 但 stdout 仍有匹配（§3.1-4 实测）。
        let out = run_command_stdout(
            "sh",
            &[
                OsString::from("-c"),
                OsString::from("printf 'coreutils: /usr/bin/env\\n'; exit 1"),
            ],
        )
        .expect("非零退出必须仍返回 stdout");
        assert_eq!(out, "coreutils: /usr/bin/env\n");

        // 完全无输出（如 `-W` 查询的包不存在）→ 空串，解析自然得空、不影响其余包。
        let empty = run_command_stdout(
            "sh",
            &[OsString::from("-c"), OsString::from("exit 1")],
        )
        .expect("非零退出但成功 spawn");
        assert!(empty.is_empty());

        // spawn 失败（命令不存在）→ None。
        assert!(run_command_stdout("ldb-no-such-command-for-test", &[]).is_none());
    }

    /// C-23：usr-merge 归一化把根首段 `/lib`、`/bin`、`/sbin`、`/lib64` 改写到 `/usr` 下。
    #[test]
    fn usr_merge_normalize_maps_merged_root_dirs() {
        assert_eq!(
            usr_merge_normalize(Path::new("/lib/modules/6.8.0-generic/updates/dkms/foo.ko")),
            PathBuf::from("/usr/lib/modules/6.8.0-generic/updates/dkms/foo.ko")
        );
        assert_eq!(
            usr_merge_normalize(Path::new("/lib/firmware/i915/fw.bin")),
            PathBuf::from("/usr/lib/firmware/i915/fw.bin")
        );
        assert_eq!(
            usr_merge_normalize(Path::new("/bin/sh")),
            PathBuf::from("/usr/bin/sh")
        );
        assert_eq!(
            usr_merge_normalize(Path::new("/sbin/depmod")),
            PathBuf::from("/usr/sbin/depmod")
        );
        assert_eq!(
            usr_merge_normalize(Path::new("/lib64/ld-linux-x86-64.so.2")),
            PathBuf::from("/usr/lib64/ld-linux-x86-64.so.2")
        );
        // 恰好只有根段时也不补尾斜杠
        assert_eq!(usr_merge_normalize(Path::new("/lib")), PathBuf::from("/usr/lib"));
    }

    /// C-23：只改写"根之后的第一个组件"，其余路径原样返回。
    #[test]
    fn usr_merge_normalize_leaves_other_paths_alone() {
        for p in [
            "/usr/lib/modules/6.8.0",   // 已是 usr 前缀（扫描的另一个根）
            "/usr/lib/firmware",        // 不做二次前缀
            "/var/lib/dkms/nvidia/1.0", // 中段的 lib 不是首段
            "/libfoo/bar",              // 前缀相近但不是独立段
            "/etc/modprobe.d/x.conf",
            "lib/modules/x.ko", // 相对路径
        ] {
            assert_eq!(usr_merge_normalize(Path::new(p)), PathBuf::from(p), "{p}");
        }
    }

    /// C-23：查包时先按归一化查询串命中，落空再看原始路径（回退查询），两者都不中则无归属。
    #[test]
    fn package_lookup_prefers_normalized_query_then_original() {
        let orig = Path::new("/lib/foo");
        let norm = usr_merge_normalize(orig);
        assert_eq!(norm, PathBuf::from("/usr/lib/foo"));

        // usr-merge 系统：dpkg 数据库存的是 /usr/lib/... → 按归一化查询串命中
        let mut merged = HashMap::new();
        merged.insert("/usr/lib/foo".to_string(), "libc6:amd64".to_string());
        assert_eq!(
            package_for(&merged, orig, &norm).map(String::as_str),
            Some("libc6:amd64")
        );

        // 非 usr-merge 系统：数据库存原始 /lib/... → 回退查询命中
        let mut plain = HashMap::new();
        plain.insert("/lib/foo".to_string(), "legacy-pkg".to_string());
        assert_eq!(
            package_for(&plain, orig, &norm).map(String::as_str),
            Some("legacy-pkg")
        );

        // 两者都不中 → None；查询串未变化（query == path）时只按该串查一次
        let absent = Path::new("/lib/absent");
        assert!(package_for(&plain, absent, absent).is_none());
        let etc = Path::new("/etc/only-in-plain");
        assert!(package_for(&plain, etc, etc).is_none());
    }

    /// C-23：无论命中与否，`owners` 的 key 只能是调用方传入的原始路径。
    ///
    /// 环境相关（dpkg/rpm 都缺失时 owners 为空，断言同样成立）；关键在于归一化查询串
    /// 永远不会作为 key 泄漏出去 —— 否则 `scan()` 按 `entry.abs_path` 回填时会全部落空。
    #[test]
    fn collect_owners_keys_are_caller_paths_not_normalized() {
        let inputs = vec![PathBuf::from(
            "/lib/modules/6.8.0-test/updates/dkms/ldb-owner-probe.ko",
        )];
        let owners = collect_owners(&inputs, None).expect("collect owners");
        assert!(
            owners.keys().all(|k| inputs.contains(k)),
            "owners 只能用原始路径做 key，实际: {:?}",
            owners.keys().collect::<Vec<_>>()
        );
        assert!(
            !owners.contains_key(&PathBuf::from(
                "/usr/lib/modules/6.8.0-test/updates/dkms/ldb-owner-probe.ko"
            )),
            "归一化查询串不得成为 key"
        );
    }

    /// 固件内容标记：属于系统包的固件 `content_stored=false`，其余保持 `true`。
    #[test]
    fn firmware_from_package_is_not_content_stored() {
        let mut entries = vec![
            entry(
                "/lib/firmware/a.bin",
                1,
                EntryKind::Firmware,
                Some(Provenance {
                    manager: "dpkg".to_string(),
                    package: "linux-firmware".to_string(),
                    version: "20240318".to_string(),
                }),
            ),
            entry("/lib/firmware/b.bin", 1, EntryKind::Firmware, None),
            entry(
                "/lib/modules/x/updates/m.ko",
                1,
                EntryKind::Module,
                Some(Provenance {
                    manager: "dpkg".to_string(),
                    package: "some-module-pkg".to_string(),
                    version: String::new(),
                }),
            ),
        ];
        mark_package_provided_firmware(&mut entries);
        assert!(!entries[0].content_stored, "包提供的固件不重复存内容");
        assert!(entries[1].content_stored, "无来源包的固件仍需存内容");
        assert!(entries[2].content_stored, "标记只作用于固件条目");
        assert_eq!(entries[2].kind, EntryKind::Module, "kind 保持不变");
    }

    /// DKMS 清单：`/var/lib/dkms/<name>/<version>` 去重后按名称、版本排序（单次枚举）。
    #[test]
    fn dkms_enumeration_lists_sorted_deduped() {
        let base = temp_dir("dkmslist");
        fs::create_dir_all(base.join("nvidia/550.1")).unwrap();
        fs::create_dir_all(base.join("nvidia/535.2")).unwrap();
        fs::create_dir_all(base.join("vbox/7.0")).unwrap();
        fs::create_dir_all(base.join("nvidia")).unwrap(); // 只有 name，无 version
        fs::write(base.join("stray"), b"x").unwrap(); // 非目录忽略

        let packages =
            enumerate_dkms(&base, &mut ScanReport::default()).packages;
        let got: Vec<(String, String)> = packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("nvidia".to_string(), "535.2".to_string()),
                ("nvidia".to_string(), "550.1".to_string()),
                ("vbox".to_string(), "7.0".to_string()),
            ]
        );
        assert!(
            enumerate_dkms(&base.join("missing"), &mut ScanReport::default())
                .packages
                .is_empty()
        );
        let _ = fs::remove_dir_all(&base);
    }

    // -----------------------------------------------------------------------
    // v0.3.0 W3 新增：C-24…C-29 / C-43
    // -----------------------------------------------------------------------

    /// C-25：`kernel/` 子树内的符号链接属于内核基线，不得被当成外置模块收录。
    #[test]
    fn symlink_inside_kernel_subtree_is_not_out_of_tree() {
        let base = temp_dir("kernellink");
        let kver_dir = base.join("6.0.0-test");
        write_file(&kver_dir.join("kernel/drivers/real.ko"));
        std::os::unix::fs::symlink("real.ko", kver_dir.join("kernel/drivers/link.ko"))
            .expect("symlink in kernel tree");
        write_file(&kver_dir.join("updates/out.ko"));

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&kver_dir, &opt, &mut report).expect("scan");

        assert_eq!(report.entries.len(), 1, "只有 kernel/ 之外的 out.ko 收录");
        assert!(report.entries[0].rel_path.ends_with("updates/out.ko"));
        assert_eq!(report.skipped_in_tree, 2, "kernel/ 下的 real.ko 与 link.ko 计为 in-tree");
        assert!(report.entries.iter().all(|e| e.kind == EntryKind::Module));
        let _ = fs::remove_dir_all(&base);
    }

    /// C-26：`build`/`source` 目录链接静默跳过，不再产生告警。
    #[test]
    fn build_and_source_kernel_links_are_silently_skipped() {
        let base = temp_dir("buildlink");
        let kver_dir = base.join("6.0.0-test");
        write_file(&kver_dir.join("updates/a.ko"));
        std::os::unix::fs::symlink("/usr/src/linux-headers-6.0.0-test", kver_dir.join("build"))
            .expect("build symlink");
        std::os::unix::fs::symlink("/usr/src/linux-headers-6.0.0-test", kver_dir.join("source"))
            .expect("source symlink");

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_module_root(&kver_dir, &opt, &mut report).expect("scan");

        assert_eq!(report.entries.len(), 1);
        assert!(
            report.warnings.is_empty(),
            "build/source 链接不得告警: {:?}",
            report.warnings
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// C-26：`report.warnings` 全局去重，并在上限后累计溢出条数。
    #[test]
    fn warnings_are_deduped_and_capped_with_overflow_count() {
        let mut report = ScanReport::default();
        push_warning(&mut report, "dup".to_string());
        push_warning(&mut report, "dup".to_string());
        assert_eq!(report.warnings.len(), 1, "重复消息只保留一条");

        // 填满到上限
        for i in 0..MAX_WARNINGS - 1 {
            push_warning(&mut report, format!("w{i}"));
        }
        assert_eq!(report.warnings.len(), MAX_WARNINGS);
        // 再多的告警只累加溢出计数
        for i in 0..50 {
            push_warning(&mut report, format!("x{i}"));
        }
        assert_eq!(report.warnings.len(), MAX_WARNINGS + 1);
        let last = report.warnings.last().unwrap();
        assert_eq!(parse_overflow_count(last), Some(50));
        // 空消息被忽略
        push_warning(&mut report, String::new());
        assert_eq!(report.warnings.len(), MAX_WARNINGS + 1);
    }

    /// C-27：配置路径扩展覆盖 initramfs 控制文件，且匹配遵守组件边界。
    #[test]
    fn config_paths_cover_initramfs_controls() {
        for p in [
            "/etc/initramfs-tools",
            "/etc/dracut.conf",
            "/etc/dracut.conf.d",
            "/etc/mkinitcpio.conf",
            "/etc/mkinitcpio.d",
            "/etc/modules",
            "/etc/sysconfig/modules",
        ] {
            assert!(CONFIG_PATHS.iter().any(|(d, _)| *d == p), "缺少 {p}");
            assert!(is_managed_config_dir(Path::new(p)), "未纳入受管路径: {p}");
        }
        assert!(!is_managed_config_dir(Path::new("/etc/modules-other")));
        assert!(is_managed_config_dir(Path::new(
            "/etc/modules-load.d/x.conf"
        )));
    }

    /// C-28：固件目录优先选真实目录（usr-merge 下回退 `/usr/lib/firmware`）。
    #[test]
    fn firmware_dir_prefers_real_directory() {
        let exists = FIRMWARE_DIRS.iter().any(|d| Path::new(d).is_dir());
        match firmware_dir() {
            Some(dir) => assert!(FIRMWARE_DIRS.contains(&dir) && Path::new(dir).is_dir()),
            None => assert!(!exists, "存在候选目录却返回 None"),
        }
        let lib_symlink = fs::symlink_metadata("/lib/firmware")
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false);
        let usr_real = fs::symlink_metadata("/usr/lib/firmware")
            .map(|m| m.is_dir() && !m.file_type().is_symlink())
            .unwrap_or(false);
        if lib_symlink && usr_real {
            assert_eq!(firmware_dir(), Some("/usr/lib/firmware"));
            assert_eq!(firmware_dir(), Some(FIRMWARE_DIRS[1]));
        }
    }

    /// C-29：解析 `dkms.conf` 的 `PACKAGE_NAME=`（引号/export/注释/空值）。
    #[test]
    fn parse_dkms_conf_package_name_variants() {
        assert_eq!(
            parse_dkms_conf_package_name("PACKAGE_NAME=nvidia\n"),
            Some("nvidia".to_string())
        );
        assert_eq!(
            parse_dkms_conf_package_name("PACKAGE_NAME=\"nvidia-550\"\n"),
            Some("nvidia-550".to_string())
        );
        assert_eq!(
            parse_dkms_conf_package_name("export PACKAGE_NAME='foo'\n"),
            Some("foo".to_string())
        );
        assert_eq!(
            parse_dkms_conf_package_name("# PACKAGE_NAME=x\nPACKAGE_NAME=bar\n"),
            Some("bar".to_string())
        );
        assert_eq!(parse_dkms_conf_package_name("PACKAGE_NAME=\n"), None);
        assert_eq!(parse_dkms_conf_package_name("OTHER=1\n"), None);
    }

    /// C-29：目录名不提示 DKMS，仅 `dkms.conf` 的 `PACKAGE_NAME` 指向已注册包时也应收录。
    #[test]
    fn dkms_conf_package_name_selects_usr_src_tree() {
        let base = temp_dir("dkmsconf");
        let dkms_root = base.join("var/lib/dkms");
        let usr_src = base.join("usr/src");
        write_file(&dkms_root.join("nvidia/550.1/module.c"));
        write_file(&usr_src.join("weird-name-1.2/dkms.conf"));
        fs::write(
            usr_src.join("weird-name-1.2/dkms.conf"),
            b"PACKAGE_NAME=\"nvidia\"\n",
        )
        .unwrap();
        write_file(&usr_src.join("unrelated/x.c"));

        let distro = dummy_distro();
        let opt = ScanOptions {
            kver: "6.0.0-test",
            distro: &distro,
            mode: BackupMode::Standard,
            cancel: None,
        };
        let mut report = ScanReport::default();
        scan_dkms_in(&dkms_root, &usr_src, &opt, &mut report).expect("scan dkms");

        assert!(report
            .entries
            .iter()
            .any(|e| e.rel_path.ends_with("usr/src/weird-name-1.2/dkms.conf")));
        assert!(!report
            .entries
            .iter()
            .any(|e| e.rel_path.contains("unrelated")));
        assert_eq!(
            report.dkms,
            vec![DkmsPackage {
                name: "nvidia".to_string(),
                version: "550.1".to_string(),
            }],
            "扫描一次同时产出 manifest 的 dkms 清单"
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// C-43：`run_command_stdout_timeout` 忽略退出码读取 stdout，超时返回 `None`。
    #[test]
    fn run_command_stdout_timeout_handles_exit_and_timeout() {
        let ok = run_command_stdout_timeout(
            "sh",
            &[
                OsString::from("-c"),
                OsString::from("printf hi; exit 1"),
            ],
            Duration::from_secs(5),
        );
        assert_eq!(ok.as_deref(), Some("hi"), "非零退出仍返回 stdout");

        let timed_out = run_command_stdout_timeout(
            "sh",
            &[
                OsString::from("-c"),
                OsString::from("sleep 5; printf late"),
            ],
            Duration::from_millis(150),
        );
        assert!(timed_out.is_none(), "超时必须返回 None 而非阻塞");

        assert!(
            run_command_stdout_timeout("ldb-no-such-command-xyz", &[], Duration::from_secs(1))
                .is_none(),
            "命令缺失返回 None"
        );
    }

    /// 冒烟：在真实主机上以 Minimal 模式跑一次，任何环境都必须 Ok（缺失项只进 warnings）。
    #[test]
    fn scan_smoke_on_host_returns_ok() {
        let distro = DistroInfo::detect();
        let kver = crate::distro::kernel_release();
        let opt = ScanOptions {
            kver: &kver,
            distro: &distro,
            mode: BackupMode::Minimal,
            cancel: None,
        };
        let report = scan(&opt).expect("scan must not fail on a read-only host");
        // Minimal 模式下条目只能来自模块目录（lib/usr/lib）与配置目录（etc）
        for e in &report.entries {
            assert!(!e.rel_path.starts_with('/') && !e.rel_path.is_empty());
            assert!(
                e.rel_path.starts_with("lib/")
                    || e.rel_path.starts_with("usr/lib/")
                    || e.rel_path.starts_with("etc/"),
                "unexpected scope: {}",
                e.rel_path
            );
            if e.kind == EntryKind::Symlink {
                assert!(e.link_target.is_some(), "符号链接必须带 link_target");
                assert_eq!(e.size, 0);
            }
        }
    }
}
