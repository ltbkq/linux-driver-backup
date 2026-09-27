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
//! 路径约定：[`ScanEntry::rel_path`] 是"去掉前导 `/` 的相对路径"
//! （如 `lib/modules/6.8.0-45-generic/updates/dkms/foo.ko`），归档直接按它落盘（DESIGN.md §4.3）。

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use crate::distro::{has_cmd, is_module_path, module_roots, DistroInfo, Family};
use crate::model::{
    AppError, AppResult, BackupMode, DkmsPackage, EntryKind, ModInfo, Provenance, ScanEntry,
    ScanReport,
};

/// 所有模式都会扫描的配置目录 / Configuration dirs scanned in every mode.
const CONFIG_DIRS: &[&str] = &[
    "/etc/modprobe.d",
    "/etc/udev/rules.d",
    "/etc/depmod.d",
    "/etc/modules-load.d",
];

/// DKMS 已注册模块库（`<pkg>/<ver>/`） / Registered DKMS modules.
const DKMS_ROOT: &str = "/var/lib/dkms";

/// DKMS 源码目录（与 `/var/lib/dkms` 的 pkg 同名，或名字含 `-dkms`） / DKMS source trees.
const USR_SRC: &str = "/usr/src";

/// 固件目录，仅 Full 模式（usr-merge 下 `/lib → /usr/lib`，无需另扫 `/usr/lib/firmware`）。
const FIRMWARE_DIR: &str = "/lib/firmware";

/// 批处理外部命令（`dpkg-query` / `rpm`）时每次传入的最大路径/包数，防命令行超长。
/// Max paths/packages per external query invocation, guarding against ARG_MAX.
const QUERY_CHUNK: usize = 256;

/// `modinfo` 失败原因最多写入的 warning 条数（去重后），避免刷屏。
/// Maximum number of distinct `modinfo` failure warnings (after dedup).
const MAX_MODINFO_WARNINGS: usize = 3;

/// `rpm -qf` 的查询格式：`NAME<TAB>VERSION-RELEASE<TAB>FILENAMES`。
/// The query format used for `rpm -qf`.
const RPM_QF_FORMAT: &str = "%{NAME}\t%{VERSION}-%{RELEASE}\t%{FILENAMES}\n";

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
        report.warnings.push(format!(
            "未识别的发行版家族（ID={id}），还原时将跳过 initramfs 更新"
        ));
    }

    // 1) out-of-tree 模块：/lib/modules/<kver> 与 /usr/lib/modules/<kver>
    let roots = module_roots();
    if roots.is_empty() {
        report
            .warnings
            .push("未找到可读的模块目录（/lib/modules、/usr/lib/modules）".to_string());
    }
    for root in &roots {
        scan_module_root(&root.join(opt.kver), opt, &mut report)?;
    }

    // 2) 配置文件：Minimal 起就包含
    for dir in CONFIG_DIRS {
        let path = Path::new(dir);
        if path.is_dir() {
            walk_files(path, EntryKind::Config, opt, &mut report)?;
        } else {
            report.warnings.push(format!("配置目录不存在或不可读: {dir}"));
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
        let fw = Path::new(FIRMWARE_DIR);
        if fw.is_dir() {
            walk_files(fw, EntryKind::Firmware, opt, &mut report)?;
            tally_firmware(&mut report);
        } else {
            report
                .warnings
                .push(format!("固件目录不存在或不可读: {FIRMWARE_DIR}"));
        }
    }

    // 5) v2 元数据：模块 modinfo（P0-2）、来源包 owner（P0-5）、固件内容标记、DKMS 清单。
    collect_module_metadata(&mut report);

    let paths: Vec<PathBuf> = report.entries.iter().map(|e| e.abs_path.clone()).collect();
    let owners = collect_owners(&paths);
    if !owners.is_empty() {
        for entry in report.entries.iter_mut() {
            if let Some(prov) = owners.get(&entry.abs_path) {
                entry.owner = Some(prov.clone());
            }
        }
    }
    // 由系统包提供的固件不再重复存内容（ROADMAP §4 的 `content_stored=false`）。
    mark_package_provided_firmware(&mut report.entries);

    // DKMS 包清单：仅 Standard/Full（与 scan_dkms 的收录范围一致）。
    if matches!(opt.mode, BackupMode::Standard | BackupMode::Full) {
        report.dkms = dkms_packages_in(Path::new(DKMS_ROOT));
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
        // 符号链接：不跟随；链接名/目标形如模块才收录（如 weak-updates/foo.ko）。
        if file_type.is_symlink() {
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
        // 相对 kver 目录的第一段即分类依据
        let rel = match entry.path().strip_prefix(kver_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if rel.starts_with("kernel") {
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
                report
                    .warnings
                    .push(format!("遍历 {} 时出错: {err}", root.display()));
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
    // 目录符号链接：walkdir 默认不跟随，这里也明确跳过并记 warning。
    if abs.is_dir() {
        report
            .warnings
            .push(format!("跳过目录符号链接（不跟随）: {}", abs.display()));
        return;
    }
    let target = match fs::read_link(abs) {
        Ok(t) => t,
        Err(err) => {
            report
                .warnings
                .push(format!("无法读取符号链接 {}: {err}", abs.display()));
            return;
        }
    };
    if !symlink_is_relevant(abs, &target) {
        report.warnings.push(format!(
            "跳过无关符号链接: {} -> {}",
            abs.display(),
            target.display()
        ));
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
/// 链接名或链接目标形如模块，或链接位于受管配置目录（[`CONFIG_DIRS`]）时才有意义。
fn symlink_is_relevant(abs: &Path, target: &Path) -> bool {
    is_module_path(abs) || is_module_path(target) || is_managed_config_dir(abs)
}

/// Whether a path sits under one of the managed configuration dirs.
///
/// 用于判断配置目录内的符号链接是否需要收录。
fn is_managed_config_dir(path: &Path) -> bool {
    CONFIG_DIRS.iter().any(|dir| path.starts_with(*dir))
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
    let mut pkgs: Vec<String> = Vec::new();
    if dkms_root.is_dir() {
        for pkg_dir in sorted_dirs(dkms_root, report) {
            if let Some(name) = pkg_dir.file_name().map(|n| n.to_string_lossy().into_owned()) {
                pkgs.push(name);
            }
            // <pkg>/<ver> 整棵树纳入（modules/ 与 source/ 都在其中）
            for ver_dir in sorted_dirs(&pkg_dir, report) {
                walk_files(&ver_dir, EntryKind::Dkms, opt, report)?;
            }
        }
    } else {
        report.warnings.push(format!(
            "DKMS 目录不存在或不可读: {}",
            dkms_root.display()
        ));
    }

    if usr_src.is_dir() {
        let prefixes: Vec<String> = pkgs.iter().map(|p| format!("{p}-")).collect();
        for dir in sorted_dirs(usr_src, report) {
            let name = match dir.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            let matched = name.contains("-dkms")
                || pkgs.contains(&name)
                || prefixes.iter().any(|pre| name.starts_with(pre.as_str()));
            if matched {
                walk_files(&dir, EntryKind::Dkms, opt, report)?;
            }
        }
    } else {
        report
            .warnings
            .push(format!("DKMS 源码目录不存在或不可读: {}", usr_src.display()));
    }
    Ok(())
}

/// List registered DKMS packages from `/var/lib/dkms/<name>/<version>` (P0-4 重建输入).
///
/// 遍历一级 `<name>` 与二级 `<version>` 目录，产出去重后按名称、版本排序的
/// [`DkmsPackage`]；根目录不存在或不可读时返回空列表（`scan_dkms` 已另行告警）。
fn dkms_packages_in(root: &Path) -> Vec<DkmsPackage> {
    let mut packages: Vec<DkmsPackage> = Vec::new();
    let read_dir = match fs::read_dir(root) {
        Ok(rd) => rd,
        Err(_) => return packages,
    };
    let mut name_dirs: Vec<PathBuf> = read_dir
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    name_dirs.sort();

    for name_dir in name_dirs {
        let name = match name_dir.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        let ver_rd = match fs::read_dir(&name_dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        let mut ver_dirs: Vec<PathBuf> = ver_rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            // `/var/lib/dkms/<pkg>/kernel-<kver>-<arch>/` 是**按内核的构建目录**，
            // 不是模块版本；只有 `<version>/` 才是（形如 `0.12.7`）。
            .filter(|p| {
                !p.file_name()
                    .map(|n| n.to_string_lossy().starts_with("kernel-"))
                    .unwrap_or(true)
            })
            .collect();
        ver_dirs.sort();
        for ver_dir in ver_dirs {
            if let Some(version) = ver_dir.file_name() {
                packages.push(DkmsPackage {
                    name: name.clone(),
                    version: version.to_string_lossy().into_owned(),
                });
            }
        }
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.version.cmp(&b.version)));
    packages.dedup();
    packages
}

/// Fill [`ScanEntry::modinfo`] for every module entry, calling `modinfo` once per module (P0-2).
///
/// 先确认存在 `modinfo`（否则记一条 warning 后返回）；失败原因去重后最多记
/// [`MAX_MODINFO_WARNINGS`] 条，避免刷屏。实际收集逻辑见
/// [`collect_module_metadata_with`]（可注入，便于单测）。
fn collect_module_metadata(report: &mut ScanReport) {
    if !report.entries.iter().any(|e| e.kind == EntryKind::Module) {
        return;
    }
    if !has_cmd("modinfo") {
        report
            .warnings
            .push("未找到 modinfo 命令，跳过模块元数据收集".to_string());
        return;
    }
    collect_module_metadata_with(report, run_modinfo);
}

/// [`collect_module_metadata`] 的可测试核心：`run` 注入"取 modinfo 文本"的实现。
/// Testable core of [`collect_module_metadata`] with an injectable `modinfo` runner.
fn collect_module_metadata_with<F>(report: &mut ScanReport, run: F)
where
    F: Fn(&Path) -> Result<String, String>,
{
    let mut failures: Vec<String> = Vec::new();
    for entry in report.entries.iter_mut() {
        if entry.kind != EntryKind::Module {
            continue;
        }
        match run(&entry.abs_path) {
            Ok(text) => entry.modinfo = Some(parse_modinfo(&text)),
            Err(reason) => {
                if failures.len() < MAX_MODINFO_WARNINGS && !failures.contains(&reason) {
                    failures.push(reason);
                }
            }
        }
    }
    for reason in failures {
        report.warnings.push(format!("modinfo 收集失败: {reason}"));
    }
}

/// Run `modinfo <module>` once and return its stdout, or a short failure reason.
///
/// 命令缺失/非零退出都返回 `Err(原因)`；调用方据此降级。
fn run_modinfo(module: &Path) -> Result<String, String> {
    let output = Command::new("modinfo")
        .arg(module)
        .output()
        .map_err(|e| format!("无法执行 modinfo: {e}"))?;
    if !output.status.success() {
        let code = output
            .status
            .code()
            .map(|c| c.to_string())
            .unwrap_or_else(|| "signal".to_string());
        return Err(format!("modinfo 退出码 {code}"));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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

/// Resolve package provenance for the given paths (P0-5), `dpkg-query` first, then `rpm`.
///
/// 先尝试 `dpkg-query -S`（按 [`QUERY_CHUNK`] 分片）并对命中的包批量取版本；若无
/// `dpkg-query` 则回退 `rpm -qf`（逐路径）。两者都缺失或查询失败时返回空 map，
/// **绝不报错**（调用方保持 `owner = None`）。
fn collect_owners(paths: &[PathBuf]) -> HashMap<PathBuf, Provenance> {
    let mut owners: HashMap<PathBuf, Provenance> = HashMap::new();
    if paths.is_empty() {
        return owners;
    }
    if has_cmd("dpkg-query") {
        collect_owners_dpkg(paths, &mut owners);
    } else if has_cmd("rpm") {
        collect_owners_rpm(paths, &mut owners);
    }
    owners
}

/// `dpkg-query -S` 批量查来源包，再 `-W` 批量取版本，写入 `owners`。
/// Query provenance in batch with `dpkg-query -S`, then resolve versions with `-W`.
fn collect_owners_dpkg(paths: &[PathBuf], owners: &mut HashMap<PathBuf, Provenance>) {
    // 归档路径字符串 -> 包名
    let mut package_by_path: HashMap<String, String> = HashMap::new();
    for chunk in paths.chunks(QUERY_CHUNK) {
        let mut args: Vec<OsString> = Vec::with_capacity(chunk.len() + 1);
        args.push(OsString::from("-S"));
        args.extend(chunk.iter().map(|p| p.as_os_str().to_os_string()));
        let Some(text) = run_command("dpkg-query", &args) else {
            continue;
        };
        for (package, path) in parse_dpkg_query_s(&text) {
            package_by_path.entry(path).or_insert(package);
        }
    }
    if package_by_path.is_empty() {
        return;
    }

    // 去重后的包名列表
    let mut packages: Vec<String> = package_by_path.values().cloned().collect();
    packages.sort();
    packages.dedup();

    let mut versions: HashMap<String, String> = HashMap::new();
    for chunk in packages.chunks(QUERY_CHUNK) {
        let mut args: Vec<OsString> = Vec::with_capacity(chunk.len() + 2);
        args.push(OsString::from("-W"));
        // dpkg-query 会解释格式串里的 `\t` / `\n` 转义。
        args.push(OsString::from("-f=${Package}\\t${Version}\\n"));
        args.extend(chunk.iter().map(|p| OsString::from(p.as_str())));
        let Some(text) = run_command("dpkg-query", &args) else {
            continue;
        };
        for line in text.lines() {
            if let Some((package, version)) = line.split_once('\t') {
                versions.insert(package.trim().to_string(), version.trim().to_string());
            }
        }
    }

    for path in paths {
        let key = path.to_string_lossy();
        if let Some(package) = package_by_path.get(&*key) {
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
}

/// `rpm -qf` 逐路径查来源包（`%{NAME}` + `%{VERSION}-%{RELEASE}`），写入 `owners`。
/// Query provenance per path with `rpm -qf`.
fn collect_owners_rpm(paths: &[PathBuf], owners: &mut HashMap<PathBuf, Provenance>) {
    for path in paths {
        let args: Vec<OsString> = vec![
            OsString::from("-qf"),
            OsString::from("--qf"),
            OsString::from(RPM_QF_FORMAT),
            path.as_os_str().to_os_string(),
        ];
        let Some(text) = run_command("rpm", &args) else {
            continue;
        };
        // 单路径查询必为同一包：取首行即可（`FILENAMES` 可能内含该包全部文件）。
        if let Some((name, version, _)) = parse_rpm_qf(&text).into_iter().next() {
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
}

/// Run a command and return its stdout on success; any failure yields `None`.
///
/// 查询类外部命令一律"尽力而为"：不存在、非零退出、非 UTF-8 都静默降级。
fn run_command(program: &str, args: &[OsString]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
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

/// Parse `rpm -qf --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{FILENAMES}\n'` output.
///
/// 返回 `(name, version, path)` 三元组；字段不足三列（或 path 为空）的脏行忽略。
fn parse_rpm_qf(text: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let mut fields = line.splitn(3, '\t');
        let name = fields.next().unwrap_or("").trim();
        let version = fields.next().unwrap_or("").trim();
        let path = fields.next().unwrap_or("").trim();
        if name.is_empty() || path.is_empty() {
            continue;
        }
        out.push((name.to_string(), version.to_string(), path.to_string()));
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

/// Sum firmware entry sizes into [`ScanReport::firmware_bytes`] (size hint for the UI).
fn tally_firmware(report: &mut ScanReport) {
    report.firmware_bytes = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Firmware)
        .map(|e| e.size)
        .sum();
}

/// Append one regular-file entry; unreadable files degrade to a warning, never an error.
///
/// 常规文件默认 `content_stored = true`；`owner`/`modinfo` 留待后续批量填充。
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
        Err(err) => report
            .warnings
            .push(format!("无法读取 {}: {err}", abs.display())),
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
            report
                .warnings
                .push(format!("无法读取目录 {}: {err}", dir.display()));
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
    match opt.cancel {
        Some(flag) if flag.load(Ordering::Relaxed) => Err(AppError::Cancelled),
        _ => Ok(()),
    }
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

    #[test]
    fn tally_firmware_sums_only_firmware_bytes() {
        let mut report = ScanReport::default();
        report
            .entries
            .push(entry("/lib/firmware/a.bin", 100, EntryKind::Firmware, None));
        report
            .entries
            .push(entry("/lib/firmware/b.bin", 250, EntryKind::Firmware, None));
        report.entries.push(entry(
            "/lib/modules/x/updates/m.ko",
            7,
            EntryKind::Module,
            None,
        ));
        tally_firmware(&mut report);
        assert_eq!(report.firmware_bytes, 350);
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

    /// P0-2：注入式收集器把 modinfo 文本填入每个 Module 条目。
    #[test]
    fn module_metadata_is_filled_from_modinfo() {
        let mut report = ScanReport::default();
        report.entries.push(entry(
            "/lib/modules/6.0.0-test/updates/dkms/a.ko",
            1,
            EntryKind::Module,
            None,
        ));
        let canned = "vermagic: 6.8.0-45-generic SMP\nfirmware: fw/a.bin\ndepends: dep1, dep2\nsig_id: PKCS#7\n";
        collect_module_metadata_with(&mut report, |_path: &Path| Ok(canned.to_string()));

        let info = report.entries[0].modinfo.as_ref().expect("metadata filled");
        assert_eq!(info.vermagic.as_deref(), Some("6.8.0-45-generic SMP"));
        assert_eq!(info.depends, vec!["dep1".to_string(), "dep2".to_string()]);
        assert_eq!(info.firmware, vec!["fw/a.bin".to_string()]);
        assert!(info.is_signed());
        assert!(report.warnings.is_empty());
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
        collect_module_metadata_with(&mut report, |_path: &Path| Err("boom".to_string()));
        assert_eq!(report.warnings.len(), 1, "同一失败原因去重后只记一条");
        assert!(report.entries.iter().all(|e| e.modinfo.is_none()));
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

    /// P0-5：解析 `rpm -qf` 的 `NAME\tVERSION-RELEASE\tFILENAMES` 行。
    #[test]
    fn parse_rpm_qf_reads_tab_separated_rows() {
        let text = "kmod-nvidia\t550.107.02-1\t/usr/lib/modules/6.8/extra/nvidia.ko\n\
                    kmod-nvidia\t550.107.02-1\t/usr/lib/modules/6.8/extra/nvidia-uvm.ko\n";
        let parsed = parse_rpm_qf(text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "kmod-nvidia");
        assert_eq!(parsed[0].1, "550.107.02-1");
        assert_eq!(parsed[0].2, "/usr/lib/modules/6.8/extra/nvidia.ko");
    }

    /// P0-5：字段不足/路径为空的脏行被忽略。
    #[test]
    fn parse_rpm_qf_skips_malformed_lines() {
        let text = "only-one-field\nname\tversion\n\t\t/path\nreal\t1.0\t/p\n";
        let parsed = parse_rpm_qf(text);
        assert_eq!(
            parsed,
            vec![("real".to_string(), "1.0".to_string(), "/p".to_string())]
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

    /// DKMS 清单：`/var/lib/dkms/<name>/<version>` 去重后按名称、版本排序。
    #[test]
    fn dkms_packages_in_lists_sorted_deduped() {
        let base = temp_dir("dkmslist");
        fs::create_dir_all(base.join("nvidia/550.1")).unwrap();
        fs::create_dir_all(base.join("nvidia/535.2")).unwrap();
        fs::create_dir_all(base.join("vbox/7.0")).unwrap();
        fs::create_dir_all(base.join("nvidia")).unwrap(); // 只有 name，无 version
        fs::write(base.join("stray"), b"x").unwrap(); // 非目录忽略

        let packages = dkms_packages_in(&base);
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
        assert!(dkms_packages_in(&base.join("missing")).is_empty());
        let _ = fs::remove_dir_all(&base);
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
