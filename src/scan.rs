//! 驱动扫描：全树遍历 + in-tree 基线排除 + 三级模式（Minimal/Standard/Full）。
//! Driver scanning: full-tree walk with in-tree baseline exclusion and the three backup modes.
//!
//! 对应 DESIGN.md §4.2 扫描策略，要点：
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
//! 路径约定：[`ScanEntry::rel_path`] 是"去掉前导 `/` 的相对路径"
//! （如 `lib/modules/6.8.0-45-generic/updates/dkms/foo.ko`），归档直接按它落盘（DESIGN.md §4.3）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use walkdir::WalkDir;

use crate::distro::{module_roots, DistroInfo, Family};
use crate::model::{AppError, AppResult, BackupMode, EntryKind, ScanEntry, ScanReport};

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
/// 全树扫描 + in-tree 基线排除；只读系统目录，**不依赖 root**。
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

    Ok(report)
}

/// Scan one `module_root/<kver>` tree, splitting in-tree and out-of-tree modules.
///
/// `kernel/` 子树下的 `.ko*` 计入 `skipped_in_tree` 并跳过；其余 `.ko*` 收录为
/// [`EntryKind::Module`]。目录不存在只记 warning（例如只装了 `/lib/modules` 的系统）。
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
        if !entry_is_file(&entry) {
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
        if entry_is_file(&entry) {
            push_file(entry.path(), kind, report);
        }
    }
    Ok(())
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

/// Sum firmware entry sizes into [`ScanReport::firmware_bytes`] (size hint for the UI).
fn tally_firmware(report: &mut ScanReport) {
    report.firmware_bytes = report
        .entries
        .iter()
        .filter(|e| e.kind == EntryKind::Firmware)
        .map(|e| e.size)
        .sum();
}

/// Append one file entry; unreadable files degrade to a warning, never an error.
fn push_file(abs: &Path, kind: EntryKind, report: &mut ScanReport) {
    match fs::metadata(abs) {
        Ok(meta) => report.entries.push(ScanEntry {
            abs_path: abs.to_path_buf(),
            rel_path: rel_path_of(abs),
            size: meta.len(),
            kind,
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

/// `*.ko` plus compressed variants (`.ko.xz`, `.ko.zst`, `.ko.gz`, …).
fn is_module_file(name: &str) -> bool {
    let mut base = name;
    for suffix in [".xz", ".zst", ".zstd", ".gz", ".bz2", ".lzo", ".lz4"] {
        if let Some(stripped) = base.strip_suffix(suffix) {
            base = stripped;
            break;
        }
    }
    base.ends_with(".ko")
}

/// Regular-file test for a walkdir entry: follows leaf symlinks, never directory symlinks.
///
/// 叶子级符号链接（如指向 `.ko` 的链接）按文件收录；目录符号链接不跟随，
/// 由 walkdir 默认行为保证不会绕出扫描树。
fn entry_is_file(entry: &walkdir::DirEntry) -> bool {
    let file_type = entry.file_type();
    if file_type.is_file() {
        return true;
    }
    if file_type.is_symlink() {
        return fs::metadata(entry.path())
            .map(|m| m.is_file())
            .unwrap_or(false);
    }
    false
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
            "foo.ko.gz",
            "foo.ko.bz2",
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
        report.entries.push(ScanEntry {
            abs_path: PathBuf::from("/lib/firmware/a.bin"),
            rel_path: "lib/firmware/a.bin".to_string(),
            size: 100,
            kind: EntryKind::Firmware,
        });
        report.entries.push(ScanEntry {
            abs_path: PathBuf::from("/lib/firmware/b.bin"),
            rel_path: "lib/firmware/b.bin".to_string(),
            size: 250,
            kind: EntryKind::Firmware,
        });
        report.entries.push(ScanEntry {
            abs_path: PathBuf::from("/lib/modules/x/updates/m.ko"),
            rel_path: "lib/modules/x/updates/m.ko".to_string(),
            size: 7,
            kind: EntryKind::Module,
        });
        tally_firmware(&mut report);
        assert_eq!(report.firmware_bytes, 350);
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
        }
    }
}
