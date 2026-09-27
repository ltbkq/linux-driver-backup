//! Restore pipeline: archive verification → guarded extraction → depmod → restorecon → initramfs.
//! 还原流水线：归档校验 → 具路径穿越防护的流式解压 → depmod → restorecon → initramfs。
//!
//! 本模块只依赖两份冻结契约：`crate::model`（DESIGN.md §5.1）与 `crate::distro`（DESIGN.md §5.2）。
//! 归档格式见 DESIGN.md §4.3：`tar.gz` = 顶层 `manifest.json` + `data/**`（去掉前导 `/` 的相对路径）。
//! 权限模型见 DESIGN.md §4.5：还原写盘需要 root，未获 root 时返回 `AppError::Privilege`，
//! 由 `main` 决定是否经 `privilege::run_helper_via_pkexec` 重入。
//!
//! Depends only on the frozen contracts `crate::model` (§5.1) and `crate::distro` (§5.2).

use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;

use crate::distro::{self, Family, SystemCmd};
use crate::model::{
    human_size, is_safe_kernel_version, AppError, AppResult, EntryKind, Manifest, ProgressFn,
};

/// 归档根目录：`data/` 之后的相对路径全部拼接到该目录之下（即解压到 `/`）。
const TARGET_ROOT: &str = "/";
/// 同名文件被覆盖前的备份后缀：`<path>.ldbak`。
const BACKUP_SUFFIX: &str = ".ldbak";
/// 还原出来的普通文件统一写成 0644（DESIGN.md §4.5 安全约束）。
const FILE_MODE: u32 = 0o644;
/// 外部命令失败时回显到错误信息里的 stderr 末尾行数。
const STDERR_TAIL_LINES: usize = 20;
/// notes 中逐条列出的链接/特殊条目上限，避免归档异常时撑爆日志。
const MAX_ITEM_NOTES: usize = 20;
/// 解压时的拷贝缓冲区大小（每块都检查一次 cancel）。
const COPY_BUF: usize = 64 * 1024;
/// 进度回调的最小推进幅度与最小间隔（节流）。
const PROGRESS_DELTA: f32 = 0.01;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);
/// 写盘阶段进度映射到 0.0..0.8，剩余 0.2 留给 depmod/initramfs。
const WRITE_PROGRESS_END: f32 = 0.8;

// ---------------------------------------------------------------------------
// 公开类型 / Public types
// ---------------------------------------------------------------------------

/// Read-only archive summary: the parsed manifest plus the uncompressed size of `data/`.
/// 归档只读摘要：解析出的顶层 `manifest.json` 与 `data/` 下条目的未压缩字节总和。
#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    /// 顶层 `manifest.json` 反序列化结果。
    pub manifest: Manifest,
    /// `data/` 下条目（链接条目除外）的未压缩字节总和。
    pub total_bytes: u64,
}

/// Everything [`run_restore`] needs: archive path, target kernel, flags and callbacks.
/// 还原请求：归档路径、目标内核、开关与回调（DESIGN.md §5.5）。
///
/// 注意：`progress` 是 `Arc<dyn Fn…>`，不实现 `Debug`，故本结构只 derive `Clone`。
#[derive(Clone)]
pub struct RestoreRequest {
    /// 待还原的 `.tar.gz` 归档。
    pub archive: PathBuf,
    /// 目标内核版本；`None` 表示使用 `manifest.kernel_release`。
    pub kver: Option<String>,
    /// 预演模式：只统计不落盘，也不执行 depmod/initramfs。
    pub dry_run: bool,
    /// 用户已确认"备份内核/架构与当前不符"时为 true。
    pub allow_kernel_mismatch: bool,
    /// 是否还原 `EntryKind::Firmware` 条目（默认关闭）。
    pub with_firmware: bool,
    /// 进度回调：写盘阶段映射到 0.0..0.8，流程结束时 1.0。
    pub progress: ProgressFn,
    /// 取消标志：置位后尽快返回 [`AppError::Cancelled`]。
    pub cancel: Arc<AtomicBool>,
}

/// Outcome of a restore run (dry-run included).
/// 还原结果（dry-run 同样返回该结构）。
#[derive(Debug, Clone, Default)]
pub struct RestoreReport {
    /// 本次是否只是预演（未写盘）。
    pub dry_run: bool,
    /// 实际写入的普通文件数（dry-run 恒为 0）。
    pub written: usize,
    /// 跳过的条目数（链接 / 特殊文件 / 未开启的固件；dry-run 恒为 0）。
    pub skipped: usize,
    /// `depmod -a <kver>` 是否成功执行（失败即返回错误，故为 true 时必然成功）。
    pub depmod_done: bool,
    /// initramfs 更新结果：`None` = 未知发行版跳过，`Some(false)` = 命令缺失或执行失败。
    pub initramfs_done: Option<bool>,
    /// 人类可读的过程说明（跳过项、非致命失败、提示等）。
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// 路径安全 / Path safety
// ---------------------------------------------------------------------------

/// Normalize an archive-relative path and reject anything that could escape the target root.
/// 逐层 normalize 归档内相对路径，拒绝绝对路径、空路径与任何 `..` 分量；非法时返回 `None`。
///
/// 这是路径穿越防护的核心纯函数（可单测）：`a/./b//c` → `a/b/c`，`a/../b` → `None`。
fn safe_rel_path(p: &str) -> Option<PathBuf> {
    if p.is_empty() || p.starts_with('/') {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return None,
            other => out.push(other),
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    // 二次保险：normalize 之后的结果必须仍是相对路径且不含 `..`。
    let s = out.to_str()?;
    if s.starts_with('/') || s.split('/').any(|c| c == "..") {
        return None;
    }
    Some(out)
}

/// Build the canonical "illegal path" error message.
/// 构造"非法归档路径"的统一错误（绝对路径或越界 `..`）。
fn illegal_path(raw: &str) -> AppError {
    AppError::Format(format!(
        "归档内含非法路径（绝对路径或越界 ..），已拒绝越界写入：{}",
        raw
    ))
}

/// Split an archive path into its `data/` payload part.
/// 拆出归档路径中 `data/` 之后的负载路径：非 `data/` 条目返回 `Ok(None)`，路径非法返回 `Err(Format)`。
///
/// 返回值保证是干净的相对路径（再次经过 `safe_rel_path`），调用方可以安全地拼到 `/` 之下。
fn data_payload(raw: &str) -> AppResult<Option<PathBuf>> {
    let rel = match safe_rel_path(raw) {
        Some(r) => r,
        None => return Err(illegal_path(raw)),
    };
    let s = rel.to_string_lossy();
    let rest = match s.strip_prefix("data/") {
        Some(r) if !r.is_empty() => r,
        // `manifest.json`、`data` 目录本身等非负载条目
        _ => return Ok(None),
    };
    match safe_rel_path(rest) {
        Some(inner) => Ok(Some(inner)),
        None => Err(illegal_path(raw)),
    }
}

/// Decide what to do with a single archive entry (pure, unit-testable).
/// 判定单个归档条目的处置方式（纯函数，dry-run 与真实解压共用）：
/// 链接一律跳过；固件按 `with_firmware` 决定；目录建目录；其它特殊文件跳过。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    Write,
    MakeDir,
    SkipLink,
    SkipSpecial,
    SkipFirmware,
}

fn plan_entry(
    is_file: bool,
    is_dir: bool,
    is_link: bool,
    is_firmware: bool,
    with_firmware: bool,
) -> EntryAction {
    if is_link {
        return EntryAction::SkipLink;
    }
    if is_file {
        return if is_firmware && !with_firmware {
            EntryAction::SkipFirmware
        } else {
            EntryAction::Write
        };
    }
    if is_dir {
        EntryAction::MakeDir
    } else {
        EntryAction::SkipSpecial
    }
}

/// Heuristic firmware detection for entries missing from the manifest.
/// manifest 中没有该条目时的固件路径判定（兜底）。
fn looks_like_firmware(rel: &str) -> bool {
    rel == "lib/firmware"
        || rel.starts_with("lib/firmware/")
        || rel == "usr/lib/firmware"
        || rel.starts_with("usr/lib/firmware/")
}

/// Classify one payload path as firmware (manifest first, path heuristic second).
/// 判定负载路径是否为固件：优先查 manifest 的 `EntryKind`，缺失时按路径兜底。
fn is_firmware(kinds: &HashMap<String, EntryKind>, rel: &Path) -> bool {
    let key = rel.to_string_lossy();
    if let Some(k) = kinds.get(key.as_ref()) {
        return *k == EntryKind::Firmware;
    }
    looks_like_firmware(&key)
}

// ---------------------------------------------------------------------------
// 归档读取 / Archive reading
// ---------------------------------------------------------------------------

/// Open a `.tar.gz` for streaming, read-only access.
/// 只读打开 `.tar.gz`，返回可流式遍历的 tar 归档。
fn open_archive(archive: &Path) -> AppResult<tar::Archive<GzDecoder<fs::File>>> {
    let file = fs::File::open(archive)?;
    Ok(tar::Archive::new(GzDecoder::new(file)))
}

/// Read one entry's path as an owned string.
/// 读取条目路径并转为自有字符串（tar 内部的长文件名扩展等由 tar 自行处理）。
fn entry_path(entry: &tar::Entry<'_, GzDecoder<fs::File>>) -> AppResult<String> {
    let p = entry
        .path()
        .map_err(|e| AppError::Format(format!("归档条目路径无效：{}", e)))?;
    Ok(p.to_string_lossy().into_owned())
}

/// Inspect a backup archive without writing anything.
/// 只读解析归档：解出顶层 `manifest.json` 并统计 `data/` 的未压缩总字节，全程不写盘。
///
/// 失败时返回 [`AppError::Format`]：缺少 `manifest.json`、JSON 解析失败、
/// 或任意条目路径含绝对路径 / `..` 越界（中文错误说明）。
pub fn inspect(archive: &Path) -> AppResult<ArchiveInfo> {
    let mut arch = open_archive(archive)?;
    let entries = arch.entries().map_err(|e| {
        AppError::Format(format!(
            "无法读取归档（不是有效的 gzip/tar 或已损坏）：{}",
            e
        ))
    })?;

    // 备份流水线把 manifest 追加在归档末尾，因此必须遍历完整个归档再取。
    let mut manifest_json: Option<String> = None;
    let mut total_bytes: u64 = 0;

    for entry in entries {
        let mut entry = entry.map_err(|e| AppError::Format(format!("归档条目损坏：{}", e)))?;
        let et = entry.header().entry_type();
        let raw = entry_path(&entry)?;

        // 先做统一的路径合法性校验（含 `manifest.json` 自身）。
        let rel = safe_rel_path(&raw).ok_or_else(|| illegal_path(&raw))?;

        if rel == Path::new("manifest.json")
            && manifest_json.is_none()
            && !et.is_symlink()
            && !et.is_hard_link()
        {
            let mut buf = String::new();
            entry.read_to_string(&mut buf).map_err(|e| {
                AppError::Format(format!("manifest.json 读取失败：{}", e))
            })?;
            manifest_json = Some(buf);
            continue;
        }

        if let Some(_inner) = data_payload(&raw)? {
            if !et.is_symlink() && !et.is_hard_link() {
                total_bytes = total_bytes.saturating_add(entry.size());
            }
        }
    }

    let json = manifest_json
        .ok_or_else(|| AppError::Format("归档缺少顶层 manifest.json，无法还原".to_string()))?;
    let manifest: Manifest = serde_json::from_str(&json)
        .map_err(|e| AppError::Format(format!("manifest.json 解析失败：{}", e)))?;

    Ok(ArchiveInfo {
        manifest,
        total_bytes,
    })
}

// ---------------------------------------------------------------------------
// 写盘辅助 / Write helpers
// ---------------------------------------------------------------------------

/// `<path>` → `<path>.ldbak`
/// 生成同名备份路径 `<path>.ldbak`（直接追加后缀，不动扩展名）。
fn backup_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

/// Remove a file, symlink or directory (used to overwrite an existing `.ldbak`).
/// 删除文件 / 符号链接 / 目录（用于覆盖已存在的 `.ldbak`）。
fn remove_any(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Move an existing target out of the way to `<path>.ldbak` before writing.
/// 写入前把同名目标备份为 `<path>.ldbak`；若 `.ldbak` 已存在则覆盖它。
/// 用 `symlink_metadata` 判断，避免同名符号链接被误当作"不存在"而被穿写。
fn backup_existing(target: &Path) -> AppResult<()> {
    if fs::symlink_metadata(target).is_err() {
        return Ok(()); // 不存在，无需备份
    }
    let bak = backup_path(target);
    remove_any(&bak)?;
    fs::rename(target, &bak)?;
    Ok(())
}

/// Copy `src` → `dst` in chunks, honouring the cancel flag; returns bytes copied.
/// 分块拷贝并逐块检查取消标志，任一块之间取消都会立即返回 `AppError::Cancelled`。
fn copy_with_cancel<R: Read, W: Write>(src: &mut R, dst: &mut W, cancel: &AtomicBool) -> AppResult<u64> {
    let mut buf = [0u8; COPY_BUF];
    let mut written: u64 = 0;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(AppError::Cancelled);
        }
        let n = src.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n])?;
        written += n as u64;
    }
    dst.flush()?;
    Ok(written)
}

/// Extract all payload files under `data/` into `/`.
/// 把 `data/` 下的负载条目流式解压到 `/`，返回 `(written, skipped, notes)`。
///
/// 安全策略：每条路径先经 [`data_payload`]（逐层 normalize，拒绝 `..` / 绝对路径）；
/// 符号链接与硬链接条目一律跳过并记入 notes；普通文件统一 0644；
/// 同名文件先备份为 `<path>.ldbak`。
fn extract(req: &RestoreRequest, kinds: &HashMap<String, EntryKind>) -> AppResult<RestoreReport> {
    let mut report = RestoreReport {
        dry_run: false,
        ..Default::default()
    };

    let mut arch = open_archive(&req.archive)?;
    let entries = arch.entries()?;

    // 进度节流状态：0.0..0.8 按"已处理条目 / manifest 条目总数"映射。
    let total = kinds.len().max(1);
    let mut processed = 0usize;
    let mut item_notes = 0usize;
    let mut link_skips = 0usize;
    let mut special_skips = 0usize;
    let mut fw_skips = 0usize;
    let mut last_p = 0f32;
    let mut last_at = Instant::now();

    (req.progress)(0.0, format!("开始还原 {} 个条目到 {}", total, TARGET_ROOT));

    for entry in entries {
        if req.cancel.load(Ordering::Relaxed) {
            return Err(AppError::Cancelled);
        }
        let mut entry = entry?;
        let raw = entry_path(&entry)?;

        let inner = match data_payload(&raw)? {
            Some(i) => i,
            None => continue, // 非 data/ 条目（如 manifest.json）
        };

        let et = entry.header().entry_type();
        let action = plan_entry(
            et.is_file(),
            et.is_dir(),
            et.is_symlink() || et.is_hard_link(),
            is_firmware(kinds, &inner),
            req.with_firmware,
        );

        match action {
            EntryAction::SkipLink => {
                report.skipped += 1;
                link_skips += 1;
                if item_notes < MAX_ITEM_NOTES {
                    item_notes += 1;
                    report.notes.push(format!(
                        "跳过链接条目（不还原符号链接/硬链接）：/{}",
                        inner.display()
                    ));
                }
            }
            EntryAction::SkipSpecial => {
                report.skipped += 1;
                special_skips += 1;
                if item_notes < MAX_ITEM_NOTES {
                    item_notes += 1;
                    report
                        .notes
                        .push(format!("跳过特殊条目（非普通文件）：/{}", inner.display()));
                }
            }
            EntryAction::SkipFirmware => {
                report.skipped += 1;
                fw_skips += 1;
            }
            EntryAction::MakeDir => {
                let dir = Path::new(TARGET_ROOT).join(&inner);
                fs::create_dir_all(&dir)?;
            }
            EntryAction::Write => {
                let target = Path::new(TARGET_ROOT).join(&inner);
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                backup_existing(&target)?;

                let mut out = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .mode(FILE_MODE)
                    .open(&target)?;
                copy_with_cancel(&mut entry, &mut out, &req.cancel)?;
                // 不依赖 umask，强制 0644。
                out.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;

                report.written += 1;
                processed += 1;

                let p = (WRITE_PROGRESS_END * processed as f32 / total as f32)
                    .min(WRITE_PROGRESS_END);
                if p >= last_p + PROGRESS_DELTA && last_at.elapsed() >= PROGRESS_INTERVAL {
                    last_p = p;
                    last_at = Instant::now();
                    (req.progress)(
                        p,
                        format!("已写入 {}/{} 个文件", processed, total),
                    );
                }
            }
        }
    }

    if fw_skips > 0 {
        report.notes.push(format!(
            "已跳过 {} 个固件条目（未开启 --with-firmware）",
            fw_skips
        ));
    }
    let unlisted = (link_skips + special_skips).saturating_sub(item_notes);
    if unlisted > 0 {
        report.notes.push(format!(
            "另有 {} 个链接/特殊条目未逐条列出",
            unlisted
        ));
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// 外部命令 / External commands
// ---------------------------------------------------------------------------

/// Keep only the last [`STDERR_TAIL_LINES`] lines of captured stderr.
/// 只保留 stderr 末尾若干行，避免错误信息过长。
fn tail_lines(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let lines: Vec<&str> = s.lines().collect();
    let start = lines.len().saturating_sub(STDERR_TAIL_LINES);
    lines[start..].join("\n").trim().to_string()
}

/// Run an external command, capturing stdout/stderr/status.
/// 执行外部命令并捕获 stdout/stderr/status；任何失败都构造 [`AppError::Command`]。
///
/// 本模块允许调用的外部命令仅限：depmod / restorecon / dracut / update-initramfs / mkinitcpio。
fn run_command(cmd: &SystemCmd) -> AppResult<String> {
    let output = Command::new(&cmd.program)
        .args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| AppError::Command {
            program: cmd.program.clone(),
            status: -1,
            stderr: format!("无法启动命令：{}", e),
        })?;

    if !output.status.success() {
        return Err(AppError::Command {
            program: cmd.program.clone(),
            status: output.status.code().unwrap_or(-1),
            stderr: tail_lines(&output.stderr),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// 还原主流程 / Restore entry point
// ---------------------------------------------------------------------------

/// Run a full restore, strictly following the seven steps below.
/// 执行还原，严格按以下 7 步（顺序不可调整，DESIGN.md §5.5）：
///
/// 1. `inspect` 取 manifest；目标 kver = `req.kver` 或 `manifest.kernel_release`，
///    必须通过 `model::is_safe_kernel_version`，否则 `AppError::Validation`。
/// 2. 校验 `manifest.arch == distro::arch()` 与 `manifest.kernel_release == 目标 kver`；
///    任一不符且未设置 `allow_kernel_mismatch` → `AppError::Validation`
///    （消息说明"备份内核/架构与当前不符，需用户确认"）。
/// 3. 需要写盘（非 dry_run）且 `distro::is_root()` 为 false → `AppError::Privilege`
///    （消息：需要 root，将通过 pkexec 提权），交由 `main` 决定重入；
///    dry_run 不需要 root，直接进入第 4 步且不写盘。
/// 4. dry_run：只遍历统计将写入的文件数与字节数并写入 notes，
///    `written=0`、`skipped=0`，跳到第 6 步返回（不做 depmod/initramfs）。
/// 5. 真实还原：流式解压 `data/` 到 `/`——逐层 normalize，拒绝 `..`、拒绝绝对路径、
///    拒绝符号链接/硬链接条目（跳过并计入 notes）；父目录 `create_dir_all`；
///    文件 mode 0o644；同名先备份为 `<path>.ldbak`（已存在 `.ldbak` 则覆盖）；
///    跳过 `with_firmware=false` 的 `EntryKind::Firmware`；
///    进度按已处理条目/总条目映射 0.0..0.8 并节流回调；cancel 置位 → `AppError::Cancelled`。
/// 6. 写盘成功后（非 dry_run 且已确认 root）：先执行 `distro::depmod_cmd(target_kver)`，
///    成功 → `depmod_done=true`，失败 → 记入 notes 且返回 `AppError::Command`
///    （不做 depmod 等于还原无效，DESIGN.md 核查 #10）；随后 RHEL 系且存在 `restorecon` 时
///    对 `/lib/modules/<kver>` 执行 `restorecon -R`（失败只记 notes，不致命）；
///    最后按 `distro::initramfs_cmd(family, kver)` 更新 initramfs：
///    命令缺失或失败 → `initramfs_done=Some(false)` + notes；
///    `family == Unknown` → `initramfs_done=None` + note"未知发行版，跳过 initramfs"。
/// 7. 所有外部命令均用 `std::process::Command` 捕获 stdout/stderr/status，
///    失败构造 `AppError::Command`。
pub fn run_restore(req: RestoreRequest) -> AppResult<RestoreReport> {
    let mut report = RestoreReport {
        dry_run: req.dry_run,
        ..Default::default()
    };

    // ---- 步骤 1：解析 manifest、确定目标内核并做安全校验 ----
    let info = inspect(&req.archive)?;
    let manifest = info.manifest;
    let target_kver = req
        .kver
        .clone()
        .unwrap_or_else(|| manifest.kernel_release.clone());

    if !is_safe_kernel_version(&target_kver) {
        return Err(AppError::Validation(format!(
            "内核版本串不满足 ^[0-9A-Za-z][0-9A-Za-z._+-]*$（或长度 >128），拒绝进入任何命令行参数：{}",
            target_kver
        )));
    }

    // ---- 步骤 2：架构 / 内核一致性 ----
    let cur_arch = distro::arch();
    let mut mismatches: Vec<String> = Vec::new();
    if manifest.arch.as_str() != cur_arch {
        mismatches.push(format!(
            "架构 备份 {} / 当前 {}",
            manifest.arch, cur_arch
        ));
    }
    if manifest.kernel_release != target_kver {
        mismatches.push(format!(
            "内核 备份 {} / 目标 {}",
            manifest.kernel_release, target_kver
        ));
    }
    if !mismatches.is_empty() {
        if req.allow_kernel_mismatch {
            report.notes.push(format!(
                "已由用户确认的不一致：{}；跨内核还原可能导致模块 ABI 不兼容",
                mismatches.join("；")
            ));
        } else {
            return Err(AppError::Validation(format!(
                "备份内核/架构与当前不符，需用户确认：{}（确认后重试并设置 allow_kernel_mismatch）",
                mismatches.join("；")
            )));
        }
    }

    // ---- 步骤 3：权限（dry_run 不需要 root）----
    if !req.dry_run && !distro::is_root() {
        return Err(AppError::Privilege(
            "还原需要 root 权限，将通过 pkexec 提权".to_string(),
        ));
    }

    // manifest 条目 → 类型表（用于固件判定与进度分母）
    let kinds: HashMap<String, EntryKind> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            safe_rel_path(&e.path).map(|p| (p.to_string_lossy().into_owned(), e.kind))
        })
        .collect();

    // ---- 步骤 4：dry-run 只统计不落盘 ----
    if req.dry_run {
        let mut files = 0usize;
        let mut bytes = 0u64;
        let mut fw_skips = 0usize;
        let mut link_skips = 0usize;

        let mut arch = open_archive(&req.archive)?;
        for entry in arch.entries()? {
            if req.cancel.load(Ordering::Relaxed) {
                return Err(AppError::Cancelled);
            }
            let entry = entry?;
            let raw = entry_path(&entry)?;
            let inner = match data_payload(&raw)? {
                Some(i) => i,
                None => continue,
            };
            let et = entry.header().entry_type();
            match plan_entry(
                et.is_file(),
                et.is_dir(),
                et.is_symlink() || et.is_hard_link(),
                is_firmware(&kinds, &inner),
                req.with_firmware,
            ) {
                EntryAction::Write => {
                    files += 1;
                    bytes = bytes.saturating_add(entry.size());
                }
                EntryAction::SkipFirmware => fw_skips += 1,
                EntryAction::SkipLink => link_skips += 1,
                EntryAction::SkipSpecial | EntryAction::MakeDir => {}
            }
        }

        let mut msg = format!("将写入 {} 个文件（{}），不落盘", files, human_size(bytes));
        if fw_skips > 0 {
            msg.push_str(&format!("；跳过 {} 个固件条目", fw_skips));
        }
        if link_skips > 0 {
            msg.push_str(&format!("；跳过 {} 个链接条目", link_skips));
        }
        report.notes.push(msg.clone());
        // 预演不写盘、不执行 depmod/initramfs，直接报告完成。
        (req.progress)(1.0, msg);
        return Ok(report);
    }

    // ---- 步骤 5：真实还原（此处必然已是 root）----
    let mut extract_report = extract(&req, &kinds)?;
    (req.progress)(
        WRITE_PROGRESS_END,
        format!(
            "文件写入完成：{} 个文件，{} 个跳过，执行 depmod …",
            extract_report.written, extract_report.skipped
        ),
    );
    report.notes.append(&mut extract_report.notes);
    report.written = extract_report.written;
    report.skipped = extract_report.skipped;

    // ---- 步骤 6：depmod → restorecon → initramfs ----
    let family = distro::DistroInfo::detect().family;

    // 6.1 depmod：失败即整体失败（否则新还原的模块不会被识别）。
    let depmod = distro::depmod_cmd(&target_kver);
    match run_command(&depmod) {
        Ok(_) => {
            report.depmod_done = true;
            report.notes.push(format!(
                "已执行：{} {}",
                depmod.program,
                depmod.args.join(" ")
            ));
        }
        Err(e) => {
            let note = format!(
                "depmod 执行失败（{} {}）：新还原的模块不会被识别，本次还原无效",
                depmod.program,
                depmod.args.join(" ")
            );
            report.notes.push(note.clone());
            return Err(match e {
                AppError::Command {
                    program,
                    status,
                    stderr,
                } => AppError::Command {
                    program,
                    status,
                    stderr: format!("{}\n{}", note, stderr),
                },
                other => other,
            });
        }
    }

    // 6.2 RHEL 系补 restorecon（失败只记 notes，不致命）。
    if family == Family::Rhel && distro::has_cmd("restorecon") {
        let target_dir = format!("/lib/modules/{}", target_kver);
        let restorecon = SystemCmd {
            program: "restorecon".to_string(),
            args: vec!["-R".to_string(), target_dir.clone()],
        };
        match run_command(&restorecon) {
            Ok(_) => report
                .notes
                .push(format!("已执行：restorecon -R {}", target_dir)),
            Err(e) => report.notes.push(format!(
                "restorecon -R {} 失败（不致命，SELinux 标签可能不正确）：{}",
                target_dir, e
            )),
        }
    }

    // 6.3 initramfs 更新（未知发行版跳过，不谎报成功）。
    match distro::initramfs_cmd(family, &target_kver) {
        None => {
            report.initramfs_done = None;
            report
                .notes
                .push("未知发行版，跳过 initramfs".to_string());
        }
        Some(cmd) => {
            if !distro::has_cmd(&cmd.program) {
                report.initramfs_done = Some(false);
                report.notes.push(format!(
                    "未找到命令 {}，跳过 initramfs 更新",
                    cmd.program
                ));
            } else {
                match run_command(&cmd) {
                    Ok(_) => {
                        report.initramfs_done = Some(true);
                        report.notes.push(format!(
                            "已执行：{} {}",
                            cmd.program,
                            cmd.args.join(" ")
                        ));
                    }
                    Err(e) => {
                        report.initramfs_done = Some(false);
                        report.notes.push(format!(
                            "initramfs 更新失败（{} {}）：{}",
                            cmd.program,
                            cmd.args.join(" "),
                            e
                        ));
                    }
                }
            }
        }
    }

    let summary = format!(
        "还原完成：写入 {} 个文件，跳过 {} 个",
        report.written, report.skipped
    );
    (req.progress)(1.0, summary.clone());
    report.notes.push(summary);
    Ok(report)
}

// ---------------------------------------------------------------------------
// 单元测试 / Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- (a) 路径穿越 / 绝对路径 / 链接拒绝 ----

    #[test]
    fn safe_rel_path_rejects_traversal() {
        assert!(safe_rel_path("../etc/passwd").is_none());
        assert!(safe_rel_path("lib/modules/../../etc/passwd").is_none());
        assert!(safe_rel_path("a/b/../../../c").is_none());
        assert!(safe_rel_path("data/..").is_none());
        assert!(safe_rel_path("data/..//etc").is_none());
    }

    #[test]
    fn safe_rel_path_rejects_absolute_and_empty() {
        assert!(safe_rel_path("/etc/passwd").is_none());
        assert!(safe_rel_path("//etc/passwd").is_none());
        assert!(safe_rel_path("").is_none());
        assert!(safe_rel_path(".").is_none());
        assert!(safe_rel_path("./").is_none());
    }

    #[test]
    fn safe_rel_path_normalizes_and_accepts() {
        assert_eq!(
            safe_rel_path("lib/modules/6.8.0/updates/x.ko"),
            Some(PathBuf::from("lib/modules/6.8.0/updates/x.ko"))
        );
        assert_eq!(
            safe_rel_path("./lib//modules/./x.ko"),
            Some(PathBuf::from("lib/modules/x.ko"))
        );
        // 单个 `..` 出现在中间也被拒绝
        assert!(safe_rel_path("./a/../b").is_none());
    }

    #[test]
    fn data_payload_splits_and_rejects() {
        // 非 data/ 条目 → Ok(None)
        assert_eq!(data_payload("manifest.json").unwrap(), None);
        assert_eq!(data_payload("data").unwrap(), None);
        assert_eq!(data_payload("data/").unwrap(), None);
        // 合法负载
        assert_eq!(
            data_payload("data/lib/modules/x.ko").unwrap(),
            Some(PathBuf::from("lib/modules/x.ko"))
        );
        // 越界 → Err(Format)
        assert!(matches!(
            data_payload("data/../../etc/passwd"),
            Err(AppError::Format(_))
        ));
        assert!(matches!(
            data_payload("data//../etc/passwd"),
            Err(AppError::Format(_))
        ));
        // 绝对路径 → Err(Format)
        assert!(matches!(
            data_payload("/etc/passwd"),
            Err(AppError::Format(_))
        ));
    }

    #[test]
    fn plan_entry_skips_links_special_and_firmware() {
        use EntryAction::*;
        // 符号链接 / 硬链接一律跳过（与固件开关无关）
        assert_eq!(plan_entry(false, false, true, false, false), SkipLink);
        assert_eq!(plan_entry(true, false, true, true, true), SkipLink);
        // 固件：未开启 → 跳过；开启 → 写入
        assert_eq!(plan_entry(true, false, false, true, false), SkipFirmware);
        assert_eq!(plan_entry(true, false, false, true, true), Write);
        assert_eq!(plan_entry(true, false, false, false, false), Write);
        // 目录 → 建目录；fifo/设备等 → 跳过
        assert_eq!(plan_entry(false, true, false, false, false), MakeDir);
        assert_eq!(plan_entry(false, false, false, false, false), SkipSpecial);
    }

    #[test]
    fn firmware_path_heuristic() {
        assert!(looks_like_firmware("lib/firmware/nvidia/a.fw"));
        assert!(looks_like_firmware("usr/lib/firmware/a.fw"));
        assert!(!looks_like_firmware("lib/modules/x.ko"));

        let mut kinds = HashMap::new();
        kinds.insert("etc/modprobe.d/x.conf".to_string(), EntryKind::Config);
        kinds.insert("opt/fw/thing.bin".to_string(), EntryKind::Firmware);
        assert!(is_firmware(
            &kinds,
            Path::new("opt/fw/thing.bin")
        ));
        assert!(!is_firmware(
            &kinds,
            Path::new("etc/modprobe.d/x.conf")
        ));
        // manifest 缺失时按路径兜底
        assert!(is_firmware(
            &kinds,
            Path::new("lib/firmware/x.fw")
        ));
        assert!(!is_firmware(&kinds, Path::new("lib/modules/x.ko")));
    }

    // ---- (b) inspect 对手工构造的 tar.gz ----

    const TEST_MANIFEST: &str = r#"{
  "format_version": 1,
  "tool_version": "0.1.0",
  "created_at": "2026-09-27T12:00:00Z",
  "kernel_release": "6.8.0-45-generic",
  "arch": "x86_64",
  "distro": {
    "id": "linuxmint",
    "version_id": "22.3",
    "pretty_name": "Linux Mint 22.3",
    "family": "debian"
  },
  "mode": "standard",
  "entries": [
    {
      "path": "lib/modules/6.8.0-45-generic/updates/dkms/foo.ko",
      "size": 5,
      "sha256": "abc",
      "kind": "module"
    }
  ],
  "warnings": []
}"#;

    /// Build a small tar.gz in `dir`; `files` are `(archive_path, bytes)`.
    /// 在临时目录里手工构造一个小 tar.gz。
    fn build_archive(dir: &Path, name: &str, files: &[(&str, &[u8])], manifest: Option<&str>) -> PathBuf {
        let path = dir.join(name);
        let file = fs::File::create(&path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        for (name, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, name, *data)
                .unwrap();
        }
        if let Some(json) = manifest {
            let mut header = tar::Header::new_gnu();
            header.set_size(json.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder
                .append_data(&mut header, "manifest.json", json.as_bytes())
                .unwrap();
        }
        builder.finish().unwrap();
        let enc = builder.into_inner().unwrap();
        enc.finish().unwrap();
        path
    }

    fn temp_case(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ldb-restore-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn inspect_reads_manifest_and_total_bytes() {
        let dir = temp_case("inspect-ok");
        let archive = build_archive(
            &dir,
            "a.tar.gz",
            &[
                ("data/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko", b"hello".as_slice()),
                ("data/etc/modprobe.d/nvidia.conf", b"1234567".as_slice()),
            ],
            Some(TEST_MANIFEST),
        );

        let info = inspect(&archive).unwrap();
        assert_eq!(info.manifest.kernel_release, "6.8.0-45-generic");
        assert_eq!(info.manifest.arch, "x86_64");
        assert_eq!(info.manifest.entries.len(), 1);
        assert_eq!(info.total_bytes, 5 + 7);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspect_missing_manifest_is_format_error() {
        let dir = temp_case("inspect-nomanifest");
        let archive = build_archive(
            &dir,
            "b.tar.gz",
            &[("data/lib/modules/x.ko", b"x".as_slice())],
            None,
        );
        match inspect(&archive) {
            Err(AppError::Format(m)) => assert!(m.contains("manifest.json"), "消息={}", m),
            other => panic!("期望 Format 错误，得到 {:?}", other),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspect_broken_manifest_json_is_format_error() {
        let dir = temp_case("inspect-badjson");
        let archive = build_archive(
            &dir,
            "c.tar.gz",
            &[("data/lib/modules/x.ko", b"x".as_slice())],
            Some("{not json"),
        );
        match inspect(&archive) {
            Err(AppError::Format(m)) => assert!(m.contains("解析失败"), "消息={}", m),
            other => panic!("期望 Format 错误，得到 {:?}", other),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    /// 写一个 tar.gz，条目路径直接写进原始 header（tar-rs 的 `set_path` 会拒绝
    /// 越界路径，因此构造恶意归档必须绕过它）。
    fn build_raw_archive(dir: &Path, name: &str, evil_paths: &[&str]) -> PathBuf {
        let path = dir.join(name);
        let file = fs::File::create(&path).unwrap();
        let enc = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        let mut builder = tar::Builder::new(enc);

        for p in evil_paths {
            let mut header = tar::Header::new_gnu();
            header.set_size(4);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            let mut raw = [0u8; 100];
            let bytes = p.as_bytes();
            assert!(bytes.len() < raw.len());
            raw[..bytes.len()].copy_from_slice(bytes);
            header.as_old_mut().name = raw;
            header.set_cksum();
            builder.append(&header, &b"evil"[..]).unwrap();
        }

        let json = TEST_MANIFEST.to_string();
        let mut header = tar::Header::new_gnu();
        header.set_size(json.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", json.as_bytes())
            .unwrap();
        builder.finish().unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        path
    }

    #[test]
    fn inspect_rejects_traversing_paths() {
        let dir = temp_case("inspect-traversal");
        let archive = build_raw_archive(
            &dir,
            "evil.tar.gz",
            &["data/../../etc/passwd", "/etc/shadow"],
        );
        match inspect(&archive) {
            Err(AppError::Format(m)) => {
                assert!(m.contains("非法路径") || m.contains(".."), "消息={}", m)
            }
            other => panic!("期望 Format 错误，得到 {:?}", other),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dry_run_reports_plan_without_touching_disk() {
        let dir = temp_case("dry-run");
        let archive = build_archive(
            &dir,
            "ok.tar.gz",
            &[
                ("data/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko", b"hello".as_slice()),
                ("data/etc/modprobe.d/nvidia.conf", b"1234567".as_slice()),
            ],
            Some(TEST_MANIFEST),
        );

        let progress: ProgressFn = Arc::new(|_v: f32, _m: String| {});
        let req = RestoreRequest {
            archive,
            kver: None,
            dry_run: true,
            allow_kernel_mismatch: false,
            with_firmware: false,
            progress,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let report = run_restore(req).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.written, 0, "dry-run 不得写盘");
        assert_eq!(report.skipped, 0);
        assert!(!report.depmod_done, "dry-run 不做 depmod");
        assert_eq!(report.initramfs_done, None, "dry-run 不做 initramfs");
        assert!(
            report.notes.iter().any(|n| n.contains("将写入 2 个文件")),
            "notes={:?}",
            report.notes
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn backup_suffix_is_plain_append() {
        assert_eq!(
            backup_path(Path::new("/lib/modules/x.ko")),
            PathBuf::from("/lib/modules/x.ko.ldbak")
        );
        assert_eq!(
            backup_path(Path::new("/etc/modprobe.d/nv.conf")),
            PathBuf::from("/etc/modprobe.d/nv.conf.ldbak")
        );
    }

    #[test]
    fn tail_lines_keeps_end_of_output() {
        let out = b"line1\nline2\nline3\n";
        let tail = tail_lines(out);
        assert!(tail.ends_with("line3"));
        assert!(tail.starts_with("line1"));
        assert!(!tail.ends_with('\n'));
    }

    #[test]
    fn write_file_sets_mode_and_backs_up() {
        // 只在 /tmp 下验证写入辅助逻辑（不触碰 /）
        let dir = temp_case("write-helpers");
        let target = dir.join("sub/file.txt");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"old").unwrap();

        backup_existing(&target).unwrap();
        assert!(!target.exists());
        assert_eq!(fs::read(backup_path(&target)).unwrap(), b"old");

        // 第二次写入：.ldbak 已存在 → 覆盖
        fs::write(&target, b"old2").unwrap();
        backup_existing(&target).unwrap();
        assert_eq!(fs::read(backup_path(&target)).unwrap(), b"old2");

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&target)
            .unwrap();
        f.write_all(b"new").unwrap();
        f.set_permissions(fs::Permissions::from_mode(FILE_MODE)).unwrap();
        drop(f);

        use std::os::unix::fs::PermissionsExt as _;
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);

        // cancel 立即生效
        let cancel = AtomicBool::new(true);
        let mut src = &b"abc"[..];
        let mut dst = Vec::new();
        assert!(matches!(
            copy_with_cancel(&mut src, &mut dst, &cancel),
            Err(AppError::Cancelled)
        ));

        let _ = fs::remove_dir_all(&dir);
    }
}
