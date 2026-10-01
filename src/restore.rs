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
    human_size, is_safe_kernel_version, AppError, AppResult, DkmsPackage, EntryKind, Manifest,
    ProgressFn, Provenance, RestoreStrategy,
};

/// 归档根目录：`data/` 之后的相对路径全部拼接到该目录之下（即解压到 `/`）。
const TARGET_ROOT: &str = "/";
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
/// 事务日志与回滚区所在目录（相对目标根）。
const STATE_DIR_REL: &str = "var/lib/linux-driver-backup";
/// 逐文件落盘的临时前缀（与目标同目录，保证 `rename` 原子且不跨文件系统）。
const STAGE_PREFIX: &str = ".ldb-staging-";
/// 允许符号链接指向的受管前缀（相对路径形式）：仅模块目录。
/// 配置文件以普通文件条目还原，因此链接目标不需要 `/etc` 权限面。
const MANAGED_PREFIXES: [&str; 2] = ["lib/modules/", "usr/lib/modules/"];
/// 默认保留的回滚代数（`RestoreRequest::keep_rollback` 的默认值）。
/// Default number of rollback generations kept.
pub const DEFAULT_KEEP_ROLLBACK: usize = 3;

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

/// 面对不可变系统时的处置策略。
/// Policy when the target system is immutable (ROADMAP P0-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImmutablePolicy {    /// 默认：拒绝直写，给出受支持的替代路径指引。
    Refuse,
    /// 使用 `rpm-ostree usroverlay` 建立临时可写覆盖层（**重启后失效**）。
    Usroverlay,
}

/// 一次还原的事务日志（用于 `--rollback`）。
/// Journal of one restore run, used by `--rollback`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct RestoreJournal {
    /// 生成时刻（UTC，RFC3339）。
    pub created_at: String,
    /// 目标内核版本。
    pub target_kver: String,
    /// 目标根（通常 `/`）。
    pub root: String,
    /// 本次触及的每个路径的原始状态。
    pub entries: Vec<JournalEntry>,
}

/// 日志中的单条记录：写入前该路径是否存在、原文件被移到哪里。
/// One journal record: whether the path existed before, and where the original went.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct JournalEntry {
    /// 目标根的相对路径。
    pub path: String,
    /// 写入前该路径是否已存在。
    pub prior_existed: bool,
    /// 原文件被移入的回滚区路径（绝对路径；`prior_existed=false` 时为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_path: Option<String>,
    /// 条目类型标签（`module` / `symlink` / `config` …），仅供人读。
    pub kind: String,
}

impl RestoreJournal {
    /// Persist the journal as JSON.
    /// 将日志写入磁盘（父目录自动创建）。
    pub fn save(&self, path: &Path) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }

    /// Load a journal from disk.
    /// 从磁盘读取日志。
    pub fn load(path: &Path) -> AppResult<Self> {
        let text = fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| AppError::Format(format!("回滚日志解析失败：{}", e)))
    }
}

/// Result of a rollback run.
/// 回滚结果。
#[derive(Debug, Clone, Default)]
pub struct RollbackReport {
    /// 被恢复为原文件的路径数。
    pub restored: usize,
    /// 被删除（当初新建）的路径数。
    pub removed: usize,
    /// 过程说明。
    pub notes: Vec<String>,
}

/// Everything [`run_restore`] needs: archive path, target kernel, flags and callbacks.
/// 还原请求：归档路径、目标内核、开关与回调（DESIGN.md §5.5 / ROADMAP §3 P0）。
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
    /// 用户已确认"备份内核与当前不符"时为 true（仅影响内核/vermagic 检查）。
    pub allow_kernel_mismatch: bool,
    /// 用户已确认"备份架构与当前不符"时为 true；与内核检查解耦（ITERATION §2.1 C-32）。
    pub allow_arch_mismatch: bool,
    /// 是否还原 `EntryKind::Firmware` 条目（默认关闭）。
    pub with_firmware: bool,
    /// 目标根：`None` = `/`；`Some(dir)` 用于离线/救援还原（ROADMAP P1-1）。
    pub root: Option<PathBuf>,
    /// 强制还原策略；`None` = 按 manifest 提示自动决策（重建 → 重装 → 弱更新 → 拷贝）。
    pub strategy: Option<crate::model::RestoreStrategy>,
    /// 不可变系统的处置策略。
    pub on_immutable: ImmutablePolicy,
    /// 严格模式：符号链接目标在归档中缺失即视为错误（默认仅提示）。
    pub strict_links: bool,
    /// 跳过 Secure Boot 签名（仅建议在 SB 关闭或另有签名流程时使用）。
    pub no_sign: bool,
    /// 离线模式下是否在目标根内执行 depmod/initramfs（`chroot <root> …`）。
    pub chroot_exec: bool,
    /// 回滚区保留代数。
    pub keep_rollback: usize,
    /// 进度回调：写盘阶段映射到 0.0..0.8，流程结束时 1.0。
    pub progress: ProgressFn,
    /// 取消标志：置位后尽快返回 [`AppError::Cancelled`]。
    pub cancel: Arc<AtomicBool>,
}

impl Default for RestoreRequest {
    /// 合理的默认：写 `/`、自动策略、不可变系统拒绝、联网签名、保留 3 代回滚。
    /// Sensible defaults: write to `/`, auto strategy, refuse immutable, sign, keep 3 rollbacks.
    fn default() -> Self {
        RestoreRequest {
            archive: PathBuf::new(),
            kver: None,
            dry_run: false,
            allow_kernel_mismatch: false,
            allow_arch_mismatch: false,
            with_firmware: false,
            root: None,
            strategy: None,
            on_immutable: ImmutablePolicy::Refuse,
            strict_links: false,
            no_sign: false,
            chroot_exec: false,
            keep_rollback: DEFAULT_KEEP_ROLLBACK,
            progress: Arc::new(|_, _| {}),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}

/// Outcome of a restore run (dry-run included).
/// 还原结果（dry-run 同样返回该结构）。
#[derive(Debug, Clone, Default)]
pub struct RestoreReport {
    /// 本次是否只是预演（未写盘）。
    pub dry_run: bool,
    /// 实际写入的普通文件数（dry-run 恒为 0）。
    pub written: usize,
    /// 实际创建的符号链接数（dry-run 恒为 0）。
    pub links_written: usize,
    /// 跳过的条目数（硬链接/特殊文件/未开启的固件；dry-run 恒为 0）。
    pub skipped: usize,
    /// 由 DKMS/akmods **重建**的包数。
    pub rebuilt: usize,
    /// 由包管理器**重装**的包数。
    pub reinstalled: usize,
    /// 签名成功的模块数。
    pub signed: usize,
    /// 仍处于未签名状态的模块数（SB 开启时非零即为隐患）。
    pub unsigned_left: usize,
    /// `depmod -a <kver>` 是否成功执行。
    pub depmod_done: bool,
    /// initramfs 更新结果：`None` = 未执行（未知发行版或离线模式），`Some(false)` = 失败。
    pub initramfs_done: Option<bool>,
    /// 本次事务日志路径（供 `--rollback` 使用；dry-run 为 `None`）。
    pub rollback_journal: Option<PathBuf>,
    /// 各策略实际处理条目数（策略中文标签 → 数量）。
    pub strategy_counts: Vec<(String, usize)>,
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
/// 符号链接按受管根校验后还原（v2）；硬链接跳过；固件按 `with_firmware` 决定；
/// 目录建目录；其它特殊文件跳过。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryAction {
    Write,
    WriteSymlink,
    MakeDir,
    SkipLink,
    SkipSpecial,
    SkipFirmware,
}

fn plan_entry(
    is_file: bool,
    is_dir: bool,
    is_symlink: bool,
    is_hard_link: bool,
    is_firmware: bool,
    with_firmware: bool,
) -> EntryAction {
    // 硬链接仍跳过：内核模块目录里几乎没有硬链接，且跨设备还原语义不安全。
    if is_hard_link {
        return EntryAction::SkipLink;
    }
    if is_symlink {
        return EntryAction::WriteSymlink;
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

/// Join a symlink's target onto its own directory and normalize the result.
/// 把符号链接目标按 POSIX 语义拼到链接所在目录并逐层 normalize；越出根或不可归一化时返回 `None`。
///
/// 例：`("lib/modules/6.8/weak-updates/a.ko", "../../6.6/extra/a.ko")`
/// → `Some("lib/modules/6.6/extra/a.ko")`。
/// Pure helper shared by validation and tests.
fn normalize_join(link_rel: &str, target: &str) -> Option<PathBuf> {
    if target.is_empty() || target.starts_with('/') {
        return None;
    }
    let mut stack: Vec<String> = Vec::new();
    let parent = match link_rel.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => String::new(),
    };
    for part in parent.split('/').chain(target.split('/')) {
        match part {
            "" | "." => continue,
            ".." => {
                // 越出根：直接判定为非法（不允许链接逃逸受管前缀之上）。
                stack.pop()?;
            }
            other => stack.push(other.to_string()),
        }
    }
    if stack.is_empty() {
        return None;
    }
    Some(PathBuf::from(stack.join("/")))
}

/// Whether a normalized relative path stays inside the managed prefixes.
/// 归一化后的相对路径是否仍落在受管前缀（`lib/modules/`、`usr/lib/modules/`、`etc/`）之内。
fn is_managed_rel(rel: &Path) -> bool {
    let s = rel.to_string_lossy();
    MANAGED_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// Validate a symlink entry (pure, unit-testable).
/// 校验符号链接条目：目标必须是相对路径，归一化后仍落在受管前缀内；返回归一化后的相对路径。
///
/// RHEL/SUSE 的 `weak-updates/<m>.ko -> ../../<kver>/extra/<m>.ko` 是**合法**形态
/// （归一化后仍在 `lib/modules/` 之下），必须放行；而 `../../etc/shadow` 之类一律拒绝。
enum LinkPlan {
    /// 按原样重建（`/etc` 下的配置别名，可含绝对目标）。
    Verbatim,
    /// 归一化后落在模块目录内的模块链接（如 weak-updates）。
    Normalized(PathBuf),
}

fn validate_link_target(link_rel: &str, target: &str) -> AppResult<LinkPlan> {
    if link_rel.starts_with("etc/") {
        // 系统配置别名允许绝对目标（见 backup.rs 同名函数注释）。
        if target.trim().is_empty() {
            return Err(AppError::Format(format!("符号链接目标为空：{}", link_rel)));
        }
        return Ok(LinkPlan::Verbatim);
    }
    if target.starts_with('/') {
        return Err(AppError::Format(format!(
            "模块目录下的符号链接不得使用绝对目标，拒绝还原：{} -> {}",
            link_rel, target
        )));
    }
    let normalized = normalize_join(link_rel, target).ok_or_else(|| {
        AppError::Format(format!(
            "符号链接目标越出受管范围，拒绝还原：{} -> {}",
            link_rel, target
        ))
    })?;
    if !is_managed_rel(&normalized) {
        return Err(AppError::Format(format!(
            "符号链接指向受管前缀之外，拒绝还原：{} -> {}（归一化：{}）",
            link_rel,
            target,
            normalized.display()
        )));
    }
    Ok(LinkPlan::Normalized(normalized))
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

/// Remove a file, symlink or directory, ignoring "not found".
/// 删除文件 / 符号链接 / 目录；目标不存在时视为成功（幂等删除）。
fn remove_any(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.is_dir() {
                fs::remove_dir_all(path)
            } else {
                fs::remove_file(path)
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

/// Resolve the effective target root (`req.root` or `/`).
/// 解析实际目标根：`req.root` 为 `None` 时返回 `/`。
fn target_root(req: &RestoreRequest) -> PathBuf {
    req.root.clone().unwrap_or_else(|| PathBuf::from(TARGET_ROOT))
}

/// A stable, sortable run id (UTC epoch seconds) used for journal/rollback naming.
/// 生成稳定的运行编号（UTC 秒级时间戳），用于日志与回滚区命名。
fn run_id() -> String {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .to_string()
}

/// Directory holding journals and rollback payloads under a given root.
/// 目标根下的事务状态目录（日志 + 回滚区）。
fn state_dir(root: &Path) -> PathBuf {
    root.join(STATE_DIR_REL)
}

/// Flatten an archive-relative path into a rollback file name (no directory nesting).
/// 把相对路径压平成回滚区内的文件名，避免在回滚区重建整棵目录树。
fn rollback_file_name(rel: &str) -> String {
    rel.replace('/', "__")
}

/// Move an existing target into the rollback area, returning the recorded path.
/// 把已存在的目标移入回滚区；返回记录用的绝对路径（目标不存在时返回 `None`）。
fn move_aside(target: &Path, rollback_dir: &Path, rel: &str) -> AppResult<Option<String>> {
    if fs::symlink_metadata(target).is_err() {
        return Ok(None);
    }
    fs::create_dir_all(rollback_dir)?;
    let dest = rollback_dir.join(rollback_file_name(rel));
    remove_any(&dest)?;
    fs::rename(target, &dest)?;
    Ok(Some(dest.to_string_lossy().into_owned()))
}

/// Find the DKMS package a module path belongs to (used by the rebuild strategy).
/// 找出模块路径对应的 DKMS 包（供"重建优先"策略使用）。
fn dkms_for_module<'a>(rel: &str, dkms: &'a [DkmsPackage]) -> Option<&'a DkmsPackage> {
    let file = rel.rsplit('/').next().unwrap_or(rel);
    let stem = file
        .split_once(".ko")
        .map(|(head, _)| head)
        .unwrap_or(file);
    let in_dkms_dir = rel.contains("/dkms/");
    for pkg in dkms {
        let matches_name = stem == pkg.name
            || stem.starts_with(&format!("{}-", pkg.name))
            || stem.starts_with(&format!("{}_", pkg.name))
            || stem.contains(&format!("_{}", pkg.name));
        if matches_name && (in_dkms_dir || stem == pkg.name) {
            return Some(pkg);
        }
        // DKMS 源码目录里的模块也按包名匹配（RHEL 的 extra/<name>/）
        if matches_name && rel.contains(&format!("/{}/", pkg.name)) {
            return Some(pkg);
        }
    }
    None
}

/// Decide the restore strategy for one manifest entry.
/// 为单个 manifest 条目决策还原策略：重建 → 重装 → 弱更新 → 拷贝。
fn decide_strategy(
    entry: &crate::model::ManifestEntry,
    manifest: &Manifest,
    family: Family,
    forced: Option<RestoreStrategy>,
    offline: bool,
) -> RestoreStrategy {
    if entry.kind != EntryKind::Module {
        return RestoreStrategy::Copy;
    }
    // 离线还原（`--root <dir>`）时，重建/重装/弱更新都会作用于**宿主**而不是目标根，
    // 因此一律降级为拷贝（由调用方提示用户）。
    if offline {
        return RestoreStrategy::Copy;
    }
    if let Some(forced) = forced {
        return forced;
    }
    if let Some(hint) = entry.strategy_hint {
        // 提示为重建/弱更新时仍需运行时条件支持，交给执行阶段降级。
        return hint;
    }
    if dkms_for_module(&entry.path, &manifest.dkms).is_some() {
        return RestoreStrategy::Rebuild;
    }
    if entry.owner.is_some() {
        return RestoreStrategy::Reinstall;
    }
    if family == Family::Rhel {
        return RestoreStrategy::WeakModules;
    }
    RestoreStrategy::Copy
}

/// Intermediate result of the transactional extraction.
/// 事务化解压的中间结果，供后续"重建/重装/弱更新/签名"步骤使用。
#[derive(Debug, Default)]
struct ExtractOutcome {
    written: usize,
    links_written: usize,
    skipped: usize,
    rebuilt: Vec<DkmsPackage>,
    reinstall: Vec<Provenance>,
    /// 已写入、建议纳入 weak-updates 的模块（绝对路径）。
    weak_modules: Vec<String>,
    /// 已写入且未签名、需要签名的模块绝对路径。
    unsigned_modules: Vec<PathBuf>,
    /// `content_stored=false` 但目标缺失的条目（提示重装提供者包）。
    missing_package_files: Vec<(String, Option<Provenance>)>,
    /// 过程说明（合并进 `RestoreReport.notes`）。
    notes: Vec<String>,
    /// 各策略处理的条目数。
    strategy_counts: Vec<(String, usize)>,
    journal_path: PathBuf,
    journal: RestoreJournal,
}

/// Extract all payload entries under `data/` into the target root, transactionally.
/// 把 `data/` 下的负载条目**事务化**解压到目标根，返回 [`ExtractOutcome`]。
///
/// 安全与正确性策略（DESIGN.md §4.5 + ROADMAP §3 P0-1/P0-4/P0-5/P0-6）：
/// - 每条路径先经 [`data_payload`]（逐层 normalize，拒绝 `..` / 绝对路径）；
/// - 符号链接经 [`validate_link_target`] 校验后按链接语义创建（weak-updates 可还原）；
/// - 普通文件先写入同目录的 `.ldb-staging-<id>-<name>` 再 `rename` 覆盖（原子替换）；
/// - 覆盖前把原文件移入回滚区，并逐条写入事务日志（供 `--rollback`）；
/// - 任一环节失败 → 立即按日志逆序回滚已提交的变更，再返回原错误；
/// - 策略为"重建/重装"的模块不拷贝二进制，改为登记到 [`ExtractOutcome`]，
///   在后续步骤由 DKMS/包管理器处理（失败则自动降级为拷贝）。
fn extract(req: &RestoreRequest, manifest: &Manifest) -> AppResult<ExtractOutcome> {
    let root = target_root(req);
    let id = run_id();
    let journal_dir = state_dir(&root);
    let rollback_dir = journal_dir.join(format!("rollback-{}", id));
    let journal_path = journal_dir.join(format!("restore-{}.json", id));
    let family = distro::DistroInfo::detect().family;

    // manifest 条目 → 类型/策略查询表（用 `data/` 之后的相对路径作 key）。
    let by_path: HashMap<String, &crate::model::ManifestEntry> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            safe_rel_path(&e.path).map(|p| (p.to_string_lossy().into_owned(), e))
        })
        .collect();

    let mut outcome = ExtractOutcome {
        journal_path: journal_path.clone(),
        journal: RestoreJournal {
            created_at: format!("epoch:{}", id),
            target_kver: String::new(),
            root: root.to_string_lossy().into_owned(),
            entries: Vec::new(),
        },
        ..Default::default()
    };
    let mut strategy_counts: HashMap<String, usize> = HashMap::new();

    let mut arch = open_archive(&req.archive)?;
    let entries = arch.entries()?;

    let total = by_path.len().max(1);
    let mut processed = 0usize;
    let mut item_notes = 0usize;
    let mut last_p = 0f32;
    let mut last_at = Instant::now();

    (req.progress)(0.0, format!("开始还原 {} 个条目到 {}", total, root.display()));

    // 包一层：任何错误都先回滚已提交的变更。
    let result = (|| -> AppResult<()> {
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
            let rel = inner.to_string_lossy().into_owned();
            let meta = by_path.get(&rel).copied();
            let et = entry.header().entry_type();

            let action = plan_entry(
                et.is_file(),
                et.is_dir(),
                et.is_symlink(),
                et.is_hard_link(),
                meta.is_some_and(|m| m.kind == EntryKind::Firmware) || looks_like_firmware(&rel),
                req.with_firmware,
            );

            // 由系统包提供的文件（content_stored=false）：只校验存在性。
            if let Some(m) = meta {
                if !m.content_stored {
                    let dest = root.join(&inner);
                    if fs::symlink_metadata(&dest).is_err() {
                        outcome
                            .missing_package_files
                            .push((rel.clone(), m.owner.clone()));
                    }
                    outcome.skipped += 1;
                    processed += 1;
                    continue;
                }
            }

            match action {
                EntryAction::WriteSymlink => {
                    let target = meta
                        .and_then(|m| m.link_target.clone())
                        .or_else(|| entry.link_name().ok().flatten().map(|l| l.to_string_lossy().into_owned()))
                        .unwrap_or_default();
                    let link_dest = root.join(&inner);
                    let plan = validate_link_target(&rel, &target)?;

                    // 模块链接：目标在归档/本机中是否存在只提示，不致命（strict_links 时升级为错误）。
                    // /etc 配置别名按原样重建，不做存在性检查。
                    let target_known = match &plan {
                        LinkPlan::Verbatim => true,
                        LinkPlan::Normalized(normalized) => {
                            let expected = root.join(normalized);
                            by_path
                                .contains_key(&normalized.to_string_lossy().into_owned())
                                || fs::symlink_metadata(&expected).is_ok()
                        }
                    };
                    if !target_known {
                        let msg = format!(
                            "符号链接目标尚不存在（可能来自另一个内核的模块）：{} -> {}",
                            rel, target
                        );
                        if req.strict_links {
                            return Err(AppError::Validation(msg));
                        }
                        if item_notes < MAX_ITEM_NOTES {
                            item_notes += 1;
                            outcome_push_note(&mut outcome, msg);
                        }
                    }

                    if let Some(parent) = link_dest.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let staged = staged_path(&link_dest, &id);
                    remove_any(&staged)?;
                    std::os::unix::fs::symlink(&target, &staged)?;
                    let rollback = move_aside(&link_dest, &rollback_dir, &rel)?;
                    fs::rename(&staged, &link_dest)?;
                    outcome.journal.entries.push(JournalEntry {
                        path: rel.clone(),
                        prior_existed: rollback.is_some(),
                        rollback_path: rollback,
                        kind: "symlink".to_string(),
                    });
                    outcome.links_written += 1;
                    processed += 1;
                }
                EntryAction::SkipLink => {
                    outcome.skipped += 1;
                    if item_notes < MAX_ITEM_NOTES {
                        item_notes += 1;
                        outcome_push_note(
                            &mut outcome,
                            format!("跳过硬链接条目（不还原）：/{}", inner.display()),
                        );
                    }
                }
                EntryAction::SkipSpecial => {
                    outcome.skipped += 1;
                    if item_notes < MAX_ITEM_NOTES {
                        item_notes += 1;
                        outcome_push_note(
                            &mut outcome,
                            format!("跳过特殊条目（非普通文件）：/{}", inner.display()),
                        );
                    }
                }
                EntryAction::SkipFirmware => {
                    outcome.skipped += 1;
                }
                EntryAction::MakeDir => {
                    fs::create_dir_all(root.join(&inner))?;
                }
                EntryAction::Write => {
                    // ---- 策略决策（仅模块条目）----
                    let mut handled = false;
                    if let Some(m) = meta {
                        let offline = target_root(req) != Path::new(TARGET_ROOT);
                        if offline && req.strategy.is_some_and(|s| s != RestoreStrategy::Copy) {
                            outcome_push_note(
                                &mut outcome,
                                format!(
                                    "离线模式（--root）下 {:?} 策略会作用于宿主而非目标根，已降级为拷贝：/{}",
                                    req.strategy.unwrap_or(RestoreStrategy::Copy),
                                    inner.display()
                                ),
                            );
                        }
                        let mut strategy =
                            decide_strategy(m, manifest, family, req.strategy, offline);
                        match strategy {
                            RestoreStrategy::Rebuild => {
                                if let Some(pkg) = dkms_for_module(&m.path, &manifest.dkms) {
                                    if !outcome.rebuilt.iter().any(|p| p == pkg) {
                                        outcome.rebuilt.push(pkg.clone());
                                        outcome_push_note(
                                            &mut outcome,
                                            format!(
                                                "策略[重建]：{} 将由 DKMS/akmods 重建（跳过拷贝）",
                                                pkg.name
                                            ),
                                        );
                                    }
                                    handled = true;
                                } else {
                                    outcome_push_note(
                                        &mut outcome,
                                        format!(
                                            "策略[重建] 缺少 DKMS 包信息，降级为拷贝：/{}",
                                            inner.display()
                                        ),
                                    );
                                    strategy = RestoreStrategy::Copy;
                                }
                            }
                            RestoreStrategy::Reinstall => {
                                if let Some(owner) = &m.owner {
                                    if !outcome.reinstall.iter().any(|p| p.package == owner.package) {
                                        outcome.reinstall.push(owner.clone());
                                    }
                                    outcome_push_note(
                                        &mut outcome,
                                        format!(
                                            "策略[重装包]：{} 将由 {} 重装（跳过拷贝）",
                                            m.path, owner.package
                                        ),
                                    );
                                    handled = true;
                                } else {
                                    strategy = RestoreStrategy::Copy;
                                }
                            }
                            RestoreStrategy::WeakModules | RestoreStrategy::Copy | RestoreStrategy::Skip => {}
                        }
                        if m.kind == EntryKind::Module {
                            *strategy_counts
                                .entry(strategy.label_zh().to_string())
                                .or_insert(0) += 1;
                        }
                    }

                    if !handled {
                        let dest = root.join(&inner);
                        if let Some(parent) = dest.parent() {
                            fs::create_dir_all(parent)?;
                        }
                        let staged = staged_path(&dest, &id);
                        remove_any(&staged)?;
                        let mut out = fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .mode(FILE_MODE)
                            .open(&staged)?;
                        copy_with_cancel(&mut entry, &mut out, &req.cancel)?;
                        out.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
                        drop(out);

                        let rollback = move_aside(&dest, &rollback_dir, &rel)?;
                        fs::rename(&staged, &dest)?;
                        outcome.journal.entries.push(JournalEntry {
                            path: rel.clone(),
                            prior_existed: rollback.is_some(),
                            rollback_path: rollback,
                            kind: format!("{:?}", meta.map(|m| m.kind).unwrap_or(EntryKind::Config)).to_lowercase(),
                        });
                        outcome.written += 1;

                        if meta.is_some_and(|m| m.kind == EntryKind::Module) {
                            let unsigned = meta
                                .and_then(|m| m.modinfo.as_ref())
                                .map(|mi| !mi.is_signed())
                                .unwrap_or(true);
                            if unsigned {
                                outcome.unsigned_modules.push(dest.clone());
                            }
                            if family == Family::Rhel {
                                outcome.weak_modules.push(dest.to_string_lossy().into_owned());
                            }
                        }
                    }
                    processed += 1;

                    let p = (WRITE_PROGRESS_END * processed as f32 / total as f32)
                        .min(WRITE_PROGRESS_END);
                    if p >= last_p + PROGRESS_DELTA && last_at.elapsed() >= PROGRESS_INTERVAL {
                        last_p = p;
                        last_at = Instant::now();
                        (req.progress)(p, format!("已处理 {}/{} 个条目", processed, total));
                    }
                }
            }
        }
        Ok(())
    })();

    if let Err(err) = result {
        let rolled_back = rollback_entries(&root, &outcome.journal, &mut Vec::new());
        let mut message = err.to_string();
        if let Ok(lines) = rolled_back {
            message.push_str(&format!(
                "\n已自动回滚 {} 条已提交变更（事务日志：{}）",
                lines,
                journal_path.display()
            ));
        }
        return Err(match err {
            AppError::Command {
                program,
                status,
                stderr,
            } => AppError::Command {
                program,
                status,
                stderr: format!("{}\n{}", message, stderr),
            },
            other => AppError::Format(format!("{}（{}）", other, message)),
        });
    }

    // 提交日志（放在解压成功之后，避免留下无用的空日志），并按代数裁剪旧回滚数据。
    outcome.journal.save(&journal_path)?;
    for note in prune_state(&journal_dir, req.keep_rollback) {
        outcome_push_note(&mut outcome, note);
    }
    let mut counts: Vec<(String, usize)> = strategy_counts.into_iter().collect();
    counts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    outcome.strategy_counts = counts;
    Ok(outcome)
}

/// Copy a specific set of archive entries into the target root (rebuild/reinstall fallback).
/// 把指定路径集合从归档**仅拷贝**写入目标根，用于"重建/重装失败"时的降级回退。
///
/// 与 [`extract`] 共用同一套事务语义（同目录暂存 + 原子 rename + 回滚区 + 日志追加），
/// 因此回退写入同样可以 `--rollback`。返回成功写入的条目数。
fn copy_entries(
    req: &RestoreRequest,
    wanted: &[String],
    journal: &mut RestoreJournal,
    journal_path: &Path,
) -> AppResult<usize> {
    if wanted.is_empty() {
        return Ok(0);
    }
    let root = target_root(req);
    let id = run_id();
    let rollback_dir = state_dir(&root).join(format!("rollback-{}", id));
    let mut copied = 0usize;

    let mut arch = open_archive(&req.archive)?;
    for entry in arch.entries()? {
        if req.cancel.load(Ordering::Relaxed) {
            return Err(AppError::Cancelled);
        }
        let mut entry = entry?;
        let raw = entry_path(&entry)?;
        let inner = match data_payload(&raw)? {
            Some(i) => i,
            None => continue,
        };
        let rel = inner.to_string_lossy().into_owned();
        if !wanted.iter().any(|w| w == &rel) {
            continue;
        }
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let dest = root.join(&inner);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let staged = staged_path(&dest, &id);
        remove_any(&staged)?;
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&staged)?;
        copy_with_cancel(&mut entry, &mut out, &req.cancel)?;
        out.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        drop(out);

        let rollback = move_aside(&dest, &rollback_dir, &rel)?;
        fs::rename(&staged, &dest)?;
        journal.entries.push(JournalEntry {
            path: rel,
            prior_existed: rollback.is_some(),
            rollback_path: rollback,
            kind: "module-fallback".to_string(),
        });
        copied += 1;
    }
    if copied > 0 {
        journal.save(journal_path)?;
    }
    Ok(copied)
}

/// Push a note into an [`ExtractOutcome`]'s journal-independent note list.
/// 向 [`ExtractOutcome`] 追加一条说明（临时借用 journal 承载，随后由调用方取走）。
///
/// 之所以复用 `journal` 之外的字段：`ExtractOutcome` 保持精简，说明统一经此函数收集。
fn outcome_push_note(outcome: &mut ExtractOutcome, msg: String) {
    outcome.notes.push(msg);
}

/// Staged (temporary) path next to the destination, guaranteeing an atomic rename.
/// 目标同目录的暂存路径，保证随后的 `rename` 原子且不跨文件系统。
fn staged_path(dest: &Path, id: &str) -> PathBuf {
    let name = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "entry".to_string());
    let staged_name = format!("{}{}-{}", STAGE_PREFIX, id, name);
    match dest.parent() {
        Some(parent) => parent.join(staged_name),
        None => PathBuf::from(staged_name),
    }
}

/// Undo committed journal entries in reverse order; returns how many were undone.
/// 按日志**逆序**撤销已提交的变更；返回撤销条数。
fn rollback_entries(root: &Path, journal: &RestoreJournal, notes: &mut Vec<String>) -> AppResult<usize> {
    let mut undone = 0usize;
    for record in journal.entries.iter().rev() {
        let target = root.join(&record.path);
        if record.prior_existed {
            if let Some(backup) = &record.rollback_path {
                // 必须用 `symlink_metadata`：回滚区里的条目本身可能是符号链接
                // （相对目标在回滚区内并不存在），`.exists()` 会跟随链接并误判为缺失。
                if fs::symlink_metadata(backup).is_ok() {
                    remove_any(&target)?;
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::rename(backup, &target)?;
                    undone += 1;
                    continue;
                }
            }
            notes.push(format!("回滚时找不到原文件备份，跳过：/{}", record.path));
        } else {
            remove_any(&target)?;
            undone += 1;
        }
    }
    Ok(undone)
}

/// Run a rollback for the given journal (or the newest one when `journal` is `None`).
/// 按指定事务日志回滚；`journal` 为 `None` 时使用最新的日志（`--rollback last`）。
pub fn run_rollback(
    root: &Path,
    journal: Option<&Path>,
    progress: ProgressFn,
) -> AppResult<RollbackReport> {
    let path = match journal {
        Some(p) => p.to_path_buf(),
        None => latest_journal(root).ok_or_else(|| {
            AppError::Validation(format!(
                "在 {} 下找不到任何还原日志，无法回滚",
                state_dir(root).display()
            ))
        })?,
    };
    let journal = RestoreJournal::load(&path)?;
    progress(0.0, format!("开始回滚：{}", path.display()));

    let mut notes = Vec::new();
    let mut report = RollbackReport::default();
    for record in journal.entries.iter().rev() {
        let target = root.join(&record.path);
        if record.prior_existed {
            match &record.rollback_path {
                Some(backup) if fs::symlink_metadata(backup).is_ok() => {
                    remove_any(&target)?;
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::rename(backup, &target)?;
                    report.restored += 1;
                }
                _ => notes.push(format!("缺少原文件备份，跳过：/{}", record.path)),
            }
        } else {
            remove_any(&target)?;
            report.removed += 1;
        }
    }
    report.notes = notes;
    // 日志用后即销：避免重复 `--rollback last` 时对已消费的条目录制"缺少备份"噪音。
    if fs::remove_file(&path).is_ok() {
        report
            .notes
            .push(format!("已消费并移除事务日志：{}", path.display()));
    }
    progress(
        1.0,
        format!("回滚完成：恢复 {} 个，删除 {}", report.restored, report.removed),
    );
    Ok(report)
}

/// Keep only the newest `keep` restore journals (and their rollback payloads).
/// 只保留最新的 `keep` 份事务日志与其回滚区，超出部分按时间清理。
fn prune_state(dir: &Path, keep: usize) -> Vec<String> {
    let mut notes = Vec::new();
    let mut ids: Vec<u64> = Vec::new();
    let Ok(iter) = fs::read_dir(dir) else {
        return notes;
    };
    for entry in iter.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(id) = name
            .strip_prefix("restore-")
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<u64>().ok())
        {
            ids.push(id);
        }
    }
    ids.sort_unstable_by(|a, b| b.cmp(a));
    for id in ids.into_iter().skip(keep.max(1)) {
        let journal = dir.join(format!("restore-{}.json", id));
        let rollback = dir.join(format!("rollback-{}", id));
        if remove_any(&journal).is_ok() && remove_any(&rollback).is_ok() {
            notes.push(format!("已清理过期回滚数据：{id}"));
        }
    }
    notes
}

/// Locate the newest restore journal under a root.
/// 找到目标根下最新的还原日志。
pub fn latest_journal(root: &Path) -> Option<PathBuf> {
    let dir = state_dir(root);
    let mut best: Option<(u64, PathBuf)> = None;
    for entry in fs::read_dir(&dir).ok()?.flatten() {
        let path = entry.path();
        // 注意：状态目录里同时存在 `rollback-*`（目录）与 `restore-*.json`（文件），
        // 必须**跳过**不匹配的条目，不能对它们使用 `?` 提前返回。
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Some(id) = name
            .strip_prefix("restore-")
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.parse::<u64>().ok())
        else {
            continue;
        };
        if best.as_ref().is_none_or(|(b, _)| id > *b) {
            best = Some((id, path));
        }
    }
    best.map(|(_, p)| p)
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
    run_command_with_input(cmd, None)
}

/// Run an external command with optional stdin payload.
/// 执行外部命令，可选地通过 stdin 输入内容（供 `weak-modules --add-modules` 使用）。
///
/// 输入非空时用 `Stdio::piped()` 写入并在写入线程内 `drop(stdin)`，避免子进程读到阻塞。
fn run_command_with_input(cmd: &SystemCmd, input: Option<&str>) -> AppResult<String> {
    let mut child = Command::new(&cmd.program)
        .args(&cmd.args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| AppError::Command {
            program: cmd.program.clone(),
            status: -1,
            stderr: format!("无法启动命令：{}", e),
        })?;

    if let Some(text) = input {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(text.as_bytes());
            let _ = stdin.flush();
            // 显式关闭，让子进程看到 EOF。
            drop(stdin);
        }
    }

    let output = child.wait_with_output().map_err(|e| AppError::Command {
        program: cmd.program.clone(),
        status: -1,
        stderr: format!("命令执行失败：{}", e),
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

/// Run a full restore.
/// 执行还原（v0.2.0 顺序，DESIGN.md §5.5 + ROADMAP §3 P0）：
///
/// 1. `inspect` 取 manifest；目标 kver = `req.kver` 或 `manifest.kernel_release`，
///    必须通过 `model::is_safe_kernel_version`。
/// 2. 校验架构、内核版本与 **vermagic（模块 ABI 指纹）**；不一致且未确认 → `Validation`。
/// 3. 权限：写 `/`（非 dry_run）且非 root → `AppError::Privilege`（由 `main` 决定 pkexec 重入）；
///    指定 `--root <dir>` 的离线还原按目标目录自身权限判定（救援场景常以普通用户预演）。
/// 4. **不可变系统闸门（P0-3）**：OSTree/Nix/只读 `/usr` 默认拒绝直写，给出替代路径。
/// 5. dry-run：统计文件/链接/字节 + **策略预览**（重建/重装/弱更新/拷贝），不落盘。
/// 6. 事务化解压（P0-1 符号链接、P0-5 来源包、P0-6 回滚日志）。
/// 7. 策略执行（P0-4）：DKMS/akmods 重建 → 包管理器重装 → `weak-modules --add-modules`。
/// 8. `depmod` → `restorecon`（RHEL）→ **Secure Boot 签名（P0-2）** → initramfs 更新。
/// 9. 汇总报告，并给出事务日志路径（供 `--rollback`）。
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

    if !manifest.format_supported() {
        return Err(AppError::Format(format!(
            "归档格式版本 {} 不受支持（本工具可读 {}-{}）",
            manifest.format_version,
            crate::model::MIN_MANIFEST_FORMAT_VERSION,
            crate::model::MANIFEST_FORMAT_VERSION
        )));
    }
    if manifest.is_legacy_v1() {
        report.notes.push(
            "该归档为 v1 格式：不含符号链接目标、来源包与模块签名元数据，还原能力受限（建议重新备份）"
                .to_string(),
        );
    }

    if !is_safe_kernel_version(&target_kver) {
        return Err(AppError::Validation(format!(
            "内核版本串不满足 ^[0-9A-Za-z][0-9A-Za-z._+-]*$（或长度 >128），拒绝进入任何命令行参数：{}",
            target_kver
        )));
    }

    let root = target_root(&req);
    let offline = root != Path::new(TARGET_ROOT);

    // ---- 步骤 2：架构 / 内核 / vermagic 一致性 ----
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

    // vermagic（模块 ABI 指纹）比对：比内核字符串更严格，跨内核拷贝 .ko 的核心判据。
    if let (Some(backup_vm), Some(current_vm)) = (
        manifest.kernel_vermagic.as_deref(),
        distro::reference_vermagic(&target_kver),
    ) {
        if backup_vm != current_vm {
            let msg = format!(
                "模块 ABI 指纹（vermagic）不一致：备份 [{}] / 目标 [{}]",
                backup_vm, current_vm
            );
            if req.allow_kernel_mismatch {
                report
                    .notes
                    .push(format!("{}；直接拷贝的 .ko 可能无法加载，建议使用 --strategy rebuild", msg));
            } else {
                return Err(AppError::Validation(format!(
                    "{}。跨内核拷贝 .ko 基本无法加载，建议 --strategy rebuild（DKMS 重建）或确认后加 --allow-kernel-mismatch",
                    msg
                )));
            }
        }
    }

    // ---- 步骤 3：权限（写 `/` 需要 root；`--root` 离线还原按目标目录权限自行判定）----
    if !req.dry_run && !offline && !distro::is_root() {
        return Err(AppError::Privilege(
            "还原需要 root 权限，将通过 pkexec 提权".to_string(),
        ));
    }

    // ---- 步骤 4：不可变系统闸门（P0-3）----
    let immutability = distro::immutability();
    if !offline {
        match immutability {
            distro::Immutability::Mutable => {}
            distro::Immutability::Ostree => match req.on_immutable {
                ImmutablePolicy::Refuse => {
                    return Err(AppError::Validation(
                        "目标为 OSTree 不可变系统（/usr 只读），拒绝直接写入 /usr/lib/modules。\
                         受支持的做法：① `rpm-ostree install <对应 kmod 包>`；\
                         ② `rpm-ostree override replace <本地 rpm>`；\
                         ③ 临时排障可加 --on-immutable usroverlay（重启即失效）。"
                            .to_string(),
                    ));
                }
                ImmutablePolicy::Usroverlay => {
                    let cmd = SystemCmd {
                        program: "rpm-ostree".to_string(),
                        args: vec!["usroverlay".to_string()],
                    };
                    if !distro::has_cmd("rpm-ostree") {
                        return Err(AppError::Privilege(
                            "未找到 rpm-ostree，无法建立临时可写覆盖层".to_string(),
                        ));
                    }
                    run_command(&cmd)?;
                    report.notes.push(
                        "已在 OSTree 系统上启用临时可写覆盖层（usroverlay）：**重启后失效**，仅用于排障"
                            .to_string(),
                    );
                }
            },
            distro::Immutability::Nix => {
                return Err(AppError::Validation(
                    "目标为 NixOS：模块由声明式配置（nixos-rebuild）管理，本工具不支持直接还原。\
                     请把驱动加入 configuration.nix 后重建系统。"
                        .to_string(),
                ));
            }
            distro::Immutability::ReadOnlyUsr => {
                return Err(AppError::Validation(
                    "目标系统的 /usr 以只读方式挂载，无法写入模块目录。\
                     请先解除只读（或使用 --root 做离线还原）。"
                        .to_string(),
                ));
            }
        }
    }
    report.notes.push(format!(
        "目标系统可变性：{}（写入根：{}）",
        immutability.label_zh(),
        root.display()
    ));

    // manifest 条目 → 类型表（dry-run 的固件判定用）
    let kinds: HashMap<String, EntryKind> = manifest
        .entries
        .iter()
        .filter_map(|e| {
            safe_rel_path(&e.path).map(|p| (p.to_string_lossy().into_owned(), e.kind))
        })
        .collect();

    // ---- 步骤 5：dry-run 只统计与预览 ----
    if req.dry_run {
        let mut files = 0usize;
        let mut links = 0usize;
        let mut bytes = 0u64;
        let mut fw_skips = 0usize;
        let mut hardlink_skips = 0usize;
        let family = distro::DistroInfo::detect().family;
        let mut plan: HashMap<String, usize> = HashMap::new();

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
            let rel = inner.to_string_lossy().into_owned();
            let et = entry.header().entry_type();
            match plan_entry(
                et.is_file(),
                et.is_dir(),
                et.is_symlink(),
                et.is_hard_link(),
                is_firmware(&kinds, &inner),
                req.with_firmware,
            ) {
                EntryAction::Write => {
                    if let Some(m) = manifest.entries.iter().find(|e| e.path == rel) {
                        // 策略只对模块条目有意义（配置/源码一律直接写入）
                        if m.kind == EntryKind::Module {
                            let offline = root != Path::new(TARGET_ROOT);
                            let s = decide_strategy(m, &manifest, family, req.strategy, offline);
                            *plan.entry(s.label_zh().to_string()).or_insert(0) += 1;
                        }
                    }
                    files += 1;
                    bytes = bytes.saturating_add(entry.size());
                }
                EntryAction::WriteSymlink => links += 1,
                EntryAction::SkipFirmware => fw_skips += 1,
                EntryAction::SkipLink => hardlink_skips += 1,
                EntryAction::SkipSpecial | EntryAction::MakeDir => {}
            }
        }

        let mut msg = format!(
            "将写入 {} 个文件 + {} 个符号链接（{}），不落盘",
            files,
            links,
            human_size(bytes)
        );
        if fw_skips > 0 {
            msg.push_str(&format!("；跳过 {} 个固件条目", fw_skips));
        }
        if hardlink_skips > 0 {
            msg.push_str(&format!("；跳过 {} 个硬链接条目", hardlink_skips));
        }
        if !plan.is_empty() {
            let mut parts: Vec<(String, usize)> = plan.into_iter().collect();
            parts.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
            let text = parts
                .iter()
                .map(|(k, v)| format!("{} {}", k, v))
                .collect::<Vec<_>>()
                .join("，");
            msg.push_str(&format!("；策略预览：{}", text));
        }
        report.notes.push(msg.clone());
        (req.progress)(1.0, msg);
        return Ok(report);
    }

    // ---- 步骤 6：事务化解压（含符号链接与策略分流）----
    let outcome = extract(&req, &manifest)?;
    report.written = outcome.written;
    report.links_written = outcome.links_written;
    report.skipped = outcome.skipped;
    report.rollback_journal = Some(outcome.journal_path.clone());
    report.strategy_counts = outcome.strategy_counts.clone();
    report.notes.extend(outcome.notes.iter().cloned());
    for (path, owner) in &outcome.missing_package_files {
        let hint = owner
            .as_ref()
            .map(|o| format!("，可用 `{}` 重装 {}", o.manager, o.package))
            .unwrap_or_default();
        report.notes.push(format!(
            "缺少由系统包提供的文件（归档未存内容）：/{}{}",
            path, hint
        ));
    }
    (req.progress)(
        WRITE_PROGRESS_END,
        format!(
            "文件写入完成：{} 个文件 + {} 个链接，{} 个跳过，开始执行重建/重装与 depmod …",
            report.written, report.links_written, report.skipped
        ),
    );

    let family = distro::DistroInfo::detect().family;
    let sb = distro::secure_boot_state();

    // ---- 步骤 7：策略执行（P0-4）----
    // 7.1 重建：RHEL 系优先 akmods，其余用 dkms install。
    let mut failed_rebuild: Vec<DkmsPackage> = Vec::new();
    let mut failed_reinstall: Vec<Provenance> = Vec::new();
    let mut rebuilt_ok: Vec<DkmsPackage> = Vec::new();
    if !outcome.rebuilt.is_empty() {
        if family == Family::Rhel {
            if let Some(cmd) = distro::akmods_cmd(&target_kver) {
                match run_command(&cmd) {
                    Ok(_) => {
                        rebuilt_ok = outcome.rebuilt.clone();
                        report
                            .notes
                            .push(format!("已重建 {} 个 DKMS 包（akmods）", rebuilt_ok.len()));
                    }
                    Err(e) => report
                        .notes
                        .push(format!("akmods 重建失败（将回退为拷贝）：{}", e)),
                }
            }
        }
        if rebuilt_ok.is_empty() {
            for pkg in &outcome.rebuilt {
                match distro::dkms_install_cmd(&pkg.name, &pkg.version, &target_kver) {
                    Some(cmd) => match run_command(&cmd) {
                        Ok(_) => {
                            rebuilt_ok.push(pkg.clone());
                            report
                                .notes
                                .push(format!("已重建：{} {}", pkg.name, pkg.version));
                        }
                        Err(e) => report.notes.push(format!(
                            "DKMS 重建失败（{} {}）：{}（将回退为拷贝）",
                            pkg.name, pkg.version, e
                        )),
                    },
                    None => report.notes.push(format!(
                        "未找到 dkms 命令，无法重建 {}（将回退为拷贝）",
                        pkg.name
                    )),
                }
            }
        }
        failed_rebuild = outcome
            .rebuilt
            .iter()
            .filter(|pkg| !rebuilt_ok.contains(pkg))
            .cloned()
            .collect();
        report.rebuilt = rebuilt_ok.len();
    }

    // 7.2 重装来源包（P0-5）：同一包只重装一次。
    let mut reinstalled_pkgs: Vec<String> = Vec::new();
    for owner in &outcome.reinstall {
        if reinstalled_pkgs.contains(&owner.package) {
            continue;
        }
        match distro::reinstall_cmd(&owner.manager, &owner.package) {
            Some(cmd) => match run_command(&cmd) {
                Ok(_) => {
                    reinstalled_pkgs.push(owner.package.clone());
                    report
                        .notes
                        .push(format!("已重装来源包：{}", owner.package));
                }
                Err(e) => report.notes.push(format!(
                    "重装来源包 {} 失败（该模块未还原）：{}",
                    owner.package, e
                )),
            },
            None => report.notes.push(format!(
                "未找到可用的包管理器（{}），无法重装 {}（将回退为拷贝）",
                owner.manager, owner.package
            )),
        }
        if !reinstalled_pkgs.contains(&owner.package) && !failed_reinstall.iter().any(|p| p.package == owner.package) {
            failed_reinstall.push(owner.clone());
        }
    }
    report.reinstalled = reinstalled_pkgs.len();

    // 7.3 RHEL/SUSE：为其它内核建立 weak-updates 兼容链接。
    if !outcome.weak_modules.is_empty() && family == Family::Rhel {
        if let Some(cmd) = distro::weak_modules_cmd() {
            let stdin = format!("{}\n", outcome.weak_modules.join("\n"));
            match run_command_with_input(&cmd, Some(&stdin)) {
                Ok(_) => report.notes.push(format!(
                    "已执行 weak-modules --add-modules（{} 个模块）",
                    outcome.weak_modules.len()
                )),
                Err(e) => report
                    .notes
                    .push(format!("weak-modules 执行失败（不致命）：{}", e)),
            }
        }
    }

    // 7.4 降级回退：重建/重装失败的模块改为直接拷贝，保证"有模块可用"。
    let mut fallback_paths: Vec<String> = Vec::new();
    for pkg in &failed_rebuild {
        for entry in &manifest.entries {
            if entry.kind == EntryKind::Module
                && dkms_for_module(&entry.path, &manifest.dkms)
                    .is_some_and(|p| p == pkg)
                && !fallback_paths.contains(&entry.path)
            {
                fallback_paths.push(entry.path.clone());
            }
        }
    }
    for owner in &failed_reinstall {
        for entry in &manifest.entries {
            if entry.kind == EntryKind::Module
                && entry
                    .owner
                    .as_ref()
                    .is_some_and(|o| o.package == owner.package)
                && !fallback_paths.contains(&entry.path)
            {
                fallback_paths.push(entry.path.clone());
            }
        }
    }
    if !fallback_paths.is_empty() {
        let mut journal = outcome.journal.clone();
        match copy_entries(&req, &fallback_paths, &mut journal, &outcome.journal_path) {
            Ok(n) if n > 0 => {
                report.written += n;
                report
                    .notes
                    .push(format!("已降级为拷贝 {} 个模块（重建/重装不可用的兜底）", n));
            }
            Ok(_) => report
                .notes
                .push("回退拷贝未命中任何条目（归档缺失对应模块）".to_string()),
            Err(e) => report
                .notes
                .push(format!("回退拷贝失败（模块可能缺失）：{}", e)),
        }
    }

    // ---- 步骤 8：depmod → restorecon → 签名 → initramfs ----
    if offline && !req.chroot_exec {
        report.notes.push(format!(
            "离线还原到 {}：跳过 depmod/restorecon/initramfs（如需在目标根内执行，请加 --chroot-exec）",
            root.display()
        ));
    } else {
        let wrap = |cmd: SystemCmd| -> SystemCmd {
            if req.chroot_exec && offline {
                let mut args = vec![root.to_string_lossy().into_owned(), cmd.program.clone()];
                args.extend(cmd.args.clone());
                SystemCmd {
                    program: "chroot".to_string(),
                    args,
                }
            } else {
                cmd
            }
        };

        // 8.1 depmod：失败即整体失败（否则新还原的模块不会被识别）。
        let depmod = wrap(distro::depmod_cmd(&target_kver));
        match run_command(&depmod) {
            Ok(_) => {
                report.depmod_done = true;
                report
                    .notes
                    .push(format!("已执行：{} {}", depmod.program, depmod.args.join(" ")));
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

        // 8.2 RHEL 系补 restorecon（失败只记 notes，不致命）。
        if family == Family::Rhel && distro::has_cmd("restorecon") && !offline {
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

        // 8.3 Secure Boot 签名（P0-2）：必须在 initramfs 之前完成。
        let unsigned = outcome.unsigned_modules.len();
        if unsigned > 0 {
            if sb.enabled && !req.no_sign && !offline {
                match distro::sign_tool(&target_kver) {
                    Some((program, prefix)) => {
                        let keys = distro::mok_keys();
                        if keys.is_empty() {
                            report.notes.push(
                                "检测到 Secure Boot，但未找到签名密钥（/var/lib/shim-signed/mok 或 /etc/pki/akmods）。\
                                 请生成并登记 MOK：openssl req -new -x509 -nodes -newkey rsa:2048 -keyout MOK.priv \
                                 -outform DER -out MOK.der -days 36500 -subj \"/CN=Driver Backup Module Signing/\" && \
                                 sudo mokutil --import MOK.der（重启时完成登记）"
                                    .to_string(),
                            );
                            report.unsigned_left = unsigned;
                        } else {
                            let mut signed = 0usize;
                            let key = &keys[0];
                            for module in &outcome.unsigned_modules {
                                let mut cmd = SystemCmd {
                                    program: program.clone(),
                                    args: prefix.clone(),
                                };
                                cmd.args.push(key.private.to_string_lossy().into_owned());
                                cmd.args.push(key.certificate.to_string_lossy().into_owned());
                                cmd.args.push(module.to_string_lossy().into_owned());
                                match run_command(&cmd) {
                                    Ok(_) => signed += 1,
                                    Err(e) => report.notes.push(format!(
                                        "签名失败（{}）：{}",
                                        module.display(),
                                        e
                                    )),
                                }
                            }
                            report.signed = signed;
                            report.unsigned_left = unsigned.saturating_sub(signed);
                            report.notes.push(format!(
                                "Secure Boot 已开启：用 {} 签名了 {}/{} 个模块",
                                key.private.display(),
                                signed,
                                unsigned
                            ));
                        }
                    }
                    None => {
                        report.unsigned_left = unsigned;
                        report.notes.push(
                            "Secure Boot 已开启，但未找到 kmodsign/sign-file，无法签名；\
                             未签名模块在 SB 下无法加载"
                                .to_string(),
                        );
                    }
                }
            } else if sb.enabled && req.no_sign {
                report.unsigned_left = unsigned;
                report
                    .notes
                    .push("Secure Boot 已开启但指定了 --no-sign：未签名模块可能无法加载".to_string());
            } else {
                report.unsigned_left = unsigned;
            }
        }

        // 8.4 签名强制时，仍有未签名模块即为失败（否则重启后模块不可用）。
        if sb.sig_enforce && report.unsigned_left > 0 {
            return Err(AppError::Validation(format!(
                "内核强制要求模块签名（CONFIG_MODULE_SIG_FORCE / module.sig_enforce），\
                 但仍有 {} 个模块未签名；请配置 MOK 密钥后重试",
                report.unsigned_left
            )));
        }

        // 8.5 initramfs 更新（未知发行版跳过，不谎报成功）。
        match distro::initramfs_cmd(family, &target_kver) {
            None => {
                report.initramfs_done = None;
                report
                    .notes
                    .push("未知发行版，跳过 initramfs".to_string());
            }
            Some(cmd) => {
                let cmd = wrap(cmd);
                if req.chroot_exec && offline {
                    // chroot 的目标程序存在性由 chroot 内部判定，这里不做宿主侧检查。
                } else if !distro::has_cmd(&cmd.program) {
                    report.initramfs_done = Some(false);
                    report
                        .notes
                        .push(format!("未找到命令 {}，跳过 initramfs 更新", cmd.program));
                }
                if report.initramfs_done.is_none() {
                    match run_command(&cmd) {
                        Ok(_) => {
                            report.initramfs_done = Some(true);
                            report
                                .notes
                                .push(format!("已执行：{} {}", cmd.program, cmd.args.join(" ")));
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
    }

    // ---- 步骤 9：汇总 ----
    let mut summary = format!(
        "还原完成：写入 {} 个文件 + {} 个链接，跳过 {} 个",
        report.written, report.links_written, report.skipped
    );
    if report.rebuilt > 0 {
        summary.push_str(&format!("，重建 {} 个", report.rebuilt));
    }
    if report.reinstalled > 0 {
        summary.push_str(&format!("，重装 {} 个包", report.reinstalled));
    }
    if report.signed > 0 {
        summary.push_str(&format!("，签名 {} 个模块", report.signed));
    }
    (req.progress)(1.0, summary.clone());
    report.notes.push(summary);
    report.notes.push(format!(
        "事务日志（可回滚）：{}（`--rollback last`）",
        outcome.journal_path.display()
    ));
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
    fn plan_entry_handles_symlinks_special_and_firmware() {
        use EntryAction::*;
        // v0.2.0：符号链接按链接语义还原（P0-1）；硬链接仍跳过。
        assert_eq!(plan_entry(false, false, true, false, false, false), WriteSymlink);
        assert_eq!(plan_entry(false, false, true, false, true, true), WriteSymlink);
        assert_eq!(plan_entry(false, false, false, true, false, false), SkipLink);
        // 固件：未开启 → 跳过；开启 → 写入
        assert_eq!(plan_entry(true, false, false, false, true, false), SkipFirmware);
        assert_eq!(plan_entry(true, false, false, false, true, true), Write);
        assert_eq!(plan_entry(true, false, false, false, false, false), Write);
        // 目录 → 建目录；fifo/设备等 → 跳过
        assert_eq!(plan_entry(false, true, false, false, false, false), MakeDir);
        assert_eq!(plan_entry(false, false, false, false, false, false), SkipSpecial);
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
            allow_arch_mismatch: false,
            with_firmware: false,
            progress,
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
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
    fn staged_and_rollback_paths_are_stable() {
        // 暂存路径必须与目标同目录（保证 rename 原子、不跨文件系统）
        let staged = staged_path(Path::new("/lib/modules/6.8/x.ko"), "1712345678");
        assert_eq!(
            staged,
            PathBuf::from("/lib/modules/6.8/.ldb-staging-1712345678-x.ko")
        );
        // 回滚区文件名压平目录层级
        assert_eq!(
            rollback_file_name("lib/modules/6.8/weak-updates/x.ko"),
            "lib__modules__6.8__weak-updates__x.ko"
        );
        // 归一化 join：weak-updates 的 `..` 形态必须落在受管前缀内
        assert_eq!(
            normalize_join("lib/modules/6.8/weak-updates/a.ko", "../../6.6/extra/a.ko"),
            Some(PathBuf::from("lib/modules/6.6/extra/a.ko"))
        );
        // 三层（归一化仍在根内）→ 归一化成功，但校验层必须拒绝（不在模块前缀内）
        assert_eq!(
            normalize_join("lib/modules/6.8/a.ko", "../../../etc/shadow"),
            Some(PathBuf::from("etc/shadow"))
        );
        // 四层 → 越出归档根，归一化即失败
        assert_eq!(normalize_join("lib/modules/6.8/a.ko", "../../../../etc/shadow"), None);
        // 绝对目标一律拒绝
        assert_eq!(normalize_join("lib/modules/6.8/a.ko", "/etc/shadow"), None);
        assert!(validate_link_target("lib/modules/6.8/a.ko", "../../../etc/shadow").is_err());
        assert!(validate_link_target("lib/modules/6.8/a.ko", "/etc/shadow").is_err());
        assert!(validate_link_target(
            "lib/modules/6.8/weak-updates/a.ko",
            "../../6.6/extra/a.ko"
        )
        .is_ok());
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
    fn rollback_restores_symlink_entries() {
        // 回归：回滚区里的条目本身是符号链接（相对目标在回滚区内不存在），
        // 早期实现用 `.exists()` 判定会跟随链接并误判为"缺少原文件备份"。
        let root = temp_case("rollback-symlink");
        let link = root.join("etc/modules-load.d/modules.conf");
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("../modules", &link).unwrap();

        let rollback_dir = state_dir(&root).join("rollback-1");
        let saved = move_aside(&link, &rollback_dir, "etc/modules-load.d/modules.conf")
            .unwrap()
            .expect("原符号链接应被移入回滚区");
        assert!(fs::symlink_metadata(&saved).unwrap().file_type().is_symlink());

        // 写入替换内容（模拟还原覆盖）
        fs::write(&link, b"replaced").unwrap();
        let journal = RestoreJournal {
            created_at: "epoch:1".to_string(),
            target_kver: "6.8.0".to_string(),
            root: root.to_string_lossy().into_owned(),
            entries: vec![JournalEntry {
                path: "etc/modules-load.d/modules.conf".to_string(),
                prior_existed: true,
                rollback_path: Some(saved),
                kind: "symlink".to_string(),
            }],
        };
        let mut notes = Vec::new();
        assert_eq!(rollback_entries(&root, &journal, &mut notes).unwrap(), 1);
        assert!(notes.is_empty(), "不应报告缺少备份：{notes:?}");
        let meta = fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_symlink(), "应恢复为符号链接");
        assert_eq!(
            fs::read_link(&link).unwrap(),
            PathBuf::from("../modules"),
            "链接目标必须原样恢复"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn latest_journal_skips_rollback_dirs_and_prune_keeps_newest() {
        let root = temp_case("journal-scan");
        let dir = state_dir(&root);
        fs::create_dir_all(&dir).unwrap();
        // 混入 rollback 目录（历史上曾导致 `?` 提前返回 None）
        fs::create_dir_all(dir.join("rollback-100")).unwrap();
        fs::write(dir.join("restore-100.json"), b"{}").unwrap();
        fs::create_dir_all(dir.join("rollback-200")).unwrap();
        fs::write(dir.join("restore-200.json"), b"{}").unwrap();
        fs::write(dir.join("restore-notanumber.json"), b"{}").unwrap();

        let newest = latest_journal(&root).expect("应能找到最新日志");
        assert!(newest.ends_with("restore-200.json"), "取到的是 {newest:?}");

        // 只保留最新 1 份 → 100 的日志与回滚区被清理，200 保留
        let notes = prune_state(&dir, 1);
        assert_eq!(notes.len(), 1);
        assert!(dir.join("restore-200.json").exists());
        assert!(!dir.join("restore-100.json").exists());
        assert!(!dir.join("rollback-100").exists());
        assert!(latest_journal(&root).unwrap().ends_with("restore-200.json"));

        // 没有日志时返回 None
        let empty = temp_case("journal-empty");
        assert!(latest_journal(&empty).is_none());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&empty);
    }

    #[test]
    fn transaction_moves_aside_and_rolls_back() {
        // 只在 /tmp 下验证事务机制（不触碰 /）
        let dir = temp_case("transaction");
        let root = dir.join("root");
        let target = root.join("lib/modules/6.8/x.ko");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"old").unwrap();

        let rollback_dir = root.join("var/lib/linux-driver-backup/rollback-1");
        let saved = move_aside(&target, &rollback_dir, "lib/modules/6.8/x.ko")
            .unwrap()
            .expect("原文件应被移入回滚区");
        assert!(!target.exists(), "原文件必须已让位");
        assert_eq!(fs::read(&saved).unwrap(), b"old");

        // 写入新内容（模拟已提交的还原）
        fs::write(&target, b"new").unwrap();
        let journal = RestoreJournal {
            created_at: "epoch:1".to_string(),
            target_kver: "6.8.0".to_string(),
            root: root.to_string_lossy().into_owned(),
            entries: vec![JournalEntry {
                path: "lib/modules/6.8/x.ko".to_string(),
                prior_existed: true,
                rollback_path: Some(saved.clone()),
                kind: "module".to_string(),
            }],
        };

        let mut notes = Vec::new();
        let undone = rollback_entries(&root, &journal, &mut notes).unwrap();
        assert_eq!(undone, 1);
        assert_eq!(fs::read(&target).unwrap(), b"old", "回滚应恢复原文件");
        assert!(notes.is_empty());

        // 原本不存在的路径：回滚应删除它
        let created = root.join("lib/modules/6.8/y.ko");
        fs::write(&created, b"fresh").unwrap();
        let journal2 = RestoreJournal {
            entries: vec![JournalEntry {
                path: "lib/modules/6.8/y.ko".to_string(),
                prior_existed: false,
                rollback_path: None,
                kind: "module".to_string(),
            }],
            ..journal
        };
        assert_eq!(rollback_entries(&root, &journal2, &mut notes).unwrap(), 1);
        assert!(!created.exists(), "回滚应删除新增文件");

        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&target)
            .unwrap();
        f.write_all(b"mode-check").unwrap();
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
