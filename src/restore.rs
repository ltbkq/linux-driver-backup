//! Restore pipeline: archive verification → guarded extraction → depmod → restorecon → initramfs.
//! 还原流水线：归档校验 → 具路径穿越防护的流式解压 → depmod → restorecon → initramfs。
//!
//! 本模块只依赖两份冻结契约：`crate::model`（DESIGN.md §5.1）与 `crate::distro`（DESIGN.md §5.2）。
//! 归档格式见 DESIGN.md §4.3：`tar.gz` = 顶层 `manifest.json` + `data/**`（去掉前导 `/` 的相对路径）。
//! 权限模型见 DESIGN.md §4.5：还原写盘需要 root，未获 root 时返回 `AppError::Privilege`，
//! 由 `main` 决定是否经 `privilege::run_helper_via_pkexec` 重入。
//!
//! Depends only on the frozen contracts `crate::model` (§5.1) and `crate::distro` (§5.2).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
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
/// C-01：`etc/` 下符号链接目标归一化后的**绝对路径白名单**（必须落在其中之一）。
/// C-01: whitelist of absolute prefixes an `etc/` symlink target may resolve into.
///
/// 覆盖实测合法样例（`/lib/linux-sound-base/…`）、usr-merge 的 `/usr/lib/…`，
/// 以及常见的 `/etc/…`、`/usr/share/…`、`/run/…` 别名；`/`、`/home/…` 等一律拒绝。
/// 与 `backup.rs::validate_link_target` 保持同一规则（v0.3.0 由 W7/C-47 合并为共享函数）。
const ALLOWED_ETC_LINK_PREFIXES: [&str; 5] =
    ["/etc/", "/lib/", "/usr/lib/", "/usr/share/", "/run/"];
/// C-02：usr-merge 系统直接位于**目标根顶层**的别名组件（`/lib -> usr/lib` 等）。
/// Top-level usr-merge alias components that may legitimately be symlinks.
///
/// 仅第 0 层组件享受该例外（在 `root=/` 与 `--root <dir>` 下同样适用），
/// 以避免 usr-merge 发行版被误杀；其余任何层级的符号链接组件一律拒绝。
const USRMERGE_TOP_ALIASES: [&str; 4] = ["lib", "bin", "sbin", "lib64"];
/// C-11：写前日志（WAL）文件后缀；正式日志为 `restore-<id>.json`。
/// C-11: write-ahead log suffix; the committed journal is `restore-<id>.json`.
const WAL_SUFFIX: &str = ".jsonl.tmp";
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
    /// Persist the journal atomically (C-11): write to a sibling temp file, fsync,
    /// then `rename` over the target so readers never observe a half-written JSON.
    /// 原子落盘（C-11，取代旧的非原子 `save`）：先写同目录临时文件并 fsync，
    /// 再 `rename` 覆盖正式路径，任何读者都不会看到写了一半的 JSON。
    pub fn save_atomic(&self, path: &Path) -> AppResult<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "restore-journal.json".to_string());
        let tmp = path.with_file_name(format!("{}.new", name));
        let json = serde_json::to_vec_pretty(self)?;
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&json)?;
            // 目录项的持久性由调用方在进程退出前保证；文件内容本身先落盘。
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Load a journal from disk: the committed pretty JSON, or (C-11) the
    /// line-delimited write-ahead log left behind by a failed/crashed run.
    /// 从磁盘读取日志：正式 JSON，或（C-11）失败/崩溃后残留的逐行写前日志。
    ///
    /// JSONL 中每行是一个 [`JournalEntry`]，行序即条目序（回滚按逆序执行）。
    pub fn load(path: &Path) -> AppResult<Self> {
        let text = fs::read_to_string(path)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.ends_with(WAL_SUFFIX) {
            let mut entries = Vec::new();
            for (idx, line) in text.lines().enumerate() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                entries.push(serde_json::from_str::<JournalEntry>(line).map_err(|e| {
                    AppError::Format(format!("回滚日志(WAL)第 {} 行解析失败：{}", idx + 1, e))
                })?);
            }
            return Ok(RestoreJournal {
                created_at: format!("wal:{}", name),
                target_kver: String::new(),
                root: String::new(),
                entries,
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| AppError::Format(format!("回滚日志解析失败：{}", e)))
    }
}

/// C-11: companion write-ahead log path of a committed journal file.
/// C-11：由正式日志路径推导其写前日志路径（`restore-<id>.json` → `restore-<id>.jsonl.tmp`）。
fn journal_wal_path(journal_path: &Path) -> PathBuf {
    let name = journal_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "restore-journal.json".to_string());
    match name.strip_suffix(".json") {
        Some(stem) => journal_path.with_file_name(format!("{}{}", stem, WAL_SUFFIX)),
        None => journal_path.with_file_name(format!("{}{}", name, WAL_SUFFIX)),
    }
}

/// C-11: append one journal entry to the write-ahead log and fsync it **before**
/// any filesystem change is made for that entry.
/// C-11：把单条日志以 JSONL 追加写入写前日志并立即 `fsync`——必须发生在该条目
/// 任何实际变更（move_aside / rename）**之前**，崩溃后凭此可回滚。
fn append_journal_wal(wal_path: &Path, entry: &JournalEntry) -> AppResult<()> {
    if let Some(parent) = wal_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(wal_path)?;
    serde_json::to_writer(&mut f, entry)?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
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
    /// 系统阶段（depmod/签名/initramfs）失败时**不**自动回滚文件（W1/C-14 逃生口）。
    /// 默认 false = 系统阶段失败即自动回滚已提交的文件后再报错。
    // TODO(W1): C-14 实现读取本字段后移除 allow(dead_code)。
    #[allow(dead_code)]
    pub no_auto_rollback_on_post: bool,
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
            no_auto_rollback_on_post: false,
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
    ///
    /// C-01：目标已经过 [`resolve_link_abs`] 词法归一化与白名单校验，
    /// 因此只可能落在 `etc/` 树内或 [`ALLOWED_ETC_LINK_PREFIXES`] 之内。
    Verbatim,
    /// 归一化后落在模块目录内的模块链接（如 weak-updates）。
    Normalized(PathBuf),
}

/// Lexically resolve a symlink target to an absolute path rooted at the archive
/// root (C-01): relative targets are joined onto the link's own directory first;
/// `..` is rejected when it would climb above the archive root for relative
/// targets, and pinned at `/` for absolute ones.
/// 把符号链接目标**词法**解析为以归档根为基准的绝对路径（C-01）：
/// 相对目标先拼到链接所在目录；相对目标的 `..` 越出归档根即返回 `None`，
/// 绝对目标的 `/..` 则停在根。例：`("etc/a/b.conf", "../x")` → `Some("/etc/x")`。
fn resolve_link_abs(link_rel: &str, target: &str) -> Option<PathBuf> {
    let absolute = target.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    if !absolute {
        if let Some((dir, _)) = link_rel.rsplit_once('/') {
            for seg in dir.split('/') {
                if !seg.is_empty() && seg != "." {
                    stack.push(seg);
                }
            }
        }
    }
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() && !absolute {
                    // 相对目标越出归档根（`etc/x -> ../../../../..`）→ 拒绝。
                    return None;
                }
            }
            other => stack.push(other),
        }
    }
    Some(PathBuf::from(format!("/{}", stack.join("/"))))
}

fn validate_link_target(link_rel: &str, target: &str) -> AppResult<LinkPlan> {
    if link_rel.starts_with("etc/") {
        // ---- C-01/C-02 符号链接禁闭（与 backup.rs::validate_link_target 同步实施）----
        // 旧实现按 `Verbatim` 原样放行（绝对路径与 `..` 全部允许），恶意归档可用
        // `data/etc/x -> /` + `data/etc/x/...` 条目以 root 任意写文件；现改为：
        // 目标必须词法解析后仍落在 `etc/` 树内，或（绝对目标）位于允许前缀白名单。
        if target.trim().is_empty() {
            return Err(AppError::Format(format!("符号链接目标为空：{}", link_rel)));
        }
        let resolved = resolve_link_abs(link_rel, target).ok_or_else(|| {
            AppError::Format(format!(
                "符号链接目标越出归档根，拒绝还原：{} -> {}",
                link_rel, target
            ))
        })?;
        let s = resolved.to_string_lossy();
        // (a) 仍在 `etc/` 树内：etc/modules-load.d/modules.conf -> ../modules → /etc/modules
        let in_etc_tree = s.as_ref() == "/etc" || s.starts_with("/etc/");
        // (b) 绝对目标位于允许前缀白名单（含 usr-merge 的 /usr/lib/…）。
        let in_whitelist = ALLOWED_ETC_LINK_PREFIXES
            .iter()
            .any(|p| s.as_ref() == p.trim_end_matches('/') || s.starts_with(p));
        if !(in_etc_tree || in_whitelist) {
            return Err(AppError::Format(format!(
                "符号链接目标越出允许前缀，拒绝还原：{} -> {}（归一化：{}）",
                link_rel,
                target,
                resolved.display()
            )));
        }
        return Ok(LinkPlan::Verbatim);
    }
    // 模块前缀链接：维持 `normalize_join` + `is_managed_rel` 既有逻辑（v0.2.0 行为）。
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

/// C-02: validate the parent directory chain of `rel` under `root` before creating
/// or writing anything, and return the (possibly not yet existing) parent path.
/// C-02：在创建/写入前逐组件校验 `root` 下 `rel` 的父路径，返回该父路径（绝对路径）。
///
/// 规则：
/// - 逐组件 `symlink_metadata`（不跟随链接）；任何已存在的**符号链接组件** → 拒绝，
///   唯一例外是直接位于 `root` 顶层的 usr-merge 别名组件（`lib` / `bin` / `sbin` / `lib64`，
///   见 [`USRMERGE_TOP_ALIASES`]，在 `root=/` 与 `--root <dir>` 下均适用）；
/// - 某组件不存在 → 其后各组件必然也不存在 → 视为安全，提前结束检查；
/// - 其它 IO 错误原样上抛。
///
/// 这堵死了"归档先把 `<root>/etc` 造成指向外部的链接、再经该链接写入"的禁闭逃逸
/// （C-02：`<root>/etc -> /tmp/evil` 时写入被拒）。
fn safe_parent(root: &Path, rel: &Path) -> AppResult<PathBuf> {
    let parent_rel = rel.parent().unwrap_or_else(|| Path::new(""));
    let full = root.join(parent_rel);
    let mut cur = root.to_path_buf();
    for (idx, comp) in parent_rel.components().enumerate() {
        let Component::Normal(name) = comp else {
            return Err(AppError::Format(format!(
                "写入路径含非法组件，拒绝写入：/{}",
                rel.display()
            )));
        };
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let name = name.to_string_lossy();
                if idx == 0 && USRMERGE_TOP_ALIASES.contains(&name.as_ref()) {
                    // usr-merge 顶层别名（/lib -> usr/lib）：放行并继续逐段检查其下各层。
                    continue;
                }
                return Err(AppError::Format(format!(
                    "写入路径含符号链接组件，拒绝写入（禁闭检查）：/{}（越界组件：{}）",
                    rel.display(),
                    cur.display()
                )));
            }
            Ok(_) => continue,
            // 组件不存在 → 其后均不存在，视为安全（结束检查）。
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(full)
}

/// C-12: delete stale `.ldb-staging-*` leftovers of *this process prefix* inside
/// `dir` only (no full-tree scan); returns how many files were removed.
/// C-12：只清扫 `dir` 本目录下匹配本进程暂存前缀 `.ldb-staging-` 的陈旧文件
/// （不扫全盘），返回删除数量。
fn sweep_staging(dir: &Path) -> usize {
    let Ok(iter) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in iter.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().starts_with(STAGE_PREFIX) && remove_any(&entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// C-12: guard that removes its staged file when dropped, so **every** exit path
/// (including `?` early returns and panics) leaves no `.ldb-staging-*` behind.
/// C-12：暂存文件守卫——`drop` 时删除暂存路径，确保 `?` 提前返回等任何退出路径
/// 都不残留 `.ldb-staging-*`（成功 `rename` 后该路径已不存在，删除是幂等空操作）。
struct StagingGuard {
    path: PathBuf,
}

impl StagingGuard {
    /// Arm the guard for `path`.
    /// 为 `path` 布防。
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        let _ = remove_any(&self.path);
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

/// C-39: format Unix epoch seconds as an RFC3339 UTC timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`) **without** pulling in a date-time dependency.
/// C-39：把 Unix 秒数格式化为 RFC3339 UTC 字符串（手写 civil-from-days，
/// 不新增 chrono/time 依赖）。日期换算基于 Howard Hinnant 的 `civil_from_days` 算法。
fn secs_to_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);
    // 把 1970-01-01 之后的日数换算为 (年, 月, 日)。
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hour, min, sec
    )
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
/// - **C-10**：manifest 是唯一权威——manifest 路径非法即硬错误，tar 中 manifest
///   未登记的普通文件/符号链接条目一律拒绝写入（目录条目放行，见循环内注释）；
/// - 符号链接经 [`validate_link_target`] 校验后按链接语义创建（weak-updates 可还原）；
/// - **C-02**：任何写入前用 [`safe_parent`] 逐组件校验父路径（拒绝符号链接组件，
///   usr-merge 顶层别名除外）；
/// - 普通文件先写入同目录的 `.ldb-staging-<id>-<name>` 再 `rename` 覆盖（原子替换），
///   暂存文件由 [`StagingGuard`] 兜底清理（**C-12**，含 `?` 提前返回路径）；
/// - **C-11（写前日志）**：每条目先 append+`fsync` 到 `restore-<id>.jsonl.tmp`，
///   **然后**才 move_aside/rename；全部成功后原子写正式 `restore-<id>.json` 并删除 WAL，
///   失败/崩溃则保留 `.jsonl.tmp` 供 `--rollback` 回退解析；
/// - 任一环节失败 → 立即按日志逆序回滚已提交的变更，再返回原错误；
/// - 策略为"重建/重装"的模块不拷贝二进制，改为登记到 [`ExtractOutcome`]，
///   在后续步骤由 DKMS/包管理器处理（失败则自动降级为拷贝）。
fn extract(
    req: &RestoreRequest,
    manifest: &Manifest,
    target_kver: &str,
) -> AppResult<ExtractOutcome> {
    let root = target_root(req);
    let id = run_id();
    let journal_dir = state_dir(&root);
    let rollback_dir = journal_dir.join(format!("rollback-{}", id));
    let journal_path = journal_dir.join(format!("restore-{}.json", id));
    // C-11：写前日志与正式日志同名不同后缀，成功收尾时删除。
    let wal_path = journal_wal_path(&journal_path);
    let family = distro::DistroInfo::detect().family;

    // C-10：manifest 条目 → 类型/策略查询表（用 `data/` 之后的相对路径作 key）。
    // 路径非法不再静默丢弃（旧实现 `filter_map` 会吞掉非法条目），直接硬错误。
    let mut by_path: HashMap<String, &crate::model::ManifestEntry> = HashMap::new();
    for e in &manifest.entries {
        let p = safe_rel_path(&e.path).ok_or_else(|| {
            AppError::Format(format!(
                "manifest 含非法路径条目（绝对路径或越界 ..），拒绝还原：{}",
                e.path
            ))
        })?;
        by_path.insert(p.to_string_lossy().into_owned(), e);
    }

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut outcome = ExtractOutcome {
        journal_path: journal_path.clone(),
        journal: RestoreJournal {
            // C-39：写真实的 RFC3339 UTC 时间与真实的目标内核（不再占位）。
            created_at: secs_to_rfc3339(now_secs),
            target_kver: target_kver.to_string(),
            root: root.to_string_lossy().into_owned(),
            entries: Vec::new(),
        },
        ..Default::default()
    };
    let mut strategy_counts: HashMap<String, usize> = HashMap::new();

    // C-12：开跑前对本次将写入的父目录各做一次陈旧暂存清扫。
    // 只扫这些目录（`manifest` 登记路径的父目录）且只删 `.ldb-staging-*`，不扫全盘。
    let mut swept: HashSet<PathBuf> = HashSet::new();
    for key in by_path.keys() {
        let parent = Path::new(key.as_str()).parent().unwrap_or_else(|| Path::new(""));
        let dir = root.join(parent);
        if !swept.insert(dir.clone()) || !dir.is_dir() {
            continue;
        }
        let stale = sweep_staging(&dir);
        if stale > 0 {
            outcome_push_note(
                &mut outcome,
                format!("已清理 {} 个陈旧暂存文件：{}", stale, dir.display()),
            );
        }
    }

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

            // C-10：manifest 权威化——tar 中 manifest 没有的**普通文件/符号链接**条目
            // 一律硬错误拒绝写入（旧实现会照单写盘）。
            // 目录条目（MakeDir）放行：备份侧从不把目录写进 manifest（backup.rs 只追加
            // Regular/Symlink 条目），目录本身由写入路径的 [`safe_parent`] 逐段校验兜底。
            if meta.is_none() && matches!(action, EntryAction::Write | EntryAction::WriteSymlink) {
                return Err(AppError::Format(format!(
                    "归档含 manifest 未登记的写入条目，拒绝写入：/{}",
                    rel
                )));
            }

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

                    // C-02：逐组件校验父路径（拒绝符号链接组件，usr-merge 顶层别名除外）。
                    let parent = safe_parent(&root, &inner)?;
                    fs::create_dir_all(&parent)?;
                    let staged = staged_path(&link_dest, &id);
                    remove_any(&staged)?;
                    // C-12：暂存的符号链接由守卫兜底清理（`?` 提前返回也不残留）。
                    let _staging = StagingGuard::new(staged.clone());
                    std::os::unix::fs::symlink(&target, &staged)?;

                    // C-11（写前日志）：先 append + fsync，再 move_aside / rename。
                    // `rollback_path` 按与 `move_aside` 相同的公式词法预计算，
                    // `prior_existed` 与其判据同源（`symlink_metadata`），故日志可先行。
                    let prior_existed = fs::symlink_metadata(&link_dest).is_ok();
                    let entry = JournalEntry {
                        path: rel.clone(),
                        prior_existed,
                        rollback_path: prior_existed.then(|| {
                            rollback_dir
                                .join(rollback_file_name(&rel))
                                .to_string_lossy()
                                .into_owned()
                        }),
                        kind: "symlink".to_string(),
                    };
                    append_journal_wal(&wal_path, &entry)?;
                    let _rollback = move_aside(&link_dest, &rollback_dir, &rel)?;
                    fs::rename(&staged, &link_dest)?;
                    outcome.journal.entries.push(entry);
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
                    // C-02：目录条目本身不入事务日志，但其父路径必须先过逐段禁闭检查
                    // （否则 `data/a/b` 在 `root/a` 是外部链接时会被 `create_dir_all` 跟随）。
                    safe_parent(&root, &inner)?;
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
                        // C-02：先逐组件校验父路径（符号链接组件一律拒绝，usr-merge
                        // 顶层别名除外），确认安全后才 `create_dir_all`。
                        let parent = safe_parent(&root, &inner)?;
                        fs::create_dir_all(&parent)?;
                        let staged = staged_path(&dest, &id);
                        remove_any(&staged)?;
                        // C-12：暂存文件由守卫兜底清理（含 `?` 提前返回与取消路径）。
                        let _staging = StagingGuard::new(staged.clone());
                        let mut out = fs::OpenOptions::new()
                            .write(true)
                            .create(true)
                            .truncate(true)
                            .mode(FILE_MODE)
                            .open(&staged)?;
                        copy_with_cancel(&mut entry, &mut out, &req.cancel)?;
                        out.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
                        drop(out);

                        // C-11（写前日志）：先 append + fsync，再 move_aside / rename；
                        // `rollback_path` 与 `move_aside` 的落点公式一致，可词法预计算。
                        let prior_existed = fs::symlink_metadata(&dest).is_ok();
                        let journal_entry = JournalEntry {
                            path: rel.clone(),
                            prior_existed,
                            rollback_path: prior_existed.then(|| {
                                rollback_dir
                                    .join(rollback_file_name(&rel))
                                    .to_string_lossy()
                                    .into_owned()
                            }),
                            kind: format!(
                                "{:?}",
                                meta.map(|m| m.kind).unwrap_or(EntryKind::Config)
                            )
                            .to_lowercase(),
                        };
                        append_journal_wal(&wal_path, &journal_entry)?;
                        let _rollback = move_aside(&dest, &rollback_dir, &rel)?;
                        fs::rename(&staged, &dest)?;
                        outcome.journal.entries.push(journal_entry);
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
        // C-11：失败路径**不删**写前日志——正式 JSON 尚未写出，`.jsonl.tmp`
        // 是 `--rollback last` 唯一可据以回滚的凭据（`latest_journal` 会回退到它）。
        let rolled_back = rollback_entries(&root, &outcome.journal, &mut Vec::new());
        let mut message = err.to_string();
        let journal_hint = if wal_path.exists() {
            wal_path.display().to_string()
        } else {
            journal_path.display().to_string()
        };
        if let Ok(lines) = rolled_back {
            message.push_str(&format!(
                "\n已自动回滚 {} 条已提交变更（事务日志：{}）",
                lines, journal_hint
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

    // C-11：全部成功 → 原子写正式日志（写临时文件 + rename），随后删除写前日志；
    // 任何时刻只存在其中一份，`--rollback` 的"优先 JSON、回退 JSONL"据此成立。
    // C-39：`created_at`（RFC3339 UTC）与 `target_kver` 在日志构造时已填真实值。
    outcome.journal.save_atomic(&journal_path)?;
    let _ = fs::remove_file(&wal_path);
    // 按代数裁剪旧回滚数据（含残留的写前日志）。
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
    // C-11：与 `extract` 同名的写前日志（同一 run id）。
    let wal_path = journal_wal_path(journal_path);
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
        // C-02/C-12：回退拷贝与主提取路径共用同一套禁闭校验与暂存清理。
        let parent = safe_parent(&root, &inner)?;
        fs::create_dir_all(&parent)?;
        let staged = staged_path(&dest, &id);
        remove_any(&staged)?;
        let _staging = StagingGuard::new(staged.clone());
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(FILE_MODE)
            .open(&staged)?;
        copy_with_cancel(&mut entry, &mut out, &req.cancel)?;
        out.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
        drop(out);

        // C-11：回退拷贝同样写前日志（追加到本 run 的 `.jsonl.tmp`）。
        let prior_existed = fs::symlink_metadata(&dest).is_ok();
        let journal_entry = JournalEntry {
            path: rel.clone(),
            prior_existed,
            rollback_path: prior_existed.then(|| {
                rollback_dir
                    .join(rollback_file_name(&rel))
                    .to_string_lossy()
                    .into_owned()
            }),
            kind: "module-fallback".to_string(),
        };
        append_journal_wal(&wal_path, &journal_entry)?;
        let _rollback = move_aside(&dest, &rollback_dir, &rel)?;
        fs::rename(&staged, &dest)?;
        journal.entries.push(journal_entry);
        copied += 1;
    }
    if copied > 0 {
        // C-11：正式日志原子重写，随后清掉写前日志（两份并存时 `--rollback` 优先 JSON）。
        journal.save_atomic(journal_path)?;
        let _ = fs::remove_file(&wal_path);
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
///
/// C-11：日志文件可以是正式 `restore-<id>.json`，也可以是崩溃/失败后残留的
/// `restore-<id>.jsonl.tmp`（逐行 JSON，行序即条目序；回滚按逆序执行，
/// 即**最后写入的条目最先撤销**）。见 [`RestoreJournal::load`]。
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
/// 只保留最新的 `keep` 份事务日志与其回滚区，超出部分按时间清理（含残留的写前日志）。
fn prune_state(dir: &Path, keep: usize) -> Vec<String> {
    let mut notes = Vec::new();
    let mut ids: Vec<u64> = Vec::new();
    let Ok(iter) = fs::read_dir(dir) else {
        return notes;
    };
    for entry in iter.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some((id, _)) = journal_file_id(&name) {
            ids.push(id);
        }
    }
    ids.sort_unstable_by(|a, b| b.cmp(a));
    ids.dedup();
    for id in ids.into_iter().skip(keep.max(1)) {
        let journal = dir.join(format!("restore-{}.json", id));
        let wal = dir.join(format!("restore-{}{}", id, WAL_SUFFIX));
        let rollback = dir.join(format!("rollback-{}", id));
        let _ = fs::remove_file(&wal);
        if remove_any(&journal).is_ok() && remove_any(&rollback).is_ok() {
            notes.push(format!("已清理过期回滚数据：{id}"));
        }
    }
    notes
}

/// C-11: classify a state-directory file name as a journal, returning
/// `(run id, is_committed_json)`. `rollback-*` dirs and unrelated files yield `None`.
/// C-11：识别状态目录里的日志文件名，返回 `(run id, 是否正式 JSON)`；
/// `rollback-*` 目录与其它杂项返回 `None`（历史上曾因对它们 `?` 提前返回而漏判）。
fn journal_file_id(name: &str) -> Option<(u64, bool)> {
    let stem = name.strip_prefix("restore-")?;
    if let Some(id) = stem
        .strip_suffix(".json")
        .and_then(|n| n.parse::<u64>().ok())
    {
        return Some((id, true));
    }
    if let Some(id) = stem
        .strip_suffix(WAL_SUFFIX)
        .and_then(|n| n.parse::<u64>().ok())
    {
        return Some((id, false));
    }
    None
}

/// Locate the newest restore journal under a root.
/// 找到目标根下最新的还原日志。
///
/// C-11：同时识别正式 `restore-<id>.json` 与崩溃残留的 `restore-<id>.jsonl.tmp`；
/// 同一 id 下**优先正式 JSON**，只有写前日志时回退返回它（供 `--rollback` 解析）。
pub fn latest_journal(root: &Path) -> Option<PathBuf> {
    let dir = state_dir(root);
    // (run id, 是否正式 JSON, 路径)：正式 JSON 在同 id 下优先于写前日志。
    let mut best: Option<(u64, bool, PathBuf)> = None;
    for entry in fs::read_dir(&dir).ok()?.flatten() {
        let path = entry.path();
        // 注意：状态目录里同时存在 `rollback-*`（目录）与两类日志文件，
        // 必须**跳过**不匹配的条目，不能对它们使用 `?` 提前返回。
        let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        let Some((id, is_json)) = journal_file_id(&name) else {
            continue;
        };
        let better = match &best {
            None => true,
            Some((best_id, best_json, _)) => id > *best_id || (id == *best_id && is_json && !*best_json),
        };
        if better {
            best = Some((id, is_json, path));
        }
    }
    best.map(|(_, _, p)| p)
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

/// C-31: decide the target kernel and whether the user asked for it explicitly.
/// C-31：决定目标内核及其"是否显式指定"（纯函数，便于单测）：
/// - `req_kver` 显式指定 → 用它，`kver_explicit = true`；
/// - 否则 `root == None`（联网/本机还原）→ `host_kver`（`distro::kernel_release()`，当前内核）；
/// - 否则 `root == Some`（`--root` 离线还原）→ `manifest_kver`。
///
/// `kver_explicit == false` 时的内核不一致只降级为 `report.notes`，
/// 不再要求 `allow_kernel_mismatch`（见 [`run_restore`] 步骤 2）。
fn resolve_target_kver(
    req_kver: Option<&str>,
    root: Option<&Path>,
    manifest_kver: &str,
    host_kver: &str,
) -> (String, bool) {
    if let Some(kver) = req_kver {
        return (kver.to_string(), true);
    }
    match root {
        None => (host_kver.to_string(), false),
        Some(_) => (manifest_kver.to_string(), false),
    }
}

/// C-18/C-31: pure decision of the immutability gate (no command execution,
/// unit-testable); the caller performs any command only in the real-run path.
/// C-18/C-31：不可变系统闸门的**纯决策**——不执行任何命令，便于单测；
/// 调用方只在实盘路径上按此决策执行（dry-run 永远到不了闸门，见 `run_restore` 步骤 4/5）。
#[derive(Debug, Clone, PartialEq, Eq)]
enum ImmutableGate {
    /// 可放行（可变系统）。
    Pass,
    /// 拒绝直写并给出替代路径（消息可直接作为 `AppError::Validation` 的内容）。
    Refuse(String),
    /// 需要先执行 `rpm-ostree usroverlay`（仅在实盘路径中执行）。
    Usroverlay,
}

fn plan_immutable_gate(imm: distro::Immutability, policy: ImmutablePolicy) -> ImmutableGate {
    match imm {
        distro::Immutability::Mutable => ImmutableGate::Pass,
        distro::Immutability::Ostree => match policy {
            ImmutablePolicy::Refuse => ImmutableGate::Refuse(
                "目标为 OSTree 不可变系统（/usr 只读），拒绝直接写入 /usr/lib/modules。\
                 受支持的做法：① `rpm-ostree install <对应 kmod 包>`；\
                 ② `rpm-ostree override replace <本地 rpm>`；\
                 ③ 临时排障可加 --on-immutable usroverlay（重启即失效）。"
                    .to_string(),
            ),
            ImmutablePolicy::Usroverlay => ImmutableGate::Usroverlay,
        },
        distro::Immutability::Nix => ImmutableGate::Refuse(
            "目标为 NixOS：模块由声明式配置（nixos-rebuild）管理，本工具不支持直接还原。\
             请把驱动加入 configuration.nix 后重建系统。"
                .to_string(),
        ),
        distro::Immutability::ReadOnlyUsr => ImmutableGate::Refuse(
            "目标系统的 /usr 以只读方式挂载，无法写入模块目录。\
             请先解除只读（或使用 --root 做离线还原）。"
                .to_string(),
        ),
    }
}

/// C-18: read-only hint shown by **dry-run** instead of running the gate.
/// C-18：dry-run 用的**只读提示**——说明实盘还原将需要什么，但不执行任何命令
/// （`rpm-ostree usroverlay` 之类只在 `run_restore` 步骤 5 的实盘路径里运行）。
fn immutable_dry_run_hint(imm: distro::Immutability) -> String {
    match imm {
        distro::Immutability::Mutable => {
            format!("目标系统可变性：{}——实盘还原可直接写入", imm.label_zh())
        }
        distro::Immutability::Ostree => {
            "实盘还原将需要 --on-immutable usroverlay（或改用 rpm-ostree 安装 kmod 包）；\
             本 dry-run 只读不执行任何命令"
                .to_string()
        }
        distro::Immutability::Nix => {
            "实盘还原将被拒绝：NixOS 需通过 configuration.nix 声明驱动；\
             本 dry-run 只读不执行任何命令"
                .to_string()
        }
        distro::Immutability::ReadOnlyUsr => {
            "实盘还原将被拒绝：/usr 只读挂载，需先解除只读或改用 --root；\
             本 dry-run 只读不执行任何命令"
                .to_string()
        }
    }
}

/// Run a full restore.
/// 执行还原（v0.2.1 顺序，DESIGN.md §5.5 + ROADMAP §3 P0 + ITERATION §2.1 C-18/C-31/C-32）：
///
/// 1. `inspect` 取 manifest；目标 kver 由 [`resolve_target_kver`] 决定（显式 `--kver` → 用它；
///    否则联网/本机默认**当前内核**、`--root` 离线默认 `manifest.kernel_release`），
///    必须通过 `model::is_safe_kernel_version`。
/// 2. 一致性校验（C-31/C-32 已拆分）：架构不符仅 `allow_arch_mismatch` 可放行；
///    内核/vermagic 不符在**显式**指定 kver 时才要求 `allow_kernel_mismatch`，
///    auto 目标降级为 `report.notes` 提示。
/// 3. 权限：写 `/`（非 dry_run）且非 root → `AppError::Privilege`（由 `main` 决定 pkexec 重入）；
///    指定 `--root <dir>` 的离线还原按目标目录自身权限判定（救援场景常以普通用户预演）。
/// 4. dry-run：统计文件/链接/字节 + **策略预览**（重建/重装/弱更新/拷贝），不落盘；
///    仅**只读**探测 [`distro::immutability`] 并提示实盘将需要什么——不执行任何命令（C-18）。
/// 5. **不可变系统闸门（P0-3）**：C-18 后移到 dry-run 分支**之后**，只有实盘还原才可能
///    执行 `rpm-ostree usroverlay`；OSTree/Nix/只读 `/usr` 默认拒绝直写，给出替代路径。
/// 6. 事务化解压（P0-1 符号链接、P0-5 来源包、P0-6 回滚日志 + C-11 写前日志）。
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
    // C-31：目标内核语义——显式 `--kver` 优先；否则联网/本机默认当前内核，
    // `--root` 离线默认 manifest 记录的内核。
    let (target_kver, kver_explicit) = resolve_target_kver(
        req.kver.as_deref(),
        req.root.as_deref(),
        &manifest.kernel_release,
        &distro::kernel_release(),
    );

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

    // ---- 步骤 2：架构（C-32 独立）/ 内核与 vermagic（C-31 分级）一致性 ----
    let cur_arch = distro::arch();
    // C-32：架构不符**只**看 `allow_arch_mismatch`，与 `allow_kernel_mismatch` 无关。
    if manifest.arch.as_str() != cur_arch {
        if req.allow_arch_mismatch {
            report.notes.push(format!(
                "已由用户确认的架构不一致：备份 {} / 当前 {}；架构不符的模块无法加载",
                manifest.arch, cur_arch
            ));
        } else {
            return Err(AppError::Validation(format!(
                "备份架构与当前不符，需用户确认：备份 {} / 当前 {}\
                 （确认后重试并设置 --allow-arch-mismatch / allow_arch_mismatch；\
                 --allow-kernel-mismatch 不覆盖架构检查）",
                manifest.arch, cur_arch
            )));
        }
    }
    // C-31：内核不符——auto 目标（未显式指定 --kver）降级为提示；
    // 显式目标才需要 `--allow-kernel-mismatch` 确认。
    if manifest.kernel_release != target_kver {
        if !kver_explicit {
            report.notes.push(format!(
                "跨内核还原：将按当前内核重建（DKMS）…（未显式指定 --kver：备份 {} / 目标 {}）",
                manifest.kernel_release, target_kver
            ));
        } else if req.allow_kernel_mismatch {
            report.notes.push(format!(
                "已由用户确认的内核不一致：备份 {} / 目标 {}；跨内核还原可能导致模块 ABI 不兼容",
                manifest.kernel_release, target_kver
            ));
        } else {
            return Err(AppError::Validation(format!(
                "备份内核与目标不符，需用户确认：备份 {} / 目标 {}\
                 （确认后重试并设置 --allow-kernel-mismatch；架构不符请改用 --allow-arch-mismatch）",
                manifest.kernel_release, target_kver
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
            if !kver_explicit {
                // C-31：auto 目标同样降级为提示（用户未点名内核，无需二次确认）。
                report.notes.push(format!(
                    "{}；自动目标内核（未显式指定 --kver）：建议 --strategy rebuild（DKMS 重建）",
                    msg
                ));
            } else if req.allow_kernel_mismatch {
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

    // C-18：此处只做**只读**的可变性探测（读标志文件与 /proc/mounts，不执行任何命令）。
    // 含命令执行的不可变闸门已后移到 dry-run 分支之后（见"步骤 5"）。
    let immutability = distro::immutability();

    // manifest 条目 → 类型表（dry-run 的固件判定用）。
    // C-10：路径非法直接硬错误，不再 `filter_map` 静默丢弃。
    let mut kinds: HashMap<String, EntryKind> = HashMap::new();
    for e in &manifest.entries {
        let p = safe_rel_path(&e.path).ok_or_else(|| {
            AppError::Format(format!(
                "manifest 含非法路径条目（绝对路径或越界 ..），拒绝还原：{}",
                e.path
            ))
        })?;
        kinds.insert(p.to_string_lossy().into_owned(), e.kind);
    }

    // ---- 步骤 4：dry-run 只统计与预览（C-18：本分支内绝不执行任何变更命令）----
    if req.dry_run {
        report.notes.push(format!(
            "目标系统可变性：{}（写入根：{}）",
            immutability.label_zh(),
            root.display()
        ));
        if !offline && immutability != distro::Immutability::Mutable {
            // 只提示"实盘还原将需要什么"，不执行 `rpm-ostree usroverlay` 等任何命令。
            report
                .notes
                .push(immutable_dry_run_hint(immutability));
        }
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

    // ---- 步骤 5：不可变系统闸门（P0-3；C-18：位于 dry-run 分支**之后**，仅实盘执行）----
    // 纯决策（`plan_immutable_gate`，可单测）与命令执行分离：只有 `Usroverlay`
    // 分支会真正运行 `rpm-ostree usroverlay`，而 dry-run 在上一分支已经 return。
    if !offline {
        match plan_immutable_gate(immutability, req.on_immutable) {
            ImmutableGate::Pass => {}
            ImmutableGate::Refuse(msg) => return Err(AppError::Validation(msg)),
            ImmutableGate::Usroverlay => {
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
        }
    }
    report.notes.push(format!(
        "目标系统可变性：{}（写入根：{}）",
        immutability.label_zh(),
        root.display()
    ));

    // ---- 步骤 6：事务化解压（含符号链接与策略分流）----
    let outcome = extract(&req, &manifest, &target_kver)?;
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
            no_auto_rollback_on_post: false,
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

    // =======================================================================
    // v0.2.1 热修包新增测试：
    // C-01 etc 链接禁闭 / C-02 写入禁闭 / C-10 manifest 权威 /
    // C-11 写前日志(WAL) / C-12 暂存清扫 / C-18 不可变闸门顺序 /
    // C-31 内核确认分级 / C-32 架构确认独立 / C-39 RFC3339 时间戳
    // =======================================================================

    /// 生成一份最小可用的 `manifest.json`（arch / kernel_release / 条目均可参数化）。
    /// Build a minimal `manifest.json` with explicit arch, kernel release and entries.
    ///
    /// `entries` 为 `(归档相对路径, EntryKind 小写标签)`；其余 v2 字段取安全默认
    /// （`content_stored=true`、无 `kernel_vermagic`、无 DKMS/来源包）。
    /// Entries are `(archive-relative path, lowercase EntryKind tag)`; other v2
    /// fields take safe defaults (content stored, no vermagic, no DKMS/provenance).
    fn manifest_json(arch: &str, kver: &str, entries: &[(&str, &str)]) -> String {
        let items: Vec<String> = entries
            .iter()
            .map(|(path, kind)| {
                format!(
                    r#"{{"path":"{}","size":5,"sha256":"abc","kind":"{}"}}"#,
                    path, kind
                )
            })
            .collect();
        let items = items.join(",");
        format!(
            r#"{{
  "format_version": 2,
  "tool_version": "0.2.1",
  "created_at": "2026-10-01T00:00:00Z",
  "kernel_release": "{kver}",
  "arch": "{arch}",
  "distro": {{"id":"linuxmint","version_id":"22.3","pretty_name":"Linux Mint 22.3","family":"debian"}},
  "mode": "standard",
  "entries": [{items}],
  "warnings": []
}}"#
        )
    }

    /// 递归断言目标根下没有任何 `.ldb-staging-*` 暂存残留（C-12）。
    /// Recursively assert that no `.ldb-staging-*` leftovers remain under the root.
    fn assert_no_staging_leftovers(root: &Path) {
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(rd) = fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if e.file_name().to_string_lossy().starts_with(STAGE_PREFIX) {
                    out.push(p.clone());
                }
                if p.is_dir() {
                    walk(&p, out);
                }
            }
        }
        let mut left = Vec::new();
        walk(root, &mut left);
        assert!(left.is_empty(), "残留暂存文件：{left:?}");
    }

    /// C-01（还原侧）：`etc/` 下符号链接目标词法解析后必须落在 `/etc` 树或白名单前缀内。
    /// C-01 (restore side): `etc/` link targets must resolve lexically into the
    /// `/etc` tree or the whitelist prefixes (`/etc/`,`/lib/`,`/usr/lib/`,
    /// `/usr/share/`,`/run/`); anything else is a Format error whose message
    /// carries the normalized path. 与 `backup.rs::validate_link_target_etc_containment_c01`
    /// 互为镜像（v0.3.0 W7/C-47 合并后二选一）。
    #[test]
    fn etc_link_target_containment_c01() {
        // ---- 拒绝：根、越出归档根的相对目标、白名单之外的路径 ----
        assert!(validate_link_target("etc/x", "/").is_err(), "`/` 必须被拒");
        assert!(
            validate_link_target("etc/x", "../../../../..").is_err(),
            "越出归档根的相对目标必须被拒"
        );
        assert!(
            validate_link_target("etc/x", "/home/user/pwn").is_err(),
            "白名单之外的绝对目标必须被拒"
        );
        assert!(
            validate_link_target("etc/x", "../../home/user/pwn").is_err(),
            "解析到 /home 的相对目标必须被拒"
        );
        assert!(validate_link_target("etc/x", "../../../root/.bashrc").is_err());
        assert!(validate_link_target("etc/x", "/librarian").is_err(), "/librarian 不是 /lib/");
        assert!(validate_link_target("etc/x", "").is_err(), "空目标必须被拒");

        // ---- 放行：etc 树内（Verbatim 重建）----
        assert!(matches!(
            validate_link_target("etc/modules-load.d/modules.conf", "../modules"),
            Ok(LinkPlan::Verbatim)
        ));
        assert!(matches!(
            validate_link_target("etc/x", "modules"),
            Ok(LinkPlan::Verbatim)
        ));
        // ---- 放行：白名单前缀（真实样例 usr-merge / usr-merge 前）----
        assert!(matches!(
            validate_link_target(
                "etc/modprobe.d/blacklist-oss.conf",
                "/lib/linux-sound-base/noOSS.modprobe.conf"
            ),
            Ok(LinkPlan::Verbatim)
        ));
        assert!(validate_link_target("etc/x", "/usr/lib/foo").is_ok());
        assert!(validate_link_target("etc/x", "/usr/share/foo").is_ok());
        assert!(validate_link_target("etc/x", "/run/foo").is_ok());

        // ---- 错误消息带归一化结果（中文侧）----
        match validate_link_target("etc/x", "/home/user/pwn") {
            Err(AppError::Format(m)) => assert!(m.contains("归一化"), "消息={m}"),
            Err(other) => panic!("expected AppError::Format, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    /// C-02：写入前的父路径禁闭检查——拒绝任何符号链接组件（仅顶层 usr-merge 别名例外）。
    /// C-02: `safe_parent` rejects every symlinked path component before any
    /// write (the top-level usr-merge aliases `lib`/`bin`/`sbin`/`lib64` are the
    /// only exception), rejects `..`/absolute components, and treats missing
    /// components as safe while returning the full parent path.
    #[test]
    fn safe_parent_rejects_symlinks_and_allows_top_level_usrmerge_alias_c02() {
        let root = temp_case("safe-parent");

        // (a) 顶层非别名符号链接 → 拒绝（`root/opt -> root/var`）
        fs::create_dir_all(root.join("var")).unwrap();
        std::os::unix::fs::symlink(root.join("var"), root.join("opt")).unwrap();
        let err = safe_parent(&root, Path::new("opt/evil.conf")).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("符号链接组件"), "顶层链接组件必须被拒：{msg}");
        assert!(matches!(err, AppError::Format(_)), "应为 Format 错误");

        // (b) 顶层 usr-merge 别名（`root/lib -> usr/lib`）放行；其下缺失组件视为安全
        fs::create_dir_all(root.join("usr/lib")).unwrap();
        std::os::unix::fs::symlink("usr/lib", root.join("lib")).unwrap();
        assert_eq!(
            safe_parent(&root, Path::new("lib/modules/6.8/x.ko")).unwrap(),
            root.join("lib/modules/6.8"),
            "别名之下的缺失组件应返回完整父路径"
        );

        // (c) 别名之下的更深层符号链接仍然拒绝（例外只限第 0 层）
        fs::create_dir_all(root.join("usr/lib/modules")).unwrap();
        std::os::unix::fs::symlink(root.join("var"), root.join("usr/lib/modules/evil")).unwrap();
        let err = safe_parent(&root, Path::new("lib/modules/evil/x.ko")).unwrap_err();
        assert!(
            err.to_string().contains("符号链接组件"),
            "更深层链接组件必须被拒：{err}"
        );

        // (d) 组件不存在 → 其后必然不存在，视为安全并返回完整父路径
        assert_eq!(
            safe_parent(&root, Path::new("a/b/c.ko")).unwrap(),
            root.join("a/b")
        );

        // (e) `..` 与绝对路径组件（RootDir / ParentDir）一律拒绝
        fs::create_dir_all(root.join("a")).unwrap();
        let err = safe_parent(&root, Path::new("a/../../x.ko")).unwrap_err();
        assert!(err.to_string().contains("非法组件"), "`..` 组件必须被拒：{err}");
        let err = safe_parent(&root, Path::new("/etc/x")).unwrap_err();
        assert!(err.to_string().contains("非法组件"), "绝对路径必须被拒：{err}");

        let _ = fs::remove_dir_all(&root);
    }

    /// C-10：tar 中 manifest 未登记的普通文件是硬错误，且已写入条目自动回滚。
    /// C-10: a regular-file entry missing from the manifest is a hard Format
    /// error; entries written before the failure are rolled back automatically
    /// and no unregistered file ever lands on disk.
    #[test]
    fn manifest_extra_write_entry_is_hard_error_c10() {
        let dir = temp_case("c10-extra");
        let root = dir.join("root");
        fs::create_dir_all(&root).unwrap();
        let manifest = manifest_json(
            distro::arch(),
            "6.8.0-45-generic",
            &[("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko", "module")],
        );
        let archive = build_archive(
            &dir,
            "c10-extra.tar.gz",
            &[
                (
                    "data/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko",
                    b"hello".as_slice(),
                ),
                // manifest 未登记 → 必须被硬错误拒绝
                ("data/etc/pwn.conf", b"evil".as_slice()),
            ],
            Some(&manifest),
        );
        let info = inspect(&archive).unwrap();
        let req = RestoreRequest {
            archive,
            root: Some(root.clone()),
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };
        let err = extract(&req, &info.manifest, &info.manifest.kernel_release).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("manifest") && msg.contains("pwn.conf"),
            "消息应指明未登记条目：{msg}"
        );
        assert!(msg.contains("已自动回滚 1 条"), "应报告自动回滚：{msg}");

        // 未登记文件绝不落盘；先前写入的条目也被回滚；无暂存残留
        assert!(!root.join("etc/pwn.conf").exists(), "未登记文件不得写入");
        assert!(
            !root.join("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko").exists(),
            "先行写入的条目必须被回滚"
        );
        assert_no_staging_leftovers(&root);
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-10：manifest 登记了非法路径（`..`）→ 解析类型表时直接硬错误，不静默过滤。
    /// C-10: a manifest entry whose path escapes the archive root is a hard
    /// error while building the lookup table — never silently dropped.
    #[test]
    fn manifest_illegal_path_is_hard_error_c10() {
        let dir = temp_case("c10-illegal");
        let root = dir.join("root");
        fs::create_dir_all(&root).unwrap();
        let manifest = manifest_json(
            distro::arch(),
            "6.8.0-45-generic",
            &[("../evil.ko", "module")],
        );
        let archive = build_archive(&dir, "c10-illegal.tar.gz", &[], Some(&manifest));
        let info = inspect(&archive).unwrap();
        let req = RestoreRequest {
            archive,
            root: Some(root.clone()),
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };
        let err = extract(&req, &info.manifest, &info.manifest.kernel_release).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("非法路径") && msg.contains("../evil.ko"),
            "消息应指明非法条目：{msg}"
        );
        assert!(!root.join("evil.ko").exists(), "非法路径不得落盘");
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-11/C-12：解压中途失败 → 写前日志保留（唯一回滚凭据）、暂存零残留、
    /// 凭 `.jsonl.tmp` 即可完成回滚。
    /// C-11/C-12: when extraction fails midway, the write-ahead log is kept as
    /// the only rollback credential, no `.ldb-staging-*` files remain, and
    /// `run_rollback` can consume the WAL to undo the partial run.
    #[test]
    fn failed_extract_keeps_write_ahead_log_and_no_staging_c11_c12() {
        let dir = temp_case("c11-wal-fail");
        let root = dir.join("root");
        fs::create_dir_all(&root).unwrap();
        // 故障注入：`root/etc` 是普通文件 → 第 1 个条目（lib/…）写入成功，
        // 第 2 个条目（etc/…）在逐段禁闭检查时撞上 ENOTDIR 而失败。
        fs::write(root.join("etc"), b"not-a-directory").unwrap();
        let manifest = manifest_json(
            distro::arch(),
            "6.8.0-45-generic",
            &[
                ("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko", "module"),
                ("etc/modprobe.d/nvidia.conf", "config"),
            ],
        );
        let archive = build_archive(
            &dir,
            "c11-wal-fail.tar.gz",
            &[
                (
                    "data/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko",
                    b"hello".as_slice(),
                ),
                ("data/etc/modprobe.d/nvidia.conf", b"1234567".as_slice()),
            ],
            Some(&manifest),
        );
        let info = inspect(&archive).unwrap();
        let req = RestoreRequest {
            archive,
            root: Some(root.clone()),
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };
        let err = extract(&req, &info.manifest, &info.manifest.kernel_release).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("已自动回滚 1 条"), "应自动回滚首个条目：{msg}");

        // 失败后：正式 JSON 不存在，但写前日志存在、有内容且逐行可解析
        let wal = latest_journal(&root).expect("失败后应能从写前日志回退定位");
        assert!(
            wal.to_string_lossy().ends_with(WAL_SUFFIX),
            "定位到的是 {wal:?}"
        );
        let text = fs::read_to_string(&wal).unwrap();
        let records: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
        assert_eq!(records.len(), 1, "WAL 应记录唯一已提交条目：{text}");
        assert!(
            serde_json::from_str::<JournalEntry>(records[0]).is_ok(),
            "WAL 每行必须是合法的 JournalEntry JSON"
        );
        // 第 1 个条目已被失败处理器回滚，磁盘上不留内容，也没有暂存残留
        assert!(!root.join("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko").exists());
        assert!(!root.join("etc/modprobe.d/nvidia.conf").exists());
        assert_no_staging_leftovers(&root);

        // 凭 WAL 回滚：删除当初新建的路径，并消费掉日志
        let report =
            run_rollback(&root, Some(wal.as_path()), Arc::new(|_v: f32, _m: String| {})).unwrap();
        assert_eq!(report.removed, 1, "回滚应删除 1 个当初新建的文件");
        assert!(!wal.exists(), "回滚后写前日志被消费");
        assert!(latest_journal(&root).is_none(), "状态目录不再有日志");
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-11：崩溃模拟——WAL 在任何变更**之前** append+fsync，正式 JSON 从未写出时
    /// 凭 `.jsonl.tmp` 仍可回滚（先写日志、后动文件的顺序契约）。
    /// C-11: crash simulation — the WAL line is fsynced *before* the file is
    /// touched and the committed JSON never appears; `run_rollback` still undoes
    /// the change from the `.jsonl.tmp` alone (write-ahead ordering contract).
    #[test]
    fn write_ahead_log_rolls_back_after_crash_c11() {
        let root = temp_case("c11-wal-crash");
        let dest = root.join("etc/pwned.conf");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, b"old").unwrap();

        let rel = "etc/pwned.conf";
        let rollback_dir = state_dir(&root).join("rollback-999");
        let journal_path = state_dir(&root).join("restore-999.json");
        let wal = journal_wal_path(&journal_path);
        let record = JournalEntry {
            path: rel.to_string(),
            prior_existed: true,
            rollback_path: Some(
                rollback_dir
                    .join(rollback_file_name(rel))
                    .to_string_lossy()
                    .into_owned(),
            ),
            kind: "config".to_string(),
        };

        // 契约顺序：先 append + fsync WAL，再 move_aside / 写入新内容
        append_journal_wal(&wal, &record).unwrap();
        move_aside(&dest, &rollback_dir, rel)
            .unwrap()
            .expect("原文件应被移入回滚区");
        fs::write(&dest, b"new").unwrap();
        // 崩溃点：正式 JSON 从未写出
        assert!(!journal_path.exists(), "模拟崩溃：无正式日志");

        let report =
            run_rollback(&root, Some(wal.as_path()), Arc::new(|_v: f32, _m: String| {})).unwrap();
        assert_eq!(report.restored, 1, "应恢复 1 个原文件");
        assert_eq!(fs::read(&dest).unwrap(), b"old", "凭 WAL 应恢复原文件");
        assert!(!wal.exists(), "回滚消费掉写前日志");
        let _ = fs::remove_dir_all(&root);
    }

    /// C-11：`latest_journal` 同时识别正式 JSON 与写前日志——更新的 id 胜出，
    /// 同一 id 下优先 JSON，只有 WAL 时回退返回它（`--rollback` 据此可用）。
    /// C-11: `latest_journal` recognises both the committed JSON and the WAL:
    /// newest run id wins, JSON beats WAL for the same id, WAL is the fallback,
    /// and `rollback-*` directories / junk files are never mistaken for journals.
    #[test]
    fn latest_journal_prefers_json_and_falls_back_to_wal_c11() {
        let root = temp_case("c11-latest");
        let dir = state_dir(&root);
        fs::create_dir_all(&dir).unwrap();
        let json = r#"{"created_at":"","target_kver":"","root":"","entries":[]}"#;
        let wal_line = r#"{"path":"a.ko","prior_existed":false,"kind":"module"}"#;
        fs::write(dir.join("restore-100.json"), json).unwrap();
        fs::write(
            dir.join(format!("restore-100{}", WAL_SUFFIX)),
            format!("{wal_line}\n"),
        )
        .unwrap();
        fs::write(
            dir.join(format!("restore-200{}", WAL_SUFFIX)),
            format!("{wal_line}\n"),
        )
        .unwrap();
        // 干扰项：rollback 目录与无关文件不得被当作日志
        fs::create_dir_all(dir.join("rollback-300")).unwrap();
        fs::write(dir.join("junk.txt"), b"x").unwrap();

        // 更新的 id（200，仅 WAL）胜出
        let newest = latest_journal(&root).unwrap();
        assert!(
            newest.ends_with(format!("restore-200{}", WAL_SUFFIX)),
            "取到的是 {newest:?}"
        );

        // 同一 id 下正式 JSON 优先于 WAL
        fs::remove_file(dir.join(format!("restore-200{}", WAL_SUFFIX))).unwrap();
        let prefer = latest_journal(&root).unwrap();
        assert!(prefer.ends_with("restore-100.json"), "取到的是 {prefer:?}");

        // 只剩 WAL → 回退返回它
        fs::remove_file(dir.join("restore-100.json")).unwrap();
        let fallback = latest_journal(&root).unwrap();
        assert!(
            fallback.to_string_lossy().ends_with(WAL_SUFFIX),
            "取到的是 {fallback:?}"
        );

        // 清空后返回 None
        fs::remove_file(dir.join(format!("restore-100{}", WAL_SUFFIX))).unwrap();
        assert!(latest_journal(&root).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    /// C-11/C-12/C-39：成功的离线还原——开跑前清扫陈旧暂存，结束后原子提交带
    /// RFC3339 UTC 时间与真实目标内核的正式日志、删除写前日志、零暂存残留。
    /// C-11/C-12/C-39: a successful offline restore sweeps stale staged files up
    /// front, then commits a journal stamped with a real RFC3339 UTC timestamp
    /// and the real target kernel, removes the WAL, and leaves no leftovers.
    #[test]
    fn successful_restore_commits_rfc3339_journal_and_sweeps_staging_c11_c12_c39() {
        let dir = temp_case("c11-c12-ok");
        let root = dir.join("root");
        let kver = "6.8.0-45-generic";
        let manifest = manifest_json(
            distro::arch(),
            kver,
            &[
                ("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko", "module"),
                ("etc/modprobe.d/nvidia.conf", "config"),
            ],
        );
        let archive = build_archive(
            &dir,
            "ok.tar.gz",
            &[
                (
                    "data/lib/modules/6.8.0-45-generic/updates/dkms/foo.ko",
                    b"hello".as_slice(),
                ),
                ("data/etc/modprobe.d/nvidia.conf", b"1234567".as_slice()),
            ],
            Some(&manifest),
        );
        // 预置陈旧暂存文件（C-12：开跑前必须被清扫并记入 notes）
        let stale_dir = root.join("lib/modules/6.8.0-45-generic/updates/dkms");
        fs::create_dir_all(&stale_dir).unwrap();
        let stale = stale_dir.join(format!("{}OLD-x.ko", STAGE_PREFIX));
        fs::write(&stale, b"stale").unwrap();

        let req = RestoreRequest {
            archive,
            root: Some(root.clone()),
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };
        let report = run_restore(req).unwrap();

        // 写入结果与暂存清扫
        assert_eq!(report.written, 2, "两个条目都应写入：{:?}", report.notes);
        assert_eq!(report.links_written, 0);
        assert!(!stale.exists(), "陈旧暂存文件必须被清扫");
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("已清理 1 个陈旧暂存文件")),
            "notes={:?}",
            report.notes
        );
        assert_no_staging_leftovers(&root);
        assert!(!report.depmod_done, "离线（--root）不得执行 depmod");
        assert!(
            report.notes.iter().any(|n| n.contains("跳过 depmod")),
            "notes={:?}",
            report.notes
        );
        assert_eq!(
            fs::read(root.join("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko")).unwrap(),
            b"hello"
        );
        assert_eq!(
            fs::read(root.join("etc/modprobe.d/nvidia.conf")).unwrap(),
            b"1234567"
        );

        // 正式日志：RFC3339 UTC + 真实目标内核 + 两个条目
        let journal_path = report.rollback_journal.clone().expect("应记录事务日志");
        assert!(journal_path.exists());
        let journal = RestoreJournal::load(&journal_path).unwrap();
        let created = &journal.created_at;
        assert_eq!(created.len(), 20, "RFC3339 应为 20 字符：{created}");
        let pat = "0000-00-00T00:00:00Z";
        assert!(
            created.chars().zip(pat.chars()).all(|(a, b)| match b {
                '0' => a.is_ascii_digit(),
                c => a == c,
            }),
            "不是 RFC3339 UTC：{created}"
        );
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        assert!(
            created.as_str() >= secs_to_rfc3339(now.saturating_sub(120)).as_str()
                && created.as_str() <= secs_to_rfc3339(now + 120).as_str(),
            "created_at 应接近当前时刻：{created}"
        );
        assert_eq!(journal.target_kver, kver, "目标内核必须写入日志");
        assert_eq!(journal.entries.len(), 2, "两个条目都要入账");

        // 成功收尾：写前日志与 .new 临时文件都不存在
        let state = state_dir(&root);
        assert!(!journal_wal_path(&journal_path).exists(), "成功后必须删除 WAL");
        let leftovers: Vec<String> = fs::read_dir(&state)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".new") || n.ends_with(WAL_SUFFIX) || n.starts_with(STAGE_PREFIX))
            .collect();
        assert!(leftovers.is_empty(), "状态目录残留临时文件：{leftovers:?}");

        let _ = fs::remove_dir_all(&dir);
    }

    /// C-31：目标内核解析的三条默认规则（纯函数）。
    /// C-31: the three defaulting rules of target-kernel resolution (pure fn).
    #[test]
    fn resolve_target_kver_defaults_c31() {
        let host = "6.8.0-99-host";
        let manifest_kver = "6.8.0-45-generic";
        // 显式 `--kver` 优先，并标记为"显式"（触发一致性确认）
        assert_eq!(
            resolve_target_kver(Some("1.2.3-foreign"), None, manifest_kver, host),
            ("1.2.3-foreign".to_string(), true)
        );
        // 未指定 + 本机/联网（root=None）→ 当前内核，非显式
        assert_eq!(
            resolve_target_kver(None, None, manifest_kver, host),
            (host.to_string(), false)
        );
        // 未指定 + `--root` 离线 → manifest 记录的内核，非显式
        assert_eq!(
            resolve_target_kver(None, Some(Path::new("/mnt")), manifest_kver, host),
            (manifest_kver.to_string(), false)
        );
    }

    /// C-32：架构确认与内核确认互相独立——`allow_kernel_mismatch=true` 绝不能
    /// 放行未确认的架构不符。
    /// C-32: arch confirmation is independent of kernel confirmation — a set
    /// `allow_kernel_mismatch` must never release an unconfirmed arch mismatch;
    /// only `allow_arch_mismatch` does.
    #[test]
    fn arch_mismatch_is_independent_of_kernel_confirmation_c32() {
        let dir = temp_case("c32-arch");
        let host_arch = distro::arch();
        let other_arch = if host_arch == "x86_64" { "aarch64" } else { "x86_64" };
        let manifest = manifest_json(
            other_arch,
            "6.8.0-45-generic",
            &[("etc/modprobe.d/x.conf", "config")],
        );
        let archive = build_archive(
            &dir,
            "c32.tar.gz",
            &[("data/etc/modprobe.d/x.conf", b"abc".as_slice())],
            Some(&manifest),
        );
        let mk = |allow_arch: bool, allow_kernel: bool| RestoreRequest {
            archive: archive.clone(),
            kver: None,
            dry_run: true, // 只校验一致性，不落盘
            allow_arch_mismatch: allow_arch,
            allow_kernel_mismatch: allow_kernel, // 即便为 true 也不得覆盖架构检查
            root: Some(dir.join("root")),
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };

        // 已确认内核不一致，但未确认架构 → 仍必须失败，且提示自己的开关
        let err = run_restore(mk(false, true)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("架构") && msg.contains("allow-arch-mismatch"),
            "架构错误必须提示自己的开关：{msg}"
        );
        assert!(
            !msg.contains("备份内核与目标不符"),
            "不应先撞内核检查：{msg}"
        );

        // 两个开关都确认 → 放行并记录确认说明
        let report = run_restore(mk(true, true)).unwrap();
        assert!(report.dry_run);
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("已由用户确认的架构不一致")),
            "notes={:?}",
            report.notes
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-31：显式 `--kver` 与备份内核不符 → 必须 `--allow-kernel-mismatch` 确认；
    /// 未显式指定时的跨内核目标只降级为提示（不阻塞）。
    /// C-31: an explicit `--kver` differing from the backup kernel requires
    /// `--allow-kernel-mismatch`; an implicit (auto) target only degrades to a
    /// note and keeps going.
    #[test]
    fn explicit_kver_mismatch_requires_kernel_confirmation_c31() {
        let dir = temp_case("c31-kver");
        let manifest = manifest_json(
            distro::arch(),
            "0.0.0-notest",
            &[("etc/modprobe.d/x.conf", "config")],
        );
        let archive = build_archive(
            &dir,
            "c31.tar.gz",
            &[("data/etc/modprobe.d/x.conf", b"abc".as_slice())],
            Some(&manifest),
        );
        let mk = |kver: Option<&str>, allow: bool, root: Option<PathBuf>| RestoreRequest {
            archive: archive.clone(),
            kver: kver.map(str::to_string),
            dry_run: true,
            allow_kernel_mismatch: allow,
            root,
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };

        // 显式目标与备份不符 + 未确认 → 硬错误，提示自己的开关
        let err = run_restore(mk(Some("1.2.3-foreign"), false, None)).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("备份内核与目标不符") && msg.contains("allow-kernel-mismatch"),
            "消息：{msg}"
        );

        // 确认后放行（dry-run 记录确认说明）
        let report = run_restore(mk(Some("1.2.3-foreign"), true, None)).unwrap();
        assert!(
            report
                .notes
                .iter()
                .any(|n| n.contains("已由用户确认的内核不一致")),
            "notes={:?}",
            report.notes
        );

        // auto（未显式 --kver）：与当前内核不一致只降级为"跨内核还原"提示
        let report = run_restore(mk(None, false, None)).unwrap();
        assert!(
            report.notes.iter().any(|n| n.contains("跨内核还原")),
            "auto 目标应降级为提示：{:?}",
            report.notes
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-18：不可变系统闸门的**纯决策**与 dry-run 只读提示（全程不执行任何命令）。
    /// C-18: pure decisions of the immutability gate plus the read-only dry-run
    /// hint — no command is ever executed by these functions.
    #[test]
    fn plan_immutable_gate_decisions_c18() {
        // 可变系统：一律放行
        assert_eq!(
            plan_immutable_gate(distro::Immutability::Mutable, ImmutablePolicy::Refuse),
            ImmutableGate::Pass
        );
        assert_eq!(
            plan_immutable_gate(distro::Immutability::Mutable, ImmutablePolicy::Usroverlay),
            ImmutableGate::Pass
        );
        // OSTree + 默认策略 → 拒绝并给出受支持的替代路径
        match plan_immutable_gate(distro::Immutability::Ostree, ImmutablePolicy::Refuse) {
            ImmutableGate::Refuse(msg) => {
                assert!(msg.contains("rpm-ostree"), "消息：{msg}");
                assert!(msg.contains("usroverlay"), "消息：{msg}");
            }
            other => panic!("期望 Refuse，得到 {other:?}"),
        }
        // OSTree + usroverlay → 需先执行命令（只在实盘路径执行，见 dry-run 测试）
        assert_eq!(
            plan_immutable_gate(distro::Immutability::Ostree, ImmutablePolicy::Usroverlay),
            ImmutableGate::Usroverlay
        );
        // NixOS / 只读 /usr：无论策略一律拒绝
        assert!(matches!(
            plan_immutable_gate(distro::Immutability::Nix, ImmutablePolicy::Refuse),
            ImmutableGate::Refuse(_)
        ));
        assert!(matches!(
            plan_immutable_gate(distro::Immutability::Nix, ImmutablePolicy::Usroverlay),
            ImmutableGate::Refuse(_)
        ));
        assert!(matches!(
            plan_immutable_gate(distro::Immutability::ReadOnlyUsr, ImmutablePolicy::Usroverlay),
            ImmutableGate::Refuse(_)
        ));
        // dry-run 提示是纯文本：说明实盘将需要什么，且明确"不执行任何命令"
        assert!(immutable_dry_run_hint(distro::Immutability::Ostree).contains("不执行任何命令"));
        assert!(immutable_dry_run_hint(distro::Immutability::Mutable).contains("可直接写入"));
        assert!(immutable_dry_run_hint(distro::Immutability::Nix).contains("configuration.nix"));
    }

    /// C-18：dry-run 必须在不可变闸门**之前**返回——即使策略为 usroverlay 也绝不
    /// 执行 `rpm-ostree usroverlay` 等任何命令，只给只读提示。
    ///
    /// 本机可变性探测读真实系统（不可注入），故除行为断言外再加一道**源码顺序
    /// 守卫**：run_restore 的步骤 4（dry-run 分支）必须先于步骤 5（闸门）出现。
    /// 手工复核（OSTree 机器）：`strace -f -e trace=execve ./target/debug/... restore
    /// --dry-run --on-immutable usroverlay …` 应看不到任何 execve("rpm-ostree")。
    /// C-18: dry-run must return *before* the immutability gate — no command runs.
    #[test]
    fn dry_run_returns_before_immutable_gate_c18() {
        let dir = temp_case("c18-dry");
        let manifest = manifest_json(
            distro::arch(),
            "6.8.0-45-generic",
            &[("etc/modprobe.d/x.conf", "config")],
        );
        let archive = build_archive(
            &dir,
            "c18.tar.gz",
            &[("data/etc/modprobe.d/x.conf", b"abc".as_slice())],
            Some(&manifest),
        );
        let req = RestoreRequest {
            archive,
            dry_run: true,
            // root=None → 不离线；若闸门先于 dry-run 执行，OSTree 机器上会运行命令
            root: None,
            on_immutable: ImmutablePolicy::Usroverlay,
            progress: Arc::new(|_v: f32, _m: String| {}),
            cancel: Arc::new(AtomicBool::new(false)),
            ..RestoreRequest::default()
        };
        let report = run_restore(req).unwrap();
        assert!(report.dry_run);
        assert!(report.rollback_journal.is_none(), "dry-run 不产生事务日志");
        // 可变性说明来自 dry-run 分支（步骤 4）
        assert!(
            report.notes.iter().any(|n| n
                .starts_with("目标系统可变性：")
                && n.contains(distro::immutability().label_zh())),
            "notes={:?}",
            report.notes
        );
        // 闸门真正执行才会出现的说明（usroverlay"重启后失效"）绝不能出现
        assert!(
            !report.notes.iter().any(|n| n.contains("重启后失效")),
            "dry-run 不得执行不可变闸门：{:?}",
            report.notes
        );

        // 源码顺序守卫：步骤 4（dry-run）必须出现在步骤 5（闸门）之前
        let src = include_str!("restore.rs");
        let dry = src
            .find("---- 步骤 4：dry-run")
            .expect("run_restore 应有 dry-run 步骤注释");
        let gate = src
            .find("plan_immutable_gate(immutability, req.on_immutable)")
            .expect("run_restore 应有不可变闸门调用");
        assert!(dry < gate, "dry-run 必须先于不可变闸门返回（C-18）");
        let _ = fs::remove_dir_all(&dir);
    }

    /// C-39：手写 RFC3339 UTC 格式化（不引入 chrono/time 依赖）的已知值。
    /// C-39: known-value checks for the hand-rolled RFC3339 UTC formatter.
    #[test]
    fn secs_to_rfc3339_known_epoch_values_c39() {
        assert_eq!(secs_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(secs_to_rfc3339(1), "1970-01-01T00:00:01Z");
        assert_eq!(secs_to_rfc3339(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(secs_to_rfc3339(946_684_800), "2000-01-01T00:00:00Z");
        // 闰年：2020-02 有 29 天 → 3 月 1 日
        assert_eq!(secs_to_rfc3339(1_583_020_800), "2020-03-01T00:00:00Z");
        assert_eq!(secs_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        // 百年规则：2100 不是闰年（epoch 4102444800 = 2100-01-01）
        assert_eq!(secs_to_rfc3339(4_102_444_800), "2100-01-01T00:00:00Z");
    }
}
