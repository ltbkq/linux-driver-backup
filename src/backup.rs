//! 备份流水线：扫描 → 打包（两段流水作业，**单遍读**）。
//! Backup pipeline: scan → pack (two-stage pipeline, single read pass).
//!
//! # 线程结构 / Thread structure
//!
//! ```text
//! Stage 1 Walker ──sync_channel(64)──▶ Stage 2 Packer
//!  crate::scan::scan()                  open 一次 → HashingReader 单遍读
//!  产出 (index, ScanEntry)              tar 读取的同时同步喂 SHA-256
//!  （有界通道 = 背压）                    末尾追加 manifest.json → fsync → rename
//! ```
//!
//! - **Stage 1 Walker**：调用 [`crate::scan::scan`] 得到 [`ScanReport`]，先按
//!   [`FirmwarePolicy`] 过滤固件条目（W5 固件按需收集），再为每个条目分配其在
//!   `entries` 中的下标后，经 `sync_channel::<(usize, ScanEntry)>(64)` 送入打包阶段。
//!   有界通道提供背压，full 模式下的 `/lib/firmware` 不会把内存吃光。
//! - **Stage 2 Packer**：`flate2::write::GzEncoder<File>` + `tar::Builder` 的唯一写者，
//!   按序写入 `data/<rel_path>`（mode `0o644`、uid/gid `0`、mtime 取自源文件
//!   `std::os::unix::fs::MetadataExt::mtime`），末尾追加 `manifest.json`。
//!   **每个文件只 `open` 一次**：[`HashingReader`] 在 tar 拉取数据的同时把字节喂给
//!   SHA-256 与进度计数器 —— C-38 的"哈希与打包双读"由此消灭（v0.2.x 的
//!   Stage 2 Hasher×N 已并入本阶段）。
//!
//! # sha256 语义（C-38；v2 字段格式不变，仅语义收紧）
//!
//! `ManifestEntry.sha256` 自 v0.3.0 起描述**归档内实际写入的字节**：数据条目在
//! 单遍读取时由 [`HashingReader`] 同步喂入 hasher，`tar::Builder::append_data`
//! 返回即得到该条目的最终摘要，随后（`manifest.json` 在全部数据条目之后追加，
//! 现有顺序已如此）写入 `ManifestEntry.sha256`。此前摘要来自独立的第二遍读取，
//! 内容在两遍之间被修改时摘要与归档不一致；现在**摘要恒等于归档内容的哈希**。
//! 字段格式（64 位小写十六进制）与 v2 字段布局保持不变。读取前后尽力检测
//! mtime/len/inode 变化并记 warning，但**摘要始终描述已写入归档的字节**。
//!
//! # 输出原子性 / Output atomicity（C-37）
//!
//! 实际写入的不是 `out_file` 本身，而是**同目录**临时名 `<out>.ldb-partial-<pid>-<seq>`
//! （见 [`partial_out_path`]）：全部成功（manifest 落位、tar finish、`sync_all`）后
//! `fs::rename` 原子替换目标路径；任何失败或取消都只删除 partial ——
//! **同路径的旧备份文件在失败时完好无损**（旧实现 `File::create` 先截断目标是缺陷）。
//!
//! # 单文件失败 / Per-file failures（C-37）
//!
//! 单个不可读文件（权限、竞态删除、打开期 IO 错误、扫描后被换成符号链接的竞态）
//! → **跳过该条目 + 计入 manifest warnings**
//! （`跳过不可读文件 / skipped unreadable: <path>`），不再中止整个备份；
//! 结构性错误（无法创建输出、`rel_path` 非法、归档头失败、数据读取中途 IO 错误、
//! manifest 序列化失败）仍然中止。
//!
//! # 顺序一致性策略 / Ordering strategy
//!
//! 采用 **「扫描序号 + Packer 侧 `BTreeMap` 重排」**：
//!
//! 1. Walker 给每个 `ScanEntry` 分配其在 `ScanReport::entries` 中的下标 `index`；
//! 2. 条目经有界通道送达，完成顺序不作假设；
//! 3. Packer **先 `recv()` 再重排**：结果放入 `BTreeMap<usize, ScanEntry>`，只有当
//!    `next` 序号就绪时才写入 tar 并推进 `next`。因此 **tar 内条目顺序、
//!    `manifest.entries` 顺序与扫描顺序完全一致**；又因为 Packer 每轮都先接收，
//!    等待某个序号不会堵住通道，背压依然成立、也不会死锁；
//! 4. 通道关闭后若 `BTreeMap` 仍非空，说明存在序号缺口（正常流程不可能出现，只有出错
//!    中止才会），此时返回 [`AppError::Format`] 兜底。
//!
//! # 进度 / Progress
//!
//! 按 DESIGN.md §4.4 的字节加权分段（哈希段由 Packer 内的 [`HashingReader`] 喂入）：
//!
//! - `0.00` 开始扫描 → `0.10` 扫描完成（强制回调，附体积与条目统计）；
//! - `0.10..=0.70` 哈希段：`bytes_hashed / total_bytes` 线性映射；
//! - `0.70..=0.95` 打包段：`bytes_packed / total_bytes` 叠加映射；
//!   两个计数器都只增不减，因此整体进度**单调不回退**；
//! - `0.95` 写入 manifest 前 → `1.00` 备份完成（强制回调）。
//!
//! C-44（以下两句与 `restore.rs` 节流对齐，恢复侧逐字照抄）：
//! - 进度回调节流统一为「距上次回调 ≥ 40ms **或** 进度增量 ≥ 0.01」（**或**语义，任一满足即上抛）。
//! - 回调**前**先在锁内取快照（值 + 消息 clone），释放锁后再调用 callback，慢回调不再阻塞流水线线程。
//!
//! # 取消 / Cancel
//!
//! `Arc<AtomicBool>` 各阶段共享，并透传给 `scan()`（Walker 阶段即可中断）。任一阶段
//! 看到取消或其它阶段报错（内部 `abort` 标志）就停止工作并关闭自己的发送端，从而让上游
//! `send()` 失败并连锁退出 —— **不会留下永久阻塞的线程**。调用线程在 join 全部阶段后
//! 删除 partial 临时文件（删除失败忽略；`out_file` 从不被失败路径触碰），
//! 再返回 [`AppError::Cancelled`] 或首个错误。
//!
//! # 错误传播 / Error propagation
//!
//! 首个错误记录进 `Arc<Mutex<Option<AppError>>>`（后到的错误被忽略）并同时置位 `abort`；
//! Packer 结束时通过 `mpsc::channel::<Option<PackerOutcome>>` 把"完成信号 + 成功载荷"
//! 发回调用线程。**所有 sender 均移入各自线程、主线程不保留副本**，任一阶段退出都会
//! 关闭其输出通道，避免接收端永久阻塞。
//!
//! # 路径安全 / Path safety
//!
//! 写入 tar 前逐条校验 `rel_path`：拒绝含 `..` 组件的路径、拒绝以 `/` 开头的绝对路径、
//! 拒绝空路径与 NUL 字节，否则返回 [`AppError::Format`]（见 DESIGN.md §4.5）。

use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use flate2::write::GzEncoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use tar::{Builder as TarBuilder, EntryType, Header};

use crate::distro::{DistroInfo, Family};
use crate::model::{
    human_size, is_safe_kernel_version, AppError, AppResult, BackupMode, DkmsPackage, EntryKind,
    Manifest, ManifestDistro, ManifestEntry, ProgressFn, RestoreStrategy, ScanEntry, ScanReport,
    MANIFEST_FORMAT_VERSION,
};
use crate::pathutil::{validate_link_target, validate_rel_path};
use crate::scan::{scan, ScanOptions};

/// Walker 发给哈希阶段的任务：`(扫描序号, 条目)`。
type ScanTask = (usize, ScanEntry);

/// tar 的具体写者类型：gzip 压缩层 + tar 打包层。
type TarWriter = TarBuilder<GzEncoder<File>>;

const CHANNEL_CAP: usize = 64;
const HASH_CHUNK: usize = 64 * 1024;
/// C-44：进度回调节流的最小间隔（与 restore.rs 对齐，`或` 语义的其中一支）。
/// C-44: minimum interval between progress callbacks (OR-semantics, aligned with restore.rs).
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(40);
/// C-44：进度回调节流的最小增量（`或` 语义的另一支）。
const PROGRESS_MIN_DELTA: f32 = 0.01;

/// 一次成功打包的产物（Packer → 调用线程）。
struct PackerOutcome {
    manifest: Manifest,
    bytes_written: u64,
    entry_count: usize,
}

/// W5 固件收集策略（`BackupRequest::firmware_policy` 解析结果）。
/// Firmware collection policy (W5), parsed from `BackupRequest::firmware_policy`.
///
/// `BackupRequest::firmware_policy` 为 `None` 时整个枚举都为 `None`，
/// 扫描与过滤**完全保持 mode 现行为**（minimal/standard/full 各自现状，零行为变化）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirmwarePolicy {
    /// `all`：整棵 `/lib/firmware` 整树收集（等同现有 full 模式行为）。
    All,
    /// `needed`：只收集模块 `modinfo.firmware` 命中的条目（standard 模式默认目标）。
    Needed,
    /// `none`：不收集任何固件条目。
    None,
}

impl FirmwarePolicy {
    /// 解析 CLI 值；未知取值返回 `None`（由调用方转成 [`AppError::Validation`]）。
    /// Parse a CLI value; unknown strings yield `None`.
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "all" => Some(FirmwarePolicy::All),
            "needed" => Some(FirmwarePolicy::Needed),
            "none" => Some(FirmwarePolicy::None),
            _ => None,
        }
    }

    /// 写入 `manifest.firmware_policy` 的规范串。
    /// The canonical string recorded into `manifest.firmware_policy`.
    fn as_str(self) -> &'static str {
        match self {
            FirmwarePolicy::All => "all",
            FirmwarePolicy::Needed => "needed",
            FirmwarePolicy::None => "none",
        }
    }
}

/// 解析并校验 `BackupRequest::firmware_policy`（W5 接线；非法值直接拒绝）。
/// Parse and validate `BackupRequest::firmware_policy` (W5 wiring; invalid values are rejected).
fn parse_firmware_policy(raw: Option<&str>) -> AppResult<Option<FirmwarePolicy>> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    match FirmwarePolicy::parse(raw.trim()) {
        Some(policy) => Ok(Some(policy)),
        None => Err(AppError::Validation(format!(
            "非法固件收集策略: {raw:?}（应为 all|needed|none）/ invalid firmware policy"
        ))),
    }
}

/// W5：把（模式, 策略）换算成实际交给 `scan()` 的扫描模式。
/// W5: map (mode, policy) onto the mode actually handed to `scan()`.
///
/// 只在**固件维度**上调整扫描范围（manifest 记录的仍是用户选择的原始 `mode`）：
///
/// | policy | Minimal | Standard | Full |
/// |---|---|---|---|
/// | `None` | Minimal | Standard | Full（零行为变化） |
/// | `all` / `needed` | Minimal（不扩权） | **Full** | Full |
/// | `none` | Minimal | Standard | **Standard**（跳过整树遍历，等价于"扫了再全丢"） |
///
/// `Standard → Full` 恰好等于"加上固件扫描"（`scan()` 里 Full = Standard + 固件树），
/// 因此 standard + `needed` 能真正收集到命中的固件；Minimal 保持不扩权，
/// 不会因为固件策略顺带引入 Standard 的 DKMS 收录范围。
fn scan_mode_for(policy: Option<FirmwarePolicy>, mode: BackupMode) -> BackupMode {
    match (policy, mode) {
        (None, m) => m,
        (Some(FirmwarePolicy::None), BackupMode::Full) => BackupMode::Standard,
        (Some(FirmwarePolicy::None), m) => m,
        (Some(FirmwarePolicy::All | FirmwarePolicy::Needed), BackupMode::Standard) => {
            BackupMode::Full
        }
        (Some(FirmwarePolicy::All | FirmwarePolicy::Needed), m) => m,
    }
}

/// 单个条目写入 tar 的结果：`None` 表示该条目被跳过（不可读，C-37）。
/// Outcome of writing one entry: `None` means the entry was skipped (unreadable, C-37).
#[derive(Debug)]
struct WrittenEntry {
    /// 实际写入内容区的字节数（符号链接与 `content_stored=false` 为 0）。
    bytes: u64,
    /// 归档内容的 SHA-256（C-38：恒等于归档内字节的摘要；
    /// 符号链接为目标字符串摘要，`content_stored=false` 为磁盘内容摘要）。
    sha256: String,
}

/// 进度节流状态（三阶段共用一把锁，保证回调有序）。
struct ProgressState {
    last_at: Instant,
    last_value: f32,
}

/// 三阶段共享状态。
struct Pipeline {
    /// 用户取消标志（由 GUI/CLI 持有，本模块只读）。
    cancel: Arc<AtomicBool>,
    /// 内部中止标志：任一阶段出错/取消后置位，其余阶段尽快退出。
    abort: Arc<AtomicBool>,
    /// 首个错误（后到者忽略），调用线程最终取出。
    first_error: Arc<Mutex<Option<AppError>>>,
    /// 进度回调（UI/CLI）。
    progress: ProgressFn,
    /// 进度节流。
    throttle: Arc<Mutex<ProgressState>>,
    /// 哈希阶段已读取的字节数（进度分子之一，单调递增）。
    bytes_hashed: Arc<AtomicU64>,
    /// 打包阶段已写入的字节数（进度分子之二，单调递增）。
    bytes_packed: Arc<AtomicU64>,
    /// 扫描得到的总字节数（扫描完成后写入）。
    total_bytes: Arc<AtomicU64>,
    /// 扫描得到的条目总数。
    entry_total: Arc<AtomicUsize>,
    /// 扫描结果（取走 `entries` 后剩余的 warnings 等元数据）。
    scan_slot: Arc<Mutex<Option<ScanReport>>>,
}

/// 取锁；若锁被中毒（某线程 panic 时持有），仍然取出内部数据继续运行。
fn heal<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Pipeline {
    /// 任一停止条件成立？（用户取消 或 其它阶段已报错）
    fn stopped(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || self.abort.load(Ordering::SeqCst)
    }

    /// 记录**第一个**错误并置位 `abort`，通知全线停止。
    fn fail(&self, err: AppError) {
        {
            let mut slot = heal(&self.first_error);
            if slot.is_none() {
                *slot = Some(err);
            }
        }
        self.abort.store(true, Ordering::SeqCst);
    }

    /// 阶段检测到停止条件后调用：若因用户取消而停且尚无错误，补记 [`AppError::Cancelled`]。
    fn note_stop(&self) {
        if self.cancel.load(Ordering::SeqCst) && !self.has_error() {
            self.fail(AppError::Cancelled);
        }
        self.abort.store(true, Ordering::SeqCst);
    }

    fn has_error(&self) -> bool {
        heal(&self.first_error).is_some()
    }

    /// 取出首个错误（调用线程专用）。
    fn take_error(&self) -> Option<AppError> {
        heal(&self.first_error).take()
    }

    /// 收尾兜底：若用户已置位取消却无人记录（竞态），这里补记。
    fn sweep_cancel(&self) {
        if self.cancel.load(Ordering::SeqCst) {
            self.fail(AppError::Cancelled);
        }
    }

    /// 上报进度；`force` 用于阶段边界，绕过节流。
    ///
    /// C-44（以下两句与 `restore.rs` 节流对齐，恢复侧逐字照抄）：
    /// - 进度回调节流统一为「距上次回调 ≥ 40ms **或** 进度增量 ≥ 0.01」（**或**语义，任一满足即上抛）。
    /// - 回调**前**先在锁内取快照（值 + 消息 clone），释放锁后再调用 callback，慢回调不再阻塞流水线线程。
    fn emit(&self, value: f32, msg: &str, force: bool) {
        let snapshot = {
            let mut state = heal(&self.throttle);
            let now = Instant::now();
            if !force {
                let elapsed = now.duration_since(state.last_at);
                let delta = (value - state.last_value).abs();
                if elapsed < PROGRESS_MIN_INTERVAL && delta < PROGRESS_MIN_DELTA {
                    return;
                }
            }
            state.last_at = now;
            state.last_value = value;
            (value, msg.to_string())
        };
        // 锁已释放，慢回调不会阻塞其它流水线线程（C-44）。
        (self.progress)(snapshot.0, snapshot.1);
    }

    /// 依据两个单调递增的字节计数器上报进度，换算到 `0.10..=0.95`（哈希与打包共用）。
    /// Report progress derived from the two monotonic byte counters (`0.10..=0.95`).
    fn emit_progress(&self, msg: &str) {
        let value = progress_value(
            self.bytes_hashed.load(Ordering::SeqCst),
            self.bytes_packed.load(Ordering::SeqCst),
            self.total_bytes.load(Ordering::SeqCst),
        );
        self.emit(value, msg, false);
    }
}

/// 供 GUI 预填的默认输出路径：`$HOME/driver-backup-<kver>-<YYYYMMDD-HHMMSS>.tar.gz`。
/// Default output path prefilled by the GUI: `~/driver-backup-<kver>-<ts>.tar.gz`.
///
/// `HOME` 取 `std::env::var("HOME")`，失败回退 `"."`；文件名中的 `kver` 先把 `/`
/// 替换为 `_`，再用 [`is_safe_kernel_version`] 兜底清洗（只保留 `[0-9A-Za-z._+-]`、
/// 首字符字母数字、长度 ≤ 128），时间戳为 UTC。
pub fn default_out_path(kver: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let name = format!(
        "driver-backup-{}-{}.tar.gz",
        sanitize_kver_filename(kver),
        utc_timestamp(unix_now(), true)
    );
    Path::new(&home).join(name)
}

/// 备份请求：目标文件、内核版本、发行版、模式，以及进度/取消句柄。
/// A backup request: destination, kernel release, distro, mode, progress and cancel handles.
pub struct BackupRequest {
    /// 目标 `.tar.gz` 路径。
    pub out_file: PathBuf,
    /// 内核版本串（`uname -r`），须通过 [`is_safe_kernel_version`]。
    pub kver: String,
    /// 发行版信息（写入 manifest）。
    pub distro: DistroInfo,
    /// 备份模式。
    pub mode: BackupMode,
    /// 固件收集策略（v0.3.0 W5/P1-3，可选）：`"all"` | `"needed"` | `"none"`。
    /// `None` = 按 `mode` 现有行为（零行为变化）；非 `None` 时按 [`FirmwarePolicy`]
    /// 过滤（或扩展）固件条目，非法取值报 [`AppError::Validation`]。
    /// Firmware collection policy (W5): `"all"` | `"needed"` | `"none"`;
    /// `None` keeps today's mode-driven behaviour (zero change).
    pub firmware_policy: Option<String>,
    /// 进度回调 `0.0..1.0`。
    pub progress: ProgressFn,
    /// 取消标志：置位后流水线尽快停止并删除半成品。
    pub cancel: Arc<AtomicBool>,
}

/// 备份结果：产物路径、体积、条目数、耗时与完整 manifest。
/// Backup result: output path, byte size, entry count, elapsed time and the manifest.
#[derive(Debug)]
pub struct BackupReport {
    /// 实际写出的 `.tar.gz`。
    pub out_file: PathBuf,
    /// `.tar.gz` 的最终字节数（压缩后）。
    pub bytes_written: u64,
    /// 归档条目数（不含 `manifest.json`）。
    pub entry_count: usize,
    /// 本次备份耗时（毫秒）。
    pub duration_ms: u128,
    /// 写入归档的 manifest 副本。
    pub manifest: Manifest,
}

/// 运行两段流水备份：Walker → Packer（单遍读），内部自建线程。
/// Run the two-stage backup pipeline (Walker → Packer, single read pass) on internal threads.
///
/// 成功返回 [`BackupReport`]；失败时删除 partial 临时文件并返回（**同路径的旧
/// `out_file` 保持原样**，C-37）：
/// - [`AppError::Validation`]：`kver` 非法、输出路径为空或 `firmware_policy` 取值非法；
/// - [`AppError::Cancelled`]：用户取消；
/// - [`AppError::Format`]：`rel_path` 含 `..` / 绝对路径等不安全路径；
/// - [`AppError::Io`] / [`AppError::Json`]：读写或序列化失败。
///
/// 进度、顺序一致性、取消与错误传播的完整说明见本文件顶部的模块文档。
pub fn run_backup(req: BackupRequest) -> AppResult<BackupReport> {
    let started = Instant::now();

    // ---- 0. 输入校验 / validation（先校验，避免创建半成品文件） ----
    let kver = req.kver.trim().to_string();
    if !is_safe_kernel_version(&kver) {
        return Err(AppError::Validation(format!(
            "非法内核版本串 / unsafe kernel release: {:?}",
            req.kver
        )));
    }
    let BackupRequest {
        out_file,
        kver: _,
        distro,
        mode,
        firmware_policy,
        progress,
        cancel,
    } = req;
    // W5：解析固件收集策略（`None` = 按 mode 现行为，零行为变化；非法取值直接拒绝）。
    let firmware_policy = parse_firmware_policy(firmware_policy.as_deref())?;
    // 固件维度换算出的扫描模式；manifest 记录的仍是用户选择的原始 `mode`。
    let scan_mode = scan_mode_for(firmware_policy, mode);
    if out_file.as_os_str().is_empty() {
        return Err(AppError::Validation(
            "备份输出路径为空 / empty output path".to_string(),
        ));
    }
    if let Some(parent) = out_file.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    // C-37：实际写入同目录 partial，全部成功后才 rename 到 out_file。
    let partial_path = partial_out_path(&out_file);

    // ---- 1. 共享状态 / shared pipeline state ----
    let pipe = Arc::new(Pipeline {
        cancel,
        abort: Arc::new(AtomicBool::new(false)),
        first_error: Arc::new(Mutex::new(None)),
        progress,
        throttle: Arc::new(Mutex::new(ProgressState {
            last_at: Instant::now(),
            last_value: f32::NEG_INFINITY,
        })),
        bytes_hashed: Arc::new(AtomicU64::new(0)),
        bytes_packed: Arc::new(AtomicU64::new(0)),
        total_bytes: Arc::new(AtomicU64::new(0)),
        entry_total: Arc::new(AtomicUsize::new(0)),
        scan_slot: Arc::new(Mutex::new(None)),
    });
    let partial_started = Arc::new(AtomicBool::new(false));

    // ---- 2. 段间有界通道 / bounded channel between the two stages ----
    let (scan_tx, scan_rx) = sync_channel::<ScanTask>(CHANNEL_CAP);
    let (done_tx, done_rx) = channel::<Option<PackerOutcome>>();

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // Stage 1：Walker 线程
    {
        let p = pipe.clone();
        let kver = kver.clone();
        let distro = distro.clone();
        let spawned = thread::Builder::new()
            .name("backup-walker".to_string())
            .spawn(move || walker_main(&p, &kver, &distro, scan_mode, firmware_policy, scan_tx));
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => pipe.fail(AppError::Io(e)),
        }
    }

    // Stage 2：Packer 线程（tar 的唯一写者；单遍读 + 原子替换）
    {
        let p = pipe.clone();
        let partial_path = partial_path.clone();
        let kver = kver.clone();
        let distro = distro.clone();
        let partial_started = partial_started.clone();
        let spawned = thread::Builder::new()
            .name("backup-packer".to_string())
            .spawn(move || {
                let outcome = packer_main(
                    &p,
                    scan_rx,
                    &partial_path,
                    &kver,
                    &distro,
                    mode,
                    firmware_policy,
                    &partial_started,
                );
                match outcome {
                    Ok(o) => {
                        let _ = done_tx.send(Some(o));
                    }
                    Err(e) => {
                        // 把错误记进 first_error（成功载荷之外只发一个"失败"信号）
                        p.fail(e);
                        let _ = done_tx.send(None);
                    }
                }
            });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => pipe.fail(AppError::Io(e)),
        }
    }

    // ---- 3. 等待流水线结束 / wait for completion ----
    // done_rx 只由 Packer 发出：成功 → Some(payload)，失败 → None；
    // 真正的错误保存在 pipe.first_error，由调用线程统一取出。
    let done = done_rx.recv().ok();
    for h in handles {
        let _ = h.join();
    }

    pipe.sweep_cancel();
    if let Some(err) = pipe.take_error() {
        remove_partial(&partial_path, &partial_started);
        return Err(err);
    }

    match done {
        Some(Some(o)) => {
            // C-37：只有流水线全部成功（manifest 落位 + tar finish + `sync_all`）后，
            // 才把同目录 partial **原子 rename** 到目标路径；rename 前 `out_file` 从未被触碰。
            if let Err(err) = std::fs::rename(&partial_path, &out_file) {
                remove_partial(&partial_path, &partial_started);
                return Err(AppError::Io(err));
            }
            Ok(BackupReport {
                out_file,
                bytes_written: o.bytes_written,
                entry_count: o.entry_count,
                duration_ms: started.elapsed().as_millis(),
                manifest: o.manifest,
            })
        }
        _ => {
            remove_partial(&partial_path, &partial_started);
            Err(AppError::Format(
                "备份流水线异常终止 / backup pipeline terminated unexpectedly".to_string(),
            ))
        }
    }
}

/// C-37：生成与目标**同目录**的临时输出名 `<name>.ldb-partial-<pid>-<seq>`。
/// C-37: build the sibling temporary output name `<name>.ldb-partial-<pid>-<seq>`.
///
/// 同目录保证 `fs::rename` 原子（不跨文件系统）；`pid` + 进程内自增序号避免并发
/// 备份互相踩踏。失败/取消路径只删除该临时文件，`out_file` 从不被触碰。
fn partial_out_path(out_file: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let name = match out_file.file_name() {
        Some(n) if !n.is_empty() => n.to_string_lossy().into_owned(),
        _ => "driver-backup.tar.gz".to_string(),
    };
    out_file.with_file_name(format!("{name}.ldb-partial-{}-{seq}", std::process::id()))
}

/// 删除 partial 临时文件（仅在确实创建过时才删，删除失败忽略）。
/// **绝不触碰 `out_file`**：同路径旧备份在任何失败路径下都完好无损（C-37）。
/// Remove the partial temp file (only when it was created; failures are ignored).
/// The final `out_file` is never touched, so a pre-existing backup survives any failure.
fn remove_partial(partial: &Path, started: &AtomicBool) {
    if started.load(Ordering::SeqCst) {
        let _ = std::fs::remove_file(partial);
    }
}

// ---------------------------------------------------------------------------
// Stage 1: Walker
// ---------------------------------------------------------------------------

/// Stage 1：全树扫描，按固件策略（W5）过滤后把条目（带序号）送入打包阶段。
/// Stage 1: scan the whole tree, apply the firmware policy (W5) and feed indexed entries downstream.
fn walker_main(
    pipe: &Pipeline,
    kver: &str,
    distro: &DistroInfo,
    scan_mode: BackupMode,
    firmware_policy: Option<FirmwarePolicy>,
    output: SyncSender<ScanTask>,
) {
    pipe.emit(0.0, "扫描中… / scanning", true);

    let opt = ScanOptions {
        kver,
        distro,
        mode: scan_mode,
        cancel: Some(&*pipe.cancel),
    };
    let mut report = match scan(&opt) {
        Ok(r) => r,
        Err(e) => {
            pipe.fail(e);
            return;
        }
    };
    if pipe.stopped() {
        pipe.note_stop();
        return;
    }

    // W5：按固件收集策略过滤扫描结果（策略为 None 时原样返回，零行为变化）。
    let entries = std::mem::take(&mut report.entries);
    let (entries, fw_stats) = apply_firmware_policy(entries, firmware_policy, &mut report);

    let total: u64 = entries.iter().map(|e| e.size).sum();
    pipe.total_bytes.store(total, Ordering::SeqCst);
    pipe.entry_total.store(entries.len(), Ordering::SeqCst);

    let mut msg = format!(
        "扫描完成：{} 个文件，{}（in-tree 跳过 {}，固件预估 {}）/ scanned",
        entries.len(),
        human_size(total),
        report.skipped_in_tree,
        human_size(report.firmware_bytes)
    );
    if let Some((considered, kept)) = fw_stats {
        if considered > 0 {
            msg.push_str(&format!(
                "；固件策略：收录 {kept}/{considered} 条 / firmware entries kept"
            ));
        }
    }
    pipe.emit(0.10, &msg, true);
    *heal(&pipe.scan_slot) = Some(report);

    for (index, entry) in entries.into_iter().enumerate() {
        if pipe.stopped() {
            pipe.note_stop();
            return;
        }
        // 背压：通道满时在这里等待；下游关闭时 send 失败，本线程随之退出。
        if output.send((index, entry)).is_err() {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// W5: 固件按需收集 / On-demand firmware collection
// ---------------------------------------------------------------------------

/// 判断条目是否属于固件命名空间：`kind == Firmware`，或路径位于 `/lib/firmware`
/// 树内（含 usr-merge 的 `usr/lib/firmware`；对分类异常的条目也兜住，宁可宽勿漏）。
/// Whether an entry lives in the firmware namespace (kind or path based).
fn is_firmware_entry(entry: &ScanEntry) -> bool {
    entry.kind == EntryKind::Firmware || is_firmware_rel(&entry.rel_path)
}

/// 路径是否落在固件目录树内（去前导 `/` 后比较）。
/// Whether a relative path sits inside the firmware tree.
fn is_firmware_rel(rel: &str) -> bool {
    let r = rel.trim_start_matches('/');
    r == "lib/firmware"
        || r == "usr/lib/firmware"
        || r.starts_with("lib/firmware/")
        || r.starts_with("usr/lib/firmware/")
}

/// 把任意路径/标签归一化到**固件命名空间内的相对路径**：去前导 `/`，再去掉
/// `lib/firmware/`、`usr/lib/firmware/` 前缀。`modinfo.firmware` 标签（如
/// `nvidia/550.54.14/firmware.elf`）本来就是该命名空间，归一化后与 `rel_path` 可直接比较。
/// Normalize any path/tag into the firmware namespace (strip `/`, `lib/firmware/`, `usr/lib/firmware/`).
fn firmware_namespace(path: &str) -> String {
    let p = path.trim_start_matches('/');
    let p = p
        .strip_prefix("lib/firmware/")
        .or_else(|| p.strip_prefix("usr/lib/firmware/"))
        .unwrap_or(p);
    p.to_string()
}

/// 从扫描结果中收集模块声明的"需要的固件名集合"（W5：`modinfo.firmware` 标签）。
/// Collect the set of firmware names requested by scanned modules (`modinfo.firmware`, W5).
fn wanted_firmware(entries: &[ScanEntry]) -> HashSet<String> {
    let mut wanted = HashSet::new();
    for entry in entries {
        let Some(modinfo) = &entry.modinfo else {
            continue;
        };
        for tag in &modinfo.firmware {
            let tag = tag.trim();
            if tag.is_empty() {
                continue;
            }
            wanted.insert(firmware_namespace(tag));
        }
    }
    wanted
}

/// W5 `needed` 的核心判定：固件条目 `rel_path` 是否命中"需要的固件名集合"。
/// Core matcher for W5 `needed`: does a firmware entry hit the wanted-name set?
///
/// # 规则 / Rules
///
/// 两侧都先归一化到固件命名空间（[`firmware_namespace`]），命中任一规则即为 `true`。
/// **宁可宽勿漏**（宁可多打包，也不漏掉模块需要的固件）：
///
/// 1. **(a) 精确名**：`normalize(rel_path) == normalize(w)`，
///    如 `nvidia/550.54.14/firmware.elf`。
/// 2. **(b) 压缩变体**：两侧各剥掉一次 `.xz` / `.zst` / `.gz` 后相等 —— 同时覆盖
///    "需要未压缩名、磁盘上是 `.xz`/`.zst`"与"需要的名字自带扩展、磁盘上是无扩展"
///    两个方向（`fw.bin` ↔ `fw.bin.xz` ↔ `fw.bin.zst`）。
/// 3. **(c) 同目录版本族**：剥压缩扩展后**删除所有连续数字段**得到"文件名模式"
///    （[`stem_family`]），两侧模式相等即命中。该规则作用于**整个归一化路径**
///    （目录与文件名都参与模式比较），因此同目录的版本族
///    （`iwlwifi-7850-29.ucode` ↔ `iwlwifi-8000-34.ucode`）、同目录同模式的
///    文件版本（`nvidia/550.54.14/firmware.elf` ↔ `…/firmware2.elf`）、以及
///    版本子目录本身（`nvidia/550.54.14/` ↔ `nvidia/550.54.15/` 的同名文件）
///    都会被一并纳入；不同厂商目录（`amdgpu/…` vs `nvidia/…`）因路径模式不同
///    不会互串，固件根目录也不会被整棵拉进来（文件名仍参与比较）。
/// 4. **(e) 目录前缀**：`rel_path` 位于 `w` 之下（`w` 是目录名时整棵子树纳入）。
///
/// `wanted` 为空集合时恒返回 `false`；空集合的 fail-open 处理见
/// [`apply_firmware_policy`]（保留全部固件 + warning），不在本函数内。
///
/// English: both sides are normalized into the firmware namespace; a match happens on
/// the exact name, on equality after stripping one `.xz`/`.zst`/`.gz` suffix on either
/// side, on an equal "stem family" (compression stripped, every digit run deleted —
/// covering same-directory version families and version subdirectories), or on a
/// directory prefix. Deliberately wide: over-archiving is preferred to missing
/// firmware a module needs.
fn firmware_matches(wanted: &HashSet<String>, rel_path: &str) -> bool {
    if wanted.is_empty() {
        return false;
    }
    let fw = firmware_namespace(rel_path);
    if fw.is_empty() {
        return false;
    }
    let fw_stripped = strip_compression_suffix(&fw);
    let fw_family = stem_family(&fw);
    for w in wanted {
        if w.is_empty() {
            continue;
        }
        if w == &fw {
            return true; // (a) 精确名 / exact name
        }
        if strip_compression_suffix(w) == fw_stripped {
            return true; // (b) 压缩变体（双向）/ compression variants, both directions
        }
        if stem_family(w) == fw_family {
            return true; // (c) 同目录版本族 / same stem family (incl. version dirs)
        }
        if fw.starts_with(w) && fw.as_bytes().get(w.len()) == Some(&b'/') {
            return true; // (e) 目录前缀 / wanted names a directory
        }
    }
    false
}

/// 剥掉一次 `.xz` / `.zst` / `.gz` 后缀（没有则原样返回）。
/// Strip one `.xz`/`.zst`/`.gz` suffix, if present.
fn strip_compression_suffix(path: &str) -> &str {
    for suffix in [".xz", ".zst", ".gz"] {
        if path.len() > suffix.len() && path.ends_with(suffix) {
            return &path[..path.len() - suffix.len()];
        }
    }
    path
}

/// 版本族模式：剥一次压缩扩展后，删除**所有连续数字段**（`iwlwifi-7850-29.ucode`
/// → `iwlwifi--.ucode`、`nvidia/550.54.14/…` → `nvidia/.././…`），用于把同一
/// 文件名模式下的不同版本号一并纳入（W5 规则 c）。
/// Stem family: compression stripped, every run of digits deleted (rule c).
fn stem_family(path: &str) -> String {
    let base = strip_compression_suffix(path);
    let mut out = String::with_capacity(base.len());
    let mut in_digits = false;
    for c in base.chars() {
        if c.is_ascii_digit() {
            in_digits = true;
            continue;
        }
        if in_digits {
            in_digits = false;
        }
        out.push(c);
    }
    out
}

/// W5：按固件收集策略过滤扫描结果。
/// Apply the firmware collection policy to the scanned entries (W5).
///
/// - 策略为 `None` → **原样返回，零行为变化**（minimal/standard/full 各自现状）；
/// - [`FirmwarePolicy::All`] → 保留全部固件条目（= 现有 full 模式整树收集行为）；
/// - [`FirmwarePolicy::None`] → 丢弃全部固件条目（不收集任何固件）；
/// - [`FirmwarePolicy::Needed`] → 只保留 [`firmware_matches`] 命中的条目；
///   命中集合为空（模块未提供 `modinfo.firmware` 标签）时**宁可宽勿漏**：
///   保留全部固件并把原因记入 `report.warnings`。
///
/// 包提供者条目（`owner` 命中、`content_stored == false`）只要命中就照常保留 ——
/// 现有机制"归档只记名、不存内容"在 `needed` 下同样生效。
///
/// 过滤后按结果重算 `report.firmware_bytes`（W3/C-28 口径：只累计
/// `content_stored = true` 的固件字节）。返回 `(条目, Some((固件总数, 保留数)))`，
/// `None` 表示策略未启用。
fn apply_firmware_policy(
    entries: Vec<ScanEntry>,
    policy: Option<FirmwarePolicy>,
    report: &mut ScanReport,
) -> (Vec<ScanEntry>, Option<(usize, usize)>) {
    let Some(policy) = policy else {
        return (entries, None);
    };
    let considered = entries.iter().filter(|e| is_firmware_entry(e)).count();
    let mut entries = entries;
    match policy {
        FirmwarePolicy::All => {}
        FirmwarePolicy::None => {
            entries.retain(|e| !is_firmware_entry(e));
        }
        FirmwarePolicy::Needed => {
            let wanted = wanted_firmware(&entries);
            if wanted.is_empty() {
                if considered > 0 {
                    report.warnings.push(
                        "固件策略 needed 未取到任何模块固件标签，保留全部固件条目 / \
                         'needed' collected no firmware tags; keeping every firmware entry"
                            .to_string(),
                    );
                }
            } else {
                entries.retain(|e| !is_firmware_entry(e) || firmware_matches(&wanted, &e.rel_path));
            }
        }
    }
    report.firmware_bytes = entries
        .iter()
        .filter(|e| is_firmware_entry(e) && e.content_stored)
        .map(|e| e.size)
        .sum();
    let kept = entries.iter().filter(|e| is_firmware_entry(e)).count();
    (entries, Some((considered, kept)))
}

/// 摘要字节 → 64 位小写十六进制串。
/// Format digest bytes as 64 lowercase hex characters.
fn hex_lower(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for &b in digest {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// 计算任意字节串的 SHA-256（64 位小写十六进制），用于符号链接目标的语义哈希。
/// Compute the SHA-256 of arbitrary bytes (lowercase hex); used for symlink target hashing.
fn sha256_hex(data: &[u8]) -> String {
    hex_lower(&Sha256::digest(data))
}

/// 读完**已打开**的文件并返回 SHA-256（`content_stored == false` 的条目用：
/// 内容不入档，但按 v2 语义保留磁盘内容摘要；不产生第二次 `open`）。
/// Read an already-open file to EOF and return its SHA-256 (no second `open`).
///
/// 每块检查一次取消；读取字节同步累加到 `bytes_hashed`（进度哈希段）。
fn hash_file_contents(file: &mut File, pipe: &Pipeline) -> AppResult<String> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        // 大文件也要能及时响应取消：每个块检查一次。
        if pipe.stopped() {
            return Err(AppError::Cancelled);
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        pipe.bytes_hashed.fetch_add(n as u64, Ordering::SeqCst);
    }
    Ok(hex_lower(&hasher.finalize()))
}

// ---------------------------------------------------------------------------
// Stage 2: Packer
// ---------------------------------------------------------------------------

/// Stage 2：tar+gzip 的唯一写者，单遍读取源文件（[`HashingReader`] 同步喂 SHA-256），
/// 按序写入 `data/<rel_path>`，末尾追加 `manifest.json`，fsync 后把 partial 原子
/// rename 到 `out_file`（C-37）。
/// Stage 2: the single tar+gzip writer; single-pass reads, manifest, fsync, atomic rename.
///
/// 乱序到达的条目先放进 `BTreeMap` 缓冲，只有 `next` 序号就绪才写入 tar，
/// 从而保证归档顺序 == 扫描顺序（详见模块文档）。
/// 单个不可读文件只跳过并记 warning（C-37）；结构性错误返回 `Err` 中止。
#[allow(clippy::too_many_arguments)]
fn packer_main(
    pipe: &Pipeline,
    input: Receiver<ScanTask>,
    partial: &Path,
    kver: &str,
    distro: &DistroInfo,
    mode: BackupMode,
    firmware_policy: Option<FirmwarePolicy>,
    partial_started: &AtomicBool,
) -> AppResult<PackerOutcome> {
    // C-37：写入同目录 partial（不是 out_file 本体），成功后才 rename 替换。
    let file = File::create(partial)?;
    partial_started.store(true, Ordering::SeqCst);
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = TarWriter::new(encoder);

    let mut pending: BTreeMap<usize, ScanEntry> = BTreeMap::new();
    let mut next: usize = 0;
    let mut manifest_entries: Vec<ManifestEntry> = Vec::new();
    let mut local_warnings: Vec<String> = Vec::new();
    let mut packed_bytes: u64 = 0;
    let family = distro.family;
    // 扫描阶段的 DKMS 清单（首次真正需要时惰性读取，避免与 Walker 写 scan_slot 竞态）。
    let mut dkms_cache: Option<Vec<DkmsPackage>> = None;

    loop {
        if pipe.stopped() {
            return Err(AppError::Cancelled);
        }
        match input.recv() {
            Ok((index, entry)) => {
                pending.insert(index, entry);
            }
            // Walker 已退出 → 通道关闭。
            Err(_) => break,
        }
        // 先接收后重排：始终排空通道，等待某个序号不会造成阻塞。
        while let Some(entry) = pending.remove(&next) {
            let total = pipe.total_bytes.load(Ordering::SeqCst);
            let written = write_entry(&mut builder, &entry, pipe, &mut local_warnings)?;
            next += 1;
            if let Some(w) = written {
                packed_bytes += w.bytes;
                pipe.bytes_packed.fetch_add(w.bytes, Ordering::SeqCst);
                let dkms = dkms_cache.get_or_insert_with(|| manifest_dkms(pipe));
                manifest_entries.push(build_manifest_entry(
                    &entry,
                    w.sha256,
                    w.bytes,
                    dkms.as_slice(),
                    family,
                ));
            }

            let entry_total = pipe.entry_total.load(Ordering::SeqCst);
            pipe.emit_progress(&format!(
                "已打包 {} / {}（{} / {} 个文件）/ packing",
                human_size(packed_bytes),
                human_size(total),
                next,
                entry_total
            ));
        }
    }

    if pipe.stopped() {
        return Err(AppError::Cancelled);
    }
    if !pending.is_empty() {
        return Err(AppError::Format(format!(
            "条目未按序到达：{} 个序号缺口 / {} entries missing in order",
            pending.len(),
            pending.len()
        )));
    }
    // 兜底：条目数必须与扫描结果完全一致 —— 即使 Walker 在"最后一个条目"处
    // 异常退出（通道正常关闭、pending 恰好为空），也不会悄悄漏备份。
    let expected = pipe.entry_total.load(Ordering::SeqCst);
    if next != expected {
        return Err(AppError::Format(format!(
            "条目不完整：扫描得到 {expected} 个条目，按序到达 {next} 个 \
             / entries incomplete: {next} of {expected}"
        )));
    }

    pipe.emit(
        0.95,
        "扫描与哈希完成，写入 manifest.json / writing manifest",
        true,
    );

    let mut warnings: Vec<String> = {
        let guard = heal(&pipe.scan_slot);
        guard
            .as_ref()
            .map(|r| r.warnings.clone())
            .unwrap_or_default()
    };
    warnings.append(&mut local_warnings);

    // DKMS 清单：优先用条目循环里已缓存的副本；空扫描时补读一次。
    let dkms = dkms_cache.unwrap_or_else(|| manifest_dkms(pipe));

    let entry_count = manifest_entries.len();
    let now = unix_now();
    // 运行时探测只影响 manifest 的元数据，失败即 `None`，绝不影响打包主流程。
    // Runtime probes only feed manifest metadata; failures degrade to `None` and never abort packing.
    let manifest = Manifest {
        format_version: MANIFEST_FORMAT_VERSION,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        created_at: utc_timestamp(now, false),
        kernel_release: kver.to_string(),
        kernel_vermagic: crate::distro::reference_vermagic(kver),
        arch: std::env::consts::ARCH.to_string(),
        distro: ManifestDistro::from_distro(distro),
        immutability: Some(crate::distro::immutability().tag().to_string()),
        secure_boot: Some(crate::distro::secure_boot_state().to_info()),
        mode,
        compression: Some("gzip".to_string()),
        entries: manifest_entries,
        dkms,
        warnings,
        firmware_policy: firmware_policy.map(|p| p.as_str().to_string()),
    };

    let json = serde_json::to_vec_pretty(&manifest)?;
    let mut header = Header::new_gnu();
    header.set_size(json.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(now.max(0) as u64);
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(EntryType::Regular);
    // append_data 会先写入路径（过长时自动追加 GNU longname 扩展）再计算校验和。
    builder.append_data(&mut header, "manifest.json", &json[..])?;

    let encoder = builder.into_inner()?;
    let file = encoder.finish()?;
    file.sync_all()?;
    let bytes_written = file.metadata()?.len();

    pipe.emit(
        1.0,
        &format!(
            "备份完成：{} 个文件，{} / backup done",
            entry_count,
            human_size(bytes_written)
        ),
        true,
    );

    Ok(PackerOutcome {
        manifest,
        bytes_written,
        entry_count,
    })
}

/// 取出扫描阶段的 DKMS 清单；`scan_slot` 为空时返回空表（绝不失败）。
/// Read the DKMS package list collected during scanning; empty when unavailable.
fn manifest_dkms(pipe: &Pipeline) -> Vec<DkmsPackage> {
    heal(&pipe.scan_slot)
        .as_ref()
        .map(|r| r.dkms.clone())
        .unwrap_or_default()
}

/// 由扫描条目构造 manifest 记录：透传 v2 字段并计算 [`RestoreStrategy`] 提示。
/// Build a manifest record from a scanned entry, carrying v2 metadata and the strategy hint.
fn build_manifest_entry(
    entry: &ScanEntry,
    sha256: String,
    size: u64,
    dkms: &[DkmsPackage],
    family: Family,
) -> ManifestEntry {
    ManifestEntry {
        path: entry.rel_path.clone(),
        size,
        sha256,
        kind: entry.kind,
        link_target: entry.link_target.clone(),
        owner: entry.owner.clone(),
        modinfo: entry.modinfo.clone(),
        content_stored: entry.content_stored,
        strategy_hint: strategy_hint(entry, dkms, family),
    }
}

/// 计算模块条目的建议还原策略；非模块条目返回 `None`。
/// Compute the suggested restore strategy for a module entry; non-modules yield `None`.
///
/// 判定顺序（ROADMAP §8 重建决策树在**归档侧**的落点）：
/// 1. 模块位于 DKMS 目录（`/var/lib/dkms/`、`/usr/src/`），或文件名/路径匹配任一
///    [`DkmsPackage::name`] → [`RestoreStrategy::Rebuild`]；
/// 2. 否则来源包已知（`owner.is_some()`）→ [`RestoreStrategy::Reinstall`]；
/// 3. 否则 RHEL 系 → [`RestoreStrategy::WeakModules`]；
/// 4. 其余（Debian/Arch/Unknown）→ [`RestoreStrategy::Copy`]。
///
/// 只写"提示"，真正执行由 `restore.rs` 决定（本模块不执行任何命令）。
fn strategy_hint(
    entry: &ScanEntry,
    dkms: &[DkmsPackage],
    family: Family,
) -> Option<RestoreStrategy> {
    if entry.kind != EntryKind::Module {
        return None;
    }
    if is_dkms_module(entry, dkms) {
        return Some(RestoreStrategy::Rebuild);
    }
    if entry.owner.is_some() {
        return Some(RestoreStrategy::Reinstall);
    }
    if family == Family::Rhel {
        return Some(RestoreStrategy::WeakModules);
    }
    Some(RestoreStrategy::Copy)
}

/// 模块是否来自 DKMS：位于 DKMS 目录，或文件名/路径匹配已知包名。
/// Whether a module originates from DKMS: under a DKMS dir, or matching a package name.
fn is_dkms_module(entry: &ScanEntry, dkms: &[DkmsPackage]) -> bool {
    in_dkms_dir(&entry.rel_path)
        || in_dkms_dir(&entry.abs_path.to_string_lossy())
        || module_matches_dkms(&entry.rel_path, dkms)
}

/// 路径（去前导 `/` 后）是否位于 `/var/lib/dkms/` 或 `/usr/src/` 之下。
/// Whether a path sits under `/var/lib/dkms/` or `/usr/src/` (leading `/` optional).
fn in_dkms_dir(path: &str) -> bool {
    let p = path.trim_start_matches('/');
    p.starts_with("var/lib/dkms/") || p.starts_with("usr/src/")
}

/// 模块文件名/路径是否匹配任一 DKMS 包名（`nvidia` ↔ `nvidia.ko` / `nvidia-uvm.ko`）。
/// Whether the module file name/path matches any DKMS package name.
fn module_matches_dkms(rel_path: &str, dkms: &[DkmsPackage]) -> bool {
    let file_name = rel_path.rsplit('/').next().unwrap_or(rel_path);
    dkms.iter().filter(|p| !p.name.is_empty()).any(|p| {
        rel_path.split('/').any(|seg| seg == p.name)
            || file_name == p.name
            || file_name.starts_with(&format!("{}.", p.name))
            || file_name.starts_with(&format!("{}-", p.name))
    })
}

/// 把一个条目写进 tar，返回其 manifest 摘要与实际写入内容区字节数（`None` = 跳过该条目）。
/// Append one entry, returning its manifest digest and content bytes (`None` = skipped).
///
/// 三种分支：
/// - **符号链接**（`kind == Symlink`）：用 `append_link` 写 tar symlink 条目，
///   **绝不打开/读取目标文件**；链接目标先经 [`validate_link_target`] 安全校验。
///   摘要 = 目标字符串的 SHA-256（v2 语义），`bytes = 0`。
/// - **`content_stored == false`**：文件由系统包提供（典型为 `linux-firmware`），
///   tar 内**不出现**该路径；仍只读打开并计算磁盘内容摘要，供 manifest 记录（v2 语义）。
/// - **普通文件**：按 `data/<rel_path>` 写入；C-38 起由 [`HashingReader`] **单遍读**，
///   摘要恒等于归档实际写入的字节；读取前后尽力检测大小变化并记 warning。
///
/// C-37：**打开期**不可读（权限/竞态删除/元数据错误）→ `Ok(None)` + warning，
/// 跳过该条目而不中止；**写入中途** IO 错误会留下半个 tar 条目，无法回滚 → `Err` 中止。
fn write_entry(
    builder: &mut TarWriter,
    entry: &ScanEntry,
    pipe: &Pipeline,
    warnings: &mut Vec<String>,
) -> AppResult<Option<WrittenEntry>> {
    let rel = entry.rel_path.as_str();
    validate_rel_path(rel)?;

    // 符号链接：写链接条目，不读取目标。
    if entry.kind == EntryKind::Symlink {
        let target = entry.link_target.as_deref().ok_or_else(|| {
            AppError::Format(format!(
                "符号链接缺少 link_target / missing link target: {rel}"
            ))
        })?;
        validate_link_target(rel, target)?;

        let mut header = Header::new_gnu();
        header.set_entry_type(EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        let tar_path = format!("data/{rel}");
        // append_link 写入 linkname（过长时自动补 GNU 'K' longlink 扩展）并计算校验和；
        // 条目类型须由调用方显式设为 Symlink（append_link 不会代设）。
        builder.append_link(&mut header, tar_path.as_str(), target)?;
        return Ok(Some(WrittenEntry {
            sha256: sha256_hex(target.as_bytes()),
            bytes: 0,
        }));
    }

    // 由系统包提供、内容不入库：tar 里不出现该路径，但按 v2 语义保留磁盘内容摘要。
    if !entry.content_stored {
        let mut file = match File::open(&entry.abs_path) {
            Ok(f) => f,
            Err(err) => {
                warnings.push(format!(
                    "跳过不可读文件 / skipped unreadable: {rel}（{err}）"
                ));
                return Ok(None);
            }
        };
        return match hash_file_contents(&mut file, pipe) {
            Ok(sha256) => Ok(Some(WrittenEntry { sha256, bytes: 0 })),
            Err(AppError::Cancelled) => Err(AppError::Cancelled),
            Err(err) => {
                warnings.push(format!(
                    "跳过不可读文件 / skipped unreadable: {rel}（{err}）"
                ));
                Ok(None)
            }
        };
    }

    let file = match File::open(&entry.abs_path) {
        Ok(f) => f,
        Err(err) => {
            warnings.push(format!(
                "跳过不可读文件 / skipped unreadable: {rel}（{err}）"
            ));
            return Ok(None);
        }
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(err) => {
            warnings.push(format!(
                "跳过不可读文件 / skipped unreadable: {rel}（{err}）"
            ));
            return Ok(None);
        }
    };
    let size = meta.len();

    let mut header = Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    let mtime = meta.mtime();
    header.set_mtime(if mtime > 0 { mtime as u64 } else { 0 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_entry_type(EntryType::Regular);

    let tar_path = format!("data/{rel}");
    let mut reader = HashingReader {
        inner: ExactReader {
            inner: file,
            remaining: size,
            pipe,
        },
        hasher: Sha256::new(),
    };
    // append_data 会先写入路径（过长时自动追加 GNU longname 扩展）再计算校验和；
    // 路径以 &str 传入，兼容 tar 0.4 对 `P: AsRef<Path>` / `Into<Vec<u8>>` 的两种签名。
    if let Err(e) = builder.append_data(&mut header, tar_path.as_str(), &mut reader) {
        // 取消/中止导致的读取失败，优先上报为 Cancelled（真实错误已在 first_error 中）。
        if pipe.stopped() {
            return Err(AppError::Cancelled);
        }
        // 数据读取中途 IO 错误：tar 已写入半个条目，无法回滚 → 结构性错误中止。
        return Err(AppError::Io(e));
    }

    let written = size - reader.inner.remaining;
    // 尽力检测部分写入（若文件在打包期间被追加，tar 只写了原始的 `size` 字节）。
    if let Ok(after) = reader.inner.inner.metadata() {
        if after.len() != size {
            warnings.push(format!(
                "文件在备份期间大小变化：{rel}（哈希时 {size} 字节，写入 {written} 字节）                 / size changed during backup"
            ));
        }
    }
    let sha256 = hex_lower(&reader.hasher.finalize());
    Ok(Some(WrittenEntry {
        sha256,
        bytes: written,
    }))
}

/// 恰好读取 `remaining` 字节的读取器：提前 EOF 视为错误，避免 tar 头与数据长度不一致。
/// A reader that yields exactly `remaining` bytes; premature EOF is reported as an error.
struct ExactReader<'a> {
    inner: File,
    remaining: u64,
    pipe: &'a Pipeline,
}

impl Read for ExactReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pipe.stopped() {
            // 注意：不能用 ErrorKind::Interrupted（io::copy 会重试它）。
            return Err(io::Error::other("backup stopped / 备份已停止"));
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.remaining) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "文件在备份期间被截断 / file truncated during backup",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// 单遍哈希读取器：透传 [`ExactReader`] 的字节，同步喂入 SHA-256 与进度哈希段（C-38）。
/// Single-pass hashing reader: forwards bytes into SHA-256 and the hash progress counter.
struct HashingReader<'a> {
    inner: ExactReader<'a>,
    hasher: Sha256,
}

impl Read for HashingReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.inner
            .pipe
            .bytes_hashed
            .fetch_add(n as u64, Ordering::SeqCst);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// 进度与时间工具 / progress & time helpers
// ---------------------------------------------------------------------------

/// 把哈希/打包两个字节计数映射到 `0.10..=0.95` 的进度值。
/// Map the hashed and packed byte counters into the `0.10..=0.95` progress band.
///
/// 按 DESIGN.md §4.4 的字节加权：哈希占 `0.10..=0.70`（权重 0.60），
/// 打包占 `0.70..=0.95`（权重 0.25）。两个计数器均单调递增，故结果单调不回退；
/// `total_bytes == 0`（空扫描）时不做除法，直接返回 `0.10`。
fn progress_value(bytes_hashed: u64, bytes_packed: u64, total_bytes: u64) -> f32 {
    let denom = total_bytes.max(1) as f64;
    let hashed = ((bytes_hashed as f64) / denom).clamp(0.0, 1.0) as f32;
    let packed = ((bytes_packed as f64) / denom).clamp(0.0, 1.0) as f32;
    0.10 + 0.60 * hashed + 0.25 * packed
}

/// 当前 Unix 时间戳（秒）；时钟早于 1970 时返回负值。
/// Current Unix timestamp in seconds; negative when the clock predates 1970.
fn unix_now() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs() as i64),
    }
}

/// 天数（自 1970-01-01 起）→ (年, 月, 日)，Howard Hinnant 的 civil_from_days 算法。
/// Days since the epoch → UTC year/month/day (Howard Hinnant's civil_from_days).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Unix 秒 → (年, 月, 日, 时, 分, 秒)，UTC。
/// Unix seconds → UTC civil date and time.
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    (
        y,
        mo,
        d,
        (rem / 3600) as u32,
        ((rem % 3600) / 60) as u32,
        (rem % 60) as u32,
    )
}

/// UTC 时间戳格式化：`compact=false` → `YYYY-MM-DDTHH:MM:SSZ`（manifest），
/// `compact=true` → `YYYYMMDD-HHMMSS`（文件名）。手写实现，不引入 chrono。
/// Format a UTC timestamp either as RFC3339 or as a compact filename stamp.
fn utc_timestamp(secs: i64, compact: bool) -> String {
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    if compact {
        format!("{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}")
    } else {
        format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z")
    }
}

/// 把任意 `kver` 清洗成可用于文件名的安全串：`/` → `_`，再兜底裁剪。
/// Sanitize an arbitrary `kver` into a filename-safe string (`/` → `_`, then trim).
fn sanitize_kver_filename(kver: &str) -> String {
    let replaced: String = kver
        .trim()
        .chars()
        .map(|c| if c == '/' { '_' } else { c })
        .collect();
    if is_safe_kernel_version(&replaced) {
        return replaced;
    }
    let mut out: String = replaced
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
        .take(127)
        .collect();
    if out.is_empty() {
        out.push_str("unknown");
    }
    let first_is_alnum = match out.chars().next() {
        Some(c) => c.is_ascii_alphanumeric(),
        None => false,
    };
    if !first_is_alnum {
        out.insert(0, 'k');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ModInfo, Provenance};
    use flate2::read::GzDecoder;
    use tar::Archive as TarArchive;

    /// 构造一个可传入 `write_entry` 的最小 [`Pipeline`]。
    fn test_pipeline() -> Pipeline {
        Pipeline {
            cancel: Arc::new(AtomicBool::new(false)),
            abort: Arc::new(AtomicBool::new(false)),
            first_error: Arc::new(Mutex::new(None)),
            progress: Arc::new(|_, _| {}),
            throttle: Arc::new(Mutex::new(ProgressState {
                last_at: Instant::now(),
                last_value: f32::NEG_INFINITY,
            })),
            bytes_hashed: Arc::new(AtomicU64::new(0)),
            bytes_packed: Arc::new(AtomicU64::new(0)),
            total_bytes: Arc::new(AtomicU64::new(0)),
            entry_total: Arc::new(AtomicUsize::new(0)),
            scan_slot: Arc::new(Mutex::new(None)),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ldb-backup-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    /// 最小扫描条目（默认普通内容、无 v2 元数据）。
    fn scan_entry(rel: &str, kind: EntryKind) -> ScanEntry {
        ScanEntry {
            abs_path: PathBuf::from(format!("/{rel}")),
            rel_path: rel.to_string(),
            size: 0,
            kind,
            link_target: None,
            owner: None,
            modinfo: None,
            content_stored: true,
        }
    }

    /// 把单条 entry 写进临时 tar.gz，再用 `tar::Archive` 读回（名称, 类型, 链接目标）。
    fn roundtrip_entry(entry: &ScanEntry) -> (u64, Vec<(String, EntryType, Option<String>)>) {
        let dir = temp_dir("roundtrip");
        let out = dir.join("out.tar.gz");
        let file = File::create(&out).expect("create archive");
        let mut builder = TarWriter::new(GzEncoder::new(file, Compression::default()));
        let pipe = test_pipeline();
        let mut warnings = Vec::new();
        let written = write_entry(&mut builder, entry, &pipe, &mut warnings)
            .expect("write entry")
            .map(|w| w.bytes)
            .unwrap_or(0);
        let file = builder
            .into_inner()
            .expect("into_inner")
            .finish()
            .expect("finish");
        file.sync_all().ok();

        let f = File::open(&out).expect("open archive");
        let mut archive = TarArchive::new(GzDecoder::new(f));
        let mut items = Vec::new();
        for e in archive.entries().expect("entries") {
            let e = e.expect("entry");
            let path = e.path().expect("path").to_string_lossy().into_owned();
            let etype = e.header().entry_type();
            let link = e
                .link_name()
                .ok()
                .flatten()
                .map(|p| p.to_string_lossy().into_owned());
            items.push((path, etype, link));
        }
        let _ = std::fs::remove_dir_all(&dir);
        (written, items)
    }

    #[test]
    fn rel_path_traversal_is_rejected() {
        assert!(validate_rel_path("..").is_err());
        assert!(validate_rel_path("../etc/passwd").is_err());
        assert!(validate_rel_path("lib/modules/6.8.0/../../etc/shadow").is_err());
        assert!(validate_rel_path("a/../b").is_err());
        assert!(validate_rel_path("/etc/passwd").is_err());
        assert!(validate_rel_path("").is_err());
        assert!(validate_rel_path("etc\0passwd").is_err());
    }

    #[test]
    fn rel_path_rejection_is_format_error() {
        match validate_rel_path("../oops") {
            Err(AppError::Format(msg)) => assert!(msg.contains("..")),
            other => panic!("expected AppError::Format, got {other:?}"),
        }
        match validate_rel_path("/abs") {
            Err(AppError::Format(_)) => {}
            other => panic!("expected AppError::Format, got {other:?}"),
        }
    }

    #[test]
    fn rel_path_normal_entries_are_accepted() {
        assert!(validate_rel_path("lib/modules/6.8.0-45-generic/updates/dkms/foo.ko").is_ok());
        assert!(validate_rel_path("etc/modprobe.d/foo.conf").is_ok());
        assert!(validate_rel_path("usr/src/virtualbox-7.0.20/Makefile").is_ok());
        assert!(validate_rel_path("lib/firmware/intel/ucode/amd-ucode.bin").is_ok());
        // 只是文件名里带两个点，不是父目录组件
        assert!(validate_rel_path("var/lib/dkms/foo..bar/1.0/x.c").is_ok());
    }

    #[test]
    fn default_out_path_is_a_safe_filename() {
        let p = default_out_path("6.8.0/45-generic");
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            name.starts_with("driver-backup-6.8.0_45-generic-"),
            "unexpected name: {name}"
        );
        assert!(name.ends_with(".tar.gz"), "unexpected name: {name}");
        assert!(!name.contains('/'), "unexpected name: {name}");

        let p2 = default_out_path("../../evil");
        let name2 = p2.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            name2.starts_with("driver-backup-"),
            "unexpected name: {name2}"
        );
        assert!(!name2.contains('/'), "unexpected name: {name2}");
        assert!(name2.ends_with(".tar.gz"), "unexpected name: {name2}");

        let p3 = default_out_path("");
        let name3 = p3.file_name().and_then(|s| s.to_str()).unwrap_or("");
        assert!(
            name3.starts_with("driver-backup-unknown-"),
            "unexpected: {name3}"
        );
    }

    #[test]
    fn kver_filename_sanitizer() {
        assert_eq!(
            sanitize_kver_filename("6.8.0-45-generic"),
            "6.8.0-45-generic"
        );
        assert_eq!(sanitize_kver_filename("6.8.0/45"), "6.8.0_45");
        assert_eq!(sanitize_kver_filename(" 6.8.0 "), "6.8.0");
        // 非法首字符补 'k'，非法字符被剔除
        assert!(is_safe_kernel_version(&sanitize_kver_filename("../..")));
        assert!(is_safe_kernel_version(&sanitize_kver_filename(
            "$(id); rm -rf /"
        )));
        assert!(sanitize_kver_filename("").starts_with("unknown"));
        assert!(sanitize_kver_filename(&"a".repeat(200)).len() <= 128);
    }

    #[test]
    fn utc_timestamp_is_utc() {
        assert_eq!(utc_timestamp(0, false), "1970-01-01T00:00:00Z");
        assert_eq!(utc_timestamp(0, true), "19700101-000000");
        assert_eq!(utc_timestamp(1_700_000_000, false), "2023-11-14T22:13:20Z");
        assert_eq!(utc_timestamp(1_700_000_000, true), "20231114-221320");
        // 闰日
        assert_eq!(utc_timestamp(1_709_164_800, false), "2024-02-29T00:00:00Z");
        // 跨年边界
        assert_eq!(utc_timestamp(1_704_067_199, false), "2023-12-31T23:59:59Z");
        assert_eq!(utc_timestamp(1_704_067_200, false), "2024-01-01T00:00:00Z");
    }

    #[test]
    fn progress_maps_hash_and_pack_to_band() {
        // 阶段边界（DESIGN.md §4.4：扫描 0–10%，哈希 10–70%，压缩 70–95%）
        assert!((progress_value(0, 0, 1_000) - 0.10).abs() < 1e-6);
        assert!((progress_value(1_000, 0, 1_000) - 0.70).abs() < 1e-6);
        assert!((progress_value(1_000, 1_000, 1_000) - 0.95).abs() < 1e-6);

        let mid = progress_value(500, 500, 1_000);
        assert!(mid > 0.10 && mid < 0.95, "mid = {mid}");

        // 空扫描（total = 0）不应除零或产生 NaN
        assert!((progress_value(0, 0, 0) - 0.10).abs() < 1e-6);

        // 文件在备份期间变大导致计数超额：钳制在 0.95，不越界
        assert!((progress_value(u64::MAX, u64::MAX, u64::MAX) - 0.95).abs() < 1e-6);

        // 单调性：任一计数器只增不减时进度不回退
        assert!(progress_value(100, 0, 1_000) < progress_value(200, 0, 1_000));
        assert!(progress_value(1_000, 100, 1_000) < progress_value(1_000, 200, 1_000));
        assert!(progress_value(500, 0, 1_000) < progress_value(500, 500, 1_000));
    }

    // -----------------------------------------------------------------------
    // v0.2.0 新增：strategy_hint（P0-4 归档侧）
    // -----------------------------------------------------------------------

    #[test]
    fn strategy_hint_rebuild_for_dkms_path() {
        // /var/lib/dkms 与 /usr/src 下的模块源码树 → 重建
        let var_lib = scan_entry(
            "var/lib/dkms/nvidia/550.129.03/modules/nvidia.ko",
            EntryKind::Module,
        );
        assert_eq!(
            strategy_hint(&var_lib, &[], Family::Debian),
            Some(RestoreStrategy::Rebuild)
        );
        let usr_src = scan_entry("usr/src/vbox-7.0/source/vbox.ko", EntryKind::Module);
        assert_eq!(
            strategy_hint(&usr_src, &[], Family::Debian),
            Some(RestoreStrategy::Rebuild)
        );
    }

    #[test]
    fn strategy_hint_rebuild_for_dkms_name() {
        let dkms = vec![DkmsPackage {
            name: "nvidia".to_string(),
            version: "550.129.03".to_string(),
        }];
        // 编译产物位于 updates/dkms，但文件名匹配 DKMS 包名 → 重建
        let module = scan_entry(
            "lib/modules/6.8.0/updates/dkms/nvidia.ko",
            EntryKind::Module,
        );
        assert_eq!(
            strategy_hint(&module, &dkms, Family::Debian),
            Some(RestoreStrategy::Rebuild)
        );
        // nvidia-uvm 命中 `<name>-` 前缀
        let uvm = scan_entry(
            "lib/modules/6.8.0/updates/dkms/nvidia-uvm.ko",
            EntryKind::Module,
        );
        assert_eq!(
            strategy_hint(&uvm, &dkms, Family::Debian),
            Some(RestoreStrategy::Rebuild)
        );
        // 压缩变体同样命中
        let zst = scan_entry("lib/modules/6.8.0/extra/nvidia.ko.zst", EntryKind::Module);
        assert_eq!(
            strategy_hint(&zst, &dkms, Family::Debian),
            Some(RestoreStrategy::Rebuild)
        );
    }

    #[test]
    fn strategy_hint_reinstall_when_owner_known() {
        let mut module = scan_entry("lib/modules/6.8.0/extra/foo.ko", EntryKind::Module);
        module.owner = Some(Provenance {
            manager: "dpkg".to_string(),
            package: "foo-dkms".to_string(),
            version: "1.0".to_string(),
        });
        assert_eq!(
            strategy_hint(&module, &[], Family::Debian),
            Some(RestoreStrategy::Reinstall)
        );
        // 已知来源包优先于 RHEL 的 weak-modules
        assert_eq!(
            strategy_hint(&module, &[], Family::Rhel),
            Some(RestoreStrategy::Reinstall)
        );
    }

    #[test]
    fn strategy_hint_weak_modules_for_rhel() {
        let module = scan_entry("lib/modules/6.8.0/extra/foo.ko", EntryKind::Module);
        assert_eq!(
            strategy_hint(&module, &[], Family::Rhel),
            Some(RestoreStrategy::WeakModules)
        );
    }

    #[test]
    fn strategy_hint_copy_and_none() {
        let module = scan_entry("lib/modules/6.8.0/extra/foo.ko", EntryKind::Module);
        assert_eq!(
            strategy_hint(&module, &[], Family::Debian),
            Some(RestoreStrategy::Copy)
        );
        assert_eq!(
            strategy_hint(&module, &[], Family::Arch),
            Some(RestoreStrategy::Copy)
        );
        assert_eq!(
            strategy_hint(&module, &[], Family::Unknown),
            Some(RestoreStrategy::Copy)
        );
        // 非模块条目一律 None
        for (rel, kind) in [
            ("etc/modprobe.d/foo.conf", EntryKind::Config),
            ("lib/firmware/vendor/fw.bin", EntryKind::Firmware),
            ("usr/src/nvidia/x.c", EntryKind::Dkms),
            ("lib/modules/6.8.0/weak-updates/foo.ko", EntryKind::Symlink),
        ] {
            let entry = scan_entry(rel, kind);
            assert_eq!(strategy_hint(&entry, &[], Family::Rhel), None, "{rel}");
        }
    }

    // -----------------------------------------------------------------------
    // v0.2.0 新增：validate_link_target（P0-1 安全守门）
    // -----------------------------------------------------------------------

    #[test]
    fn validate_link_target_accepts_relative_within_managed() {
        // weak-updates 的典型形态：指向另一内核的同名模块
        assert!(validate_link_target(
            "lib/modules/6.8.0-45-generic/weak-updates/foo.ko",
            "../../6.8.0-40-generic/extra/foo.ko"
        )
        .is_ok());
        // /usr/lib/modules 前缀同样受管
        assert!(validate_link_target(
            "usr/lib/modules/6.8.0/weak-updates/foo.ko",
            "../../6.8.0-40/extra/foo.ko"
        )
        .is_ok());
        // `/etc` 下的配置别名：解析后落在 `etc/` 树内 / 允许前缀白名单 → 放行
        // （真实案例：/etc/modprobe.d/blacklist-oss.conf -> /lib/linux-sound-base/…）
        assert!(
            validate_link_target("etc/modprobe.d/alias.conf", "../modprobe.d/other.conf").is_ok()
        );
        assert!(validate_link_target(
            "etc/modprobe.d/blacklist-oss.conf",
            "/lib/linux-sound-base/noOSS.modprobe.conf"
        )
        .is_ok());
        // 模块目录下仍不允许绝对目标
        assert!(validate_link_target("lib/modules/6.8/a.ko", "/etc/shadow").is_err());
        // 同目录相对目标
        assert!(validate_link_target("lib/modules/6.8.0/extra/a.ko", "b.ko").is_ok());
    }

    #[test]
    fn validate_link_target_rejects_absolute_and_escape() {
        // 模块目录下的绝对路径目标（如 /etc/shadow）一律拒绝
        assert!(
            validate_link_target("lib/modules/6.8.0/weak-updates/foo.ko", "/etc/shadow").is_err()
        );
        // C-01：`/etc` 下的链接也不再"原样放行"——越出归档根的相对目标必须拒绝，
        // 否则恶意归档可用 `data/etc/x -> ../../../../..` + 后续条目做禁闭逃逸
        // （链接自身路径合法并不足够，解析后的目标同样要受约束）。
        assert!(validate_link_target("etc/modprobe.d/x.conf", "../../../../etc/shadow").is_err());
        // 归一化后落在受管前缀之外
        assert!(validate_link_target(
            "lib/modules/6.8.0/weak-updates/foo.ko",
            "../../../../srv/foo.ko"
        )
        .is_err());
        // 空目标 / NUL
        assert!(validate_link_target("lib/modules/x/a.ko", "").is_err());
        assert!(validate_link_target("lib/modules/x/a.ko", "bad\0target").is_err());
        // 越界一律是 AppError::Format
        match validate_link_target("lib/modules/x/a.ko", "/etc/shadow") {
            Err(AppError::Format(_)) => {}
            other => panic!("expected AppError::Format, got {other:?}"),
        }
    }

    /// C-01（v0.2.1）：`etc/` 链接目标的禁闭校验——与 restore.rs 同一规则。
    /// C-01 (v0.2.1): containment check for `etc/` symlink targets (same rule as restore.rs).
    #[test]
    fn validate_link_target_etc_containment_c01() {
        // ---- 拒绝：解析结果既不在 etc 树内、也不在允许前缀白名单 ----
        assert!(validate_link_target("etc/x", "/").is_err(), "`/` 必须被拒");
        assert!(
            validate_link_target("etc/x", "../../../../..").is_err(),
            "越出归档根的相对目标必须被拒"
        );
        assert!(
            validate_link_target("etc/x", "/home/user/pwn").is_err(),
            "白名单之外的绝对目标必须被拒"
        );
        // 相对目标归一化后同样要落在白名单内（/../.. → /home/user/pwn）
        assert!(
            validate_link_target("etc/modprobe.d/x.conf", "../../home/user/pwn").is_err(),
            "解析到 /home 的相对目标必须被拒"
        );

        // ---- 放行：白名单前缀与 etc 树内 ----
        // v0.2.0 实测样例（usr-merge 之前）
        assert!(validate_link_target(
            "etc/modprobe.d/blacklist-oss.conf",
            "/lib/linux-sound-base/noOSS.modprobe.conf"
        )
        .is_ok());
        // usr-merge 形态
        assert!(validate_link_target("etc/x", "/usr/lib/foo").is_ok());
        // etc 树内的相对目标（modules-load.d → ../modules）
        assert!(validate_link_target("etc/modules-load.d/modules.conf", "../modules").is_ok());

        // 错误类型为 Format，且错误信息带归一化结果
        match validate_link_target("etc/x", "/home/user/pwn") {
            Err(AppError::Format(m)) => assert!(m.contains("normalized"), "消息={m}"),
            other => panic!("expected AppError::Format, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // v0.2.0 新增：write_entry（P0-1 符号链接归档 + content_stored=false）
    // -----------------------------------------------------------------------

    #[test]
    fn write_entry_symlink_is_stored_as_link() {
        let mut entry = scan_entry("lib/modules/6.8.0/weak-updates/foo.ko", EntryKind::Symlink);
        entry.link_target = Some("../../6.8.0-40-generic/extra/foo.ko".to_string());

        let (written, items) = roundtrip_entry(&entry);
        assert_eq!(written, 0, "符号链接不写内容字节，size 记为 0");
        assert_eq!(items.len(), 1);
        let (path, etype, link) = &items[0];
        assert_eq!(path, "data/lib/modules/6.8.0/weak-updates/foo.ko");
        assert_eq!(*etype, EntryType::Symlink, "tar 内必须是 symlink 条目");
        assert_eq!(link.as_deref(), Some("../../6.8.0-40-generic/extra/foo.ko"));
    }

    #[test]
    fn write_entry_rejects_escaping_symlink() {
        let mut entry = scan_entry("lib/modules/6.8.0/weak-updates/foo.ko", EntryKind::Symlink);
        entry.link_target = Some("/etc/shadow".to_string());
        let dir = temp_dir("badlink");
        let out = dir.join("out.tar.gz");
        let file = File::create(&out).unwrap();
        let mut builder = TarWriter::new(GzEncoder::new(file, Compression::default()));
        let pipe = test_pipeline();
        let mut warnings = Vec::new();
        match write_entry(&mut builder, &entry, &pipe, &mut warnings) {
            Err(AppError::Format(_)) => {}
            other => panic!("expected AppError::Format, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_entry_skips_content_not_stored() {
        let dir = temp_dir("nostore");
        let src = dir.join("fw.bin");
        std::fs::write(&src, b"firmware-bytes").expect("write firmware");
        let out = dir.join("out.tar.gz");
        let file = File::create(&out).unwrap();
        let mut builder = TarWriter::new(GzEncoder::new(file, Compression::default()));

        let mut entry = scan_entry("lib/firmware/vendor/fw.bin", EntryKind::Firmware);
        entry.abs_path = src.clone();
        entry.content_stored = false;

        let pipe = test_pipeline();
        let mut warnings = Vec::new();
        let written = write_entry(&mut builder, &entry, &pipe, &mut warnings)
            .unwrap()
            .expect("content_stored=false 仍产出 manifest 摘要")
            .bytes;
        assert_eq!(written, 0, "content_stored=false 不写内容字节");
        assert!(warnings.is_empty(), "不应触发大小变化告警: {warnings:?}");

        let file = builder.into_inner().unwrap().finish().unwrap();
        file.sync_all().ok();
        let f = File::open(&out).unwrap();
        let mut archive = TarArchive::new(GzDecoder::new(f));
        let names: Vec<String> = archive
            .entries()
            .unwrap()
            .map(|e| e.unwrap().path().unwrap().to_string_lossy().into_owned())
            .collect();
        assert!(
            !names.iter().any(|n| n == "data/lib/firmware/vendor/fw.bin"),
            "tar 内不得出现未存储内容的路径: {names:?}"
        );

        // manifest 记录仍然生成（build_manifest_entry 负责）
        let me = build_manifest_entry(&entry, "deadbeef".to_string(), written, &[], Family::Debian);
        assert_eq!(me.path, "lib/firmware/vendor/fw.bin");
        assert!(
            !me.content_stored,
            "manifest 记录须标记 content_stored=false"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_entry_transfers_v2_fields_and_sets_strategy() {
        let mut entry = scan_entry(
            "lib/modules/6.8.0/updates/dkms/nvidia.ko",
            EntryKind::Module,
        );
        entry.content_stored = false;
        entry.link_target = Some("ignored-for-module".to_string());
        entry.owner = Some(Provenance {
            manager: "dpkg".to_string(),
            package: "nvidia-dkms".to_string(),
            version: "550".to_string(),
        });
        entry.modinfo = Some(ModInfo {
            vermagic: Some("6.8.0-45-generic SMP".to_string()),
            ..Default::default()
        });
        let dkms = vec![DkmsPackage {
            name: "nvidia".to_string(),
            version: "550".to_string(),
        }];

        let me = build_manifest_entry(&entry, "cafe".to_string(), 0, &dkms, Family::Debian);
        assert_eq!(me.path, entry.rel_path);
        assert_eq!(me.sha256, "cafe");
        assert!(!me.content_stored);
        assert_eq!(me.link_target.as_deref(), Some("ignored-for-module"));
        assert_eq!(
            me.owner.as_ref().map(|o| o.package.as_str()),
            Some("nvidia-dkms")
        );
        assert!(me
            .modinfo
            .as_ref()
            .and_then(|m| m.vermagic.as_deref())
            .is_some());
        assert_eq!(me.strategy_hint, Some(RestoreStrategy::Rebuild));
    }
}
