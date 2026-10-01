//! 备份流水线：扫描 → 哈希 → 打包（三段多线程流水作业）。
//! Backup pipeline: scan → hash → pack (three-stage multithreaded pipeline).
//!
//! # 线程结构 / Thread structure
//!
//! ```text
//! Stage 1 Walker ──sync_channel(64)──▶ Stage 2 Hasher×N ──sync_channel(64)──▶ Stage 3 Packer
//!  crate::scan::scan()                  读文件 + SHA-256                      GzEncoder<File>
//!  产出 (index, ScanEntry)              累加 bytes_hashed 计数器             + tar::Builder
//!  （有界通道 = 背压）                    （有界通道 = 背压）                    末尾追加 manifest.json
//! ```
//!
//! - **Stage 1 Walker**：调用 [`crate::scan::scan`] 得到 [`ScanReport`]，为每个条目分配
//!   其在 `entries` 中的下标后，经 `sync_channel::<(usize, ScanEntry)>(64)` 送入哈希阶段。
//!   有界通道提供背压，full 模式下的 `/lib/firmware` 不会把内存吃光。
//! - **Stage 2 Hasher × N**（`N = min(4, available_parallelism())`）：打开文件计算 SHA-256，
//!   **边读边把字节数累加到共享原子计数器 `bytes_hashed`** 供进度使用，产出
//!   [`HashedEntry`] 再经 `sync_channel::<HashedEntry>(64)` 送入打包阶段。
//!   tar 只能有唯一写者，因此哈希阶段**绝不写 tar**，只做"读 + 哈希"。
//! - **Stage 3 Packer**：`flate2::write::GzEncoder<File>` + `tar::Builder` 的唯一写者，
//!   按序写入 `data/<rel_path>`（mode `0o644`、uid/gid `0`、mtime 取自源文件
//!   `std::os::unix::fs::MetadataExt::mtime`），末尾追加 `manifest.json`。
//!
//! # 顺序一致性策略 / Ordering strategy
//!
//! 采用 **「扫描序号 + Packer 侧 `BTreeMap` 重排」**（即允许多哈希线程并行的正确版本）：
//!
//! 1. Walker 给每个 `ScanEntry` 分配其在 `ScanReport::entries` 中的下标 `index`；
//! 2. N 个哈希线程并发读取，完成顺序必然乱序；
//! 3. Packer **先 `recv()` 再重排**：结果放入 `BTreeMap<usize, HashedEntry>`，只有当
//!    `next` 序号就绪时才写入 tar 并推进 `next`。因此 **tar 内条目顺序、
//!    `manifest.entries` 顺序与扫描顺序完全一致**；又因为 Packer 每轮都先接收，
//!    等待某个序号不会堵住通道，背压依然成立、也不会死锁；
//! 4. 通道关闭后若 `BTreeMap` 仍非空，说明存在序号缺口（正常流程不可能出现，只有出错
//!    中止才会），此时返回 [`AppError::Format`] 兜底。
//!
//! # 进度 / Progress
//!
//! 按 DESIGN.md §4.4 的字节加权分段：
//!
//! - `0.00` 开始扫描 → `0.10` 扫描完成（强制回调，附体积与条目统计）；
//! - `0.10..=0.70` 哈希阶段：`bytes_hashed / total_bytes` 线性映射；
//! - `0.70..=0.95` 打包阶段：`bytes_packed / total_bytes` 叠加映射；
//!   两个计数器都只增不减，因此整体进度**单调不回退**；
//! - `0.95` 写入 manifest 前 → `1.00` 备份完成（强制回调）。
//!
//! 回调统一节流：**距上次回调 ≥ 100ms 或进度变化 ≥ 1%** 才上抛（阶段边界的
//! 0.00/0.10/0.95/1.00 强制上抛），避免刷爆 UI 事件队列。
//!
//! # 取消 / Cancel
//!
//! `Arc<AtomicBool>` 三阶段共享，并透传给 `scan()`（Walker 阶段即可中断）。任一阶段
//! 看到取消或其它阶段报错（内部 `abort` 标志）就停止工作并关闭自己的发送端，从而让上游
//! `send()` 失败并连锁退出 —— **不会留下永久阻塞的线程**。调用线程在 join 全部阶段后
//! 删除半成品 `out_file`（删除失败忽略），再返回 [`AppError::Cancelled`] 或首个错误。
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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
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
use crate::scan::{scan, ScanOptions};

/// Walker 发给哈希阶段的任务：`(扫描序号, 条目)`。
type ScanTask = (usize, ScanEntry);

/// tar 的具体写者类型：gzip 压缩层 + tar 打包层。
type TarWriter = TarBuilder<GzEncoder<File>>;

const CHANNEL_CAP: usize = 64;
const HASH_CHUNK: usize = 64 * 1024;
const PROGRESS_MIN_INTERVAL: Duration = Duration::from_millis(100);
const PROGRESS_MIN_DELTA: f32 = 0.01;

/// 一次成功打包的产物（Packer → 调用线程）。
struct PackerOutcome {
    manifest: Manifest,
    bytes_written: u64,
    entry_count: usize,
}

/// 哈希阶段的产出：条目 + 序号 + SHA-256 + 实际读到的字节数。
struct HashedEntry {
    index: usize,
    entry: ScanEntry,
    sha256: String,
    hashed_bytes: u64,
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
    fn emit(&self, value: f32, msg: &str, force: bool) {
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
        (self.progress)(value, msg.to_string());
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

/// 运行三段流水备份：Walker → Hasher×N → Packer，内部自建线程。
/// Run the three-stage backup pipeline (Walker → Hashers → Packer) on internal threads.
///
/// 成功返回 [`BackupReport`]；失败时删除半成品 `out_file`（删除失败忽略）并返回：
/// - [`AppError::Validation`]：`kver` 非法或输出路径为空；
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
        progress,
        cancel,
    } = req;
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
    let file_started = Arc::new(AtomicBool::new(false));

    // ---- 2. 三段之间的有界通道 / bounded channels between stages ----
    let (scan_tx, scan_rx) = sync_channel::<ScanTask>(CHANNEL_CAP);
    let (hash_tx, hash_rx) = sync_channel::<HashedEntry>(CHANNEL_CAP);
    let (done_tx, done_rx) = channel::<Option<PackerOutcome>>();
    let shared_scan_rx = Arc::new(Mutex::new(scan_rx));

    let mut handles: Vec<JoinHandle<()>> = Vec::new();

    // Stage 1：Walker 线程
    {
        let p = pipe.clone();
        let kver = kver.clone();
        let distro = distro.clone();
        let spawned = thread::Builder::new()
            .name("backup-walker".to_string())
            .spawn(move || walker_main(&p, &kver, &distro, mode, scan_tx));
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => pipe.fail(AppError::Io(e)),
        }
    }

    // Stage 2：Hasher × N（N = min(4, 可用核数)）
    let n_hashers = thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .min(4);
    for i in 0..n_hashers {
        let p = pipe.clone();
        let input = shared_scan_rx.clone();
        let output = hash_tx.clone();
        let spawned = thread::Builder::new()
            .name(format!("backup-hasher-{i}"))
            .spawn(move || hasher_main(&p, &input, &output));
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => pipe.fail(AppError::Io(e)),
        }
    }
    // 关键：主线程不保留发送端副本，最后一个哈希线程退出即关闭哈希通道。
    drop(hash_tx);
    drop(shared_scan_rx);

    // Stage 3：Packer 线程（tar 的唯一写者）
    {
        let p = pipe.clone();
        let out_file = out_file.clone();
        let kver = kver.clone();
        let distro = distro.clone();
        let file_started = file_started.clone();
        let spawned = thread::Builder::new()
            .name("backup-packer".to_string())
            .spawn(move || {
                let outcome =
                    packer_main(&p, hash_rx, &out_file, &kver, &distro, mode, &file_started);
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
        remove_partial(&out_file, &file_started);
        return Err(err);
    }

    match done {
        Some(Some(o)) => Ok(BackupReport {
            out_file,
            bytes_written: o.bytes_written,
            entry_count: o.entry_count,
            duration_ms: started.elapsed().as_millis(),
            manifest: o.manifest,
        }),
        _ => {
            remove_partial(&out_file, &file_started);
            Err(AppError::Format(
                "备份流水线异常终止 / backup pipeline terminated unexpectedly".to_string(),
            ))
        }
    }
}

/// 删除半成品输出文件（仅在确实创建过时才删，删除失败忽略）。
/// Remove the partially written archive; failures are ignored.
fn remove_partial(out_file: &Path, file_started: &AtomicBool) {
    if file_started.load(Ordering::SeqCst) {
        let _ = std::fs::remove_file(out_file);
    }
}

// ---------------------------------------------------------------------------
// Stage 1: Walker
// ---------------------------------------------------------------------------

/// Stage 1：全树扫描并把条目（带序号）送入哈希阶段。
/// Stage 1: scan the whole tree and feed indexed entries into the hashing stage.
fn walker_main(
    pipe: &Pipeline,
    kver: &str,
    distro: &DistroInfo,
    mode: BackupMode,
    output: SyncSender<ScanTask>,
) {
    pipe.emit(0.0, "扫描中… / scanning", true);

    let opt = ScanOptions {
        kver,
        distro,
        mode,
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

    let total: u64 = report.entries.iter().map(|e| e.size).sum();
    pipe.total_bytes.store(total, Ordering::SeqCst);
    let entries = std::mem::take(&mut report.entries);
    pipe.entry_total.store(entries.len(), Ordering::SeqCst);

    pipe.emit(
        0.10,
        &format!(
            "扫描完成：{} 个文件，{}（in-tree 跳过 {}，固件预估 {}）/ scanned",
            entries.len(),
            human_size(total),
            report.skipped_in_tree,
            human_size(report.firmware_bytes)
        ),
        true,
    );
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
// Stage 2: Hasher × N
// ---------------------------------------------------------------------------

/// Stage 2：读文件算 SHA-256，边读边累加进度计数，再把结果送入打包阶段。
/// Stage 2: read files, compute SHA-256, feed the progress counter and hand over.
///
/// 多个哈希线程共享同一个 `Receiver`（`Arc<Mutex<Receiver>>`，recv 返回后立即释放锁），
/// 各自持有独立的 `SyncSender` 发送端。本阶段不写 tar。
fn hasher_main(
    pipe: &Pipeline,
    input: &Mutex<Receiver<ScanTask>>,
    output: &SyncSender<HashedEntry>,
) {
    loop {
        if pipe.stopped() {
            pipe.note_stop();
            return;
        }
        // 只在 recv 期间持锁，取到任务立刻释放，保证多线程并发哈希。
        let task = {
            let guard = heal(input);
            guard.recv()
        };
        let (index, entry) = match task {
            Ok(t) => t,
            // Walker 已结束：本线程退出并释放发送端。
            Err(_) => return,
        };
        // 符号链接不读取目标：哈希"链接目标字符串"本身（P0-1 归档侧）。
        // Symlinks do not open their target: hash the link target string instead.
        let hash_result = if entry.kind == EntryKind::Symlink {
            let target = entry.link_target.as_deref().unwrap_or("");
            Ok((sha256_hex(target.as_bytes()), 0))
        } else {
            hash_file(&entry.abs_path, pipe)
        };
        match hash_result {
            Ok((sha256, hashed_bytes)) => {
                let item = HashedEntry {
                    index,
                    entry,
                    sha256,
                    hashed_bytes,
                };
                if output.send(item).is_err() {
                    // Packer 已退出。
                    return;
                }
            }
            Err(e) => {
                pipe.fail(e);
                return;
            }
        }
    }
}

/// 读取整个文件并计算 SHA-256，同时把读取字节累加到 `bytes_hashed` 并上报进度。
/// Read a whole file, compute SHA-256, count the bytes into `bytes_hashed` and report progress.
fn hash_file(path: &Path, pipe: &Pipeline) -> AppResult<(String, u64)> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK];
    let mut total: u64 = 0;
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
        total += n as u64;
        pipe.bytes_hashed.fetch_add(n as u64, Ordering::SeqCst);
    }
    let digest = hasher.finalize();
    let mut sha256 = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        let b = *byte;
        sha256.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        sha256.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    pipe.emit_progress(&format!(
        "已哈希 {} / {} / hashing",
        human_size(pipe.bytes_hashed.load(Ordering::SeqCst)),
        human_size(pipe.total_bytes.load(Ordering::SeqCst))
    ));
    Ok((sha256, total))
}

/// 计算任意字节串的 SHA-256（64 位小写十六进制），用于符号链接目标的语义哈希。
/// Compute the SHA-256 of arbitrary bytes (lowercase hex); used for symlink target hashing.
fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest.iter() {
        let b = *byte;
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

// ---------------------------------------------------------------------------
// Stage 3: Packer
// ---------------------------------------------------------------------------

/// Stage 3：tar+gzip 的唯一写者，按序写入 `data/<rel_path>` 并在末尾追加 `manifest.json`。
/// Stage 3: the single tar+gzip writer; appends `data/<rel_path>` entries and `manifest.json`.
///
/// 乱序到达的哈希结果先放进 `BTreeMap` 缓冲，只有 `next` 序号就绪才写入 tar，
/// 从而保证归档顺序 == 扫描顺序（详见模块文档）。
#[allow(clippy::too_many_arguments)]
fn packer_main(
    pipe: &Pipeline,
    input: Receiver<HashedEntry>,
    out_file: &Path,
    kver: &str,
    distro: &DistroInfo,
    mode: BackupMode,
    file_started: &AtomicBool,
) -> AppResult<PackerOutcome> {
    let file = File::create(out_file)?;
    file_started.store(true, Ordering::SeqCst);
    let encoder = GzEncoder::new(file, Compression::default());
    let mut builder = TarWriter::new(encoder);

    let mut pending: BTreeMap<usize, HashedEntry> = BTreeMap::new();
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
            Ok(item) => {
                pending.insert(item.index, item);
            }
            // 所有哈希线程退出 → 通道关闭。
            Err(_) => break,
        }
        // 先接收后重排：始终排空通道，等待某个序号不会造成阻塞。
        while pending.contains_key(&next) {
            let item = match pending.remove(&next) {
                Some(v) => v,
                None => break,
            };
            let total = pipe.total_bytes.load(Ordering::SeqCst);
            let written = write_entry(
                &mut builder,
                &item.entry,
                item.hashed_bytes,
                pipe,
                &mut local_warnings,
            )?;
            packed_bytes += written;
            pipe.bytes_packed.fetch_add(written, Ordering::SeqCst);
            next += 1;
            let dkms = dkms_cache.get_or_insert_with(|| manifest_dkms(pipe));
            manifest_entries.push(build_manifest_entry(
                &item.entry,
                item.sha256.clone(),
                written,
                dkms.as_slice(),
                family,
            ));

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
            "哈希结果不完整：{} 个条目未按序到达 / {} hashed entries missing in order",
            pending.len(),
            pending.len()
        )));
    }
    // 兜底：条目数必须与扫描结果完全一致 —— 即使某个哈希线程在"最后一个条目"处
    // 异常退出（通道正常关闭、pending 恰好为空），也不会悄悄漏备份。
    let expected = pipe.entry_total.load(Ordering::SeqCst);
    if next != expected {
        return Err(AppError::Format(format!(
            "哈希结果不完整：扫描得到 {expected} 个条目，按序到达 {next} 个 \
             / hashed entries incomplete: {next} of {expected}"
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
        firmware_policy: None, // 预置字段：W5 阶段由 --firmware 策略接线
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

/// 把一个条目写进 tar，返回实际写入内容区的字节数（符号链接与未存储内容均为 0）。
/// Append one entry to the tar archive and return the bytes written for its content.
///
/// 三种分支：
/// - **符号链接**（`kind == Symlink`）：用 `append_link` 写 tar symlink 条目，
///   **绝不打开/读取目标文件**；链接目标先经 [`validate_link_target`] 安全校验。
///   该条目的 `sha256` 由哈希阶段按"链接目标字符串"计算，`size = 0`。
/// - **`content_stored == false`**：文件由系统包提供（典型为 `linux-firmware`），
///   此处**不写入 tar 内容、也不打开源文件**，仅由调用方在 `manifest.json` 中保留该条目
///   （`content_stored=false`）；还原侧据此把动作从"解包"改为"校验该路径已存在"。
/// - **普通文件**：按 `data/<rel_path>` 写入并比对哈希阶段记录的字节数。
fn write_entry(
    builder: &mut TarWriter,
    entry: &ScanEntry,
    hashed_bytes: u64,
    pipe: &Pipeline,
    warnings: &mut Vec<String>,
) -> AppResult<u64> {
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
        return Ok(0);
    }

    // 由系统包提供、内容不入库：tar 里不出现该路径，manifest 记录由调用方保留。
    if !entry.content_stored {
        return Ok(0);
    }

    let file = File::open(&entry.abs_path)?;
    let meta = file.metadata()?;
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
    let mut reader = ExactReader {
        inner: file,
        remaining: size,
        pipe,
    };
    // append_data 会先写入路径（过长时自动追加 GNU longname 扩展）再计算校验和；
    // 路径以 &str 传入，兼容 tar 0.4 对 `P: AsRef<Path>` / `Into<Vec<u8>>` 的两种签名。
    if let Err(e) = builder.append_data(&mut header, tar_path.as_str(), &mut reader) {
        // 取消/中止导致的读取失败，优先上报为 Cancelled（真实错误已在 first_error 中）。
        if pipe.stopped() {
            return Err(AppError::Cancelled);
        }
        return Err(AppError::Io(e));
    }

    let written = size - reader.remaining;
    if written != hashed_bytes {
        warnings.push(format!(
            "文件在备份期间大小变化：{rel}（哈希 {hashed_bytes} 字节，写入 {written} 字节）\
             / size changed during backup"
        ));
    }
    Ok(written)
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

/// 校验归档内相对路径：拒绝 `..`、绝对路径、空路径与 NUL。
/// Validate an in-archive relative path: reject `..`, absolute paths, empties and NULs.
fn validate_rel_path(rel: &str) -> AppResult<()> {
    if rel.is_empty() {
        return Err(AppError::Format(
            "归档内路径为空 / empty relative path".to_string(),
        ));
    }
    if rel.starts_with('/') {
        return Err(AppError::Format(format!(
            "归档内路径不得以 / 开头 / absolute path not allowed: {rel}"
        )));
    }
    if rel.contains('\0') {
        return Err(AppError::Format(format!(
            "归档内路径含 NUL 字节 / NUL byte in path: {rel}"
        )));
    }
    // 冗余的字面 `..` 检查（DESIGN.md §4.5）：任何形态的父目录跳转都被拒绝。
    // 注意：只拒绝"作为路径组件出现"的 `..`（等价于下面 components() 的 ParentDir），
    // 文件名里内嵌两个点（如 `foo..bar`）不是越界路径，不应误伤。
    for seg in rel.split('/') {
        if seg == ".." {
            return Err(AppError::Format(format!(
                "归档内路径含 `..` 组件 / parent-directory component not allowed: {rel}"
            )));
        }
    }
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(AppError::Format(format!(
                    "归档内路径含非法组件 / unsafe path component: {rel}"
                )))
            }
        }
    }
    Ok(())
}

/// 受管前缀（`rel_path` 命名空间）：符号链接目标归一化后必须落在其中之一。
/// Managed prefixes in the `rel_path` namespace; a symlink target must stay within one.
const MANAGED_LINK_PREFIXES: [&str; 2] = ["lib/modules/", "usr/lib/modules/"];

/// C-01：`etc/` 下符号链接目标归一化后的**绝对路径白名单**（必须落在其中之一）。
/// C-01: whitelist of absolute prefixes an `etc/` symlink target may resolve into.
///
/// 覆盖实测合法样例（`/lib/linux-sound-base/…`）、usr-merge 的 `/usr/lib/…` 以及
/// `/etc/…`、`/usr/share/…`、`/run/…` 别名；`/`、`/home/…` 等一律拒绝。
/// 与 `restore.rs::validate_link_target` 的同名常量保持一致——v0.3.0 由 W7/C-47
/// 合并为共享函数，v0.2.1 按 ITERATION §4-W0-A 先各自实现并互相指认。
const ALLOWED_ETC_LINK_PREFIXES: [&str; 5] =
    ["/etc/", "/lib/", "/usr/lib/", "/usr/share/", "/run/"];

/// C-01: lexically resolve a symlink target to an absolute path rooted at the
/// archive root: relative targets are joined onto the link's own directory first;
/// `..` is rejected when it would climb above the root for relative targets and
/// pinned at `/` for absolute ones. `None` means "escapes the archive root".
/// C-01：把符号链接目标**词法**解析为以归档根为基准的绝对路径（不访问文件系统）：
/// 相对目标先拼到链接所在目录；相对目标的 `..` 越出根即返回 `None`，
/// 绝对目标的 `/..` 则停在根。例：`("etc/a/b.conf", "../x")` → `Some("/etc/x")`。
fn resolve_link_abs(link_rel: &str, target: &str) -> Option<String> {
    let absolute = target.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    if !absolute {
        if let Some(i) = link_rel.rfind('/') {
            for seg in link_rel[..i].split('/') {
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
                    // 相对目标越出归档根（如 `etc/x -> ../../../../..`）→ 拒绝。
                    return None;
                }
            }
            other => stack.push(other),
        }
    }
    Some(format!("/{}", stack.join("/")))
}

/// 校验符号链接目标：拒绝绝对路径与越界目标，归一化后须仍落在受管前缀内。
/// Validate a symlink target: reject absolute or escaping targets; after lexical
/// normalization it must still reside under a managed prefix.
///
/// 允许 `..` 组件（RHEL/SUSE 的 `weak-updates/<m>.ko -> ../../<other-kver>/extra/<m>.ko`
/// 正依赖它），但以 `link_rel` 所在目录为起点做**纯词法归一化**（不触碰文件系统）：
/// 一旦越过归档根即判为 [`AppError::Format`]。同时拒绝空目标、含 NUL、以 `/` 开头的目标。
fn validate_link_target(link_rel: &str, target: &str) -> AppResult<()> {
    // ---- C-01/C-02 符号链接禁闭（与 restore.rs::validate_link_target 同步实施）----
    // `/etc` 下存在**绝对目标**的系统配置别名（如 /etc/modprobe.d/blacklist-oss.conf
    // -> /lib/linux-sound-base/noOSS.modprobe.conf），这类目标继续放行；但旧实现对
    // `..` 越根与任意绝对路径（`/`、`/home/user/pwn`）也原样放行，恶意归档可借此
    // 用 `data/etc/x -> /` + `data/etc/x/...` 条目以 root 任意写文件，故改为：
    // 目标必须词法解析后仍落在 `etc/` 树内，或（绝对目标）位于允许前缀白名单。
    if link_rel.starts_with("etc/") {
        if target.trim().is_empty() {
            return Err(AppError::Format(format!(
                "符号链接目标为空：{}",
                link_rel
            )));
        }
        let resolved = resolve_link_abs(link_rel, target).ok_or_else(|| {
            AppError::Format(format!(
                "符号链接目标越出归档根 / link target escapes archive root: {link_rel} -> {target}"
            ))
        })?;
        // (a) 仍在 `etc/` 树内（如 etc/modules-load.d/modules.conf -> ../modules）。
        let in_etc_tree = resolved == "/etc" || resolved.starts_with("/etc/");
        // (b) 绝对目标位于允许前缀白名单（含 usr-merge 的 /usr/lib/…）。
        let in_whitelist = ALLOWED_ETC_LINK_PREFIXES
            .iter()
            .any(|p| resolved.as_str() == p.trim_end_matches('/') || resolved.starts_with(p));
        if !(in_etc_tree || in_whitelist) {
            return Err(AppError::Format(format!(
                "符号链接目标越出允许前缀 / etc link target outside allowed prefixes: \
                 {link_rel} -> {target} (normalized: {resolved})"
            )));
        }
        return Ok(());
    }
    if target.is_empty() {
        return Err(AppError::Format(format!(
            "符号链接目标为空 / empty link target: {link_rel}"
        )));
    }
    if target.contains('\0') {
        return Err(AppError::Format(format!(
            "符号链接目标含 NUL 字节 / NUL byte in link target: {link_rel}"
        )));
    }
    if target.starts_with('/') {
        return Err(AppError::Format(format!(
            "符号链接目标不得为绝对路径 / absolute link target not allowed: {link_rel} -> {target}"
        )));
    }
    let parent = match link_rel.rfind('/') {
        Some(i) => &link_rel[..i],
        None => "",
    };
    let combined = if parent.is_empty() {
        target.to_string()
    } else {
        format!("{parent}/{target}")
    };
    let normalized = normalize_lexical(&combined).ok_or_else(|| {
        AppError::Format(format!(
            "符号链接目标越界 / link target escapes archive root: {link_rel} -> {target}"
        ))
    })?;
    if MANAGED_LINK_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(AppError::Format(format!(
            "符号链接目标不在受管前缀内 / link target outside managed prefixes: {link_rel} -> {target}"
        )))
    }
}

/// 词法归一化相对路径（不访问文件系统）；因 `..` 越出根时返回 `None`。
/// Lexically normalize a relative path (no filesystem access); `None` when `..` escapes the root.
fn normalize_lexical(path: &str) -> Option<String> {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop()?;
            }
            other => stack.push(other),
        }
    }
    if stack.is_empty() {
        None
    } else {
        Some(stack.join("/"))
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
        let written =
            write_entry(&mut builder, entry, 0, &pipe, &mut warnings).expect("write entry");
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
        assert!(
            validate_link_target("lib/modules/6.8/a.ko", "/etc/shadow").is_err()
        );
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
        assert!(
            validate_link_target("etc/modprobe.d/x.conf", "../../../../etc/shadow").is_err()
        );
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
        assert!(validate_link_target(
            "etc/modules-load.d/modules.conf",
            "../modules"
        )
        .is_ok());

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
        match write_entry(&mut builder, &entry, 0, &pipe, &mut warnings) {
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
        let written = write_entry(&mut builder, &entry, 14, &pipe, &mut warnings).unwrap();
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
