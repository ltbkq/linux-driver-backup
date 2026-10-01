//! Privilege elevation: `pkexec` self re-exec and the helper line protocol.
//! 提权模块：`pkexec` 自进程重入（DESIGN.md §4.5）与 helper 行协议的收发两端。
//!
//! - 发送端（GUI 普通用户进程）：[`run_helper_via_pkexec`] 启动
//!   `pkexec <self> --helper-restore <args…>`，逐行解析行协议驱动进度条。
//!   交给 `pkexec` 前会先做可执行文件信任校验（C-03：属主 root 且组/其他不可写，
//!   见 [`check_elevatable`]），拒绝以 root 执行用户可写的二进制。
//! - 接收端（root helper 进程）：[`HelperSink`] 把 `PROGRESS` / `NOTE` / `RESULT`
//!   三类行写到 stdout，每行 `println!` 后立即 flush，保证 GUI 实时读取。
//!
//! 行协议（DESIGN.md §4.5，字段以 `\t` 分隔）：
//! ```text
//! PROGRESS\t<float>\t<utf-8 消息>
//! NOTE\t<消息>
//! RESULT\tOK|FAIL\t<消息>
//! ```
//!
//! 取消传播（C-04）：父进程把 helper 的 **stdin 保持为管道**；用户点"取消"时
//! 先关闭写端 → helper 端 `read` 得到 EOF → 置位本地取消标志 → 回滚已做部分 →
//! 输出 `RESULT\tFAIL\t已取消` 后退出。超过宽限期仍未退出则向进程组补发
//! `SIGTERM`（`process_group(0)`）并 `kill` 兜底。

use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::model::{AppError, AppResult, ProgressFn};

/// Command-line flag that marks this executable as the root-side restore helper.
/// 标记"由 pkexec 重入的 root 还原 helper"的命令行开关。
pub const HELPER_FLAG: &str = "--helper-restore";

/// Max number of stderr lines echoed back in an error message.
/// 错误信息里回显的 stderr 末尾行数上限。
const STDERR_TAIL_LINES: usize = 20;

/// Max stderr lines kept while draining (rolling window, keeps the tail).
/// 排空 stderr 时保留的滚动窗口行数上限。
const STDERR_KEEP: usize = 500;

/// Poll interval while waiting for helper output, so cancel stays responsive.
/// helper 确认取消时使用的协议消息（`RESULT\tFAIL\t<此文本>`，§5.3）。
/// Protocol message the helper uses to confirm a cancellation (§5.3).
const CANCELLED_MSG: &str = "已取消";

/// `RESULT\tFAIL` 的消息是否表示"用户取消"（C-04：区分取消与真实失败）。
/// Whether a `RESULT\tFAIL` message means "user cancelled" (C-04).
fn is_cancelled_msg(msg: &str) -> bool {
    msg.trim() == CANCELLED_MSG
}

/// 取消后等待 helper 自行回滚退出的宽限期。
/// Grace period after cancellation before the process-group fallback fires.
const CANCEL_GRACE: Duration = Duration::from_secs(10);

/// 等待 helper 输出的轮询间隔（保证取消标志及时生效）。
const POLL: Duration = Duration::from_millis(100);

/// How long to wait for the reader threads to finish after the child exits.
/// 子进程退出后，等待排空线程收尾的最长时间（防止孙进程继承管道导致无限阻塞）。
const DRAIN_WAIT: Duration = Duration::from_millis(300);

// ---------------------------------------------------------------------------
// 行协议 / Line protocol
// ---------------------------------------------------------------------------

/// One decoded helper protocol line.
/// helper 行协议解码后的消息。
#[derive(Debug, Clone, PartialEq)]
pub enum HelperMsg {
    /// `PROGRESS\t<float>\t<消息>`：驱动进度条，同时携带状态文本。
    Progress(f32, String),
    /// `NOTE\t<消息>`：进度不变，只更新状态文本。
    Note(String),
    /// `RESULT\tOK|FAIL\t<消息>`：结束标志，`true` = OK。
    Result(bool, String),
}

/// Decode a single helper protocol line; blank or unknown lines return `None`.
/// 解码一行 helper 行协议；空行、未知标签、字段缺失或数值非法一律返回 `None`（容错，不视为错误）。
///
/// 消息正文用 `splitn(3, '\t')` 保留其内部的制表符，因此消息可含 `\t`（但不含换行）。
pub fn parse_line(line: &str) -> Option<HelperMsg> {
    // 只剥掉行尾换行，保留消息本身的空白。
    let line = line.strip_suffix('\n').unwrap_or(line);
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.is_empty() {
        return None;
    }

    let mut it = line.splitn(3, '\t');
    match it.next()? {
        "PROGRESS" => {
            let v: f32 = it.next()?.trim().parse().ok()?;
            if !v.is_finite() {
                return None;
            }
            Some(HelperMsg::Progress(v, it.next().unwrap_or("").to_string()))
        }
        "NOTE" => Some(HelperMsg::Note(it.next().unwrap_or("").to_string())),
        "RESULT" => {
            let ok = match it.next()? {
                "OK" => true,
                "FAIL" => false,
                _ => return None,
            };
            Some(HelperMsg::Result(
                ok,
                it.next().unwrap_or("").to_string(),
            ))
        }
        _ => None,
    }
}

/// Append-only formatting helpers are kept private: only [`HelperSink`] writes to stdout.
/// 行协议的组装与写出（每行 println + flush）。
fn sanitize(msg: &str) -> String {
    // 消息内不能出现换行，否则会破坏"一行一条"的协议。
    msg.replace(['\n', '\r'], " ")
}

/// Write one protocol line to stdout and flush immediately.
/// 写出一行协议并立即 flush（helper 进程退出前不能留在缓冲区里）。
fn emit(line: &str) {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let _ = writeln!(lock, "{}", line);
    let _ = lock.flush();
}

// ---------------------------------------------------------------------------
// helper 端输出 / Helper-side sink
// ---------------------------------------------------------------------------

/// Root-side stdout writer for the helper line protocol.
/// root 进程内的 helper 行协议输出器：每行 `println!` 后立即 `flush()`。
#[derive(Debug, Default, Clone, Copy)]
pub struct HelperSink;

impl HelperSink {
    /// Create a sink (unit struct, provided for symmetry with other constructors).
    /// 创建输出器（单元结构体）。
    pub fn new() -> Self {
        HelperSink
    }

    /// Emit `PROGRESS\t<float>\t<utf-8 消息>` and drive the progress bar.
    /// 输出 `PROGRESS\t<float>\t<utf-8 消息>`，同时更新进度条与状态文本。
    pub fn progress(&self, v: f32, msg: &str) {
        emit(&format!("PROGRESS\t{}\t{}", v, sanitize(msg)));
    }

    /// Emit `NOTE\t<消息>`: keep the current progress, refresh the status text only.
    /// 输出 `NOTE\t<消息>`：进度保持不变，仅刷新状态文本。
    pub fn note(&self, msg: &str) {
        emit(&format!("NOTE\t{}", sanitize(msg)));
    }

    /// Emit `RESULT\tOK|FAIL\t<消息>`: the terminal line of the protocol.
    /// 输出 `RESULT\tOK|FAIL\t<消息>`：协议的结束行。
    pub fn result(&self, ok: bool, msg: &str) {
        emit(&format!(
            "RESULT\t{}\t{}",
            if ok { "OK" } else { "FAIL" },
            sanitize(msg)
        ));
    }
}

// ---------------------------------------------------------------------------
// 发送端 / Caller side
// ---------------------------------------------------------------------------

/// Environment-variable escape hatch that disables [`check_elevatable`]:
/// only the exact value `1` counts (`0` / `true` / trailing space keep the check on).
/// 关闭 [`check_elevatable`] 的环境变量逃生口：取值必须**恰为** `1` 才生效
/// （`0`、`true`、带空格等一律按未开启处理）。
pub const UNSAFE_ELEVATION_ENV: &str = "LDB_ALLOW_UNSAFE_ELEVATION";

/// Bilingual guidance appended to every rejection from [`check_elevatable`].
/// [`check_elevatable`] 拒绝提权时附带的双语指引（安装到 /usr、AppImage 不可用、逃生口及其风险）。
const ELEVATION_GUIDANCE: &str = "请先用安装脚本或包管理器安装到 /usr 后重试 / install to /usr via the install script or a package manager, then retry；AppImage 无法用于图形界面还原 / AppImage cannot be used for GUI restore；仅供开发调试：环境变量 LDB_ALLOW_UNSAFE_ELEVATION=1 可绕过本检查（高危：pkexec 将以 root 执行用户可写的二进制）/ development only: LDB_ALLOW_UNSAFE_ELEVATION=1 bypasses this check (DANGEROUS: pkexec will run a user-writable binary as root)";

/// Whether the [`UNSAFE_ELEVATION_ENV`] escape hatch is on (`Some("1")` only).
/// 逃生口是否开启：仅 `Some("1")` 算开启。
fn unsafe_elevation_enabled(raw: Option<OsString>) -> bool {
    raw.is_some_and(|v| v.to_str() == Some("1"))
}

/// Pre-elevation trust check for the binary `pkexec` will run as root (C-03).
/// 提权前的可执行文件信任校验：交给 `pkexec` 以 root 执行的二进制必须可信（C-03）。
///
/// # 威胁模型 / Threat model
///
/// - **用户可写提权 / user-writable elevation**：`pkexec` 直接以 root 执行 `exe`，
///   因此开发构建（`target/debug/…`，用户可写目录）与 AppImage（挂载在用户可写的
///   临时挂载点）都允许同用户攻击者就地替换二进制 → root 执行任意代码。
///   故要求 `st_uid == 0` **且** `st_mode & 0o022 == 0`（组、其他均不可写），
///   把"有能力改写该文件"的主体收缩为 root 自身。
/// - **TOCTOU 收窄 / window narrowing**：`fs::metadata` 跟随符号链接，读取的是
///   canonicalize 之后那一路径在 **stat 时刻** 的属主与权限；校验点紧贴 `pkexec`
///   spawn 之前，把原先 canonicalize→spawn 的整段竞态窗口收窄到 stat→spawn 的几行。
///   残余风险：父目录本身可写时仍可 `rename` 替换整个文件 —— 安装到 `/usr` 后父目录同样不可写。
/// - **逃生口 / escape hatch**：`allow_unsafe == true`（即 `LDB_ALLOW_UNSAFE_ELEVATION=1`）
///   跳过校验，仅供开发调试，发行环境绝不可用。
///
/// Passes the canonicalized path through unchanged on success; otherwise returns
/// [`AppError::Privilege`] with bilingual guidance (install to `/usr`, AppImage unusable
/// for GUI restore, dev-only escape hatch with an explicit risk warning).
/// 通过时原样返回传入的（canonicalize 后的）路径，否则返回带双语指引的 [`AppError::Privilege`]。
pub fn check_elevatable(exe: &Path, allow_unsafe: bool) -> AppResult<PathBuf> {
    let meta = match fs::metadata(exe) {
        Ok(m) => m,
        Err(e) => {
            // stat 失败同样 fail closed：无法证明可信就拒绝提权（逃生口除外）。
            if allow_unsafe {
                return Ok(exe.to_path_buf());
            }
            return Err(AppError::Privilege(format!(
                "无法读取可执行文件的属主与权限 / cannot read owner & mode of {}: {e}；\
                 已拒绝提权 / refusing to elevate；{ELEVATION_GUIDANCE}",
                exe.display()
            )));
        }
    };

    let uid = meta.uid();
    let mode = meta.mode();
    if uid == 0 && (mode & 0o022) == 0 {
        return Ok(exe.to_path_buf());
    }
    if allow_unsafe {
        return Ok(exe.to_path_buf());
    }
    let perm = mode & 0o777;
    Err(AppError::Privilege(format!(
        "可执行文件位于用户可写路径，已拒绝提权 / refusing to elevate a user-writable binary: \
         {}（属主 uid={uid}，模式 {perm:04o} / uid={uid}, mode={perm:04o}）；{ELEVATION_GUIDANCE}",
        exe.display()
    )))
}

/// Absolute path of the current executable, canonicalized **and trust-checked** for the pkexec re-exec.
/// 当前可执行文件的绝对路径（canonicalize + 信任校验后），用于 pkexec 自进程重入。
///
/// 校验语义与威胁模型见 [`check_elevatable`]：属主非 root 或组/其他可写即拒绝提权
/// （未安装的开发构建与 AppImage 都会被拒）。仅当 [`UNSAFE_ELEVATION_ENV`] 取值恰为 `1`
/// 时跳过校验，并向 **stderr** 打印一行警告 —— stdout 是 helper 行协议通道，绝不能被污染。
/// Trust semantics live in [`check_elevatable`]; the escape hatch warns on stderr only,
/// so the stdout line protocol stays intact.
pub fn self_exe() -> AppResult<PathBuf> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let allow_unsafe = unsafe_elevation_enabled(std::env::var_os(UNSAFE_ELEVATION_ENV));
    if allow_unsafe {
        eprintln!(
            "警告：{UNSAFE_ELEVATION_ENV}=1 已跳过提权前的可执行文件信任校验，pkexec 将以 root 执行用户可写的二进制（仅供开发调试，风险自负） / WARNING: {UNSAFE_ELEVATION_ENV}=1 skipped the pre-elevation trust check; pkexec will run a user-writable binary as root (development only, at your own risk)"
        );
    }
    check_elevatable(&exe, allow_unsafe)
}

/// Join captured stderr lines into a readable suffix (last [`STDERR_TAIL_LINES`] lines).
/// 把捕获到的 stderr 行拼成可读的尾部片段。
fn stderr_tail(lines: &Mutex<Vec<String>>) -> String {
    let guard = lines.lock().unwrap_or_else(|e| e.into_inner());
    if guard.is_empty() {
        return String::new();
    }
    let start = guard.len().saturating_sub(STDERR_TAIL_LINES);
    format!("；stderr 尾部：\n{}", guard[start..].join("\n"))
}

/// Wait for a drain thread for at most `wait`, then detach it.
/// 最多等待 `wait` 让排空线程收尾，超时则放弃等待（线程随后在管道关闭时自行退出）。
///
/// 之所以不能无限 `join`：孙进程可能继承了 stdout/stderr 管道，
/// 无限等待会让"取消"按钮卡死在 GUI 线程上。
fn join_within(handle: Option<std::thread::JoinHandle<()>>, wait: Duration) {
    let Some(h) = handle else { return };
    let deadline = Instant::now() + wait;
    while !h.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(h); // 未结束则分离，由线程自行退出
}

/// Run `pkexec <self> --helper-restore <args…>` and stream the helper line protocol into `progress`.
/// 启动 `pkexec <self> --helper-restore <args…>`，逐行解析行协议并通过 `progress` 回调驱动 UI。
///
/// 行协议状态机（每读一行都检查 `cancel`）：
/// - `PROGRESS\t<v>\t<msg>` → `progress(v.clamp(0..1), msg)`，并记录"当前进度"；
/// - `NOTE\t<msg>` → `progress(当前进度, msg)`（进度不变，仅刷新状态文本）；
/// - `RESULT\tOK\t<msg>` → 结束并返回 `Ok(msg)`；
/// - `RESULT\tFAIL\t<msg>` → 结束并返回 `AppError::Privilege(msg)`；
/// - 空行 / 未知行 → 忽略；
/// - 未收到任何 `RESULT` 就 EOF → 非 0 退出码返回 `AppError::Privilege`
///   （附 stderr 尾部；pkexec 取消密码输入时即为此分支），0 退出码则提示协议不完整；
/// - `cancel` 置位 → `child.kill()` 后返回 `AppError::Cancelled`。
pub fn run_helper_via_pkexec(
    args: &[String],
    progress: ProgressFn,
    cancel: Arc<AtomicBool>,
) -> AppResult<String> {
    if cancel.load(Ordering::Relaxed) {
        return Err(AppError::Cancelled);
    }

    let exe = self_exe()?;
    let mut cmd = Command::new("pkexec");
    cmd.arg(&exe)
        .arg(HELPER_FLAG)
        .args(args)
        .stdin(Stdio::piped()) // C-04：取消 = 关闭本管道写端（helper 收到 EOF）
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0); // C-04 兜底：pkexec 与 helper 同组，便于组信号收敛

    let mut child = cmd.spawn().map_err(|e| {
        AppError::Privilege(format!(
            "无法启动 pkexec（{}）：{}；请确认已安装 polkit/pkexec，或改用 sudo 运行 CLI 模式",
            exe.display(),
            e
        ))
    })?;

    // 保留 stdin 句柄：取消时 drop 它 = 向 helper 传递 EOF（C-04）。
    let mut child_stdin = child.stdin.take();

    let stdout = match child.stdout.take() {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(AppError::Privilege(
                "pkexec 未捕获到 stdout，无法读取 helper 行协议".to_string(),
            ));
        }
    };
    let stderr = child.stderr.take();

    // stderr 单独用线程排空，避免子进程把管道写满后阻塞死锁。
    let stderr_lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let stderr_thread = stderr.map(|s| {
        let sink = Arc::clone(&stderr_lines);
        std::thread::spawn(move || {
            for line in BufReader::new(s).lines().map_while(Result::ok) {
                let mut guard = sink.lock().unwrap_or_else(|e| e.into_inner());
                guard.push(line);
                if guard.len() > STDERR_KEEP {
                    guard.remove(0);
                }
            }
        })
    });

    // stdout 交给读取线程按行投递，主线程用 recv_timeout 轮询，保证 cancel 及时生效。
    let (tx, rx) = mpsc::channel::<String>();
    let stdout_thread = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let mut ok_msg: Option<String> = None;
    let mut fail_msg: Option<String> = None;
    let mut last_v = 0f32;
    let mut cancelled = false;

    loop {
        if cancel.load(Ordering::Relaxed) {
            cancelled = true;
            break;
        }
        match rx.recv_timeout(POLL) {
            Ok(line) => {
                match parse_line(&line) {
                    Some(HelperMsg::Progress(v, msg)) => {
                        last_v = v;
                        progress(v.clamp(0.0, 1.0), msg);
                    }
                    Some(HelperMsg::Note(msg)) => {
                        progress(last_v.clamp(0.0, 1.0), msg);
                    }
                    Some(HelperMsg::Result(true, msg)) => {
                        ok_msg = Some(msg);
                        break;
                    }
                    Some(HelperMsg::Result(false, msg)) => {
                        // W2/C-04：helper 自身确认的取消要归类为 Cancelled 而非提权失败。
                        if is_cancelled_msg(&msg) {
                            cancelled = true;
                        }
                        fail_msg = Some(msg);
                        break;
                    }
                    None => { /* 空行/未知行：容错忽略 */ }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => { /* 继续轮询，检查 cancel */ }
            Err(mpsc::RecvTimeoutError::Disconnected) => break, // EOF
        }
    }

    // 统一收割：确保子进程退出并回收线程。
    if cancelled {
        // C-04：先关闭 stdin 写端（helper EOF → 置位取消 → 回滚 → RESULT FAIL 已取消），
        // 给它宽限期自行收敛；超时才动用进程组信号与 kill 兜底。
        drop(child_stdin.take());
        let deadline = Instant::now() + CANCEL_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,      // 已退出
                Ok(None) => {}             // 仍在运行
                Err(_) => break,
            }
            if Instant::now() >= deadline {
                // 兜底：向整个进程组（pkexec+helper）发 TERM，再强杀 pkexec 本体。
                let _ = Command::new("kill")
                    .args(["-s", "TERM", "--", &format!("-{}", child.id())])
                    .status();
                let _ = child.kill();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    drop(child_stdin.take()); // 正常路径：确保写端关闭，避免孙进程持有管道
    let _ = child.kill(); // 已退出时返回 Err，忽略
    let status = child
        .wait()
        .map_err(|e| AppError::Privilege(format!("等待 pkexec 结束失败：{}", e)))?;
    // 有限等待排空线程收尾（孙进程可能继承管道，不能无限 join）
    join_within(Some(stdout_thread), DRAIN_WAIT);
    join_within(stderr_thread, DRAIN_WAIT);
    if cancelled {
        return Err(AppError::Cancelled);
    }
    if let Some(msg) = ok_msg {
        return Ok(msg);
    }
    if let Some(msg) = fail_msg {
        return Err(AppError::Privilege(msg));
    }

    // 没有收到 RESULT：多半是 pkexec 认证失败 / 用户取消了密码输入。
    let tail = stderr_tail(&stderr_lines);
    let code = status.code().unwrap_or(-1);
    if code != 0 {
        Err(AppError::Privilege(format!(
            "pkexec 提权失败或用户取消了密码输入（退出码 {}）{}",
            code, tail
        )))
    } else {
        Err(AppError::Privilege(format!(
            "pkexec 已结束但 helper 未返回 RESULT 行（协议不完整）{}",
            tail
        )))
    }
}

// ---------------------------------------------------------------------------
// 单元测试 / Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn cancelled_result_line_is_recognised() {
        // §5.3 行协议：取消 = RESULT FAIL 已取消（不能与真实失败混淆）。
        assert!(is_cancelled_msg("已取消"));
        assert!(is_cancelled_msg(" 已取消 "));
        assert!(!is_cancelled_msg("提权失败"));
        assert!(!is_cancelled_msg("还原失败：磁盘满"));
        assert_eq!(
            parse_line("RESULT\tFAIL\t已取消"),
            Some(HelperMsg::Result(false, "已取消".to_string()))
        );
    }

    #[test]
    fn parses_progress_line() {
        assert_eq!(
            parse_line("PROGRESS\t0.42\t正在解压"),
            Some(HelperMsg::Progress(0.42, "正在解压".to_string()))
        );
        assert_eq!(
            parse_line("PROGRESS\t1\tdone"),
            Some(HelperMsg::Progress(1.0, "done".to_string()))
        );
        // 消息字段可缺失（容错）
        assert_eq!(
            parse_line("PROGRESS\t0.5"),
            Some(HelperMsg::Progress(0.5, String::new()))
        );
        // 消息内部的制表符保留
        assert_eq!(
            parse_line("PROGRESS\t0.5\ta\tb"),
            Some(HelperMsg::Progress(0.5, "a\tb".to_string()))
        );
    }

    #[test]
    fn parses_note_line() {
        assert_eq!(
            parse_line("NOTE\t跳过 3 个链接条目"),
            Some(HelperMsg::Note("跳过 3 个链接条目".to_string()))
        );
        assert_eq!(parse_line("NOTE\t"), Some(HelperMsg::Note(String::new())));
        assert_eq!(parse_line("NOTE"), Some(HelperMsg::Note(String::new())));
    }

    #[test]
    fn parses_result_lines() {
        assert_eq!(
            parse_line("RESULT\tOK\t还原完成"),
            Some(HelperMsg::Result(true, "还原完成".to_string()))
        );
        assert_eq!(
            parse_line("RESULT\tFAIL\t提权失败"),
            Some(HelperMsg::Result(false, "提权失败".to_string()))
        );
        // CRLF 容错
        assert_eq!(
            parse_line("RESULT\tOK\tdone\r\n"),
            Some(HelperMsg::Result(true, "done".to_string()))
        );
        // 未知状态
        assert_eq!(parse_line("RESULT\tMAYBE\tx"), None);
    }

    #[test]
    fn tolerates_empty_and_unknown_lines() {
        assert_eq!(parse_line(""), None);
        assert_eq!(parse_line("\n"), None);
        assert_eq!(parse_line("   "), None);
        assert_eq!(parse_line("garbage without tabs"), None);
        assert_eq!(parse_line("PROGRESS\tnot-a-number\tm"), None);
        assert_eq!(parse_line("PROGRESS\tNaN\tm"), None);
        assert_eq!(parse_line("PROGRESS\tinf\tm"), None);
        assert_eq!(parse_line("HELPER\t0.5\tx"), None);
    }

    #[test]
    fn protocol_lines_are_single_line() {
        // 消息里的换行必须被压平，否则会破坏"一行一条"
        let sink = HelperSink::new();
        let _ = sink; // 输出到 stdout 无法断言，仅保证不 panic
        assert_eq!(sanitize("a\nb\r\nc"), "a b  c");
        assert_eq!(sanitize("正常消息"), "正常消息");
    }

    #[test]
    fn helper_flag_is_stable() {
        // main.rs 与 GUI 依赖该常量，改动会破坏 pkexec 重入契约
        assert_eq!(HELPER_FLAG, "--helper-restore");
    }

    // -----------------------------------------------------------------------
    // C-03：提权前的可执行文件信任校验 / pre-elevation trust check
    // -----------------------------------------------------------------------

    /// 与 scan.rs / backup.rs 夹具同款的临时目录（名字带 pid，避免并行测试互踩）。
    fn temp_dir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("ldb-priv-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    /// 造一个夹具二进制：临时文件 + 指定权限位（属主 = 当前测试进程的 euid）。
    fn make_exe(tag: &str, mode: u32) -> PathBuf {
        let p = temp_dir(tag).join("app");
        fs::write(&p, b"#!binary").expect("write exe");
        fs::set_permissions(&p, fs::Permissions::from_mode(mode)).expect("chmod");
        p
    }

    /// C-03：属主非 root 或组/其他可写的二进制一律拒绝提权。
    ///
    /// **属主分支按夹具文件的“实际 uid”分叉**（既无法在普通用户下构造 root 属主文件，
    /// 也无法在 root 下构造用户属主文件，且不引入 libc/nix 依赖）：
    /// - 普通用户（`uid != 0`，本机开发）：0755 也必须 `Err` —— 测 uid 分支；
    /// - root（CI 容器常见，euid == 0）：跳过 uid 分支，只测 mode 分支 ——
    ///   root 属主 + 0755 → `Ok`，0775（组可写）→ `Err`，0666 → `Err`。
    #[test]
    fn rejects_untrusted_elevation_target() {
        let exe = make_exe("untrusted", 0o755);
        let uid = fs::metadata(&exe).expect("stat fixture").uid();

        if uid == 0 {
            // root 属主无法在本分支构造“用户属主”样例，uid 分支由普通用户路径覆盖。
            assert!(
                check_elevatable(&exe, false).is_ok(),
                "root-owned 0755 must be accepted"
            );
        } else {
            let err = check_elevatable(&exe, false)
                .expect_err("user-owned 0755 must be refused even though mode is clean");
            match err {
                AppError::Privilege(m) => {
                    assert!(m.contains("已拒绝提权"), "{m}");
                    assert!(m.contains("refusing to elevate a user-writable binary"), "{m}");
                    assert!(m.contains("/usr"), "{m}");
                    assert!(m.contains("AppImage"), "{m}");
                    assert!(m.contains("LDB_ALLOW_UNSAFE_ELEVATION=1"), "{m}");
                }
                other => panic!("expected AppError::Privilege, got {other:?}"),
            }
        }

        // mode 分支（root / 普通用户皆适用）：组可写 → Err；组与其他可写 → Err。
        for mode in [0o775u32, 0o666u32] {
            fs::set_permissions(&exe, fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(
                check_elevatable(&exe, false).is_err(),
                "mode {mode:04o} must be refused"
            );
        }
    }

    /// C-03：`allow_unsafe=true`（`LDB_ALLOW_UNSAFE_ELEVATION=1`）跳过校验并原样返回路径。
    /// uid/mode 两种不满足情形（普通用户属主 or 0666）在 root 与普通用户下都成立。
    #[test]
    fn allow_unsafe_overrides_elevatable_check() {
        let exe = make_exe("unsafe", 0o666);
        assert!(
            check_elevatable(&exe, false).is_err(),
            "0666 must be refused by default"
        );
        let got = check_elevatable(&exe, true).expect("allow_unsafe must pass");
        assert_eq!(got, exe, "returns the canonicalized path unchanged");
    }

    /// C-03：无法 stat 的路径（不存在 / 链接断裂）同样 fail closed。
    #[test]
    fn refuses_unstatable_elevation_target() {
        let exe = temp_dir("missing").join("no-such-binary");
        let err = check_elevatable(&exe, false).expect_err("missing file must be refused");
        assert!(matches!(err, AppError::Privilege(_)), "got {err:?}");
        // 逃生口对 stat 失败也放行（开发调试语义，随后 pkexec 自会报文件不存在）。
        let got = check_elevatable(&exe, true).expect("allow_unsafe must pass");
        assert_eq!(got, exe);
    }

    /// 逃生口环境变量只认取值恰为 `1`（`0` / `true` / 带空格一律不生效）。
    #[test]
    fn unsafe_elevation_env_requires_exact_one() {
        assert!(unsafe_elevation_enabled(Some(OsString::from("1"))));
        assert!(!unsafe_elevation_enabled(Some(OsString::from("0"))));
        assert!(!unsafe_elevation_enabled(Some(OsString::from("true"))));
        assert!(!unsafe_elevation_enabled(Some(OsString::from("1 "))));
        assert!(!unsafe_elevation_enabled(None));
    }
}
