//! Privilege elevation: `pkexec` self re-exec and the helper line protocol.
//! 提权模块：`pkexec` 自进程重入（DESIGN.md §4.5）与 helper 行协议的收发两端。
//!
//! - 发送端（GUI 普通用户进程）：[`run_helper_via_pkexec`] 启动
//!   `pkexec <self> --helper-restore <args…>`，逐行解析行协议驱动进度条。
//! - 接收端（root helper 进程）：[`HelperSink`] 把 `PROGRESS` / `NOTE` / `RESULT`
//!   三类行写到 stdout，每行 `println!` 后立即 flush，保证 GUI 实时读取。
//!
//! 行协议（DESIGN.md §4.5，字段以 `\t` 分隔）：
//! ```text
//! PROGRESS\t<float>\t<utf-8 消息>
//! NOTE\t<消息>
//! RESULT\tOK|FAIL\t<消息>
//! ```

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
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

/// Absolute path of the current executable, canonicalized for the pkexec re-exec.
/// 当前可执行文件的绝对路径（canonicalize 后），用于 pkexec 自进程重入。
pub fn self_exe() -> AppResult<PathBuf> {
    let exe = std::env::current_exe()?;
    Ok(exe.canonicalize()?)
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
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(|e| {
        AppError::Privilege(format!(
            "无法启动 pkexec（{}）：{}；请确认已安装 polkit/pkexec，或改用 sudo 运行 CLI 模式",
            exe.display(),
            e
        ))
    })?;

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
    let _ = child.kill(); // 已退出时返回 Err，忽略
    let status = child
        .wait()
        .map_err(|e| AppError::Privilege(format!("等待 pkexec 结束失败：{}", e)))?;
    // 有限等待排空线程收尾（孙进程可能继承管道，不能无限 join）
    join_within(Some(stdout_thread), DRAIN_WAIT);
    join_within(stderr_thread, DRAIN_WAIT);
    if cancelled {        return Err(AppError::Cancelled);
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
}
