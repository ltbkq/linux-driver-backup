// 模块：退出码集成测试 —— C-33（ITERATION §5.1 / §2.1）
// Module: exit-code integration tests — C-33 (ITERATION §5.1 / §2.1).
//
// 契约 / Contract:
//   0 = 成功或用户主动取消 success or user cancellation
//   1 = 运行失败 runtime failure（含 JSON 输出失败）
//   2 = 用法/参数错误 usage error
//
// 这些用例通过 `CARGO_BIN_EXE_<name>` 真实运行编译产物，覆盖 §6 要求的
// “退出码矩阵”验收；仅依赖本机（扫描/备份免 root），且刻意不触发任何真实写盘，
// 与 `scan::tests::scan_smoke_on_host_returns_ok` 同一前提。
// These cases execute the real binary via `CARGO_BIN_EXE_<name>` and cover the
// exit-code matrix required by §6. They never write to the system (safe even as root).

use std::io::Write;
use std::process::{Command, Stdio};

/// 构造子进程命令 / Build a child process of the freshly compiled binary.
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_linux-driver-backup"))
}

/// 退出码 2：未知参数 / Unknown flag → usage error.
#[test]
fn unknown_flag_exits_two() {
    let out = bin().arg("--definitely-not-a-flag").output().expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// 退出码 2：缺必填值与非法取值（C-34：helper 路径严格校验）。
/// Exit 2: missing required values and invalid values (C-34: strict helper validation).
#[test]
fn missing_or_invalid_value_exits_two() {
    let out = bin().args(["--restore"]).output().expect("spawn");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let out = bin()
        .args(["--helper-restore", "--archive", "a", "--on-immutable", "bogus"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

/// 退出码 0：`--version` 成功；`--scan --json` 输出可解析 JSON。
/// Exit 0: `--version` and a successful, parseable `--scan --json`.
#[test]
fn success_paths_exit_zero() {
    let out = bin().arg("--version").output().expect("spawn");
    assert_eq!(out.status.code(), Some(0));

    let out = bin().args(["--scan", "--json"]).output().expect("spawn");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is valid JSON");
    assert!(parsed.get("entries").is_some());
}

/// 退出码 0：交互式还原在提示处回答 `n` = 用户主动取消（C-33 关键变更：旧版返回 1）。
/// Exit 0: declining the interactive restore prompt is a user cancellation (the key
/// C-33 change — v0.2.0 returned 1 here).
#[test]
fn declined_restore_prompt_exits_zero() {
    // 先造一个真实归档（备份免 root、只读系统目录）。
    let dir = std::env::temp_dir().join(format!("ldb-exitcodes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("tempdir");
    let archive = dir.join("a.tar.gz");

    let backup = bin()
        .args(["--backup", "--out", archive.to_str().expect("utf8"), "--mode", "minimal"])
        .output()
        .expect("spawn");
    assert_eq!(backup.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&backup.stderr));

    let mut child = bin()
        .args(["--restore", "--archive", archive.to_str().expect("utf8")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"n\n")
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("已取消"));

    let _ = std::fs::remove_dir_all(&dir);
}

/// 退出码 1：读取归档失败（运行失败）与非 root 真实还原（缺权限）都必须返回 1。
/// Exit 1: an unreadable archive and a root-less real restore both fail with 1.
///
/// 刻意选择这两个失败路径：不需要写盘，root/非 root 环境均安全。
/// Both failure paths are chosen because they never write anywhere (safe as root).
#[test]
fn failed_restore_exits_one() {
    // a) 归档不存在 → “读取归档失败” → 1
    let out = bin()
        .args(["--restore", "--archive", "/nonexistent/ldb-nope.tar.gz", "--yes"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    // b) 非 root 下 `--yes` 真实还原 → “需要 root” → 1（root 环境无法构造该失败，跳过）
    //    Non-root real restore hits the "requires root" gate → 1 (skipped when euid==0).
    let euid = unsafe { geteuid() };
    if euid != 0 {
        let dir = std::env::temp_dir().join(format!("ldb-exitcodes-nr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tempdir");
        let archive = dir.join("a.tar.gz");
        let backup = bin()
            .args(["--backup", "--out", archive.to_str().expect("utf8"), "--mode", "minimal"])
            .output()
            .expect("spawn");
        assert_eq!(backup.status.code(), Some(0));

        let out = bin()
            .args(["--restore", "--archive", archive.to_str().expect("utf8"), "--yes"])
            .output()
            .expect("spawn");
        assert_eq!(out.status.code(), Some(1), "stderr: {}", String::from_utf8_lossy(&out.stderr));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// C-07：非 root 下 `--helper-restore` 必须自证失败（RESULT FAIL + 退出码 1）。
/// C-07: `--helper-restore` must refuse to run without root.
#[test]
fn helper_refuses_non_root() {
    if unsafe { geteuid() } == 0 {
        eprintln!("euid==0，跳过非 root 拒绝断言 / skipping non-root refusal assertion");
        return;
    }
    let out = bin()
        .args(["--helper-restore", "--archive", "/nonexistent/a.tar.gz"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("RESULT\tFAIL") && stdout.contains("root"),
        "stdout: {stdout}"
    );
}

/// C-07：非法 PKEXEC_UID 必须拒绝（仅 root 环境可构造，非 root 走上面的 euid 门）。
/// C-07: a malformed PKEXEC_UID must be refused (only reachable as root).
#[test]
fn helper_rejects_invalid_pkexec_uid() {
    if unsafe { geteuid() } != 0 {
        eprintln!("euid!=0，跳过 PKEXEC_UID 断言 / skipping PKEXEC_UID assertion");
        return;
    }
    let out = bin()
        .args(["--helper-restore", "--archive", "/nonexistent/a.tar.gz"])
        .env("PKEXEC_UID", "not-a-number")
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PKEXEC_UID"), "stdout: {stdout}");
}

// 直接读 euid（裸 extern 声明，避免为一个符号引入 libc 依赖）。
// Read euid via a bare extern declaration (no libc dependency for one symbol).
extern "C" {
    fn geteuid() -> u32;
}
