// 模块：W7 CLI 集成测试 —— `--verify` / `--diagnose` / `--config`（ITERATION §4-W7）
// Module: W7 CLI integration tests — `--verify` / `--diagnose` / `--config`.
//
// 通过 `CARGO_BIN_EXE_<name>` 真实运行编译产物；每个子进程都把 `HOME` /
// `XDG_CONFIG_HOME` 指向临时目录，避免读到运行者真实的 `/etc` 或 `~/.config` 配置。
// Every child process points `HOME` / `XDG_CONFIG_HOME` at a temp dir so the tests
// never pick up the developer's real config files.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

/// 测试专用临时目录 / A per-process temp directory.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ldb-w7-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("tempdir");
    dir
}

/// 构造子进程命令，并把配置发现隔离到 `home` 之下。
/// Build a child process with config discovery confined under `home`.
fn bin_at(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_linux-driver-backup"));
    cmd.env("HOME", home);
    cmd.env("XDG_CONFIG_HOME", home.join(".config"));
    cmd
}

/// 造一个真实归档（备份免 root、只读系统目录）。
/// Produce a real archive (backup needs no root and only reads system dirs).
fn make_archive(home: &Path, archive: &Path) {
    let out = bin_at(home)
        .args([
            "--backup",
            "--out",
            archive.to_str().expect("utf8"),
            "--mode",
            "minimal",
        ])
        .output()
        .expect("spawn backup");
    assert_eq!(
        out.status.code(),
        Some(0),
        "backup stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `--verify`：健康归档文本模式返回 0、`--json` 模式返回 `ok=true`。
/// `--verify`: a healthy archive passes with exit 0, and `--json` reports `ok=true`.
#[test]
fn verify_healthy_archive_passes() {
    let dir = temp_dir("verify-ok");
    let archive = dir.join("a.tar.gz");
    make_archive(&dir, &archive);

    let text = bin_at(&dir)
        .args(["--verify", "--archive", archive.to_str().expect("utf8")])
        .output()
        .expect("spawn verify");
    assert_eq!(
        text.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(String::from_utf8_lossy(&text.stdout).contains("通过 / OK"));

    let json = bin_at(&dir)
        .args([
            "--verify",
            archive.to_str().expect("utf8"),
            "--json",
        ])
        .output()
        .expect("spawn verify json");
    assert_eq!(json.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("verify --json is valid JSON");
    assert_eq!(parsed["ok"], serde_json::Value::Bool(true));
    assert!(parsed["content_verified"].as_u64().unwrap_or(0) >= 1);

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--verify`：截断（损坏）的归档必须返回 1，绝不谎报通过（C-06）。
/// `--verify`: a truncated archive must exit 1 — never report success (C-06).
#[test]
fn verify_corrupt_archive_fails() {
    let dir = temp_dir("verify-bad");
    let archive = dir.join("a.tar.gz");
    make_archive(&dir, &archive);

    let bytes = std::fs::read(&archive).expect("read archive");
    let truncated = dir.join("truncated.tar.gz");
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).expect("write truncated");

    let out = bin_at(&dir)
        .args(["--verify", truncated.to_str().expect("utf8")])
        .output()
        .expect("spawn verify");
    assert_eq!(
        out.status.code(),
        Some(1),
        "stdout: {} / stderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--diagnose`：生成 tar.gz，内含 `report.txt` / `report.json`（W7 / P1-6）。
/// `--diagnose`: writes a tar.gz containing `report.txt` / `report.json`.
#[test]
fn diagnose_writes_a_bundle() {
    let dir = temp_dir("diagnose");
    let out_path = dir.join("diag.tar.gz");

    let out = bin_at(&dir)
        .args(["--diagnose", "--out", out_path.to_str().expect("utf8")])
        .output()
        .expect("spawn diagnose");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out_path.is_file(), "诊断包未生成");

    let file = std::fs::File::open(&out_path).expect("open bundle");
    let mut ar = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut names = Vec::new();
    for entry in ar.entries().expect("entries") {
        let mut entry = entry.expect("entry");
        let name = entry.path().expect("path").display().to_string();
        if name == "report.json" {
            let mut buf = String::new();
            entry.read_to_string(&mut buf).expect("read report");
            let parsed: serde_json::Value =
                serde_json::from_str(&buf).expect("report.json valid");
            assert!(parsed.get("kernel_release").is_some());
        }
        names.push(name);
    }
    assert!(names.iter().any(|n| n == "report.txt"), "{names:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// `--config` 与配置发现：配置里的 `out_dir` 补全 `--backup` 缺省的 `--out`（W7）。
/// `--config` / discovery: `out_dir` fills the missing `--backup --out` (W7).
#[test]
fn config_out_dir_supplies_backup_default() {
    let dir = temp_dir("config");
    let out_dir = dir.join("backups");
    std::fs::create_dir_all(&out_dir).expect("out dir");
    let cfg_path = dir.join(".config/linux-driver-backup/config.toml");
    std::fs::create_dir_all(cfg_path.parent().expect("parent")).expect("cfg dir");
    std::fs::write(
        &cfg_path,
        format!("out_dir = \"{}\"\nmode = \"minimal\"\n", out_dir.display()),
    )
    .expect("write config");

    // 不传 `--out`：由发现的用户级配置补全，成功且落在 out_dir 内。
    let out = bin_at(&dir)
        .args(["--backup"])
        .output()
        .expect("spawn backup");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let produced = std::fs::read_dir(&out_dir)
        .expect("read out dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    assert!(
        produced.iter().any(|n| n.starts_with("driver-backup-") && n.ends_with(".tar.gz")),
        "out_dir 内未生成归档: {produced:?}"
    );

    // 显式 `--config` 指向坏文件 → 用法错误（退出码 2）。
    let bad = dir.join("bad.toml");
    std::fs::write(&bad, "out_dir = \n").expect("write bad");
    let out = bin_at(&dir)
        .args(["--backup", "--config", bad.to_str().expect("utf8")])
        .output()
        .expect("spawn");
    assert_eq!(
        out.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 显式 `--config` 指向不存在的文件 → 用法错误（退出码 2）。
    let out = bin_at(&dir)
        .args(["--backup", "--config", "/nonexistent/ldb.toml"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    let _ = std::fs::remove_dir_all(&dir);
}
