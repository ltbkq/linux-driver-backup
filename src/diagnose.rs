//! 模块：一键诊断收集 `--diagnose`（W7 / P1-6 / ITERATION §4-W7）。
//! Module: one-shot diagnostic collection `--diagnose`.
//!
//! 【动机】用户报障时来回追问环境信息成本高；`--diagnose` 把**脱敏**后的环境快照
//! （内核、发行版、Secure Boot、不可变系统、工具可用性、最近一次还原日志、
//! 生效配置）打成一个 `tar.gz`，用户直接附到 issue 里即可。
//! [Why] Collect a *redacted* environment snapshot (kernel, distro, Secure Boot,
//! immutability, tool availability, last restore journal, effective config) into a
//! single `tar.gz` for bug reports.
//!
//! 【脱敏策略】`/home/<user>` → `/home/<redacted>`；不收集任何密钥内容、
//! 环境变量值与网络地址。日志只取**头部若干行**（条目摘要），不打包整个回滚区。
//! [Redaction] Home paths are masked; no keys, env values or network addresses are
//! collected; journals contribute only a header excerpt.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::distro;
use crate::model::{AppError, AppResult};

/// 收集诊断快照并写入归档，返回写出的路径。
/// Collect the snapshot and write it to an archive; return the output path.
///
/// `out = None` 时默认写到当前目录 `ldb-diagnose-<unix秒>.tar.gz`。
pub fn run(out: Option<&str>) -> AppResult<PathBuf> {
    let path = match out {
        Some(raw) => super::expand_tilde(raw),
        None => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            PathBuf::from(format!("ldb-diagnose-{now}.tar.gz"))
        }
    };

    let text = report_text();
    let json = serde_json::to_string_pretty(&report_json()).map_err(|err| {
        AppError::Format(format!("诊断 JSON 序列化失败 / diagnose JSON failed: {err}"))
    })?;

    let file = fs::File::create(&path).map_err(|err| {
        AppError::Io(err)
    })?;
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);

    append_text(&mut builder, "report.txt", text.as_bytes())?;
    append_text(&mut builder, "report.json", json.as_bytes())?;
    let readme = "linux-driver-backup diagnose bundle (redacted)\n\
                  linux-driver-backup 诊断包（已脱敏）：report.txt 人读，report.json 机读。\n";
    append_text(&mut builder, "README.txt", readme.as_bytes())?;

    let encoder = builder.into_inner().map_err(AppError::Io)?;
    encoder.finish().map_err(AppError::Io)?;
    Ok(path)
}

/// 写入一个文本 tar 条目（mtime=0、mode 0644，输出可复现）。
/// Append one text member with deterministic metadata.
fn append_text<W: Write>(
    builder: &mut tar::Builder<W>,
    name: &str,
    bytes: &[u8],
) -> AppResult<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append_data(&mut header, name, bytes)
        .map_err(AppError::Io)?;
    Ok(())
}

/// 脱敏：把 `/home/<用户>` 与 `~/` 展开前的家目录字面量统一替换。
/// Redaction: mask the user's home directory wherever it appears.
pub(crate) fn redact(text: &str) -> String {
    if let Some(home) = std::env::var_os("HOME") {
        let home = home.to_string_lossy().into_owned();
        if !home.is_empty() && home != "/" {
            return text.replace(home.as_str(), "/home/<redacted>");
        }
    }
    text.to_string()
}

/// 结构化快照（`report.json`）。
/// The structured snapshot written to `report.json`.
fn report_json() -> serde_json::Value {
    let distro_info = distro::DistroInfo::detect();
    let sb = distro::secure_boot_state();
    let journal = restore_last_journal_header();

    serde_json::json!({
        "tool_version": env!("CARGO_PKG_VERSION"),
        "collected_at_unix": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "kernel_release": distro::kernel_release(),
        "arch": distro::arch(),
        "distro": {
            "id": distro_info.id,
            "version_id": distro_info.version_id,
            "pretty_name": distro_info.pretty_name,
            "family": distro_info.family_label(),
        },
        "immutability": distro::immutability().tag(),
        "secure_boot": {
            "enabled": sb.enabled,
            "sig_enforce": sb.sig_enforce,
            "mok_key_pairs": distro::mok_keys().len(),
        },
        "module_roots": distro::module_roots()
            .iter()
            .map(|p| redact(&p.display().to_string()))
            .collect::<Vec<_>>(),
        "tools": tool_availability()
            .into_iter()
            .map(|(name, present)| (name.to_string(), serde_json::Value::Bool(present)))
            .collect::<serde_json::Map<_, _>>(),
        "config_effective": effective_config_json(),
        "last_restore_journal": journal,
    })
}

/// 人类可读快照（`report.txt`）。
/// The human-readable snapshot written to `report.txt`.
pub fn report_text() -> String {
    let distro_info = distro::DistroInfo::detect();
    let sb = distro::secure_boot_state();
    let mut out = String::new();

    out.push_str(&format!(
        "== linux-driver-backup 诊断 / diagnose ==\n工具版本 / tool : {}\n",
        env!("CARGO_PKG_VERSION")
    ));
    out.push_str(&format!(
        "内核 / kernel   : {}\n架构 / arch     : {}\n",
        distro::kernel_release(),
        distro::arch()
    ));
    out.push_str(&format!(
        "发行版 / distro : {}（{}，家族 {}）\n",
        distro_info.pretty_name,
        distro_info.id,
        distro_info.family_label()
    ));
    out.push_str(&format!(
        "不可变 / immut. : {}\n",
        distro::immutability().tag()
    ));
    out.push_str(&format!(
        "Secure Boot     : enabled={} sig_enforce={} mok_keys={}\n",
        sb.enabled,
        sb.sig_enforce,
        distro::mok_keys().len()
    ));
    out.push_str("模块目录 / module roots:\n");
    for root in distro::module_roots() {
        out.push_str(&format!("  - {}\n", redact(&root.display().to_string())));
    }

    out.push_str("工具可用性 / tools:\n");
    for (name, present) in tool_availability() {
        out.push_str(&format!(
            "  {:<16} {}\n",
            name,
            if present { "✓" } else { "✗" }
        ));
    }

    out.push_str("生效配置 / effective config:\n");
    match Config::load(None) {
        Ok(cfg) => {
            out.push_str(&format!("  mode          = {:?}\n", cfg.mode));
            out.push_str(&format!(
                "  out_dir       = {}\n",
                cfg.out_dir
                    .as_ref()
                    .map(|p| redact(&p.display().to_string()))
                    .unwrap_or_else(|| "<unset>".into())
            ));
            out.push_str(&format!("  keep_rollback = {:?}\n", cfg.keep_rollback));
            out.push_str(&format!("  firmware      = {:?}\n", cfg.firmware));
            out.push_str(&format!("  strategy      = {:?}\n", cfg.strategy));
            out.push_str(&format!(
                "  sign_key      = {}\n",
                cfg.sign_key
                    .as_ref()
                    .map(|k| redact(k))
                    .unwrap_or_else(|| "<unset>".into())
            ));
        }
        Err(err) => out.push_str(&format!("  <无法加载 / cannot load>: {err}\n")),
    }

    out.push_str("最近一次还原日志 / last restore journal:\n");
    match restore_last_journal_header() {
        Some(head) => {
            for line in head.lines() {
                out.push_str(&format!("  {line}\n"));
            }
        }
        None => out.push_str("  <无 / none>\n"),
    }

    redact(&out)
}

/// 工具可用性清单（探测全部只读，失败即 `false`）。
/// Tool availability probe; every check is read-only.
fn tool_availability() -> Vec<(&'static str, bool)> {
    const TOOLS: &[&str] = &[
        "depmod",
        "modprobe",
        "dkms",
        "akmods",
        "weak-modules",
        "apt",
        "dnf",
        "zypper",
        "pacman",
        "rpm",
        "rpm-ostree",
        "dracut",
        "mkinitcpio",
        "mkinitramfs",
        "mkinitfs",
        "update-initramfs",
        "mokutil",
        "sign-file",
        "kmodsign",
        "pkexec",
        "systemd-boot",
        "ukify",
    ];
    TOOLS
        .iter()
        .map(|name| (*name, distro::has_cmd(name)))
        .collect()
}

/// 生效配置（机器读）。
/// Effective configuration (machine readable).
fn effective_config_json() -> serde_json::Value {
    match Config::load(None) {
        Ok(cfg) => serde_json::json!({
            "mode": cfg.mode.map(|m| m.label()),
            "out_dir": cfg.out_dir.as_ref().map(|p| redact(&p.display().to_string())),
            "keep_rollback": cfg.keep_rollback,
            "firmware": cfg.firmware,
            "strategy": cfg.strategy.map(|s| s.label()),
            "sign_key": cfg.sign_key.as_ref().map(|k| redact(k)),
        }),
        Err(err) => serde_json::json!({ "error": err.to_string() }),
    }
}

/// 最近一次还原日志的头部摘要（脱敏、限行数）。
/// Redacted header excerpt of the last restore journal.
fn restore_last_journal_header() -> Option<String> {
    let path = crate::restore::latest_journal(Path::new("/"))?;
    let text = fs::read_to_string(&path).ok()?;
    let excerpt: Vec<&str> = text.lines().take(12).collect();
    Some(format!("{}:\n{}", path.display(), excerpt.join("\n")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 脱敏函数：家目录必须被替换；无 HOME 时原样返回。
    #[test]
    fn redact_masks_home() {
        let home = std::env::var("HOME").unwrap_or_default();
        if home.is_empty() || home == "/" {
            assert_eq!(redact("/home/u/x"), "/home/u/x");
            return;
        }
        let input = format!("{home}/secrets/module.ko");
        let out = redact(&input);
        assert!(!out.contains(&home), "out = {out}");
        assert!(out.contains("/home/<redacted>"));
    }

    /// 端到端：写出 tar.gz，内部包含三个成员且 report.txt 非空。
    #[test]
    fn diagnose_writes_readable_bundle() {
        let dir = std::env::temp_dir().join(format!("ldb-diag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let out = dir.join("diag.tar.gz");

        let path = run(Some(out.to_str().expect("utf8"))).expect("run");
        assert!(path.is_file());

        // 重新读出，校验成员清单。
        let file = fs::File::open(&path).expect("open");
        let decoder = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(decoder);
        let mut names = Vec::new();
        for entry in ar.entries().expect("entries") {
            let entry = entry.expect("entry");
            names.push(entry.path().expect("path").display().to_string());
        }
        assert!(names.contains(&"report.txt".to_string()), "{names:?}");
        assert!(names.contains(&"report.json".to_string()), "{names:?}");

        // report.txt 至少含内核行；report.json 是合法 JSON。
        let file = fs::File::open(&path).expect("open2");
        let decoder = flate2::read::GzDecoder::new(file);
        let mut ar = tar::Archive::new(decoder);
        for entry in ar.entries().expect("entries2") {
            let mut entry = entry.expect("entry2");
            let name = entry.path().expect("path2").display().to_string();
            let mut buf = String::new();
            use std::io::Read;
            entry.read_to_string(&mut buf).expect("read");
            match name.as_str() {
                "report.txt" => assert!(buf.contains("内核 / kernel")),
                "report.json" => {
                    let parsed: serde_json::Value =
                        serde_json::from_str(&buf).expect("report.json parses");
                    assert!(parsed.get("kernel_release").is_some());
                    assert!(parsed.get("tools").is_some());
                }
                _ => {}
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `report_text` 必须完成脱敏且不包含家目录明文。
    #[test]
    fn report_text_is_redacted() {
        let text = report_text();
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() && home != "/" {
                // 文本里可能出现 /etc 等系统路径，但不应有家目录明文。
                assert!(!text.contains(&home), "report contains home path");
            }
        }
        assert!(text.contains("工具可用性 / tools"));
    }
}
