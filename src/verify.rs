//! 模块：归档体检 `--verify`（W7 / P1-7 / ITERATION §4-W7、C-06）。
//! Module: archive integrity check `--verify`.
//!
//! 【动机】manifest 一直携带逐文件 SHA-256，但 v0.2.x 的还原流程**从不校验**
//! （C-06：传输损坏不可检测）。`--verify` 把这条校验链补全，并输出 vermagic /
//! 架构 / 内核匹配状态，供用户在还原前体检归档。
//! [Why] The manifest has always carried per-file SHA-256 but nothing ever
//! verified it (C-06). `--verify` closes that gap and reports kernel/arch/vermagic
//! status so archives can be checked before a restore.
//!
//! 【单遍实现】manifest 位于归档**末尾**，因此先流式哈希全部 `data/` 内存入
//! 映射，遍历结束解析 manifest 再逐条比对——一次解压完成全部工作。
//! [Single pass] `manifest.json` sits at the end of the archive, so contents are
//! hashed into a map first and compared after the manifest is parsed: one pass.
//!
//! 【语义对齐 backup.rs】普通文件 = 内容哈希；符号链接 = **目标字符串**哈希、
//! `size = 0`（与 `backup.rs::sha256_hex(target.as_bytes())` 一致）；
//! `content_stored = false` 的条目不要求出现在归档中。
//!
//! [Summary] Single-pass SHA-256 verification of every stored entry against the
//! manifest, plus informational kernel/arch/vermagic comparison. Exit code 1 when
//! `report.ok` is false.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::Path;

use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};

use crate::distro;
use crate::model::{AppError, AppResult, Manifest};

/// 单条校验问题（路径 + 描述，双语）。
/// One verification problem (path + bilingual description).
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyIssue {
    /// 归档内相对路径（不含 `data/` 前缀）。
    pub path: String,
    /// 问题描述。
    pub problem: String,
}

/// 体检报告（`--json` 输出即本结构的序列化）。
/// The verification report; `--json` serialises exactly this struct.
#[derive(Debug, Clone, serde::Serialize)]
pub struct VerifyReport {
    /// 被体检的归档路径。
    pub archive: String,
    /// manifest 声明的格式版本。
    pub format_version: u32,
    /// 生成归档的工具版本。
    pub tool_version: String,
    /// 归档创建时刻（RFC3339）。
    pub created_at: String,
    /// 归档的内核版本串。
    pub kernel_release: String,
    /// 当前内核版本串。
    pub current_kernel: String,
    /// 内核是否一致（信息项，不参与 `ok` 判定）。
    pub kernel_match: bool,
    /// 归档架构。
    pub arch: String,
    /// 当前架构。
    pub current_arch: String,
    /// 架构是否一致（信息项）。
    pub arch_match: bool,
    /// 归档记录的 vermagic。
    pub vermagic: Option<String>,
    /// 当前内核参考树的 vermagic。
    pub current_vermagic: Option<String>,
    /// vermagic 是否一致；任一缺失为 `None`（信息项）。
    pub vermagic_match: Option<bool>,
    /// manifest 条目总数。
    pub entries_total: usize,
    /// 校验通过的**内容**条目数。
    pub content_verified: usize,
    /// 校验通过的**符号链接**条目数。
    pub links_verified: usize,
    /// 标记为未存储（由来源包提供者）而合理缺席的条目数。
    pub not_stored: usize,
    /// 归档内实际内容字节数（不含链接）。
    pub payload_bytes: u64,
    /// 校验问题清单（`ok == issues.is_empty()`）。
    pub issues: Vec<VerifyIssue>,
    /// manifest 中备份期记录的告警（原样透传）。
    pub manifest_warnings: Vec<String>,
    /// 完整性是否通过（仅由 `issues` 决定；内核/架构差异不破坏完整性）。
    pub ok: bool,
}

/// 一个已流式哈希完的 `data/` 条目。
/// One already-hashed `data/` entry.
struct FileFact {
    /// 内容（或链接目标）的 SHA-256 十六进制。
    sha: String,
    /// 内容字节数（链接为 0）。
    size: u64,
    /// tar 内是否为符号链接条目。
    is_link: bool,
    /// 链接目标（仅链接）。
    link_target: Option<String>,
}

/// 十六进制编码。
/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

/// 打开 gzip/tar 归档（与 `restore::inspect` 相同的读取方式）。
/// Open the gzip/tar archive (same reading path as `restore::inspect`).
fn open(archive: &Path) -> AppResult<tar::Archive<GzDecoder<fs::File>>> {
    let file = fs::File::open(archive).map_err(|err| {
        AppError::Format(format!(
            "无法打开归档 / cannot open archive {}: {err}",
            archive.display()
        ))
    })?;
    Ok(tar::Archive::new(GzDecoder::new(file)))
}

/// 体检归档：逐条校验 SHA-256 + 内核/架构/vermagic 信息比对。
/// Verify the archive: per-entry SHA-256 plus informational kernel/arch checks.
///
/// 完整性判定与环境差异分离：`issues` 只记录**完整性**问题（哈希不符、缺条目、
/// 多余条目、非法路径）；内核/vermagic/架构差异只写入信息字段，因为它们由
/// 还原策略（C-31/C-32）裁决，而不是体检。
pub fn verify(archive: &Path) -> AppResult<VerifyReport> {
    let mut reader = open(archive)?;
    let entries = reader.entries().map_err(|err| {
        AppError::Format(format!(
            "无法读取归档（不是有效的 gzip/tar 或已损坏）/ unreadable archive: {err}"
        ))
    })?;

    let mut facts: HashMap<String, FileFact> = HashMap::new();
    let mut illegal: Vec<String> = Vec::new();
    let mut manifest_json: Option<String> = None;

    for entry in entries {
        let mut entry = entry.map_err(|err| {
            AppError::Format(format!("归档条目损坏 / corrupt archive entry: {err}"))
        })?;
        let et = entry.header().entry_type();
        let raw = String::from_utf8_lossy(&entry.path_bytes()).into_owned();

        if raw == "manifest.json" && manifest_json.is_none() && !et.is_symlink() {
            let mut buf = String::new();
            entry.read_to_string(&mut buf).map_err(|err| {
                AppError::Format(format!("manifest.json 读取失败 / read failed: {err}"))
            })?;
            manifest_json = Some(buf);
            continue;
        }

        // 只关心 data/ 前缀；先做词法合法性检查（只读操作，不落盘，但仍标记问题）。
        let Some(rel) = raw.strip_prefix("data/").map(str::to_string) else {
            continue;
        };
        if rel.is_empty()
            || rel.starts_with('/')
            || rel.split('/').any(|seg| seg == ".." || seg == ".")
        {
            illegal.push(raw.clone());
            continue;
        }
        if et.is_dir() {
            continue;
        }

        if et.is_symlink() {
            let target = entry
                .header()
                .link_name_bytes()
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .unwrap_or_default();
            let mut hasher = Sha256::new();
            hasher.update(target.as_bytes());
            facts.insert(
                rel,
                FileFact {
                    // 与 backup.rs 的 v2 语义一致：链接摘要 = **目标字符串**的 SHA-256。
                    sha: hex(&hasher.finalize()),
                    size: 0,
                    is_link: true,
                    link_target: Some(target),
                },
            );
            continue;
        }
        if et.is_hard_link() {
            // 备份流水线不会产出硬链接；出现即视为结构异常。
            illegal.push(format!("{raw}（意外硬链接 / unexpected hard link）"));
            continue;
        }

        // 普通文件：流式哈希。
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = entry.read(&mut buf).map_err(|err| {
                AppError::Format(format!("读取 {} 失败 / read failed: {rel}", err))
            })?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size = size.saturating_add(n as u64);
        }
        facts.insert(
            rel,
            FileFact {
                sha: hex(&hasher.finalize()),
                size,
                is_link: false,
                link_target: None,
            },
        );
    }

    let manifest_json = manifest_json.ok_or_else(|| {
        AppError::Format("归档缺少 manifest.json / archive has no manifest.json".to_string())
    })?;
    let manifest: Manifest = serde_json::from_str(&manifest_json)
        .map_err(|err| AppError::Format(format!("manifest.json 解析失败 / parse failed: {err}")))?;
    if !manifest.format_supported() {
        return Err(AppError::Format(format!(
            "归档格式版本 v{} 不受支持（当前支持 v{}–v{}）/ unsupported format version",
            manifest.format_version,
            crate::model::MIN_MANIFEST_FORMAT_VERSION,
            crate::model::MANIFEST_FORMAT_VERSION
        )));
    }

    // ---- 逐条比对 ----
    let mut issues: Vec<VerifyIssue> = Vec::new();
    for path in &illegal {
        issues.push(VerifyIssue {
            path: path.clone(),
            problem: "非法路径 / illegal path".to_string(),
        });
    }

    let mut content_verified = 0usize;
    let mut links_verified = 0usize;
    let mut not_stored = 0usize;
    let mut payload_bytes: u64 = 0;
    let mut manifest_paths: HashSet<&str> = HashSet::new();

    for me in &manifest.entries {
        manifest_paths.insert(me.path.as_str());
        match facts.get(&me.path) {
            None => {
                if me.content_stored {
                    issues.push(VerifyIssue {
                        path: me.path.clone(),
                        problem: format!(
                            "缺失：manifest 登记但归档无内容 / missing (manifest lists it): sha256={}",
                            me.sha256
                        ),
                    });
                } else {
                    // 由来源包提供者覆盖，合理缺席。
                    not_stored += 1;
                }
            }
            Some(fact) => {
                if fact.is_link {
                    if me.kind != crate::model::EntryKind::Symlink {
                        issues.push(VerifyIssue {
                            path: me.path.clone(),
                            problem: "类型不一致：manifest 非链接而归档为链接 / kind mismatch"
                                .to_string(),
                        });
                        continue;
                    }
                    // 目标串与哈希都要对得上（v2 记录 link_target；v1 无链接条目）。
                    if let Some(expected) = &me.link_target {
                        if fact.link_target.as_deref() != Some(expected.as_str()) {
                            issues.push(VerifyIssue {
                                path: me.path.clone(),
                                problem: format!(
                                    "链接目标不符 / link target mismatch: manifest={} archive={}",
                                    expected,
                                    fact.link_target.as_deref().unwrap_or("<none>")
                                ),
                            });
                            continue;
                        }
                    }
                    if fact.sha != me.sha256 {
                        issues.push(VerifyIssue {
                            path: me.path.clone(),
                            problem: format!(
                                "链接目标哈希不符 / link hash mismatch: 期望 {} 实际 {}",
                                me.sha256, fact.sha
                            ),
                        });
                        continue;
                    }
                    links_verified += 1;
                    continue;
                }

                if !me.content_stored {
                    issues.push(VerifyIssue {
                        path: me.path.clone(),
                        problem: "标记为未存储却存在内容 / marked not-stored but content present"
                            .to_string(),
                    });
                    continue;
                }
                if fact.sha != me.sha256 {
                    issues.push(VerifyIssue {
                        path: me.path.clone(),
                        problem: format!(
                            "SHA-256 不符 / sha256 mismatch: 期望 {} 实际 {}",
                            me.sha256, fact.sha
                        ),
                    });
                    continue;
                }
                if fact.size != me.size {
                    issues.push(VerifyIssue {
                        path: me.path.clone(),
                        problem: format!(
                            "体积不符 / size mismatch: 期望 {} 实际 {}",
                            me.size, fact.size
                        ),
                    });
                    continue;
                }
                content_verified += 1;
                payload_bytes = payload_bytes.saturating_add(fact.size);
            }
        }
    }

    // 归档里有、manifest 没有的 data/ 条目（还原时会按 C-10 拒绝写入）。
    for key in facts.keys() {
        if !manifest_paths.contains(key.as_str()) {
            issues.push(VerifyIssue {
                path: key.clone(),
                problem: "多余：归档有而 manifest 未登记 / extra (not in manifest)".to_string(),
            });
        }
    }

    // ---- 环境信息（只读探测，不参与完整性判定）----
    let current_kernel = distro::kernel_release();
    let current_arch = distro::arch();
    let current_vermagic = distro::reference_vermagic(&current_kernel);
    let vermagic_match = match (&manifest.kernel_vermagic, &current_vermagic) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };

    let ok = issues.is_empty();
    let kernel_match = manifest.kernel_release == current_kernel;
    let arch_match = manifest.arch == current_arch;
    Ok(VerifyReport {
        archive: archive.display().to_string(),
        format_version: manifest.format_version,
        tool_version: manifest.tool_version.clone(),
        created_at: manifest.created_at.clone(),
        kernel_release: manifest.kernel_release.clone(),
        current_kernel,
        kernel_match,
        arch: manifest.arch.clone(),
        current_arch: current_arch.to_string(),
        arch_match,
        vermagic: manifest.kernel_vermagic.clone(),
        current_vermagic,
        vermagic_match,
        entries_total: manifest.entries.len(),
        content_verified,
        links_verified,
        not_stored,
        payload_bytes,
        issues,
        manifest_warnings: manifest.warnings.clone(),
        ok,
    })
}

/// 生成人类可读的双语体检报告（文本模式输出）。
/// Render a bilingual human-readable report (text-mode output).
pub fn format_report(r: &VerifyReport) -> String {
    let mark = |b: bool| if b { "✓" } else { "✗" };
    let mut out = String::new();
    out.push_str(&format!(
        "归档体检 / archive verification: {} —— {}\n",
        r.archive,
        if r.ok {
            "通过 / OK"
        } else {
            "发现问题 / ISSUES FOUND"
        }
    ));
    out.push_str(&format!(
        "  格式 / format : v{}（工具 {}，创建于 {}）\n",
        r.format_version, r.tool_version, r.created_at
    ));
    out.push_str(&format!(
        "  内核 / kernel : {} {}（当前 {}）\n",
        mark(r.kernel_match),
        r.kernel_release,
        r.current_kernel
    ));
    out.push_str(&format!(
        "  架构 / arch   : {} {}（当前 {}）\n",
        mark(r.arch_match),
        r.arch,
        r.current_arch
    ));
    match (&r.vermagic, r.vermagic_match) {
        (Some(v), Some(m)) => out.push_str(&format!(
            "  vermagic      : {} {v}（当前 {}）\n",
            mark(m),
            r.current_vermagic.as_deref().unwrap_or("<unknown>")
        )),
        (Some(v), None) => out.push_str(&format!(
            "  vermagic      : {v}（当前内核无法读取，跳过比对 / current unavailable）\n"
        )),
        (None, _) => out.push_str("  vermagic      : 归档未记录 / not recorded\n"),
    }
    out.push_str(&format!(
        "  条目 / entries: {}（内容 ✓ {}，链接 ✓ {}，来源包缺席 {}）\n",
        r.entries_total, r.content_verified, r.links_verified, r.not_stored
    ));
    out.push_str(&format!(
        "  体积 / payload: {}\n",
        crate::model::human_size(r.payload_bytes)
    ));
    for issue in &r.issues {
        out.push_str(&format!("  ✗ {}: {}\n", issue.path, issue.problem));
    }
    for warning in &r.manifest_warnings {
        out.push_str(&format!("  ⚠ {warning}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distro::Family;
    use crate::model::{
        BackupMode, EntryKind, Manifest, ManifestDistro, ManifestEntry, MANIFEST_FORMAT_VERSION,
    };
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::path::PathBuf;

    fn hex_of(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex(&hasher.finalize())
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ldb-verify-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    /// 构造测试归档：普通文件 + 链接 + manifest（置于末尾，与备份一致）。
    /// Build a fixture archive: regular file + symlink + manifest at the end.
    fn build_archive(
        dir: &Path,
        name: &str,
        files: &[(&str, &[u8])],
        links: &[(&str, &str)],
        extra_manifest: &[(&str, bool)], // (path, content_stored) 额外登记
        unlisted: &[(&str, &[u8])],      // 写入 tar 但**不登记** manifest（制造多余条目）
        tamper: bool,                    // manifest 里的 sha 记错
    ) -> PathBuf {
        let out = dir.join(name);
        let file = fs::File::create(&out).expect("create");
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let mut entries_json: Vec<ManifestEntry> = Vec::new();
        for (rel, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("data/{rel}"), *bytes)
                .expect("append data");
            let sha = if tamper {
                "deadbeef".repeat(8)
            } else {
                hex_of(bytes)
            };
            entries_json.push(ManifestEntry {
                path: (*rel).to_string(),
                size: bytes.len() as u64,
                sha256: sha,
                kind: EntryKind::Config,
                link_target: None,
                owner: None,
                modinfo: None,
                content_stored: true,
                strategy_hint: None,
            });
        }
        for (rel, target) in links {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            header.set_mode(0o777);
            // append_link 自行计算校验和（与 backup.rs 生产路径一致）。
            builder
                .append_link(&mut header, format!("data/{rel}"), *target)
                .expect("append link");
            entries_json.push(ManifestEntry {
                path: (*rel).to_string(),
                size: 0,
                sha256: hex_of(target.as_bytes()),
                kind: EntryKind::Symlink,
                link_target: Some((*target).to_string()),
                owner: None,
                modinfo: None,
                content_stored: true,
                strategy_hint: None,
            });
        }
        for (rel, stored) in extra_manifest {
            entries_json.push(ManifestEntry {
                path: (*rel).to_string(),
                size: 4,
                sha256: hex_of(b"skip"),
                kind: EntryKind::Module,
                link_target: None,
                owner: None,
                modinfo: None,
                content_stored: *stored,
                strategy_hint: None,
            });
        }
        // 只有 manifest、没有归档内容：由 content_stored=true 且不在 tar 中表达。
        for (rel, bytes) in unlisted {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("data/{rel}"), *bytes)
                .expect("append unlisted");
        }

        let manifest = Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            tool_version: "0.3.0-test".to_string(),
            created_at: "2026-10-01T00:00:00Z".to_string(),
            kernel_release: distro::kernel_release(),
            kernel_vermagic: None,
            arch: crate::distro::arch().to_string(),
            distro: ManifestDistro {
                id: "test".into(),
                version_id: "1".into(),
                pretty_name: "Test Linux".into(),
                family: Family::Debian,
            },
            immutability: None,
            secure_boot: None,
            mode: BackupMode::Minimal,
            compression: Some("gzip".into()),
            entries: entries_json,
            dkms: Vec::new(),
            warnings: vec!["示例告警 / sample warning".into()],
            firmware_policy: None,
        };
        let json = serde_json::to_vec_pretty(&manifest).expect("serialize");
        let mut header = tar::Header::new_gnu();
        header.set_size(json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "manifest.json", &json[..])
            .expect("append manifest");
        let encoder = builder.into_inner().expect("finish tar");
        encoder.finish().expect("finish gz");
        out
    }

    /// 健康归档：全部通过。
    #[test]
    fn healthy_archive_verifies_ok() {
        let dir = temp_dir("healthy");
        let archive = build_archive(
            &dir,
            "good.tar.gz",
            &[("etc/foo.conf", b"hello"), ("etc/bar.conf", b"world!")],
            &[("etc/link.conf", "foo.conf")],
            &[],
            &[],
            false,
        );
        let report = verify(&archive).expect("verify");
        assert!(report.ok, "issues: {:?}", report.issues);
        assert_eq!(report.content_verified, 2);
        assert_eq!(report.links_verified, 1);
        assert_eq!(report.not_stored, 0);
        assert_eq!(report.payload_bytes, 11);
        assert_eq!(report.manifest_warnings.len(), 1);
        assert!(format_report(&report).contains("通过 / OK"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 内容哈希被篡改 → 不通过（C-06：损坏可检测）。
    #[test]
    fn tampered_content_fails_verification() {
        let dir = temp_dir("tamper");
        let archive = build_archive(
            &dir,
            "bad.tar.gz",
            &[("etc/foo.conf", b"hello")],
            &[],
            &[],
            &[],
            true,
        );
        let report = verify(&archive).expect("verify");
        assert!(!report.ok);
        assert!(report
            .issues
            .iter()
            .any(|i| i.problem.contains("SHA-256 不符")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 缺条目 + 多余条目 + 合理缺席：三种情形各自的归类。
    #[test]
    fn missing_extra_and_not_stored_are_classified() {
        let dir = temp_dir("class");
        // manifest 登记 `ghost`（content_stored=true）但归档不含；登记 `pkg` 不存储；
        // 归档含 `rogue` 但 manifest 没有 —— 用第二个归档叠加。
        let archive = build_archive(
            &dir,
            "mix.tar.gz",
            &[("kept", b"k")],
            &[],
            &[("ghost", true), ("pkg", false)],
            &[("rogue", b"r")],
            false,
        );
        let report = verify(&archive).expect("verify");
        assert!(!report.ok);
        assert_eq!(report.not_stored, 1, "pkg 合理缺席");
        assert!(report
            .issues
            .iter()
            .any(|i| i.path == "ghost" && i.problem.contains("缺失")));
        assert!(report
            .issues
            .iter()
            .any(|i| i.path == "rogue" && i.problem.contains("多余")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 链接目标被改写 → 归类为目标不符。
    #[test]
    fn link_target_tamper_is_detected() {
        let dir = temp_dir("link");
        let archive = build_archive(
            &dir,
            "link.tar.gz",
            &[],
            &[("etc/l", "original.conf")],
            &[],
            &[],
            false,
        );
        // 直接改 manifest 里的 link_target（模拟归档被构造工具篡改）。
        // 重打包：读出原归档、篡改后重写。
        let bytes = fs::read(&archive).expect("read");
        let mut decoder = GzDecoder::new(&bytes[..]);
        let mut raw = Vec::new();
        decoder.read_to_end(&mut raw).expect("gunzip");
        let mut ar = tar::Archive::new(&raw[..]);
        let mut rebuilt: Vec<(String, Vec<u8>, Option<String>, tar::Header)> = Vec::new();
        for entry in ar.entries().expect("entries") {
            let mut entry = entry.expect("entry");
            let path = String::from_utf8_lossy(&entry.path_bytes()).into_owned();
            let link = entry
                .header()
                .link_name_bytes()
                .map(|b| String::from_utf8_lossy(&b).into_owned());
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).expect("read entry");
            let header = entry.header().clone();
            rebuilt.push((path, buf, link, header));
        }
        let out2 = dir.join("tampered-link.tar.gz");
        let file = fs::File::create(&out2).expect("create");
        let enc = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(enc);
        for (path, buf, link, mut header) in rebuilt {
            if path == "manifest.json" {
                let text = String::from_utf8(buf).expect("utf8");
                let mut manifest: Manifest = serde_json::from_str(&text).expect("manifest");
                manifest.entries[0].link_target = Some("evil.conf".into());
                let json = serde_json::to_vec_pretty(&manifest).expect("json");
                header.set_size(json.len() as u64);
                header.set_cksum();
                builder
                    .append_data(&mut header, path, &json[..])
                    .expect("append");
            } else if let Some(target) = link {
                builder
                    .append_link(&mut header, path, target)
                    .expect("append");
            } else {
                header.set_cksum();
                builder
                    .append_data(&mut header, path, &buf[..])
                    .expect("append");
            }
        }
        let enc = builder.into_inner().expect("tar finish");
        enc.finish().expect("gz finish");

        let report = verify(&out2).expect("verify");
        assert!(!report.ok);
        assert!(report
            .issues
            .iter()
            .any(|i| i.problem.contains("链接目标不符")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 损坏/不存在的归档路径 → `AppError::Format`（不 panic）。
    #[test]
    fn broken_archive_is_format_error() {
        let dir = temp_dir("broken");
        let missing = dir.join("nope.tar.gz");
        assert!(matches!(verify(&missing), Err(AppError::Format(_))));

        let garbage = dir.join("garbage.tar.gz");
        fs::write(&garbage, b"this is not gzip at all").expect("write");
        assert!(matches!(verify(&garbage), Err(AppError::Format(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
