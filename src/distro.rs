//! 发行版探测、内核信息与系统命令适配。
//! Distro detection, kernel info and system-command adaptation (std only, no libc/tokio/sys-info, no `unsafe`).
//!
//! 本模块只依赖 `std`，按 DESIGN.md §4.1 的发行版自适应规则工作：
//!
//! - 解析 `/etc/os-release`（缺失时回退 `/usr/lib/os-release`），先按 `ID` 精确匹配，
//!   未命中再按 `ID_LIKE` 逐项匹配，否则归为 [`Family::Unknown`]；
//! - 内核版本读 `/proc/sys/kernel/osrelease`，root 身份读 `/proc/self/status` 的 `Uid:` 行；
//! - 系统命令（`depmod` / `update-initramfs` / `dracut` / `mkinitcpio`）只描述为
//!   [`SystemCmd`]（program + args），由调用方决定是否真正执行；
//! - 模块目录候选 `/lib/modules` 与 `/usr/lib/modules` 按规范化路径去重（usr-merge 系统下二者等价）。

use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Distribution family that decides the initramfs command and extra restore steps.
/// 发行版家族，决定 initramfs 更新命令与还原期的附加步骤（详见 DESIGN.md §4.1）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Family {
    /// Debian-based (ubuntu/debian/linuxmint/…), initramfs via `update-initramfs` / Debian 系.
    #[serde(rename = "debian")]
    Debian,
    /// RHEL-based (rhel/centos/fedora/rocky/…), initramfs via `dracut` / RHEL 系.
    #[serde(rename = "rhel")]
    Rhel,
    /// Arch-based (arch/manjaro/…), initramfs via `mkinitcpio` / Arch 系.
    #[serde(rename = "arch")]
    Arch,
    /// Unknown family: skip initramfs instead of faking success / 未知发行版，跳过更新.
    #[serde(rename = "unknown")]
    Unknown,
}

impl Family {
    /// Map a single `ID`/`ID_LIKE` token to a family, case-insensitively.
    /// 把一个 os-release 的 `ID`/`ID_LIKE` 词元映射为家族（大小写不敏感）。
    fn from_token(token: &str) -> Option<Family> {
        match token.trim().to_ascii_lowercase().as_str() {
            // DESIGN.md §4.1 映射表
            "ubuntu" | "debian" | "linuxmint" | "pop" | "elementary" | "kali" | "raspbian" => {
                Some(Family::Debian)
            }
            "rhel" | "centos" | "fedora" | "rocky" | "alma" | "ol" | "amzn" => Some(Family::Rhel),
            "arch" | "manjaro" | "endeavouros" | "artix" | "garuda" => Some(Family::Arch),
            _ => None,
        }
    }
}

/// Detected distribution info: key `os-release` fields plus the resolved family.
/// 已探测的发行版信息（os-release 的关键字段 + 归类结果）。
#[derive(Debug, Clone)]
pub struct DistroInfo {
    /// `ID` field, e.g. `"ubuntu"` / 发行版标识
    pub id: String,
    /// `ID_LIKE` tokens, e.g. `["debian"]`; fallback when `ID` is unknown / 未识别时的回退依据
    ///
    /// 冻结契约字段（DESIGN.md §5.2）：`detect()` 依赖它回退匹配，CLI/GUI 暂不直接展示。
    #[allow(dead_code)]
    pub id_like: Vec<String>,
    /// `VERSION_ID`, e.g. `"24.04"` / 版本号
    pub version_id: String,
    /// `PRETTY_NAME`, e.g. `"Ubuntu 24.04.1 LTS"` / 展示用全名
    pub pretty_name: String,
    /// Resolved family: exact `ID` → `ID_LIKE` → [`Family::Unknown`] / 归类结果
    pub family: Family,
}

impl DistroInfo {
    /// Detect the running distribution from `os-release`.
    ///
    /// 读 `/etc/os-release`，按规范在它缺失时回退到 `/usr/lib/os-release`；
    /// 两个文件都不可读时返回 [`Family::Unknown`] 的空信息（不 panic、不报错，
    /// 由调用方通过 [`DistroInfo::family`] 决定降级行为）。
    pub fn detect() -> Self {
        for path in ["/etc/os-release", "/usr/lib/os-release"] {
            if let Ok(content) = fs::read_to_string(path) {
                return parse_os_release(&content);
            }
        }
        DistroInfo {
            id: String::new(),
            id_like: Vec::new(),
            version_id: String::new(),
            pretty_name: String::new(),
            family: Family::Unknown,
        }
    }

    /// Human-readable family label used by the UI (`"Debian 系"` / `"RHEL 系"` / …).
    ///
    /// 中文标签，直接显示在 GUI 的系统信息行与 `--scan` 输出中。
    pub fn family_label(&self) -> &'static str {
        match self.family {
            Family::Debian => "Debian 系",
            Family::Rhel => "RHEL 系",
            Family::Arch => "Arch 系",
            Family::Unknown => "未知发行版",
        }
    }
}

impl fmt::Display for DistroInfo {
    /// One-line summary for the UI `system-info` row.
    ///
    /// 优先用 `PRETTY_NAME`（其自身通常已含版本号，如 `Linux Mint 22.3`）；
    /// 缺失时回退 `ID + VERSION_ID`。形如 `Linux Mint 22.3 (Debian 系)`。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.pretty_name.is_empty() {
            return write!(f, "{} ({})", self.pretty_name, self.family_label());
        }
        let id = if self.id.is_empty() {
            "未知系统"
        } else {
            self.id.as_str()
        };
        if self.version_id.is_empty() {
            write!(f, "{} ({})", id, self.family_label())
        } else {
            write!(f, "{} {} ({})", id, self.version_id, self.family_label())
        }
    }
}

/// Parse `os-release` text into [`DistroInfo`] (pure function, unit-test friendly).
///
/// 支持 `KEY=value`、双引号（含 `\"` `\\` `` \` `` `\$` 转义）、单引号、空行与 `#` 注释；
/// 值内部的 `=` 原样保留。探测顺序：`ID` → `ID_LIKE` 逐项 → `Unknown`。
pub fn parse_os_release(content: &str) -> DistroInfo {
    let mut kv: HashMap<String, String> = HashMap::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        // os-release 的键必须是 [A-Za-z0-9_]+，否则视为脏数据丢弃
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        kv.insert(key.to_string(), unquote_value(val.trim()));
    }

    let id = kv.get("ID").cloned().unwrap_or_default();
    let id_like: Vec<String> = kv
        .get("ID_LIKE")
        .map(|s| s.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();

    let family = Family::from_token(&id)
        .or_else(|| id_like.iter().find_map(|t| Family::from_token(t)))
        .unwrap_or(Family::Unknown);

    DistroInfo {
        id,
        id_like,
        version_id: kv.get("VERSION_ID").cloned().unwrap_or_default(),
        pretty_name: kv.get("PRETTY_NAME").cloned().unwrap_or_default(),
        family,
    }
}

/// 去掉 os-release 值的外层引号并还原双引号内的转义。
/// Strip the outer quotes of an os-release value and unescape `\\`/`\"`/`` \` ``/`\$`.
fn unquote_value(v: &str) -> String {
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        let inner = &v[1..v.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c == '\\' {
                match chars.next() {
                    Some(e @ ('"' | '\\' | '`' | '$')) => out.push(e),
                    // 其余反斜杠序列按字面保留（os-release 不允许自定义转义）
                    Some(e) => {
                        out.push('\\');
                        out.push(e);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(c);
            }
        }
        out
    } else if v.len() >= 2 && v.starts_with('\'') && v.ends_with('\'') {
        v[1..v.len() - 1].to_string()
    } else {
        v.to_string()
    }
}

/// Current kernel release string, `"unknown"` on any failure.
///
/// 读 `/proc/sys/kernel/osrelease`（如 `6.8.0-45-generic`）；procfs 不可读时回退 `"unknown"`。
pub fn kernel_release() -> String {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Architecture of the running process, e.g. `"x86_64"`.
///
/// 取自 `std::env::consts::ARCH`，与 `uname -m` 的常见取值一致（`x86_64` / `aarch64`）。
pub fn arch() -> &'static str {
    env::consts::ARCH
}

/// Whether the current process has an effective UID of 0.
///
/// 解析 `/proc/self/status` 的 `Uid:` 行，第 2 个字段为 effective uid；
/// procfs 不可读时保守返回 `false`。
pub fn is_root() -> bool {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return false,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            let mut fields = rest.split_whitespace();
            let _real = fields.next();
            return fields.next() == Some("0");
        }
    }
    false
}

/// Existing module roots: `/lib/modules` + `/usr/lib/modules`, deduplicated.
///
/// 只返回实际存在的目录；usr-merge 系统（`/lib → /usr/lib`）下二者规范化路径相同，
/// 只保留先出现的 `/lib/modules`，避免重复扫描同一棵树。
pub fn module_roots() -> Vec<PathBuf> {
    module_roots_from(&[
        PathBuf::from("/lib/modules"),
        PathBuf::from("/usr/lib/modules"),
    ])
}

/// [`module_roots`] 的可测试实现：过滤不存在项并按规范化路径去重。
/// Testable core of [`module_roots`]: drop missing paths, dedupe by canonical path.
fn module_roots_from(candidates: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen: Vec<PathBuf> = Vec::new();
    for cand in candidates {
        match fs::metadata(cand) {
            Ok(m) if m.is_dir() => {}
            // 不存在 / 不可读 / 不是目录 → 静默跳过（调用方按空结果给 warning）
            _ => continue,
        }
        // 规范化路径用于去重：符号链接等价的候选只保留第一个字面路径
        let key = fs::canonicalize(cand).unwrap_or_else(|_| cand.clone());
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        out.push(cand.clone());
    }
    out
}

/// A system command described without executing it: `program` + `args`.
///
/// 由 `restore.rs`/`privilege.rs` 转成 `std::process::Command` 执行；
/// helper 模式下可直接拼成一行协议日志。
#[derive(Debug, Clone)]
pub struct SystemCmd {
    /// Executable name resolved via `PATH` / 可执行文件名
    pub program: String,
    /// Full argument list, excluding `argv[0]` / 参数列表（不含 argv[0]）
    pub args: Vec<String>,
}

/// `depmod -a <kver>` — 还原后刷新 `modules.dep`/`modules.alias`，缺它模块不会被识别。
/// Build `depmod -a <kver>`; without it restored modules are invisible to the kernel.
pub fn depmod_cmd(kver: &str) -> SystemCmd {
    SystemCmd {
        program: "depmod".to_string(),
        args: vec!["-a".to_string(), kver.to_string()],
    }
}

/// Family-specific initramfs update command, `None` for [`Family::Unknown`].
///
/// Debian → `update-initramfs -u -k <kver>`；RHEL → `dracut --force --kver <kver>`；
/// Arch → `mkinitcpio -P`（全量重建，不接收 kver）；未知发行版返回 `None` 表示"跳过"，
/// 调用方须如实上报 `initramfs_done = None` 而非谎报成功。
pub fn initramfs_cmd(family: Family, kver: &str) -> Option<SystemCmd> {
    let cmd = match family {
        Family::Debian => SystemCmd {
            program: "update-initramfs".to_string(),
            args: vec!["-u".to_string(), "-k".to_string(), kver.to_string()],
        },
        Family::Rhel => SystemCmd {
            program: "dracut".to_string(),
            args: vec!["--force".to_string(), "--kver".to_string(), kver.to_string()],
        },
        Family::Arch => SystemCmd {
            program: "mkinitcpio".to_string(),
            args: vec!["-P".to_string()],
        },
        Family::Unknown => return None,
    };
    Some(cmd)
}

/// Look a program up in `PATH`; `true` when an executable file is found.
///
/// 含 `/` 的名字按路径直接检查；否则逐个 PATH 目录检查
/// （任意可执行位 `0o111` 置位即认为可执行，跟随符号链接）。
pub fn has_cmd(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if name.contains('/') {
        return is_executable(Path::new(name));
    }
    let dirs: Vec<PathBuf> = match env::var_os("PATH") {
        Some(val) => env::split_paths(&val).collect(),
        // PATH 缺失时退化为 FHS 默认目录，行为与常见 shell 一致
        None => [
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
        .iter()
        .map(PathBuf::from)
        .collect(),
    };
    dirs.iter().any(|dir| is_executable(&dir.join(name)))
}

/// 是否为（跟随符号链接后的）可执行普通文件 / Executable regular file (symlinks followed).
fn is_executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let p = env::temp_dir().join(format!("ldb-distro-{}-{}", tag, std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).expect("create temp dir");
        p
    }

    #[test]
    fn parses_double_quoted_values() {
        let content = "\
NAME=\"Ubuntu\"
VERSION=\"24.04.1 LTS (Noble Numbat)\"
ID=ubuntu
VERSION_ID=\"24.04\"
PRETTY_NAME=\"Ubuntu 24.04.1 LTS\"
ANSI_COLOR=\"0;32\"
BUG_REPORTS=\"https://bugs.launchpad.net/ubuntu?a=b\"
HOME_URL=\"https://www.ubuntu.com/\"
";
        let d = parse_os_release(content);
        assert_eq!(d.id, "ubuntu");
        assert_eq!(d.version_id, "24.04");
        assert_eq!(d.pretty_name, "Ubuntu 24.04.1 LTS");
        assert_eq!(d.family, Family::Debian);
        // 值内部的 `=` 原样保留（只按第一个 `=` 分割）
        assert_eq!(unquote_value("\"a=b\""), "a=b");
    }

    #[test]
    fn unquotes_escaped_double_and_single_quotes() {
        // 单引号：内容按字面保留，不做转义
        let d = parse_os_release("ID=\"ubuntu\"\nPRETTY_NAME='Ubuntu 24.04 \"LTS\"'\n");
        assert_eq!(d.pretty_name, "Ubuntu 24.04 \"LTS\"");
        assert_eq!(d.family, Family::Debian);

        // 双引号：\\ → \，\" → "，\$ → $；未知转义（\t）保留字面反斜杠
        assert_eq!(unquote_value("\"p\\\\q\\\"r\\$s\\t\""), "p\\q\"r$s\\t");
        assert_eq!(unquote_value("'lit\\eral'"), "lit\\eral");
        assert_eq!(unquote_value("plain"), "plain");
        assert_eq!(unquote_value("\""), "\"", "残缺引号按字面保留");
    }

    #[test]
    fn ignores_comments_blank_lines_and_bad_keys() {
        let d = parse_os_release(
            "# comment\n\n   \nID=debian\nnot-a-kv-line\n=oops\nBAD KEY=1\nVERSION_ID='12'\n",
        );
        assert_eq!(d.id, "debian");
        assert_eq!(d.family, Family::Debian);
        assert_eq!(d.version_id, "12", "单引号值应被剥掉");
    }

    #[test]
    fn id_like_falls_back_when_id_unknown() {
        let d = parse_os_release("ID=myedge\nID_LIKE=\"rhel fedora\"\nVERSION_ID=\"9\"\n");
        assert_eq!(d.id, "myedge");
        assert_eq!(d.id_like, vec!["rhel".to_string(), "fedora".to_string()]);
        assert_eq!(d.family, Family::Rhel, "ID 未命中应按 ID_LIKE 逐项回退");

        // ID_LIKE 单引号 + 大小写不敏感
        let d2 = parse_os_release("ID=MyDistro\nID_LIKE='Arch'\n");
        assert_eq!(d2.family, Family::Arch);
    }

    #[test]
    fn unknown_when_neither_id_nor_id_like_match() {
        let d = parse_os_release("ID=plan9\nID_LIKE=\"weirdos\"\nPRETTY_NAME=\"Plan 9\"\n");
        assert_eq!(d.family, Family::Unknown);
        assert_eq!(d.pretty_name, "Plan 9", "未知发行版仍保留 pretty_name 供展示");
        // 完全没有 ID 字段也是 Unknown
        assert_eq!(parse_os_release("").family, Family::Unknown);
    }

    #[test]
    fn mapping_table_matches_design_4_1() {
        for id in [
            "ubuntu", "debian", "linuxmint", "pop", "elementary", "kali", "raspbian",
        ] {
            assert_eq!(Family::from_token(id), Some(Family::Debian), "{id}");
        }
        for id in ["rhel", "centos", "fedora", "rocky", "alma", "ol", "amzn"] {
            assert_eq!(Family::from_token(id), Some(Family::Rhel), "{id}");
        }
        for id in ["arch", "manjaro", "endeavouros", "artix", "garuda"] {
            assert_eq!(Family::from_token(id), Some(Family::Arch), "{id}");
        }
        assert_eq!(Family::from_token("suse"), None);
        assert_eq!(Family::from_token("UBUNTU"), Some(Family::Debian), "大小写不敏感");
    }

    #[test]
    fn family_label_and_display_are_human_readable() {
        let mut d = parse_os_release("ID=linuxmint\nVERSION_ID=\"22.3\"\nPRETTY_NAME=\"Linux Mint 22.3\"\n");
        assert_eq!(d.family_label(), "Debian 系");
        // pretty_name 已含版本号 → 不再重复拼接
        assert_eq!(format!("{d}"), "Linux Mint 22.3 (Debian 系)");

        // 缺 pretty_name → 回退 ID + VERSION_ID
        d.pretty_name.clear();
        assert_eq!(format!("{d}"), "linuxmint 22.3 (Debian 系)");

        // 全缺 → 未知系统占位
        d.family = Family::Unknown;
        d.version_id.clear();
        d.id.clear();
        assert_eq!(d.family_label(), "未知发行版");
        assert_eq!(format!("{d}"), "未知系统 (未知发行版)");
    }

    #[test]
    fn system_command_builders_match_design_4_1() {
        let depmod = depmod_cmd("6.8.0-45-generic");
        assert_eq!(depmod.program, "depmod");
        assert_eq!(depmod.args, vec!["-a", "6.8.0-45-generic"]);

        let deb = initramfs_cmd(Family::Debian, "6.8.0-45-generic").expect("debian");
        assert_eq!(deb.program, "update-initramfs");
        assert_eq!(deb.args, vec!["-u", "-k", "6.8.0-45-generic"]);

        let rhel = initramfs_cmd(Family::Rhel, "6.8.0").expect("rhel");
        assert_eq!(rhel.program, "dracut");
        assert_eq!(rhel.args, vec!["--force", "--kver", "6.8.0"]);

        let arch = initramfs_cmd(Family::Arch, "6.8.0").expect("arch");
        assert_eq!(arch.program, "mkinitcpio");
        assert_eq!(arch.args, vec!["-P"]);

        assert!(initramfs_cmd(Family::Unknown, "6.8.0").is_none());
    }

    #[test]
    fn has_cmd_finds_real_programs_only() {
        assert!(has_cmd("sh"), "/bin/sh 在任何 Linux 上都应存在");
        assert!(!has_cmd("definitely-not-a-real-program-xyz"));
        assert!(!has_cmd(""));
        // 含 '/' 时按路径直查
        assert!(has_cmd("/bin/sh") || has_cmd("/usr/bin/sh"));
        assert!(!has_cmd("/definitely/missing/bin"));
    }

    #[test]
    fn module_roots_dedupes_symlinks_and_drops_missing() {
        let base = temp_dir("roots");
        let real = base.join("lib").join("modules");
        fs::create_dir_all(&real).unwrap();
        let link = base.join("alias"); // 符号链接 → 真实目录（模拟 usr-merge）
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let other = base.join("usr").join("modules");
        fs::create_dir_all(&other).unwrap();
        let missing = base.join("nope");

        let roots = module_roots_from(&[real.clone(), link, other.clone(), missing.clone()]);
        assert_eq!(roots, vec![real, other], "符号链接等价项去重，缺失项丢弃");

        // 一个都不存在 → 空结果（调用方据此给 warning）
        assert!(module_roots_from(std::slice::from_ref(&missing)).is_empty());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn kernel_release_is_never_empty() {
        assert!(!kernel_release().is_empty());
        assert!(!arch().is_empty());
    }
}
