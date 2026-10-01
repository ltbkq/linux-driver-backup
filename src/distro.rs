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
use std::sync::{Mutex, OnceLock};

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
    /// Detect the distribution of the running (host) system from `os-release`.
    ///
    /// 读 `/etc/os-release`，按规范在它缺失时回退到 `/usr/lib/os-release`；
    /// 两个文件都不可读时返回 [`Family::Unknown`] 的空信息（不 panic、不报错，
    /// 由调用方通过 [`DistroInfo::family`] 决定降级行为）。
    ///
    /// 语义等价于 [`DistroInfo::detect_at`]`(Path::new("/"))`（W0→W4 起为薄包装）。
    pub fn detect() -> Self {
        Self::detect_at(Path::new("/"))
    }

    /// Detect the distribution described by an (offline) target root — `os-release` under `root`.
    ///
    /// 读 `<root>/etc/os-release`，缺失回退 `<root>/usr/lib/os-release`；目标根下两者
    /// 都不可读时**回退宿主** `/etc/os-release`（Live USB 救援场景仍能给出可用信息，
    /// 与 [`DistroInfo::detect`] 的语义衔接）；全部失败返回 [`Family::Unknown`] 空信息。
    /// `root = "/"` 时与 [`DistroInfo::detect`] 完全一致（C-20：`--root` 模式只读目标根）。
    pub fn detect_at(root: &Path) -> Self {
        for rel in ["etc/os-release", "usr/lib/os-release"] {
            if let Ok(content) = fs::read_to_string(root.join(rel)) {
                return parse_os_release(&content);
            }
        }
        if root != Path::new("/") {
            for path in ["/etc/os-release", "/usr/lib/os-release"] {
                if let Ok(content) = fs::read_to_string(path) {
                    return parse_os_release(&content);
                }
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
///
/// 语义等价于 [`module_roots_at`]`(Path::new("/"))`（W4/C-20 起为薄包装）。
pub fn module_roots() -> Vec<PathBuf> {
    module_roots_at(Path::new("/"))
}

/// Module roots of an (offline) target root — `<root>/lib/modules` +
/// `<root>/usr/lib/modules`, deduplicated by canonical path.
///
/// `--root` 离线模式的目标根模块目录（W4/C-20）：读 **目标根** 而非宿主；
/// `root = "/"` 时与 [`module_roots`] 完全一致。缺失项静默丢弃。
pub fn module_roots_at(root: &Path) -> Vec<PathBuf> {
    module_roots_from(&[root.join("lib/modules"), root.join("usr/lib/modules")])
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

/// Family-specific initramfs update command; `None` when no known tool applies.
///
/// 发行版 initramfs 更新命令矩阵（DESIGN.md §4.1 + v0.3.0 W4 / ROADMAP P1-2 / D11）：
///
/// - **Debian** → `update-initramfs -u -k <kver>`；
/// - **RHEL** → `dracut --force --kver <kver>`；
/// - **Arch** → `mkinitcpio -P`（全量重建，不接收 kver）；
/// - **[`Family::Unknown`]（SUSE / Alpine / Void / Gentoo 等未归入三族的发行版）按
///   可用命令探测**：
///   - `mkinitfs` → **Alpine**：`mkinitfs <kver>`（工具名是 `mkinitfs`，**不是**
///     `mkinitramfs` —— 后者是 Debian initramfs-tools 的内部脚本，见 ROADMAP 核验 #23）；
///   - `dracut` → **Void / Gentoo / SUSE**：`dracut --force --kver <kver>`（SUSE 的
///     `mkinitrd` 只是 dracut 的包装，两者并存时优先直接 dracut —— 参数确定无疑；
///     **命令矩阵待 P-2（opensuse/tumbleweed、alpine 容器）验证**）；
///   - `mkinitrd` → 只装了 SUSE 旧式 `mkinitrd` 的系统：`mkinitrd -k <kver>`
///     （参数格式 **待 P-2 验证**）；
///   - 以上皆无（**Slackware** 等无统一标准的发行版，只有
///     `mkinitrd_command_generator.sh` 之类站点脚本）→ 返回 `None`：**调用方已有
///     逻辑**（`restore.rs` 的 `initramfs_cmd` `None` 分支）会把
///     `initramfs_done = None` 并提示"跳过 initramfs"，不谎报成功。
/// - UKI（统一内核镜像）系统的 `ukify build` 路线是**独立的保守实现**
///   （[`uki_detected_at`] + [`ukify_build_cmd_at`]，未接线进本函数）——无法确定
///   目标是否 UKI 系统时保持现有行为不变，**待 P-2 容器验证**后再决定是否接线。
pub fn initramfs_cmd(family: Family, kver: &str) -> Option<SystemCmd> {
    initramfs_cmd_with(family, kver, has_cmd)
}

/// [`initramfs_cmd`] 的可测试核心：命令可用性由 `has` 注入（逐 family 单测用）。
/// Testable core of [`initramfs_cmd`] with injectable command availability.
fn initramfs_cmd_with<F>(family: Family, kver: &str, has: F) -> Option<SystemCmd>
where
    F: Fn(&str) -> bool,
{
    let dracut = || SystemCmd {
        program: "dracut".to_string(),
        args: vec!["--force".to_string(), "--kver".to_string(), kver.to_string()],
    };
    let cmd = match family {
        Family::Debian => SystemCmd {
            program: "update-initramfs".to_string(),
            args: vec!["-u".to_string(), "-k".to_string(), kver.to_string()],
        },
        Family::Rhel => dracut(),
        Family::Arch => SystemCmd {
            program: "mkinitcpio".to_string(),
            args: vec!["-P".to_string()],
        },
        Family::Unknown => {
            if has("mkinitfs") {
                SystemCmd {
                    program: "mkinitfs".to_string(),
                    args: vec![kver.to_string()],
                }
            } else if has("dracut") {
                dracut()
            } else if has("mkinitrd") {
                SystemCmd {
                    program: "mkinitrd".to_string(),
                    args: vec!["-k".to_string(), kver.to_string()],
                }
            } else {
                // Slackware 等：无统一标准工具 → None（调用方已有提示逻辑，见文档）。
                return None;
            }
        }
    };
    Some(cmd)
}

/// Detect a UKI (Unified Kernel Image) based installation under `root` (W4/P1-2, 保守实现).
///
/// 检测 `<root>/boot/efi/EFI/` 下的 UKI 特征：任一子目录中的 `systemd-boot*.efi`
/// 引导器，或 `<root>/boot/efi/EFI/Linux/*.efi` 机器 UKI 的标准落位。
///
/// **未接线**：本函数只做检测与命令构造，不改变 [`initramfs_cmd`] 的现有行为 ——
/// 无法确定目标是否为 UKI 系统时宁可维持现状（ROADMAP P1-2 要求 UKI 系统改走
/// `ukify build` 并重签，接线前需 P-2/QEMU 场景验证）。**待 P-2 容器验证**。
#[allow(dead_code)] // W4 预留 API：restore 侧 UKI 接线前暂未调用 / reserved until wired (P-2)
pub fn uki_detected_at(root: &Path) -> bool {
    let efi_dir = root.join("boot/efi/EFI");
    let Ok(rd) = fs::read_dir(&efi_dir) else {
        return false;
    };
    for entry in rd.filter_map(|e| e.ok()) {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let lower = name.to_ascii_lowercase();
        // EFI/Linux/*.efi：机器 UKI 的标准落位
        if path.is_dir() && lower == "linux" {
            if dir_has_efi_image(&path) {
                return true;
            }
            continue;
        }
        // EFI/<loader>/systemd-boot*.efi：systemd-boot 引导器特征
        if lower.starts_with("systemd-boot") && lower.ends_with(".efi") {
            return true;
        }
    }
    false
}

/// 目录下是否存在 `.efi` 镜像（UKI 检测的辅助判断）。
/// Whether a directory contains any `.efi` image (helper for UKI detection).
fn dir_has_efi_image(dir: &Path) -> bool {
    fs::read_dir(dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok()).any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .to_ascii_lowercase()
                    .ends_with(".efi")
            })
        })
        .unwrap_or(false)
}

/// Provisional `ukify build` command for `<kver>` (W4/P1-2; 参数为草案，待 P-2 验证).
///
/// 需要 PATH 上有 `ukify`；`--linux`/`--initrd` 在 `<root>` 下按常见路径探测（Debian
/// 的 `/boot/initrd.img-<kver>`、RHEL 的 `/boot/initramfs-<kver>.img` …），探测不到
/// 时省略对应参数（由 `ukify` 自行报错）。**未接线，待 P-2 容器验证。**
#[allow(dead_code)] // W4 预留 API：restore 侧 UKI 接线前暂未调用 / reserved until wired (P-2)
pub fn ukify_build_cmd_at(root: &Path, kver: &str) -> Option<SystemCmd> {
    ukify_build_cmd_inner(root, kver, has_cmd)
}

/// [`ukify_build_cmd_at`] 的可测试核心：`ukify` 可用性由 `has` 注入。
/// Testable core of [`ukify_build_cmd_at`] with injectable `ukify` availability.
fn ukify_build_cmd_inner<F>(root: &Path, kver: &str, has: F) -> Option<SystemCmd>
where
    F: Fn(&str) -> bool,
{
    if !has("ukify") {
        return None;
    }
    let linux_candidates = [format!("boot/vmlinuz-{kver}"), "boot/vmlinuz".to_string()];
    let initrd_candidates = [
        format!("boot/initrd.img-{kver}"),       // Debian / Ubuntu
        format!("boot/initramfs-{kver}.img"),    // RHEL / Fedora
        format!("boot/initramfs-{kver}"),        // Gentoo
        format!("boot/initramfs.img-{kver}"),    // 部分旧 RHEL
    ];
    let mut args: Vec<String> = vec!["build".to_string()];
    if let Some(linux) = linux_candidates.iter().map(|p| root.join(p)).find(|p| p.is_file()) {
        args.push("--linux".to_string());
        args.push(linux.display().to_string());
    }
    if let Some(initrd) = initrd_candidates
        .iter()
        .map(|p| root.join(p))
        .find(|p| p.is_file())
    {
        args.push("--initrd".to_string());
        args.push(initrd.display().to_string());
    }
    args.push("--uname".to_string());
    args.push(kver.to_string());
    Some(SystemCmd {
        program: "ukify".to_string(),
        args,
    })
}

/// `has_cmd` 的进程级结果缓存（C-43 ②）：PATH 扫描是纯读操作，同一进程内
/// PATH 不会变化，重复扫描纯属浪费（restore 侧逐条 `has_cmd(&cmd.program)` 尤甚）。
/// Process-wide cache of `has_cmd` results (C-43): PATH lookups are pure reads and the
/// environment does not change mid-process, so results are memoised.
///
/// 键为 `String` 而非 `&'static str`：调用方会传动态串（如 `has_cmd(&cmd.program)`）。
/// 测试若改动 PATH，须在改动前后调用 [`reset_has_cmd_cache`]（仅测试构建可用）。
static HAS_CMD_CACHE: OnceLock<Mutex<HashMap<String, bool>>> = OnceLock::new();

/// Look a program up in `PATH`; `true` when an executable file is found.
///
/// 含 `/` 的名字按路径直接检查；否则逐个 PATH 目录检查
/// （任意可执行位 `0o111` 置位即认为可执行，跟随符号链接）。
/// 结果经 [`HAS_CMD_CACHE`] 进程级缓存（C-43 ②）。
pub fn has_cmd(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if let Some(cache) = HAS_CMD_CACHE.get() {
        // 缓存锁中毒（持锁线程 panic）不影响判定，只是退回一次性查询。
        if let Ok(guard) = cache.lock() {
            if let Some(cached) = guard.get(name) {
                return *cached;
            }
        }
    }
    let found = has_cmd_uncached(name);
    if let Some(cache) = HAS_CMD_CACHE.get() {
        if let Ok(mut guard) = cache.lock() {
            guard.insert(name.to_string(), found);
        }
    }
    found
}

/// [`has_cmd`] 的未缓存实现（先做缓存查找失败后的实际 PATH 查询）。
/// Uncached PATH lookup behind [`has_cmd`].
fn has_cmd_uncached(name: &str) -> bool {
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

/// 清空 `has_cmd` 的进程级缓存（**仅测试**：有测试改动 PATH 时在改动前后调用）。
/// Drop the `has_cmd` cache — test-only, for tests that mutate `PATH`.
#[cfg(test)]
pub fn reset_has_cmd_cache() {
    if let Some(cache) = HAS_CMD_CACHE.get() {
        if let Ok(mut guard) = cache.lock() {
            guard.clear();
        }
    }
}

/// 是否为（跟随符号链接后的）可执行普通文件 / Executable regular file (symlinks followed).
fn is_executable(path: &Path) -> bool {
    match fs::metadata(path) {
        Ok(m) => m.is_file() && m.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

// ===========================================================================
// v0.2.0 新增：不可变系统 / Secure Boot / 重建命令（设计文档 P0-2…P0-4）
// v0.2.0 additions: immutable OS, Secure Boot, rebuild commands (ROADMAP P0-2…P0-4)
// ===========================================================================

/// 目标系统的可变性模型（决定能否直接写入 `/lib/modules`）。
/// How mutable the target system is — decides whether `/lib/modules` may be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Immutability {
    /// 常规可变系统，直接写入。
    Mutable,
    /// OSTree / rpm-ostree 系（Silverblue、Bazzite、MicroOS…）：`/usr` 只读。
    Ostree,
    /// NixOS：`/run/current-system` 管理，本工具不支持直接还原。
    Nix,
    /// `/usr` 以只读方式挂载（但非 OSTree）。
    ReadOnlyUsr,
}

impl Immutability {
    /// 稳定的机器可读标识（写入 manifest）。
    /// Stable machine-readable tag written into the manifest.
    pub fn tag(&self) -> &'static str {
        match self {
            Immutability::Mutable => "mutable",
            Immutability::Ostree => "ostree",
            Immutability::Nix => "nix",
            Immutability::ReadOnlyUsr => "read-only-usr",
        }
    }

    /// 中文说明，供 GUI/CLI 展示。
    /// Chinese description for the GUI/CLI.
    pub fn label_zh(&self) -> &'static str {
        match self {
            Immutability::Mutable => "常规可变系统",
            Immutability::Ostree => "OSTree 不可变系统（/usr 只读）",
            Immutability::Nix => "NixOS（声明式，不支持直接还原）",
            Immutability::ReadOnlyUsr => "/usr 只读挂载",
        }
    }
}

/// 探测目标系统是否不可变：先看 OSTree/Nix 标志文件，再看 `/usr` 挂载选项。
/// Detect immutability: OSTree/Nix markers first, then the `/usr` mount options.
///
/// 语义等价于 [`immutability_at`]`(Path::new("/"))`（W4/C-20 起为薄包装）。
pub fn immutability() -> Immutability {
    immutability_at(Path::new("/"))
}

/// Detect immutability of an (offline) target root (W4/C-20).
///
/// `--root` 离线模式只读 **目标根** 下的标志文件：`<root>/run/ostree-booted`、
/// `<root>/run/current-system`；`/usr` 挂载选项只对真实根 `/` 有意义，故
/// `root != "/"` 时不做只读挂载判定（离线目录通常只是普通挂载点）。
/// `root = "/"` 时与 [`immutability`] 完全一致。
pub fn immutability_at(root: &Path) -> Immutability {
    if root.join("run/ostree-booted").exists() {
        return Immutability::Ostree;
    }
    if root.join("run/current-system").exists() {
        return Immutability::Nix;
    }
    // 只读 `/usr` 的挂载语义只对真实根成立（离线目录自身的挂载选项无意义）。
    if root == Path::new("/") && usr_is_read_only() {
        return Immutability::ReadOnlyUsr;
    }
    Immutability::Mutable
}

/// `/proc/mounts` 中承载 `/usr` 的条目是否带 `ro` 选项。
/// Whether the mount entry backing `/usr` carries the `ro` option.
fn usr_is_read_only() -> bool {
    let Ok(content) = fs::read_to_string("/proc/mounts") else {
        return false;
    };
    // 选择挂载点最长的匹配项（`/usr` 可能被单独挂载），并做八进制转义还原。
    let mut best: Option<(usize, bool)> = None;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let _dev = fields.next();
        let Some(mount_point) = fields.next() else { continue };
        let _fstype = fields.next();
        let Some(options) = fields.next() else { continue };
        let mount_point = mount_point.replace("\\040", " ");
        let is_usr = mount_point == "/usr" || mount_point == "/";
        if !is_usr {
            continue;
        }
        let ro = options.split(',').any(|o| o == "ro");
        if best.is_none_or(|(len, _)| mount_point.len() > len) {
            best = Some((mount_point.len(), ro));
        }
    }
    best.is_some_and(|(_, ro)| ro)
}

/// Secure Boot 与模块签名强制状态。
/// Secure Boot state plus whether the kernel enforces module signatures.
#[derive(Debug, Clone, Default)]
pub struct SecureBootState {
    /// 固件 Secure Boot 是否开启（`mokutil --sb-state`）。
    pub enabled: bool,
    /// 内核是否强制要求签名（`CONFIG_MODULE_SIG_FORCE` / `module.sig_enforce=1`）。
    pub sig_enforce: bool,
}

impl SecureBootState {
    /// 转为可写入 manifest 的紧凑结构。
    /// Convert into the compact structure stored in the manifest.
    pub fn to_info(&self) -> crate::model::SecureBootInfo {
        crate::model::SecureBootInfo {
            enabled: self.enabled,
            sig_enforce: self.sig_enforce,
        }
    }
}

/// 探测 Secure Boot 与签名强制状态；任何一步失败都退化为"未开启/未强制"。
/// Probe Secure Boot and signature enforcement; failures degrade to "off".
///
/// 语义等价于 [`secure_boot_state_at`]`(Path::new("/"))`（W4/C-20 起为薄包装）。
pub fn secure_boot_state() -> SecureBootState {
    secure_boot_state_at(Path::new("/"))
}

/// Probe Secure Boot / signature enforcement of an (offline) target root (W4/C-20).
///
/// `--root` 离线模式**不读宿主**的 Secure Boot：改为读 `<root>/sys/firmware/efi/efivars`
/// 下的 `SecureBoot-*` 变量；读不到则保守返回"关闭"（调用方应优先采用 manifest 中
/// 备份机记录的 `secure_boot`）。`root = "/"` 时与 [`secure_boot_state`] 完全一致。
pub fn secure_boot_state_at(root: &Path) -> SecureBootState {
    SecureBootState {
        enabled: secure_boot_enabled_at(root),
        sig_enforce: module_sig_enforced_at(root),
    }
}

/// 通过 `mokutil --sb-state` 判断 Secure Boot；无 EFI 变量时直接判定为关闭。
///
/// `root = "/"` 保持既有宿主行为不变；`--root` 离线时改读目标根下的 efivars
/// （不运行宿主 `mokutil`，否则会误报宿主的 Secure Boot 状态）。
fn secure_boot_enabled_at(root: &Path) -> bool {
    if root == Path::new("/") {
        return secure_boot_enabled();
    }
    read_efivar_secure_boot(root).unwrap_or(false)
}

/// Host Secure Boot probe (unchanged pre-W4 behaviour).
/// 宿主 Secure Boot 探测（W4 前的既有行为，保持不变）。
fn secure_boot_enabled() -> bool {
    if !Path::new("/sys/firmware/efi").exists() {
        return false;
    }
    let Ok(output) = std::process::Command::new("mokutil")
        .arg("--sb-state")
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&output.stdout).to_ascii_lowercase();
    text.contains("secureboot enabled") || text.contains("secure boot enabled")
}

/// Read `SecureBoot-*` from `<root>/sys/firmware/efi/efivars` (last byte != 0 = on).
///
/// 直接读 efivars（无需 root，见 ITERATION §3.1-6）：变量值前 4 字节是属性，
/// 其后 1 字节为 `1`（开启）/ `0`（关闭）。变量缺失或读取失败返回 `None`。
fn read_efivar_secure_boot(root: &Path) -> Option<bool> {
    let dir = root.join("sys/firmware/efi/efivars");
    let entries = fs::read_dir(&dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("SecureBoot-") {
            continue;
        }
        let bytes = fs::read(entry.path()).ok()?;
        let value = bytes.get(4).copied()?; // 跳过 4 字节属性
        return Some(value != 0);
    }
    None
}

/// 判断内核是否强制要求模块签名：先看 `/sys/module/module/parameters/sig_enforce`，
/// 再看 `/proc/cmdline` 的 `module.sig_enforce=1`。
///
/// `root = "/"` 保持既有宿主行为不变；`--root` 离线时只读目标根下同名路径
/// （通常不存在 → 保守返回 false，由 manifest 记录兜底）。
fn module_sig_enforced_at(root: &Path) -> bool {
    if root == Path::new("/") {
        return module_sig_enforced();
    }
    if let Ok(value) = fs::read_to_string(root.join("sys/module/module/parameters/sig_enforce"))
    {
        if value.trim() == "Y" || value.trim() == "1" {
            return true;
        }
    }
    fs::read_to_string(root.join("proc/cmdline"))
        .map(|c| {
            c.split_whitespace()
                .any(|a| a == "module.sig_enforce=1" || a == "module.sig_enforce")
        })
        .unwrap_or(false)
}

/// Host signature-enforcement probe (unchanged pre-W4 behaviour).
/// 宿主签名强制探测（W4 前的既有行为，保持不变）。
fn module_sig_enforced() -> bool {
    if let Ok(value) = fs::read_to_string("/sys/module/module/parameters/sig_enforce") {
        if value.trim() == "Y" || value.trim() == "1" {
            return true;
        }
    }
    fs::read_to_string("/proc/cmdline")
        .map(|c| {
            c.split_whitespace()
                .any(|a| a == "module.sig_enforce=1" || a == "module.sig_enforce")
        })
        .unwrap_or(false)
}

/// 一对 MOK 密钥（私钥 + DER 证书），用于给还原的模块签名。
/// A MOK key pair (private key + DER certificate) used to sign restored modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MokKeyPair {
    /// 私钥路径（应当仅 root 可读）。
    pub private: PathBuf,
    /// DER 证书路径。
    pub certificate: PathBuf,
}

/// 在常见位置寻找 MOK 密钥对：Debian/Ubuntu 的 `/var/lib/shim-signed/mok/`，
/// Fedora/RHEL 的 `/etc/pki/akmods/`（`private_key.priv` + `public_key.der`）。
/// Look for MOK key pairs in the usual places (Debian's shim-signed path and Fedora's akmods).
pub fn mok_keys() -> Vec<MokKeyPair> {
    let mut found = Vec::new();

    let debian = Path::new("/var/lib/shim-signed/mok");
    let priv_key = debian.join("MOK.priv");
    let cert = debian.join("MOK.der");
    if priv_key.is_file() && cert.is_file() {
        found.push(MokKeyPair {
            private: priv_key,
            certificate: cert,
        });
    }

    let fedora = Path::new("/etc/pki/akmods");
    let fedora_priv = fedora.join("private_key.priv");
    let fedora_cert = fedora.join("public_key.der");
    if fedora_priv.is_file() && fedora_cert.is_file() {
        found.push(MokKeyPair {
            private: fedora_priv,
            certificate: fedora_cert,
        });
    }

    found
}

/// 返回可用的模块签名命令（优先 `kmodsign`，其次内核头里的 `sign-file`）。
/// Return an available module signing command (`kmodsign` first, then `sign-file`).
///
/// 返回值中的 `args_prefix` 形如 `["sha256"]`（`sign-file` 需要算法参数，
/// `kmodsign` 则不需要，调用方按需拼接 私钥/证书/模块路径）。
/// The returned `args_prefix` is `["sha256"]` for `sign-file` and empty for `kmodsign`.
pub fn sign_tool(kernel_release: &str) -> Option<(String, Vec<String>)> {
    // 两者**都要求**首个参数是哈希算法：
    //   sign-file sha256 <key> <x509> <module>        （内核源码树 scripts/sign-file）
    //   kmodsign  sha256 <key> <x509> <module>        （Debian/Ubuntu 的 sbsigntool 版）
    // 因此统一返回前缀 ["sha256"]，调用方再拼 私钥/证书/模块路径。
    // 优先 sign-file（各发行版行为一致），其次 kmodsign。
    let candidates = [
        format!("/usr/src/linux-headers-{kernel_release}/scripts/sign-file"),
        format!("/lib/modules/{kernel_release}/build/scripts/sign-file"),
        format!("/usr/src/kernels/{kernel_release}/scripts/sign-file"),
    ];
    for path in candidates {
        if is_executable(Path::new(&path)) {
            return Some((path, vec!["sha256".to_string()]));
        }
    }
    if has_cmd("sign-file") {
        return Some(("sign-file".to_string(), vec!["sha256".to_string()]));
    }
    if has_cmd("kmodsign") {
        return Some(("kmodsign".to_string(), vec!["sha256".to_string()]));
    }
    None
}

/// 取目标内核的参考 `vermagic`（借用该内核任一 in-tree 模块的元数据）。
/// Reference `vermagic` for the target kernel, borrowed from any in-tree module.
///
/// 语义等价于 [`reference_vermagic_at`]`(Path::new("/"), kernel_release)`（W4/C-20）。
pub fn reference_vermagic(kernel_release: &str) -> Option<String> {
    reference_vermagic_at(Path::new("/"), kernel_release)
}

/// Reference `vermagic` for a kernel of an (offline) target root (W4/C-20).
///
/// `--root` 离线模式只借用 **目标根** 内 `<root>/lib/modules/<kver>/kernel/**`（或
/// `usr/lib/modules`）的 in-tree 模块元数据；`root = "/"` 时与 [`reference_vermagic`]
/// 完全一致。找不到任何模块返回 `None`。
pub fn reference_vermagic_at(root: &Path, kernel_release: &str) -> Option<String> {
    for mroot in module_roots_at(root) {
        let kernel_dir = mroot.join(kernel_release).join("kernel");
        if let Some(module) = first_file_with_prefix(&kernel_dir) {
            return module_vermagic(&module);
        }
    }
    None
}

/// 在目录树中寻找第一个 `*.ko*` 文件（用于取参考 vermagic）。
/// Find the first `*.ko*` file in a directory tree (used for the reference vermagic).
fn first_file_with_prefix(dir: &Path) -> Option<PathBuf> {
    let walker = walkdir::WalkDir::new(dir).max_depth(6).follow_links(false);
    for entry in walker.into_iter().flatten() {
        let path = entry.path();
        if entry.file_type().is_file() && is_module_path(path) {
            return Some(path.to_path_buf());
        }
    }
    None
}

/// 内核模块的压缩后缀白名单（`.ko` 之外的部分由调用方拼接）。
/// Compression suffixes recognised for kernel modules (the `.ko` part is added by callers).
pub const MODULE_COMPRESSION_SUFFIXES: [&str; 7] =
    [".xz", ".zst", ".zstd", ".gz", ".bz2", ".lzo", ".lz4"];

/// 路径是否形如内核模块（`.ko` 及其压缩变体）。
/// Whether a path looks like a kernel module (`.ko` plus compressed variants).
pub fn is_module_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.ends_with(".ko")
        || MODULE_COMPRESSION_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(&format!(".ko{suffix}")))
}

/// 读取模块的 `vermagic`（调用 `modinfo`，失败返回 `None`）。
/// Read a module's `vermagic` via `modinfo`; returns `None` when unavailable.
pub fn module_vermagic(module: &Path) -> Option<String> {
    let output = std::process::Command::new("modinfo")
        .arg("-F")
        .arg("vermagic")
        .arg(module)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// DKMS 重建命令：`dkms install -m <name> -v <version> -k <kver>`。
/// DKMS rebuild command: `dkms install -m <name> -v <version> -k <kver>`.
pub fn dkms_install_cmd(name: &str, version: &str, kernel_release: &str) -> Option<SystemCmd> {
    has_cmd("dkms").then(|| SystemCmd {
        program: "dkms".to_string(),
        args: vec![
            "install".to_string(),
            // `--force`：已装过的模块也真正重建（否则 DKMS 会提示
            // "already installed … skip" 并直接返回 0，等于没重建）。
            "--force".to_string(),
            "-m".to_string(),
            name.to_string(),
            "-v".to_string(),
            version.to_string(),
            "-k".to_string(),
            kernel_release.to_string(),
        ],
    })
}

/// Fedora 系重建命令：`akmods --force --kernels <kver>`。
/// Fedora rebuild command: `akmods --force --kernels <kver>`.
pub fn akmods_cmd(kernel_release: &str) -> Option<SystemCmd> {
    has_cmd("akmods").then(|| SystemCmd {
        program: "akmods".to_string(),
        args: vec![
            "--force".to_string(),
            "--kernels".to_string(),
            kernel_release.to_string(),
        ],
    })
}

/// 重装来源包：Debian 用 `apt-get install --reinstall`，RPM 用 `dnf reinstall`。
/// Reinstall a provenance package: `apt-get install --reinstall` or `dnf reinstall`.
pub fn reinstall_cmd(manager: &str, package: &str) -> Option<SystemCmd> {
    match manager {
        "dpkg" if has_cmd("apt-get") => Some(SystemCmd {
            program: "apt-get".to_string(),
            args: vec![
                "install".to_string(),
                "--reinstall".to_string(),
                "-y".to_string(),
                package.to_string(),
            ],
        }),
        "rpm" if has_cmd("dnf") => Some(SystemCmd {
            program: "dnf".to_string(),
            args: vec![
                "reinstall".to_string(),
                "-y".to_string(),
                package.to_string(),
            ],
        }),
        "rpm" if has_cmd("yum") => Some(SystemCmd {
            program: "yum".to_string(),
            args: vec![
                "reinstall".to_string(),
                "-y".to_string(),
                package.to_string(),
            ],
        }),
        _ => None,
    }
}

/// RHEL/SUSE 的 `weak-modules --add-modules`（模块列表经 stdin 传入）。
/// RHEL/SUSE `weak-modules --add-modules`, with the module list fed on stdin.
pub fn weak_modules_cmd() -> Option<SystemCmd> {
    has_cmd("weak-modules").then(|| SystemCmd {
        program: "weak-modules".to_string(),
        args: vec!["--add-modules".to_string()],
    })
}

/// 触发 `pkexec` 时使用的策略：由调用方拼接 `pkexec <self> --helper-restore …`。
/// The elevation entry point is assembled by the caller (`pkexec <self> --helper-restore …`).
pub fn pkexec_available() -> bool {
    has_cmd("pkexec")
}

#[cfg(test)]
mod tests {

    #[test]
    fn immutability_tags_and_labels_are_stable() {
        assert_eq!(Immutability::Mutable.tag(), "mutable");
        assert_eq!(Immutability::Ostree.tag(), "ostree");
        assert_eq!(Immutability::Nix.tag(), "nix");
        assert_eq!(Immutability::ReadOnlyUsr.tag(), "read-only-usr");
        for v in [
            Immutability::Mutable,
            Immutability::Ostree,
            Immutability::Nix,
            Immutability::ReadOnlyUsr,
        ] {
            assert!(!v.label_zh().is_empty());
        }
        // 本机为常规可变系统（CI/开发机均如此）；只断言不 panic 且来自四态之一
        let detected = immutability();
        assert!(matches!(
            detected,
            Immutability::Mutable
                | Immutability::Ostree
                | Immutability::Nix
                | Immutability::ReadOnlyUsr
        ));
        // Secure Boot 探测也不得 panic（本机为关闭态）
        let sb = secure_boot_state();
        let info = sb.to_info();
        assert_eq!(info.enabled, sb.enabled);
        assert_eq!(info.sig_enforce, sb.sig_enforce);
    }

    #[test]
    fn module_path_detection_covers_compressed_variants() {
        for ok in [
            "/lib/modules/6.8/x.ko",
            "/lib/modules/6.8/x.ko.zst",
            "/lib/modules/6.8/x.ko.xz",
            "/lib/modules/6.8/x.ko.zstd",
            "/lib/modules/6.8/x.ko.gz",
            "/lib/modules/6.8/x.ko.lz4",
        ] {
            assert!(is_module_path(Path::new(ok)), "{ok} 应被识别为模块");
        }
        for bad in ["/lib/modules/6.8/README", "/etc/modprobe.d/x.conf"] {
            assert!(!is_module_path(Path::new(bad)), "{bad} 不应被识别为模块");
        }
    }

    #[test]
    fn sign_tool_prefix_is_hash_algorithm() {
        // 无论选到 sign-file 还是 kmodsign，前缀都必须是 ["sha256"]
        if let Some((program, prefix)) = sign_tool(&kernel_release()) {
            assert!(!program.is_empty());
            assert_eq!(prefix, vec!["sha256".to_string()]);
        }
        // 伪造一个不存在的内核版本时不应 panic（可能回退到 PATH 上的 sign-file）
        let _ = sign_tool("0.0.0-nonexistent-kernel");
    }

    #[test]
    fn reinstall_command_maps_package_managers() {
        // 本机为 Debian 系：dpkg 应映射到 apt-get install --reinstall
        if has_cmd("apt-get") {
            let cmd = reinstall_cmd("dpkg", "foo-dkms").expect("应能构造 apt-get 命令");
            assert_eq!(cmd.program, "apt-get");
            assert!(cmd.args.contains(&"--reinstall".to_string()));
            assert!(cmd.args.contains(&"foo-dkms".to_string()));
        }
        // 未知包管理器一律返回 None（不猜）
        assert!(reinstall_cmd("pacman", "foo").is_none());
        assert!(reinstall_cmd("", "foo").is_none());
    }

    #[test]
    fn mok_keys_are_valid_pairs_when_present() {
        for pair in mok_keys() {
            assert!(pair.private.is_file(), "私钥必须存在：{:?}", pair.private);
            assert!(pair.certificate.is_file(), "证书必须存在：{:?}", pair.certificate);
        }
    }

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

    /// C-43 ②：`has_cmd` 进程级缓存可清空且结果稳定（测试改动 PATH 前后须可重置）。
    #[test]
    fn has_cmd_cache_is_resettable() {
        reset_has_cmd_cache();
        let first = has_cmd("sh");
        reset_has_cmd_cache();
        assert_eq!(first, has_cmd("sh"), "缓存清空不改变 PATH 查询结果");
        assert!(!has_cmd("ldb-no-such-binary-xyzzy"), "不存在的命令应为 false");
    }

    // ---- W4/C-20：目标根感知探测 API ----

    /// W4/C-20：`module_roots_at` 只读 `<root>` 下的模块目录（含 usr-merge 去重）。
    #[test]
    fn module_roots_at_reads_target_root_w4() {
        let base = temp_dir("roots-at");
        fs::create_dir_all(base.join("usr/lib/modules")).unwrap();
        // usr-merge：root/lib -> root/usr/lib，两者规范化后等价 → 只保留首个
        std::os::unix::fs::symlink("usr/lib", base.join("lib")).unwrap();
        let roots = module_roots_at(&base);
        assert_eq!(roots.len(), 1, "符号链接等价项应去重：{roots:?}");
        assert!(roots[0].starts_with(&base), "必须落在目标根下：{roots:?}");

        // root="/" 时与既有 module_roots 一致
        assert_eq!(module_roots_at(Path::new("/")), module_roots());
        let _ = fs::remove_dir_all(&base);
    }

    /// W4/C-20：`reference_vermagic_at` 只借用目标根下册内核目录（缺失返回 None）。
    #[test]
    fn reference_vermagic_at_reads_target_root_w4() {
        let base = temp_dir("vermagic-at");
        // 目标根下没有内核模块 → None（且绝不回退宿主）
        assert_eq!(reference_vermagic_at(&base, "0.0.0-nonexistent"), None);
        // root="/" 时与既有行为一致（同入参结果相同）
        assert_eq!(
            reference_vermagic_at(Path::new("/"), "0.0.0-nonexistent"),
            reference_vermagic("0.0.0-nonexistent")
        );
        let _ = fs::remove_dir_all(&base);
    }

    /// W4/C-20：`immutability_at` 读目标根下的 OSTree/Nix 标志文件。
    #[test]
    fn immutability_at_reads_target_root_w4() {
        let base = temp_dir("immut-at");
        assert_eq!(immutability_at(&base), Immutability::Mutable);
        fs::create_dir_all(base.join("run")).unwrap();
        fs::write(base.join("run/ostree-booted"), b"").unwrap();
        assert_eq!(immutability_at(&base), Immutability::Ostree);
        fs::remove_file(base.join("run/ostree-booted")).unwrap();
        fs::write(base.join("run/current-system"), b"").unwrap();
        assert_eq!(immutability_at(&base), Immutability::Nix);
        // root="/" 与既有薄包装一致（本机可变）
        assert_eq!(immutability_at(Path::new("/")), immutability());
        let _ = fs::remove_dir_all(&base);
    }

    /// W4/C-20：`secure_boot_state_at` 离线时只读目标根的 efivars，不跑宿主 mokutil。
    #[test]
    fn secure_boot_state_at_reads_target_root_w4() {
        let base = temp_dir("sb-at");
        // 无 efivars → 关闭
        assert!(!secure_boot_state_at(&base).enabled);
        let efivars = base.join("sys/firmware/efi/efivars");
        fs::create_dir_all(&efivars).unwrap();
        // 属性 4 字节 + 值 1 字节（1 = 开启）
        fs::write(efivars.join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), [
            0u8, 0, 0, 0, 1,
        ])
        .unwrap();
        assert!(secure_boot_state_at(&base).enabled, "efivars 值为 1 → 开启");
        fs::write(efivars.join("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), [
            0u8, 0, 0, 0, 0,
        ])
        .unwrap();
        assert!(!secure_boot_state_at(&base).enabled, "efivars 值为 0 → 关闭");
        // root="/" 与既有薄包装一致
        let a = secure_boot_state_at(Path::new("/"));
        let b = secure_boot_state();
        assert_eq!(a.enabled, b.enabled);
        assert_eq!(a.sig_enforce, b.sig_enforce);
        let _ = fs::remove_dir_all(&base);
    }
}
