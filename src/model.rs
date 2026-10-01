//! 共享类型与错误定义 —— 全项目的依赖根。
//! Shared types and errors — the dependency root of the whole crate.
//!
//! 本文件实现 DESIGN.md **§5.1 的冻结契约（frozen contract）**：并行开发的其它单元
//! （`distro` / `scan` / `restore` / `privilege` / `main`）只能按下述签名引用本文件，
//! 任何签名偏差都会导致 W3 集成编译失败，因此只允许**增补**辅助方法，不得改动既有签名。
//! This file implements the frozen contract of DESIGN.md §5.1. Sibling modules may only
//! rely on the signatures below; additions are allowed, changes to existing signatures
//! are not.
//!
//! 文档规范见 DESIGN.md 附录 A：中文为主，公共 API 的 doc comment 首句为英文。

use std::path::PathBuf;
use std::sync::Arc;

use crate::distro::{DistroInfo, Family};

/// UI/CLI 共用的进度回调：`Arc<dyn Fn(0.0..1.0, 消息)>`。
/// Progress callback shared by the GUI and the CLI.
pub type ProgressFn = Arc<dyn Fn(f32, String) + Send + Sync>;

/// 三级备份模式（`minimal` / `standard` / `full`）。
/// Three-level backup mode, serialized in lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupMode {
    /// 最小：OOT 模块 + `/etc` 配置。
    Minimal,
    /// 标准（默认）：minimal + DKMS 源码。
    Standard,
    /// 完整：standard + `/lib/firmware`。
    Full,
}

impl BackupMode {
    /// 由 UI ComboBox / CLI 下标构造模式，非法下标回退到 `Standard`。
    /// Build a mode from a UI/CLI index; an out-of-range index falls back to `Standard`.
    pub fn from_index(i: i32) -> Self {
        match i {
            0 => BackupMode::Minimal,
            1 => BackupMode::Standard,
            2 => BackupMode::Full,
            _ => BackupMode::Standard,
        }
    }

    /// 下标表示法：`0` / `1` / `2`。
    /// Index form used by `mode-index` bindings: `0` / `1` / `2`.
    ///
    /// 冻结契约方法（DESIGN.md §5.1）：与 [`BackupMode::from_index`] 互为逆运算，
    /// 供未来「把 CLI 模式回写到 GUI」等场景使用。
    #[allow(dead_code)]
    pub fn index(&self) -> i32 {
        match self {
            BackupMode::Minimal => 0,
            BackupMode::Standard => 1,
            BackupMode::Full => 2,
        }
    }

    /// 用于 UI/CLI 展示的英文标签。
    /// Human readable English label for the UI/CLI.
    pub fn label(&self) -> &'static str {
        match self {
            BackupMode::Minimal => "Minimal",
            BackupMode::Standard => "Standard",
            BackupMode::Full => "Full",
        }
    }
}

/// 归档内单个条目的分类。
/// Classification of one archived entry, serialized in lowercase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    /// 内核模块（`.ko`，含 in-tree 之外的 updates/extra 等）。
    Module,
    /// DKMS 源码树（`/usr/src`、`/var/lib/dkms`）。
    Dkms,
    /// 配置（`/etc/modprobe.d`、`/etc/udev/rules.d`、`/etc/depmod.d` …）。
    Config,
    /// 固件 blob（`/lib/firmware`，仅 full 模式）。
    Firmware,
    /// 符号链接（v2 新增）：RHEL/SUSE 的 `weak-updates/<m>.ko -> ../../<kver>/extra/…`
    /// 依赖它才能对多个内核生效，因此必须按链接语义保存与还原。
    /// Symlink entry (new in v2) — required for RHEL/SUSE `weak-updates/` chains.
    Symlink,
}

/// 文件来源包（v2 新增）：告诉还原侧"这个文件本可由包管理器修复"。
/// Package provenance (new in v2): lets restore prefer reinstalling the package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Provenance {
    /// 包管理器：`dpkg` / `rpm`。
    pub manager: String,
    /// 包名，如 `v4l2loopback-dkms`。
    pub package: String,
    /// 包版本（查询不到时为空串）。
    #[serde(default)]
    pub version: String,
}

/// 模块的 `.modinfo` 关键元数据（v2 新增）。
/// Selected `.modinfo` metadata of a kernel module (new in v2).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ModInfo {
    /// `vermagic=`：模块与内核的 ABI 指纹，跨内核还原的核心判据。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vermagic: Option<String>,
    /// `depends=`：模块依赖（用于依赖闭包）。
    #[serde(default)]
    pub depends: Vec<String>,
    /// `firmware=`：所需固件（供 0.3.0 按需收集固件）。
    #[serde(default)]
    pub firmware: Vec<String>,
    /// `sig_id=`：签名算法摘要（`PKCS#7` 等），空表示未签名。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_id: Option<String>,
    /// `sig_key=`：签名密钥指纹。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig_key: Option<String>,
}

impl ModInfo {
    /// 是否已签名（存在 `sig_id` 即视为已签名）。
    /// Whether the module carries a signature.
    pub fn is_signed(&self) -> bool {
        self.sig_id.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// 还原策略（v2 新增）："重建优于拷贝"的具体落点。
/// Restore strategy (new in v2) — where "rebuild beats copy" lands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RestoreStrategy {
    /// 由 DKMS 源码重建（`dkms install` / `akmods`）。
    Rebuild,
    /// 由包管理器重装来源包（`apt --reinstall` / `dnf reinstall`）。
    Reinstall,
    /// 写入 `extra/` 后由 `weak-modules` 建立兼容链接（RHEL/SUSE）。
    WeakModules,
    /// 直接拷贝 `.ko`（兜底）。
    Copy,
    /// 跳过（如固件在未开启 `--with-firmware` 时）。
    Skip,
}

impl RestoreStrategy {
    /// 英文短标签（W6/C-48：与 `label_zh` 并存，CLI 英文文案用此方法）。
    /// Short English label (W6/C-48: pairs with `label_zh` for English CLI copy).
    pub fn label(&self) -> &'static str {
        match self {
            RestoreStrategy::Rebuild => "rebuild",
            RestoreStrategy::Reinstall => "reinstall",
            RestoreStrategy::WeakModules => "weak-update",
            RestoreStrategy::Copy => "copy",
            RestoreStrategy::Skip => "skip",
        }
    }

    /// 中文短标签，供 GUI/CLI 展示。
    /// Short Chinese label for the GUI/CLI.
    pub fn label_zh(&self) -> &'static str {
        match self {
            RestoreStrategy::Rebuild => "重建",
            RestoreStrategy::Reinstall => "重装包",
            RestoreStrategy::WeakModules => "弱更新链接",
            RestoreStrategy::Copy => "拷贝",
            RestoreStrategy::Skip => "跳过",
        }
    }
}

/// Non-file side effect of a restore (W1/C-15, ITERATION §5.3): one command run
/// during the system phase, plus the compensation command that undoes it.
/// 还原的非文件副作用（W1/C-15，ITERATION §5.3）：系统阶段执行的一条命令，
/// 以及回滚时用于补偿它的命令。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CommandEntry {
    /// Program that was run / 执行的程序名。
    pub program: String,
    /// Arguments passed to the program / 传给程序的参数。
    pub args: Vec<String>,
    /// Full compensation argv (including the program) run on rollback; `None`
    /// means the effect cannot be compensated precisely.
    /// 回滚时执行的补偿命令完整 argv（含程序名）；`None` 表示无法精确补偿。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub undone_by: Option<Vec<String>>,
    /// Whether only a best-effort compensation is possible (e.g. a package was
    /// reinstalled at a newer version); recorded as a note on rollback.
    /// 是否只可"尽力补偿"（如包重装为新版本）；回滚时记入 notes。
    #[serde(default)]
    pub best_effort: bool,
    /// Human-readable description / 人类可读说明。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

/// One entry of a [`RestorePlan`] (W1/C-19): the decision taken for one manifest
/// path before any write — shared by dry-run reporting and the real run.
/// [`RestorePlan`] 中的单条决策（W1/C-19）：dry-run 与实跑共用，保证统计同源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedEntry {
    /// Archive-relative path (without the `data/` prefix) / 归档相对路径（不含 `data/`）。
    pub path: String,
    /// Entry classification / 条目分类。
    pub kind: EntryKind,
    /// Resolved (degraded) restore strategy / 已解析（含降级）的还原策略。
    pub strategy: RestoreStrategy,
    /// Whether the payload is stored in the archive / 内容是否存入归档。
    pub content_stored: bool,
    /// Uncompressed size recorded in the manifest / manifest 记录的字节数。
    pub size: u64,
    /// Symlink target (only for `EntryKind::Symlink`) / 符号链接目标（仅 Symlink）。
    pub link_target: Option<String>,
}

/// Deterministic restore plan (W1/C-19): the shared source of truth for dry-run
/// statistics and the real run; W6 per-module selection will consume it too.
/// 确定性还原计划（W1/C-19）：dry-run 统计与实跑的共同事实源；W6 勾选还原亦将消费它。
#[derive(Debug, Clone, Default)]
pub struct RestorePlan {
    /// Per-entry decisions / 逐条计划。
    pub entries: Vec<PlannedEntry>,
    /// Regular files that will be copied directly (excludes modules that will be
    /// rebuilt/reinstalled) / 将直接拷贝的普通文件数（不含将重建/重装的模块）。
    pub files: usize,
    /// Symlinks that will be created / 将写入的符号链接数。
    pub links: usize,
    /// Bytes that will be copied directly / 将直接拷贝的字节数。
    pub bytes: u64,
    /// Firmware entries skipped because firmware restore is disabled / 未开启固件而跳过的条目数。
    pub firmware_skipped: usize,
    /// Entries skipped because the payload is provided by a system package /
    /// 内容未存入归档（由系统包提供）而跳过的条目数。
    pub provided_skipped: usize,
    /// Counts per strategy (Chinese label → count) / 各策略条目数（中文标签 → 数量）。
    pub strategy_counts: Vec<(String, usize)>,
    /// Plan-level notes (e.g. offline downgrade) / 计划阶段说明（如离线降级）。
    pub notes: Vec<String>,
}

impl RestorePlan {
    /// Resolved strategy for a manifest-relative path, when planned.
    /// 某 manifest 相对路径的已解析策略（若在计划内）。
    pub fn strategy_for(&self, path: &str) -> Option<RestoreStrategy> {
        self.entries
            .iter()
            .find(|e| e.path == path)
            .map(|e| e.strategy)
    }
}

/// Secure Boot 上下文（v2 新增）。
/// Secure Boot context recorded in the manifest (new in v2).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecureBootInfo {
    /// 固件是否处于 Secure Boot 开启状态。
    pub enabled: bool,
    /// 内核是否强制要求签名（`CONFIG_MODULE_SIG_FORCE` / `module.sig_enforce`）。
    pub sig_enforce: bool,
}

/// 归档中记录的 DKMS 包（v2 新增），供还原侧走"重建"路径。
/// A DKMS package recorded in the manifest (new in v2) so restore can rebuild.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DkmsPackage {
    /// DKMS 模块名（`dkms status` 的第一列）。
    pub name: String,
    /// 模块版本。
    pub version: String,
}

/// 扫描得到的一个待备份条目（文件或符号链接）。
/// One scanned entry: a regular file or a symlink.
#[derive(Debug, Clone)]
pub struct ScanEntry {
    /// 源文件绝对路径（读取用）。
    pub abs_path: PathBuf,
    /// 归档内相对路径：去掉前导 `/`，写入时位于 `data/` 之下。
    pub rel_path: String,
    /// 扫描时刻的字节数（符号链接记为 0）。
    pub size: u64,
    /// 条目分类。
    pub kind: EntryKind,
    /// 符号链接目标（仅 `kind == Symlink`；原样保存 `readlink` 结果）。
    pub link_target: Option<String>,
    /// 来源包（`dpkg -S` / `rpm -qf` 查询结果）。
    pub owner: Option<Provenance>,
    /// 模块元数据（仅 `kind == Module` 时尽力收集）。
    pub modinfo: Option<ModInfo>,
    /// 内容是否存入归档（`false` 表示由系统包提供，仅记录存在性）。
    pub content_stored: bool,
}

/// 一次扫描的完整结果（`scan::scan` 的返回值）。
/// Full result of one scan pass, as returned by `scan::scan`.
#[derive(Debug, Clone, Default)]
pub struct ScanReport {
    /// 按遍历顺序排列的条目；顺序即归档顺序。
    pub entries: Vec<ScanEntry>,
    /// 因 in-tree 基线而跳过的条目数（不备份，仅统计）。
    pub skipped_in_tree: usize,
    /// `/lib/firmware` 在该模式下的预估体积（用于 UI 提示）。
    pub firmware_bytes: u64,
    /// 扫描期的可恢复问题（不会中止扫描，但会写入 manifest）。
    pub warnings: Vec<String>,
    /// 扫描中发现的 DKMS 包（供 manifest v2 与"重建优先"策略使用）。
    pub dkms: Vec<DkmsPackage>,
}

/// manifest 中的逐文件记录。
/// Per-file record inside `manifest.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestEntry {
    /// 归档内相对路径（不含 `data/` 前缀）。
    pub path: String,
    /// 归档中的字节数。
    pub size: u64,
    /// 内容的 SHA-256（64 位小写十六进制）；符号链接为**目标字符串**的哈希。
    pub sha256: String,
    /// 条目分类。
    pub kind: EntryKind,
    /// 符号链接目标（v2；v1 归档缺省为 `None`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// 来源包（v2）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Provenance>,
    /// 模块元数据（v2）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modinfo: Option<ModInfo>,
    /// 内容是否存入归档（v2；v1 归档按 `true` 处理）。
    #[serde(default = "default_true")]
    pub content_stored: bool,
    /// 建议的还原策略（v2）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy_hint: Option<RestoreStrategy>,
}

/// serde 默认值：内容默认已存储（v1 兼容）。
/// serde default: content is stored by default (v1 compatibility).
fn default_true() -> bool {
    true
}

/// manifest 中的发行版快照。
/// Distro snapshot embedded into `manifest.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManifestDistro {
    /// `/etc/os-release` 的 `ID`。
    pub id: String,
    /// `VERSION_ID`。
    pub version_id: String,
    /// `PRETTY_NAME`。
    pub pretty_name: String,
    /// 归一化后的发行版家族。
    pub family: Family,
}

impl ManifestDistro {
    /// 从发行版探测结果构造 manifest 用的发行版快照。
    /// Build the manifest distro snapshot from a detected `DistroInfo`.
    pub fn from_distro(info: &DistroInfo) -> Self {
        ManifestDistro {
            id: info.id.clone(),
            version_id: info.version_id.clone(),
            pretty_name: info.pretty_name.clone(),
            family: info.family,
        }
    }
}

/// 归档根目录下的 `manifest.json`：元数据 + 逐文件 SHA-256。
/// The `manifest.json` at the archive root: metadata plus per-file SHA-256.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    /// 归档格式版本；读取时接受 [`MIN_MANIFEST_FORMAT_VERSION`]..=[`MANIFEST_FORMAT_VERSION`]。
    pub format_version: u32,
    /// 生成该归档的工具版本（`CARGO_PKG_VERSION`）。
    pub tool_version: String,
    /// 生成时刻（UTC，RFC3339：`YYYY-MM-DDTHH:MM:SSZ`）。
    pub created_at: String,
    /// 内核版本串（`uname -r`）。
    pub kernel_release: String,
    /// 备份时内核的 `vermagic`（v2 新增；还原前比对的基准）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_vermagic: Option<String>,
    /// 架构（如 `x86_64`）。
    pub arch: String,
    /// 发行版快照。
    pub distro: ManifestDistro,
    /// 备份机的不可变系统类型（v2 新增，如 `mutable` / `ostree` / `nix` / `read-only-usrs`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub immutability: Option<String>,
    /// 备份机的 Secure Boot 上下文（v2 新增）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_boot: Option<SecureBootInfo>,
    /// 备份模式。
    pub mode: BackupMode,
    /// 归档压缩方式（v2 新增，如 `gzip`）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<String>,
    /// 逐文件记录，顺序与归档内 `data/` 的写入顺序一致。
    pub entries: Vec<ManifestEntry>,
    /// DKMS 包清单（v2 新增），供"重建优先"策略使用。
    #[serde(default)]
    pub dkms: Vec<DkmsPackage>,
    /// 扫描与打包期的可恢复问题。
    #[serde(default)]
    pub warnings: Vec<String>,
    /// 固件收集策略（v0.3.0 W5/P1-3，可选）：`"all"` | `"needed"` | `"none"`。
    /// 缺省 = 不记录 → 视为 `needed`（与 v2 归档现有行为一致，向后兼容）。
    /// Firmware collection policy (v0.3.0 W5): `"all"` | `"needed"` | `"none"`.
    /// Absent = existing v2 behaviour (`needed`) for backward compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firmware_policy: Option<String>,
}

impl Manifest {
    /// 判断 manifest 的格式版本是否受支持（v1 与 v2 均可读）。
    /// Whether the recorded format version is supported (both v1 and v2 are readable).
    pub fn format_supported(&self) -> bool {
        (MIN_MANIFEST_FORMAT_VERSION..=MANIFEST_FORMAT_VERSION).contains(&self.format_version)
    }

    /// 是否为 v1 归档（缺少 v2 的符号链接/来源包等元数据）。
    /// Whether this is a v1 archive (no symlink/provenance metadata).
    pub fn is_legacy_v1(&self) -> bool {
        self.format_version < 2
    }
}

/// 归档格式版本号（当前为 2；v0.2.0 起，注释此前误写为 1 —— C-49 已修正）。
/// Archive format version; currently 2 (the comment wrongly said 1 — fixed per C-49).
pub const MANIFEST_FORMAT_VERSION: u32 = 2;

/// 仍然可读的最低归档格式版本（v1 归档向后兼容）。
/// Oldest archive format version we can still read (v1 stays compatible).
pub const MIN_MANIFEST_FORMAT_VERSION: u32 = 1;

/// 统一错误类型：IO / JSON / 归档格式 / 输入校验 / 取消 / 外部命令 / 提权。
/// Unified error type for the whole crate.
///
/// 注意：本枚举内嵌 `std::io::Error` 与 `serde_json::Error`（二者不可克隆、不可比较），
/// 因此只能 `#[derive(Debug)]`，不要试图给它加 `Clone` / `PartialEq`。
#[derive(Debug)]
pub enum AppError {
    /// 文件/目录等 IO 失败。
    Io(std::io::Error),
    /// `serde_json` 解析或序列化失败。
    Json(serde_json::Error),
    /// 归档 / manifest 不合法。
    Format(String),
    /// 输入不合法（如 `kver` 含非法字符）。
    Validation(String),
    /// 用户取消。
    Cancelled,
    /// 外部命令非零退出。
    Command {
        /// 命令程序名。
        program: String,
        /// 退出码（信号杀掉时为 `128 + sig` 之类的约定值）。
        status: i32,
        /// 捕获到的标准错误。
        stderr: String,
    },
    /// 提权失败 / 未获得 root。
    Privilege(String),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Io(e) => write!(f, "I/O 错误 / I/O error: {e}"),
            AppError::Json(e) => write!(f, "JSON 错误 / JSON error: {e}"),
            AppError::Format(m) => write!(f, "归档格式错误 / archive format error: {m}"),
            AppError::Validation(m) => write!(f, "输入校验失败 / validation error: {m}"),
            AppError::Cancelled => write!(f, "操作已取消 / operation cancelled"),
            AppError::Command {
                program,
                status,
                stderr,
            } => {
                let stderr = stderr.trim();
                write!(
                    f,
                    "命令 `{program}` 失败（退出码 {status}）/ command failed: {stderr}"
                )
            }
            AppError::Privilege(m) => write!(f, "提权失败 / privilege error: {m}"),
        }
    }
}

impl std::error::Error for AppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AppError::Io(e) => Some(e),
            AppError::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        AppError::Io(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> Self {
        AppError::Json(e)
    }
}

/// 所有模块统一的结果类型。
/// Result alias used by every module.
pub type AppResult<T> = Result<T, AppError>;

/// 把字节数格式化为 1024 进制的人类可读体积，例如 `"512 B"`、`"1.2 KiB"`。
/// Format a byte count into a human readable binary-unit string such as `1.2 KiB`.
///
/// 规则：小于 1024 时输出整数 + ` B`（`0 B` / `512 B`），否则保留一位小数
/// （`1.2 KiB` / `3.4 MiB` / `1.1 GiB`），单位依次为 KiB / MiB / GiB / TiB。
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// 校验内核版本串是否可安全进入命令行参数与文件名。
/// Check whether a kernel release string is safe to embed in command-line arguments.
///
/// 规则：非空、字节长度 ≤ 128、首字符为 ASCII 字母或数字、其余字符仅限
/// `[0-9A-Za-z._+-]` —— 即 DESIGN.md §4.5 的 `^[0-9A-Za-z][0-9A-Za-z._+-]*$`
/// 再加长度上限。
pub fn is_safe_kernel_version(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    let first = match s.chars().next() {
        Some(c) => c,
        None => return false,
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distro::Family;
    use std::error::Error; // 让 `source()` 在作用域内 / bring `source()` into scope

    fn sample_manifest() -> Manifest {
        Manifest {
            format_version: MANIFEST_FORMAT_VERSION,
            tool_version: "0.2.0".to_string(),
            created_at: "2026-09-27T12:00:00Z".to_string(),
            kernel_release: "6.8.0-45-generic".to_string(),
            kernel_vermagic: Some(
                "6.8.0-45-generic SMP preempt mod_unload modversions".to_string(),
            ),
            arch: "x86_64".to_string(),
            distro: ManifestDistro {
                id: "linuxmint".to_string(),
                version_id: "22.3".to_string(),
                pretty_name: "Linux Mint 22.3".to_string(),
                family: Family::Debian,
            },
            immutability: Some("mutable".to_string()),
            secure_boot: Some(SecureBootInfo {
                enabled: false,
                sig_enforce: false,
            }),
            mode: BackupMode::Standard,
            compression: Some("gzip".to_string()),
            entries: vec![
                ManifestEntry {
                    path: "lib/modules/6.8.0-45-generic/updates/dkms/foo.ko".to_string(),
                    size: 123_456,
                    sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_string(),
                    kind: EntryKind::Module,
                    link_target: None,
                    owner: Some(Provenance {
                        manager: "dpkg".to_string(),
                        package: "foo-dkms".to_string(),
                        version: "1.0-1".to_string(),
                    }),
                    modinfo: Some(ModInfo {
                        vermagic: Some("6.8.0-45-generic SMP mod_unload".to_string()),
                        depends: vec!["bar".to_string()],
                        firmware: vec!["foo/bar.bin".to_string()],
                        sig_id: None,
                        sig_key: None,
                    }),
                    content_stored: true,
                    strategy_hint: Some(RestoreStrategy::Rebuild),
                },
                ManifestEntry {
                    path: "lib/modules/6.8.0-45-generic/weak-updates/foo.ko".to_string(),
                    size: 0,
                    sha256: "abc".to_string(),
                    kind: EntryKind::Symlink,
                    link_target: Some("../../6.8.0-40-generic/extra/foo.ko".to_string()),
                    owner: None,
                    modinfo: None,
                    content_stored: true,
                    strategy_hint: None,
                },
            ],
            dkms: vec![DkmsPackage {
                name: "foo".to_string(),
                version: "1.0".to_string(),
            }],
            warnings: vec!["测试告警 / test warning".to_string()],
            firmware_policy: None,
        }
    }

    #[test]
    fn human_size_uses_binary_units() {
        assert_eq!(human_size(0), "0 B");
        assert_eq!(human_size(1), "1 B");
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.0 KiB");
        assert_eq!(human_size(1234), "1.2 KiB");
        assert_eq!(human_size(3_565_158), "3.4 MiB");
        assert_eq!(human_size(1_181_116_006), "1.1 GiB");
        assert_eq!(human_size(1024 * 1024), "1.0 MiB");
    }

    #[test]
    fn kernel_version_validation() {
        assert!(is_safe_kernel_version("6.8.0-45-generic"));
        assert!(is_safe_kernel_version("6.1.0-1-amd64"));
        assert!(is_safe_kernel_version("6.6.8-arch1-1"));
        assert!(is_safe_kernel_version("5.15.0+foo_bar.baz"));
        assert!(is_safe_kernel_version(&"a".repeat(128)));

        assert!(!is_safe_kernel_version(""));
        assert!(!is_safe_kernel_version(&"a".repeat(129)));
        assert!(!is_safe_kernel_version("6.8.0/../x"));
        assert!(!is_safe_kernel_version("-6.8.0"));
        assert!(!is_safe_kernel_version("_6.8.0"));
        assert!(!is_safe_kernel_version("6.8.0 x"));
        assert!(!is_safe_kernel_version("6.8.0;rm -rf /"));
        assert!(!is_safe_kernel_version("6.8.0$(id)"));
        assert!(!is_safe_kernel_version("6.8.0-α"));
        assert!(!is_safe_kernel_version("\n"));
    }

    #[test]
    fn manifest_json_roundtrip() {
        let m = sample_manifest();
        let json = serde_json::to_string_pretty(&m).expect("manifest serialize");
        let back: Manifest = serde_json::from_str(&json).expect("manifest deserialize");

        assert_eq!(back.format_version, MANIFEST_FORMAT_VERSION);
        assert_eq!(back.tool_version, m.tool_version);
        assert_eq!(back.created_at, m.created_at);
        assert_eq!(back.kernel_release, m.kernel_release);
        assert_eq!(back.arch, m.arch);
        assert_eq!(back.mode, m.mode);
        assert_eq!(back.distro.id, m.distro.id);
        assert_eq!(back.distro.version_id, m.distro.version_id);
        assert_eq!(back.distro.pretty_name, m.distro.pretty_name);
        assert_eq!(back.distro.family, m.distro.family);
        assert_eq!(back.entries.len(), m.entries.len());
        assert_eq!(back.entries[0].path, m.entries[0].path);
        assert_eq!(back.entries[0].size, m.entries[0].size);
        // v2 字段必须原样往返
        assert_eq!(back.entries[0].strategy_hint, m.entries[0].strategy_hint);
        assert_eq!(back.entries[0].owner, m.entries[0].owner);
        assert_eq!(back.entries[0].modinfo, m.entries[0].modinfo);
        assert_eq!(back.entries[1].link_target, m.entries[1].link_target);
        assert_eq!(back.kernel_vermagic, m.kernel_vermagic);
        assert_eq!(back.dkms, m.dkms);
        assert_eq!(back.entries[0].sha256, m.entries[0].sha256);
        assert_eq!(back.entries[0].kind, m.entries[0].kind);
        assert_eq!(back.warnings, m.warnings);

        // 往返稳定：重新序列化应与首次序列化逐字节一致
        assert_eq!(serde_json::to_string_pretty(&back).unwrap(), json);
    }

    #[test]
    fn enums_serialize_in_lowercase() {
        assert_eq!(
            serde_json::to_string(&BackupMode::Minimal).unwrap(),
            "\"minimal\""
        );
        assert_eq!(
            serde_json::to_string(&BackupMode::Standard).unwrap(),
            "\"standard\""
        );
        assert_eq!(
            serde_json::to_string(&BackupMode::Full).unwrap(),
            "\"full\""
        );
        assert_eq!(
            serde_json::to_string(&EntryKind::Module).unwrap(),
            "\"module\""
        );
        assert_eq!(serde_json::to_string(&EntryKind::Dkms).unwrap(), "\"dkms\"");
        assert_eq!(
            serde_json::to_string(&EntryKind::Config).unwrap(),
            "\"config\""
        );
        assert_eq!(
            serde_json::to_string(&EntryKind::Firmware).unwrap(),
            "\"firmware\""
        );

        let mode: BackupMode = serde_json::from_str("\"full\"").unwrap();
        assert_eq!(mode, BackupMode::Full);
        let kind: EntryKind = serde_json::from_str("\"dkms\"").unwrap();
        assert_eq!(kind, EntryKind::Dkms);
        // warnings 字段缺省时应能反序列化（#[serde(default)]）
        let no_warn: Manifest = serde_json::from_str(
            r#"{"format_version":1,"tool_version":"0.1.0","created_at":"2026-09-27T12:00:00Z",
                "kernel_release":"6.8.0-45-generic","arch":"x86_64",
                "distro":{"id":"debian","version_id":"12","pretty_name":"Debian GNU/Linux 12",
                          "family":"debian"},
                "mode":"standard","entries":[]}"#,
        )
        .unwrap();
        assert!(no_warn.warnings.is_empty());
    }

    #[test]
    fn mode_index_roundtrip_and_fallback() {
        assert_eq!(BackupMode::from_index(0), BackupMode::Minimal);
        assert_eq!(BackupMode::from_index(1), BackupMode::Standard);
        assert_eq!(BackupMode::from_index(2), BackupMode::Full);
        // 非法下标回退 Standard（DESIGN.md §5.1）
        assert_eq!(BackupMode::from_index(-1), BackupMode::Standard);
        assert_eq!(BackupMode::from_index(3), BackupMode::Standard);
        assert_eq!(BackupMode::from_index(99), BackupMode::Standard);

        assert_eq!(BackupMode::Minimal.index(), 0);
        assert_eq!(BackupMode::Standard.index(), 1);
        assert_eq!(BackupMode::Full.index(), 2);
        assert_eq!(BackupMode::Standard.label(), "Standard");
    }

    #[test]
    fn app_error_display_and_source() {
        let io_err = AppError::from(std::io::Error::new(std::io::ErrorKind::NotFound, "gone"));
        assert!(io_err.to_string().contains("I/O"));
        assert!(io_err.source().is_some());

        let fmt = AppError::Format("bad entry".to_string());
        assert!(fmt.to_string().contains("bad entry"));
        assert!(fmt.source().is_none());

        let cmd = AppError::Command {
            program: "depmod".to_string(),
            status: 1,
            stderr: "oops".to_string(),
        };
        assert!(cmd.to_string().contains("depmod"));
        assert!(cmd.to_string().contains("oops"));

        let cancel: AppResult<()> = Err(AppError::Cancelled);
        assert!(matches!(cancel, Err(AppError::Cancelled)));
    }

    #[test]
    fn v1_archive_stays_readable_with_defaults() {
        // 最小 v1 manifest：没有任何 v2 字段。
        let v1 = r#"{
            "format_version": 1,
            "tool_version": "0.1.2",
            "created_at": "2026-09-20T00:00:00Z",
            "kernel_release": "6.5.0-1-amd64",
            "arch": "x86_64",
            "distro": {"id":"debian","version_id":"12","pretty_name":"Debian 12","family":"debian"},
            "mode": "minimal",
            "entries": [
                {"path":"lib/modules/6.5.0-1-amd64/extra/a.ko","size":10,"sha256":"aa","kind":"module"}
            ]
        }"#;
        let manifest: Manifest = serde_json::from_str(v1).expect("v1 必须可被 v2 读取");
        assert_eq!(manifest.format_version, 1);
        assert!(manifest.format_supported());
        assert!(manifest.is_legacy_v1());
        assert!(manifest.kernel_vermagic.is_none());
        assert!(manifest.dkms.is_empty());
        assert!(manifest.secure_boot.is_none());
        // v2 字段按默认值补齐：内容视为已存储、无链接目标。
        assert!(manifest.entries[0].content_stored);
        assert!(manifest.entries[0].link_target.is_none());
        assert!(manifest.entries[0].modinfo.is_none());
        assert!(manifest.entries[0].strategy_hint.is_none());
    }

    #[test]
    fn future_format_version_is_rejected() {
        let mut manifest = sample_manifest();
        manifest.format_version = MANIFEST_FORMAT_VERSION + 1;
        assert!(!manifest.format_supported());
        assert!(!manifest.is_legacy_v1());
    }

    #[test]
    fn modinfo_signature_detection() {
        let unsigned = ModInfo::default();
        assert!(!unsigned.is_signed());
        let signed = ModInfo {
            sig_id: Some("PKCS#7".to_string()),
            sig_key: Some("AA:BB".to_string()),
            ..Default::default()
        };
        assert!(signed.is_signed());
        let empty_sig = ModInfo {
            sig_id: Some(String::new()),
            ..Default::default()
        };
        assert!(!empty_sig.is_signed());
    }

    #[test]
    fn strategy_labels_are_stable() {
        assert_eq!(RestoreStrategy::Rebuild.label_zh(), "重建");
        assert_eq!(RestoreStrategy::Reinstall.label_zh(), "重装包");
        assert_eq!(RestoreStrategy::WeakModules.label_zh(), "弱更新链接");
        assert_eq!(RestoreStrategy::Copy.label_zh(), "拷贝");
        assert_eq!(RestoreStrategy::Skip.label_zh(), "跳过");
    }

    /// W1/C-19：`RestorePlan` 的按路径查询是稳定契约。
    #[test]
    fn restore_plan_strategy_lookup_w1() {
        let plan = RestorePlan {
            entries: vec![
                PlannedEntry {
                    path: "lib/modules/6.8/x.ko".to_string(),
                    kind: EntryKind::Module,
                    strategy: RestoreStrategy::Rebuild,
                    content_stored: true,
                    size: 10,
                    link_target: None,
                },
                PlannedEntry {
                    path: "etc/modprobe.d/x.conf".to_string(),
                    kind: EntryKind::Config,
                    strategy: RestoreStrategy::Copy,
                    content_stored: true,
                    size: 3,
                    link_target: None,
                },
            ],
            files: 1,
            links: 0,
            bytes: 3,
            ..Default::default()
        };
        assert_eq!(
            plan.strategy_for("lib/modules/6.8/x.ko"),
            Some(RestoreStrategy::Rebuild)
        );
        assert_eq!(
            plan.strategy_for("etc/modprobe.d/x.conf"),
            Some(RestoreStrategy::Copy)
        );
        assert_eq!(plan.strategy_for("missing"), None);
    }

    /// W1/C-15：`CommandEntry` 必须可 JSON 往返（journal 需持久化）。
    #[test]
    fn command_entry_roundtrip_w1() {
        let entry = CommandEntry {
            program: "dkms".to_string(),
            args: vec!["install".to_string(), "-m".to_string(), "foo".to_string()],
            undone_by: Some(vec![
                "dkms".to_string(),
                "remove".to_string(),
                "-m".to_string(),
                "foo".to_string(),
            ]),
            best_effort: false,
            note: "DKMS 重建 foo".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: CommandEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, entry);
        // 缺省字段可反序列化（向后兼容）
        let minimal: CommandEntry =
            serde_json::from_str(r#"{"program":"depmod","args":["-a","6.8"]}"#).unwrap();
        assert_eq!(minimal.undone_by, None);
        assert!(!minimal.best_effort);
        assert!(minimal.note.is_empty());
    }
}
