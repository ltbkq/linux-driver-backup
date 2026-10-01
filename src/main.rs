//! 模块：程序入口 —— GUI 装配、CLI 分发与 root helper 重入。
//! Module: entry point — GUI wiring, CLI dispatch and root helper re-entry.
//!
//! 【职责 / Responsibilities】
//! 1. 无参数：启动 Slint GUI，绑定 4 个冻结回调（DESIGN.md §4.6），耗时工作全部放到
//!    `std::thread` 工作线程，经 `Weak::upgrade_in_event_loop` 回写属性（严禁在回调里
//!    捕获 `AppWindow` 强引用，否则引用环会导致窗口关不掉）。
//! 2. CLI：手写参数解析（不引入 clap），实现 `--scan/--backup/--restore/--helper-restore`
//!    （DESIGN.md §5.7），便于无显示环境、脚本与 CI 冒烟测试。
//! 3. `--helper-restore`：由 `pkexec <自身> …` 以 root 重入的**无 GUI** 分支，按
//!    `PROGRESS/NOTE/RESULT` 行协议回传结果（DESIGN.md §4.5）。
//!
//! [Summary] GUI mode wires the four frozen callbacks and runs all heavy work on worker
//! threads; CLI mode implements the hand-rolled argument parsing; helper mode is the
//! root-only, GUI-less re-entry driven by the `PROGRESS/NOTE/RESULT` line protocol.

mod backup;
mod config;
mod diagnose;
mod distro;
mod model;
mod pathutil;
mod privilege;
mod restore;
mod scan;
mod verify;

slint::include_modules!();

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use slint::{ComponentHandle, Model, ModelRc, VecModel};

use crate::distro::DistroInfo;
use crate::model::{
    human_size, AppError, AppResult, BackupMode, EntryKind, ProgressFn, RestoreStrategy, ScanReport,
};
use crate::scan::ScanOptions;

/// 命令行入口的解析结果。
/// Parsed command line entry point.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Cmd {
    /// 无参数 → 启动 GUI。 / No arguments → launch the GUI.
    Gui,
    /// `--help` / `-h`。
    Help,
    /// `--version` / `-V`。
    Version,
    /// `--scan [--mode <m>] [--json] [--config <f>]`。
    /// `mode`/`config` 为 `None` 表示未显式指定，由配置文件或默认值补全（W7）。
    Scan {
        mode: Option<BackupMode>,
        json: bool,
        config: Option<String>,
    },
    /// `--backup [--out <f>] [--mode <m>] [--kver <k>] [--firmware <p>] [--config <f>]`
    ///   （`out` 缺省时可由配置 `out_dir` 补全，W7）。
    Backup {
        out: Option<String>,
        mode: Option<BackupMode>,
        kver: Option<String>,
        firmware: Option<String>,
        config: Option<String>,
    },
    /// `--restore --archive <f> [--dry-run] [--yes] [--with-firmware] [--allow-kernel-mismatch]`
    ///   `[--root <dir>] [--strategy <s>] [--on-immutable <p>] [--strict-links] [--no-sign] [--chroot-exec]`
    Restore {
        archive: String,
        dry_run: bool,
        yes: bool,
        with_firmware: bool,
        allow_kernel_mismatch: bool,
        allow_arch_mismatch: bool,
        root: Option<String>,
        strategy: Option<RestoreStrategy>,
        on_immutable: bool,
        strict_links: bool,
        no_sign: bool,
        chroot_exec: bool,
        /// 还原前强制执行 `--verify` 完整性校验（W7 / §5.2）。
        require_verify: bool,
        /// 系统阶段失败时不自动回滚（W1-C14 逃生口）。
        no_auto_rollback_on_post: bool,
        /// 回滚保留代数（`None` 取配置或默认值）。
        keep_rollback: Option<usize>,
        /// `--config <f>` 显式配置路径。
        config: Option<String>,
    },
    /// `--rollback [last|<id>] [--root <dir>]`
    Rollback {
        journal: Option<String>,
        root: Option<String>,
    },
    /// `--helper-restore --archive <f> [--kver <k>] [--with-firmware] …`（内部）。
    Helper {
        archive: String,
        kver: Option<String>,
        with_firmware: bool,
        allow_kernel_mismatch: bool,
        allow_arch_mismatch: bool,
        root: Option<String>,
        strategy: Option<RestoreStrategy>,
        on_immutable: bool,
        strict_links: bool,
        no_sign: bool,
        chroot_exec: bool,
        /// 回滚保留代数（GUI 经参数透传，root 下读不到用户配置）。
        keep_rollback: Option<usize>,
        /// W6/P1-5：勾选还原的路径清单文件（每行一个 manifest 相对路径；`None` = 全部）。
        selected_file: Option<String>,
    },
    /// `--helper-rollback [last|<id>] [--root <dir>]`（内部，pkexec 重入）。
    HelperRollback {
        journal: Option<String>,
        root: Option<String>,
    },
    /// `--verify --archive <f> [--json]`（或位置参数 `--verify <f>`）。
    Verify { archive: String, json: bool },
    /// `--diagnose [--out <f>]`（或位置参数 `--diagnose <f>`）。
    Diagnose { out: Option<String> },
}

// ===========================================================================
// 参数解析 / Argument parsing
// ===========================================================================

/// 把 `--mode` 的取值映射为 [`BackupMode`]。
/// Map the `--mode` value onto [`BackupMode`].
fn parse_mode(value: &str) -> Result<BackupMode, String> {
    match value {
        "minimal" => Ok(BackupMode::Minimal),
        "standard" => Ok(BackupMode::Standard),
        "full" => Ok(BackupMode::Full),
        other => Err(format!(
            "`--mode` 取值非法：`{other}`（可选 minimal | standard | full）"
        )),
    }
}

/// 把 `--strategy` 的取值映射为还原策略（`auto` → `None` 表示自动决策）。
/// Map the `--strategy` value onto a restore strategy (`auto` → `None`).
fn parse_strategy(value: &str) -> Result<Option<RestoreStrategy>, String> {
    match value {
        "auto" => Ok(None),
        "rebuild" => Ok(Some(RestoreStrategy::Rebuild)),
        "reinstall" => Ok(Some(RestoreStrategy::Reinstall)),
        "weak-modules" | "weakmodules" => Ok(Some(RestoreStrategy::WeakModules)),
        "copy" => Ok(Some(RestoreStrategy::Copy)),
        other => Err(format!(
            "`--strategy` 取值非法：`{other}`（可选 auto | rebuild | reinstall | weak-modules | copy）"
        )),
    }
}

/// 把 `--firmware` 取值映射为三态策略（W5 / ITERATION §4-W5）。
/// Map the `--firmware` value onto the three-state firmware policy.
fn parse_firmware(value: &str) -> Result<String, String> {
    match value {
        v @ ("all" | "needed" | "none") => Ok(v.to_string()),
        other => Err(format!(
            "`--firmware` 取值非法：`{other}`（可选 all | needed | none）"
        )),
    }
}

/// 解析非负整数取值（`--keep-rollback`）。
/// Parse a non-negative integer option value (`--keep-rollback`).
fn parse_usize(value: &str) -> Result<usize, String> {
    value
        .replace('_', "")
        .parse::<usize>()
        .map_err(|_| format!("`--keep-rollback` 取值非法：`{value}`（需非负整数）"))
}

/// 取参数值：支持 `--mode standard` 与 `--mode=standard` 两种写法。
/// Take an option value, accepting both `--mode standard` and `--mode=standard`.
fn take_value(
    args: &[String],
    idx: &mut usize,
    name: &str,
    inline: Option<&str>,
) -> Result<String, String> {
    if let Some(v) = inline {
        if v.is_empty() {
            return Err(format!("`{name}` 缺少取值"));
        }
        *idx += 1;
        return Ok(v.to_string());
    }
    *idx += 1;
    match args.get(*idx) {
        Some(v) if !v.starts_with('-') => {
            *idx += 1;
            Ok(v.clone())
        }
        _ => Err(format!("`{name}` 缺少取值")),
    }
}

/// 解析 `--name=value` 形式的等号写法。
/// Split an `--name=value` style argument.
fn split_inline(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((name, value)) => (name, Some(value)),
        None => (arg, None),
    }
}

/// 解析命令行参数（不含 argv[0]）。
/// Parse the command line (excluding argv[0]).
fn parse_args(args: &[String]) -> Result<Cmd, String> {
    if args.is_empty() {
        return Ok(Cmd::Gui);
    }

    let (first, first_inline) = split_inline(&args[0]);
    if first_inline.is_some() {
        return Err(format!("未知参数：`{}`", args[0]));
    }

    match first {
        "--help" | "-h" => Ok(Cmd::Help),
        "--version" | "-V" => Ok(Cmd::Version),
        "--scan" => {
            let mut idx = 1;
            let mut mode: Option<BackupMode> = None;
            let mut json = false;
            let mut config: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--json" => {
                        if inline.is_some() {
                            return Err("`--json` 不接受取值".to_string());
                        }
                        json = true;
                        idx += 1;
                    }
                    "--mode" => {
                        mode = Some(parse_mode(&take_value(args, &mut idx, "--mode", inline)?)?)
                    }
                    "--config" => config = Some(take_value(args, &mut idx, "--config", inline)?),
                    other => return Err(format!("`--scan` 不支持参数 `{other}`")),
                }
            }
            Ok(Cmd::Scan { mode, json, config })
        }
        "--backup" => {
            let mut idx = 1;
            let mut out: Option<String> = None;
            let mut mode: Option<BackupMode> = None;
            let mut kver: Option<String> = None;
            let mut firmware: Option<String> = None;
            let mut config: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--out" => out = Some(take_value(args, &mut idx, "--out", inline)?),
                    "--mode" => {
                        mode = Some(parse_mode(&take_value(args, &mut idx, "--mode", inline)?)?)
                    }
                    "--kver" => kver = Some(take_value(args, &mut idx, "--kver", inline)?),
                    "--firmware" => {
                        firmware = Some(parse_firmware(&take_value(
                            args,
                            &mut idx,
                            "--firmware",
                            inline,
                        )?)?)
                    }
                    "--config" => config = Some(take_value(args, &mut idx, "--config", inline)?),
                    other => return Err(format!("`--backup` 不支持参数 `{other}`")),
                }
            }
            // `--out` 缺省合法（W7）：由配置 `out_dir` + 默认文件名补全；
            // 两者都没有时在执行期报用法错误（退出码 2）。
            Ok(Cmd::Backup {
                out,
                mode,
                kver,
                firmware,
                config,
            })
        }
        "--restore" => {
            let mut idx = 1;
            let mut archive: Option<String> = None;
            let mut dry_run = false;
            let mut yes = false;
            let mut with_firmware = false;
            let mut allow_kernel_mismatch = false;
            let mut allow_arch_mismatch = false;
            let mut root: Option<String> = None;
            let mut strategy: Option<RestoreStrategy> = None;
            let mut on_immutable = false;
            let mut strict_links = false;
            let mut no_sign = false;
            let mut chroot_exec = false;
            let mut require_verify = false;
            let mut no_auto_rollback_on_post = false;
            let mut keep_rollback: Option<usize> = None;
            let mut config: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--archive" => archive = Some(take_value(args, &mut idx, "--archive", inline)?),
                    "--dry-run" => {
                        dry_run = true;
                        idx += 1;
                    }
                    "--yes" | "-y" => {
                        yes = true;
                        idx += 1;
                    }
                    "--with-firmware" => {
                        with_firmware = true;
                        idx += 1;
                    }
                    "--allow-kernel-mismatch" => {
                        allow_kernel_mismatch = true;
                        idx += 1;
                    }
                    "--allow-arch-mismatch" => {
                        allow_arch_mismatch = true;
                        idx += 1;
                    }
                    "--root" => root = Some(take_value(args, &mut idx, "--root", inline)?),
                    "--strategy" => {
                        strategy =
                            parse_strategy(&take_value(args, &mut idx, "--strategy", inline)?)?
                    }
                    "--on-immutable" => {
                        let v = take_value(args, &mut idx, "--on-immutable", inline)?;
                        on_immutable = match v.as_str() {
                            "usroverlay" => true,
                            "refuse" => false,
                            other => {
                                return Err(format!(
                                "`--on-immutable` 取值非法：`{other}`（可选 refuse | usroverlay）"
                            ))
                            }
                        };
                    }
                    "--strict-links" => {
                        strict_links = true;
                        idx += 1;
                    }
                    "--no-sign" => {
                        no_sign = true;
                        idx += 1;
                    }
                    "--chroot-exec" => {
                        chroot_exec = true;
                        idx += 1;
                    }
                    "--require-verify" => {
                        require_verify = true;
                        idx += 1;
                    }
                    "--no-auto-rollback-on-post" => {
                        no_auto_rollback_on_post = true;
                        idx += 1;
                    }
                    "--keep-rollback" => {
                        keep_rollback = Some(parse_usize(&take_value(
                            args,
                            &mut idx,
                            "--keep-rollback",
                            inline,
                        )?)?)
                    }
                    "--config" => config = Some(take_value(args, &mut idx, "--config", inline)?),
                    other => return Err(format!("`--restore` 不支持参数 `{other}`")),
                }
            }
            let archive =
                archive.ok_or_else(|| "`--restore` 必须提供 `--archive <归档路径>`".to_string())?;
            Ok(Cmd::Restore {
                archive,
                dry_run,
                yes,
                with_firmware,
                allow_kernel_mismatch,
                allow_arch_mismatch,
                root,
                strategy,
                on_immutable,
                strict_links,
                no_sign,
                chroot_exec,
                require_verify,
                no_auto_rollback_on_post,
                keep_rollback,
                config,
            })
        }
        "--rollback" => {
            let mut idx = 1;
            let mut journal: Option<String> = None;
            let mut root: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--root" => root = Some(take_value(args, &mut idx, "--root", inline)?),
                    other if other.starts_with('-') => {
                        return Err(format!("`--rollback` 不支持参数 `{other}`"))
                    }
                    other => {
                        journal = Some(other.to_string());
                        idx += 1;
                    }
                }
            }
            Ok(Cmd::Rollback { journal, root })
        }
        "--helper-restore" => {
            let mut idx = 1;
            let mut archive: Option<String> = None;
            let mut kver: Option<String> = None;
            let mut with_firmware = false;
            let mut keep_rollback: Option<usize> = None;
            let mut selected_file: Option<String> = None;
            let mut allow_kernel_mismatch = false;
            let mut allow_arch_mismatch = false;
            let mut root: Option<String> = None;
            let mut strategy: Option<RestoreStrategy> = None;
            let mut on_immutable = false;
            let mut strict_links = false;
            let mut no_sign = false;
            let mut chroot_exec = false;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--archive" => archive = Some(take_value(args, &mut idx, "--archive", inline)?),
                    "--kver" => kver = Some(take_value(args, &mut idx, "--kver", inline)?),
                    "--with-firmware" => {
                        with_firmware = true;
                        idx += 1;
                    }
                    "--allow-kernel-mismatch" => {
                        allow_kernel_mismatch = true;
                        idx += 1;
                    }
                    "--allow-arch-mismatch" => {
                        allow_arch_mismatch = true;
                        idx += 1;
                    }
                    "--root" => root = Some(take_value(args, &mut idx, "--root", inline)?),
                    "--strategy" => {
                        strategy =
                            parse_strategy(&take_value(args, &mut idx, "--strategy", inline)?)?
                    }
                    "--on-immutable" => {
                        // 提权路径与 `--restore` 同样严格校验取值（ITERATION C-34）。
                        // Strict value validation on the privileged path, matching `--restore`.
                        let v = take_value(args, &mut idx, "--on-immutable", inline)?;
                        on_immutable = match v.as_str() {
                            "usroverlay" => true,
                            "refuse" => false,
                            other => {
                                return Err(format!(
                                    "`--on-immutable` 取值非法：{other}（可选 refuse | usroverlay）"
                                ))
                            }
                        };
                    }
                    "--strict-links" => {
                        strict_links = true;
                        idx += 1;
                    }
                    "--no-sign" => {
                        no_sign = true;
                        idx += 1;
                    }
                    "--chroot-exec" => {
                        chroot_exec = true;
                        idx += 1;
                    }
                    "--keep-rollback" => {
                        keep_rollback = Some(parse_usize(&take_value(
                            args,
                            &mut idx,
                            "--keep-rollback",
                            inline,
                        )?)?)
                    }
                    "--selected-file" => {
                        selected_file = Some(take_value(args, &mut idx, "--selected-file", inline)?)
                    }
                    other => return Err(format!("`--helper-restore` 不支持参数 `{other}`")),
                }
            }
            let archive = archive
                .ok_or_else(|| "`--helper-restore` 必须提供 `--archive <归档路径>`".to_string())?;
            Ok(Cmd::Helper {
                archive,
                kver,
                with_firmware,
                allow_kernel_mismatch,
                allow_arch_mismatch,
                root,
                strategy,
                on_immutable,
                strict_links,
                no_sign,
                chroot_exec,
                keep_rollback,
                selected_file,
            })
        }
        "--helper-rollback" => {
            let mut idx = 1;
            let mut journal: Option<String> = None;
            let mut root: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--root" => root = Some(take_value(args, &mut idx, "--root", inline)?),
                    // 位置参数：`last` 或日志 id。
                    other if !other.starts_with('-') && inline.is_none() => {
                        journal = Some(other.to_string());
                        idx += 1;
                    }
                    other => return Err(format!("`--helper-rollback` 不支持参数 `{other}`")),
                }
            }
            Ok(Cmd::HelperRollback { journal, root })
        }
        "--verify" => {
            let mut idx = 1;
            let mut archive: Option<String> = None;
            let mut json = false;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--archive" => archive = Some(take_value(args, &mut idx, "--archive", inline)?),
                    "--json" => {
                        if inline.is_some() {
                            return Err("`--json` 不接受取值".to_string());
                        }
                        json = true;
                        idx += 1;
                    }
                    // 位置参数写法：`--verify /path/a.tar.gz`（§5.2 的 `--verify [ARCHIVE]`）。
                    other if !other.starts_with('-') && inline.is_none() => {
                        archive = Some(other.to_string());
                        idx += 1;
                    }
                    other => return Err(format!("`--verify` 不支持参数 `{other}`")),
                }
            }
            let archive = archive.ok_or_else(|| {
                "`--verify` 需要归档路径（`--archive <f>` 或位置参数）".to_string()
            })?;
            Ok(Cmd::Verify { archive, json })
        }
        "--diagnose" => {
            let mut idx = 1;
            let mut out: Option<String> = None;
            while idx < args.len() {
                let (name, inline) = split_inline(&args[idx]);
                match name {
                    "--out" => out = Some(take_value(args, &mut idx, "--out", inline)?),
                    // 位置参数写法：`--diagnose out.tar.gz`。
                    other if !other.starts_with('-') && inline.is_none() => {
                        out = Some(other.to_string());
                        idx += 1;
                    }
                    other => return Err(format!("`--diagnose` 不支持参数 `{other}`")),
                }
            }
            Ok(Cmd::Diagnose { out })
        }
        other => Err(format!(
            "未知子命令：`{other}`（参见 `--help` / see `--help`）"
        )),
    }
}

/// 中英双语用法说明。
/// Bilingual usage text.
fn usage() -> String {
    format!(
        "linux-driver-backup {version} —— Linux 驱动备份与还原工具 / Linux driver backup & restore\n\
         \n\
         用法 / Usage:\n\
         \x20 linux-driver-backup                                   # 启动图形界面 / launch the GUI\n\
         \x20 linux-driver-backup --scan [--mode <m>] [--json]      # 扫描外置驱动 / scan out-of-tree drivers\n\
         \x20 linux-driver-backup --backup [--out <f>] [--mode <m>] [--kver <k>] [--firmware all|needed|none]\n\
         \x20 linux-driver-backup --restore --archive <f> [--dry-run] [--yes] [--with-firmware] [--allow-kernel-mismatch]\n\
         \x20                              [--allow-arch-mismatch] [--require-verify] [--keep-rollback <n>] [--config <f>]\n\
         \x20                              [--root <dir>] [--strategy auto|rebuild|reinstall|weak-modules|copy]\n\
         \x20                              [--on-immutable refuse|usroverlay] [--strict-links] [--no-sign] [--chroot-exec]\n\
         \x20                              [--no-auto-rollback-on-post]\n\
         \x20 linux-driver-backup --rollback [last|<id>] [--root <dir>]   # 回滚上一次还原 / undo the last restore\n\
         \x20 linux-driver-backup --verify [--archive] <f> [--json]       # 归档体检 / verify archive integrity\n\
         \x20 linux-driver-backup --diagnose [--out <f>]                   # 诊断收集（脱敏）/ redacted diagnostics\n\
         \x20 linux-driver-backup --helper-restore --archive <f> [--kver <k>] [--with-firmware]\n\
         \n\
         说明 / Notes:\n\
         \x20 模式 <m>：minimal | standard（默认）| full（含 /lib/firmware）\n\
         \x20 配置文件 / config: /etc/linux-driver-backup.toml 与 ~/.config/linux-driver-backup/config.toml\n\
         \x20   （键 mode/out_dir/keep_rollback/sign_key/firmware/strategy；`--config` 显式指定，CLI 旗标优先）。\n\
         \x20 备份无需 root；真实还原需要 root（GUI 走 pkexec 单次提权，CLI 请用 sudo 运行）。\n\
         \x20 `--helper-restore` 仅供内部提权重入使用，用户不应手动调用。\n\
         \x20 Backup needs no root; a real restore does (GUI elevates once via pkexec,\n\
         \x20 CLI users should run with sudo). `--helper-restore` is internal-only.\n\
         \n\
         退出码 / Exit codes: 0 成功或用户主动取消 success or user cancellation\n\
         \x20                      | 1 业务失败 failure | 2 用法错误 usage error\n",
        version = env!("CARGO_PKG_VERSION")
    )
}

// ===========================================================================
// 通用小工具 / Small helpers
// ===========================================================================

/// 展开仅前缀的 `~`（不处理 `~user`），其余原样返回。
/// Expand a leading `~` only; everything else is returned as-is.
fn expand_tilde(path: &str) -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        if path == "~" {
            return PathBuf::from(home);
        }
        if let Some(rest) = path.strip_prefix("~/") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// 还原策略 → CLI 取值 token（`--strategy` / helper 透传统一用此表）。
/// Map a restore strategy to its CLI token (shared by `--strategy` and helper passthrough).
fn strategy_token(strategy: RestoreStrategy) -> &'static str {
    match strategy {
        RestoreStrategy::Rebuild => "rebuild",
        RestoreStrategy::Reinstall => "reinstall",
        RestoreStrategy::WeakModules => "weak-modules",
        RestoreStrategy::Copy => "copy",
        RestoreStrategy::Skip => "skip",
    }
}

/// 把扫描告警整理成 GUI 常驻面板文案（空则返回空串，面板自动隐藏）。
/// Render scan warnings for the persistent GUI panel (empty string hides it).
fn warnings_panel_text(warnings: &[String]) -> String {
    if warnings.is_empty() {
        return String::new();
    }
    let mut out = format!("扫描告警 / warnings（{}）：", warnings.len());
    for warning in warnings.iter().take(8) {
        out.push_str(&format!("\n  ⚠ {warning}"));
    }
    if warnings.len() > 8 {
        out.push_str(&format!(
            "\n  … 其余 {} 条见 `--diagnose` 诊断包",
            warnings.len() - 8
        ));
    }
    out
}

/// W6/P1-5：由 GUI 勾选状态计算要还原的路径集合（展开 `modinfo.depends` 依赖闭包）。
/// Returns the selected restore paths, dependency-closed; `None` means "restore all".
///
/// 全部条目都勾选时返回 `None`（等价整档还原，避免生成大列表）。勾选 nvidia 会自动
/// 带上 nvidia-uvm 等在 `depends` 中被引用的模块。
fn selected_paths(ui: &AppWindow) -> Option<Vec<String>> {
    let model = ui.get_modules();
    let items: Vec<ModuleItem> = model.iter().collect();
    if items.is_empty() || items.iter().all(|item| item.selected) {
        return None;
    }
    let mut by_stem: HashMap<String, String> = HashMap::new();
    for item in &items {
        let stem = item.name.trim_end_matches(".ko").to_string();
        by_stem.insert(stem, item.path.to_string());
    }
    let mut chosen: HashSet<String> = HashSet::new();
    for item in &items {
        if !item.selected {
            continue;
        }
        chosen.insert(item.path.to_string());
        let mut stack: Vec<String> = item
            .depends
            .split_whitespace()
            .map(str::to_string)
            .collect();
        while let Some(dep) = stack.pop() {
            if let Some(path) = by_stem.get(&dep) {
                if chosen.insert(path.clone()) {
                    if let Some(next) = items.iter().find(|x| x.path.as_str() == path.as_str()) {
                        stack.extend(next.depends.split_whitespace().map(str::to_string));
                    }
                }
            }
        }
    }
    Some(chosen.into_iter().collect())
}

/// 条目分类的中文短标签，用于 GUI 列表。
/// Short Chinese label for an entry kind, used by the GUI list.
fn kind_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::Module => "模块",
        EntryKind::Dkms => "DKMS",
        EntryKind::Config => "配置",
        EntryKind::Firmware => "固件",
        EntryKind::Symlink => "链接",
    }
}

/// 打印到 stderr 的 CLI 进度回调（200ms 或 1% 节流）。
/// CLI progress callback printing to stderr, throttled to 200ms or 1%.
fn cli_progress() -> ProgressFn {
    let last = Arc::new(Mutex::new((
        Instant::now() - Duration::from_secs(10),
        -1.0f32,
    )));
    Arc::new(move |value: f32, msg: String| {
        let mut guard = last.lock().unwrap_or_else(|e| e.into_inner());
        let (at, previous) = *guard;
        let force = value <= 0.0 || value >= 1.0;
        if !force && at.elapsed() < Duration::from_millis(200) && (value - previous).abs() < 0.01 {
            return;
        }
        *guard = (Instant::now(), value);
        let percent = (value.clamp(0.0, 1.0) * 100.0).round() as i32;
        eprintln!("[{percent:>3}%] {msg}");
    })
}

/// GUI 进度回调：节流后经事件循环回写 `progress` / `status-text`。
/// GUI progress callback: throttled, posted to the event loop to update the UI.
fn gui_progress(weak: slint::Weak<AppWindow>) -> ProgressFn {
    let last = Arc::new(Mutex::new((
        Instant::now() - Duration::from_secs(10),
        -1.0f32,
    )));
    Arc::new(move |value: f32, msg: String| {
        let mut guard = last.lock().unwrap_or_else(|e| e.into_inner());
        let (at, previous) = *guard;
        let force = value <= 0.0 || value >= 1.0;
        if !force && at.elapsed() < Duration::from_millis(100) && (value - previous).abs() < 0.01 {
            return;
        }
        *guard = (Instant::now(), value);
        drop(guard);
        let _ = weak.upgrade_in_event_loop(move |ui| {
            ui.set_progress(value.clamp(0.0, 1.0));
            if !msg.is_empty() {
                ui.set_status_text(msg.into());
            }
        });
    })
}

/// 在事件循环里结束一次 GUI 任务：复位忙碌态并写入结果文案。
/// Finish a GUI task on the event loop: clear the busy flag and show the result.
fn finish_gui(weak: &slint::Weak<AppWindow>, running: &Arc<AtomicBool>, ok: bool, msg: String) {
    let weak = weak.clone();
    let running = Arc::clone(running);
    let _ = weak.upgrade_in_event_loop(move |ui| {
        running.store(false, Ordering::SeqCst);
        ui.set_busy(false);
        if ok {
            ui.set_progress(1.0);
        } else {
            ui.set_progress(0.0);
        }
        ui.set_status_text(msg.into());
    });
}

/// 开始一次 GUI 任务：互斥保护 + 复位取消位与进度。
/// Begin a GUI task: mutual exclusion plus cancel/progress reset.
fn begin_task(
    ui: &AppWindow,
    running: &Arc<AtomicBool>,
    cancel: &Arc<AtomicBool>,
    status: &str,
) -> bool {
    if running.swap(true, Ordering::SeqCst) {
        ui.set_status_text("已有任务正在运行，请先取消或等待完成。".into());
        return false;
    }
    cancel.store(false, Ordering::SeqCst);
    ui.set_busy(true);
    ui.set_progress(0.0);
    ui.set_status_text(status.into());
    true
}

/// 把扫描结果转成 GUI 列表项：跳过固件条目并限制条数，返回 `(列表, 是否截断, 总数)`。
/// Convert a scan report into GUI rows: firmware entries are dropped and the list is
/// capped; returns `(rows, truncated, total_non_firmware)`.
fn to_module_items(report: &ScanReport) -> (Vec<ModuleItem>, bool, usize) {
    const MAX_ROWS: usize = 500;
    let mut rows = Vec::new();
    let mut total = 0usize;
    for entry in &report.entries {
        if entry.kind == EntryKind::Firmware {
            continue;
        }
        total += 1;
        if rows.len() >= MAX_ROWS {
            continue;
        }
        let name = entry
            .abs_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| entry.rel_path.clone());
        let owner = entry
            .owner
            .as_ref()
            .map(|p| format!("{}:{}", p.manager, p.package))
            .unwrap_or_default();
        let vermagic = entry
            .modinfo
            .as_ref()
            .and_then(|m| m.vermagic.clone())
            .unwrap_or_default();
        let depends = entry
            .modinfo
            .as_ref()
            .map(|m| m.depends.join(" "))
            .unwrap_or_default();
        rows.push(ModuleItem {
            selected: true, // W6/P1-5：默认预选；依赖闭包在 Rust 侧展开
            name: name.into(),
            path: entry.rel_path.clone().into(),
            size: human_size(entry.size).into(),
            kind: kind_label(entry.kind).into(),
            owner: owner.into(),
            vermagic: vermagic.into(),
            depends: depends.into(),
        });
    }
    let truncated = total > rows.len();
    (rows, truncated, total)
}

// ===========================================================================
// CLI 子命令 / CLI subcommands
// ===========================================================================

/// `--scan`：扫描并打印（`--json` 输出机器可读 JSON）。
/// `--scan`: scan and print, optionally as machine-readable JSON.
fn run_cli_scan(mode: Option<BackupMode>, json: bool, config: Option<String>) -> i32 {
    // W7：配置补全默认模式（CLI `--mode` 永远优先）。
    let cfg = match config::Config::load(config.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("参数错误 / invalid arguments: {err}");
            return 2;
        }
    };
    let mode = mode.or(cfg.mode).unwrap_or(BackupMode::Standard);
    let kver = distro::kernel_release();
    let info = DistroInfo::detect();
    let cancel = AtomicBool::new(false);
    let options = ScanOptions {
        kver: &kver,
        distro: &info,
        mode,
        cancel: Some(&cancel),
    };

    match scan::scan(&options) {
        Ok(report) => {
            if json {
                // JSON 输出失败必须以非零退出，脚本/CI 不应把残缺输出当成功（C-33）。
                // A failed JSON emit must exit non-zero so scripts never treat partial output as success.
                if let Err(err) = print_scan_json(&report, &info, &kver, mode) {
                    eprintln!("{err}");
                    return 1;
                }
            } else {
                println!(
                    "内核 / kernel: {}    发行版 / distro: {}    模式 / mode: {}",
                    kver,
                    info,
                    mode.label()
                );
                println!(
                    "in-tree 跳过 {} 个；共 {} 个条目；固件 {}",
                    report.skipped_in_tree,
                    report.entries.len(),
                    human_size(report.firmware_bytes)
                );
                for entry in &report.entries {
                    println!(
                        "  [{:<4}] {:>10}  {}",
                        kind_label(entry.kind),
                        human_size(entry.size),
                        entry.rel_path
                    );
                }
                for warning in &report.warnings {
                    eprintln!("警告 / warning: {warning}");
                }
            }
            0
        }
        Err(err) => {
            eprintln!("扫描失败 / scan failed: {err}");
            1
        }
    }
}

/// 输出 `--scan --json` 的 JSON 结构。
/// Emit the JSON document for `--scan --json`.
fn print_scan_json(
    report: &ScanReport,
    info: &DistroInfo,
    kver: &str,
    mode: BackupMode,
) -> Result<(), String> {
    use serde_json::json;
    let entries: Vec<serde_json::Value> = report
        .entries
        .iter()
        .map(|entry| {
            json!({
                "path": entry.rel_path,
                "size": entry.size,
                "kind": serde_json::to_value(entry.kind).unwrap_or(serde_json::Value::Null),
            })
        })
        .collect();
    let document = json!({
        "kernel_release": kver,
        "arch": distro::arch(),
        "distro": {
            "id": info.id,
            "version_id": info.version_id,
            "pretty_name": info.pretty_name,
            "family": info.family,
        },
        "mode": mode,
        "skipped_in_tree": report.skipped_in_tree,
        "firmware_bytes": report.firmware_bytes,
        "entry_count": report.entries.len(),
        "warnings": report.warnings,
        "entries": entries,
    });
    let text = serde_json::to_string_pretty(&document)
        .map_err(|err| format!("JSON 序列化失败 / JSON serialization failed: {err}"))?;
    println!("{text}");
    Ok(())
}

/// 业务错误 → 进程退出码：用户主动取消为 0，其余失败为 1（ITERATION §5.1 / C-33）。
/// Map a business error to an exit code: user cancellation is 0, any other failure is 1.
fn exit_code(err: &AppError) -> i32 {
    match err {
        AppError::Cancelled => 0,
        _ => 1,
    }
}

/// C-46：**备份**结果的唯一汇总文案（CLI / GUI 共用，避免多处措辞漂移）。
/// C-46: single source of truth for the backup summary line (CLI / GUI).
fn format_backup_summary(report: &backup::BackupReport) -> String {
    format!(
        "备份完成 / backup finished: {}（{} 个条目，{}，耗时 {:.1}s，归档格式 v{}）",
        report.out_file.display(),
        report.entry_count,
        human_size(report.bytes_written),
        report.duration_ms as f64 / 1000.0,
        report.manifest.format_version
    )
}

/// C-46：**还原**结果的唯一汇总文案（CLI / helper / GUI 共用）。
/// C-46: single source of truth for the restore summary line (CLI / helper / GUI).
fn format_restore_summary(report: &restore::RestoreReport) -> String {
    if report.dry_run {
        return "预演完成 / dry-run finished（未写盘 / nothing written）".to_string();
    }
    format!(
        "还原完成 / restore finished: 写入 {} 个文件 + {} 个链接，跳过 {} 个；重建 {}，重装 {}，签名 {}（未签名 {}）；depmod={}，initramfs={}",
        report.written,
        report.links_written,
        report.skipped,
        report.rebuilt,
        report.reinstalled,
        report.signed,
        report.unsigned_left,
        report.depmod_done,
        match report.initramfs_done {
            Some(true) => "已更新 / updated",
            Some(false) => "失败 / failed",
            None => "跳过 / skipped",
        }
    )
}

/// `--verify`：逐条校验归档完整性（C-06），默认文本，`--json` 输出结构化报告。
/// `--verify`: per-entry archive integrity check (C-06); text by default, `--json` for machines.
fn run_cli_verify(archive: String, json: bool) -> i32 {
    let path = expand_tilde(&archive);
    match verify::verify(&path) {
        Ok(report) => {
            if json {
                match serde_json::to_string_pretty(&report) {
                    Ok(text) => println!("{text}"),
                    Err(err) => {
                        eprintln!("JSON 序列化失败 / JSON serialization failed: {err}");
                        return 1;
                    }
                }
            } else {
                print!("{}", verify::format_report(&report));
            }
            if report.ok {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("校验失败 / verification failed: {err}");
            exit_code(&err)
        }
    }
}

/// `--diagnose`：生成脱敏诊断包（W7 / P1-6）。
/// `--diagnose`: produce a redacted diagnostic bundle (W7 / P1-6).
fn run_cli_diagnose(out: Option<String>) -> i32 {
    match diagnose::run(out.as_deref()) {
        Ok(path) => {
            println!("诊断包已生成 / diagnostics written: {}", path.display());
            0
        }
        Err(err) => {
            eprintln!("诊断收集失败 / diagnose failed: {err}");
            exit_code(&err)
        }
    }
}

/// `--backup`：打包外置驱动到 `.tar.gz`。
/// `--backup`: pack out-of-tree drivers into a `.tar.gz` archive.
fn run_cli_backup(
    out: Option<String>,
    mode: Option<BackupMode>,
    kver: Option<String>,
    firmware: Option<String>,
    config: Option<String>,
) -> i32 {
    // W7：配置补全模式 / 输出目录 / 固件策略（CLI 旗标永远优先）。
    let cfg = match config::Config::load(config.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("参数错误 / invalid arguments: {err}");
            return 2;
        }
    };
    let mode = mode.or(cfg.mode).unwrap_or(BackupMode::Standard);
    let firmware_policy = firmware.or(cfg.firmware);
    let kver = kver.unwrap_or_else(distro::kernel_release);
    let out_path = match out {
        Some(raw) => expand_tilde(&raw),
        None => match &cfg.out_dir {
            Some(dir) => dir.join(format!("driver-backup-{kver}.tar.gz")),
            None => {
                eprintln!(
                    "`--backup` 必须提供 `--out <归档路径>`（或在配置中设置 out_dir / \
                     pass --out or set out_dir in the config）"
                );
                return 2;
            }
        },
    };
    let request = backup::BackupRequest {
        out_file: out_path.clone(),
        kver: kver.clone(),
        distro: DistroInfo::detect(),
        mode,
        progress: cli_progress(),
        firmware_policy,
        cancel: Arc::new(AtomicBool::new(false)),
    };

    eprintln!(
        "开始备份 / starting backup: 内核 {kver}，模式 {}，输出 {}",
        mode.label(),
        out_path.display()
    );
    match backup::run_backup(request) {
        Ok(report) => {
            println!("{}", format_backup_summary(&report));
            0
        }
        Err(err) => {
            let code = exit_code(&err);
            match &err {
                AppError::Cancelled => eprintln!("已取消 / cancelled"),
                other => eprintln!("备份失败 / backup failed: {other}"),
            }
            code
        }
    }
}

/// 还原选项集合：`--restore` 与 `--helper-restore` 共用的**唯一结构体**（C-45）。
/// Restore option set shared by `--restore` and `--helper-restore` (C-45).
///
/// 两种 CLI 入口与 GUI 都以本结构体表达还原意图，并经 [`RestoreOptions::to_request`]
/// 转换为 `restore::RestoreRequest`，消除原先 12 个位置参数的 helper 调用。
struct RestoreOptions {
    archive: String,
    /// `--helper-restore` 的目标内核（`--restore` 不用，交由 restore 侧自动决策）。
    kver: Option<String>,
    dry_run: bool,
    yes: bool,
    with_firmware: bool,
    allow_kernel_mismatch: bool,
    allow_arch_mismatch: bool,
    root: Option<String>,
    strategy: Option<RestoreStrategy>,
    on_immutable: bool,
    strict_links: bool,
    no_sign: bool,
    chroot_exec: bool,
    require_verify: bool,
    no_auto_rollback_on_post: bool,
    keep_rollback: Option<usize>,
    config: Option<String>,
    /// 已解析的勾选路径（GUI 本地路径直接填；helper 从 `selected_file` 读出）。
    selected: Option<Vec<String>>,
    /// 勾选清单文件路径（仅 helper 传输用；读入 `selected` 后清空）。
    selected_file: Option<String>,
}

impl RestoreOptions {
    /// 由选项生成 `restore::RestoreRequest`（CLI / helper 共用，C-45）。
    /// Build a `RestoreRequest` from these options (shared by CLI and helper).
    fn to_request(&self, progress: ProgressFn, cancel: Arc<AtomicBool>) -> restore::RestoreRequest {
        restore::RestoreRequest {
            archive: expand_tilde(&self.archive),
            kver: self.kver.clone(),
            dry_run: self.dry_run,
            allow_kernel_mismatch: self.allow_kernel_mismatch,
            allow_arch_mismatch: self.allow_arch_mismatch,
            no_auto_rollback_on_post: self.no_auto_rollback_on_post,
            with_firmware: self.with_firmware,
            root: self.root.as_deref().map(expand_tilde),
            strategy: self.strategy,
            on_immutable: if self.on_immutable {
                restore::ImmutablePolicy::Usroverlay
            } else {
                restore::ImmutablePolicy::Refuse
            },
            strict_links: self.strict_links,
            no_sign: self.no_sign,
            chroot_exec: self.chroot_exec,
            keep_rollback: self.keep_rollback.unwrap_or(restore::DEFAULT_KEEP_ROLLBACK),
            selected: self.selected.clone(),
            progress,
            cancel,
        }
    }
}

/// `--restore`：校验并还原归档。
/// `--restore`: verify and restore an archive.
///
/// CLI 在无 root 且非 `--dry-run` 时**不会**自动 `pkexec`，而是提示用户改用 `sudo`
/// （GUI 才自动提权）；`--dry-run` 不需要 root，始终可执行。
/// Without root, the CLI never auto-elevates (only the GUI does): it tells the user to
/// re-run with sudo. `--dry-run` needs no root and always works.
fn run_cli_restore(mut opts: RestoreOptions) -> i32 {
    let path = expand_tilde(&opts.archive);

    // W7：配置补全默认策略 / 回滚代数（CLI 旗标永远优先）。
    let cfg = match config::Config::load(opts.config.as_deref()) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("参数错误 / invalid arguments: {err}");
            return 2;
        }
    };
    opts.strategy = opts.strategy.or(cfg.strategy);
    opts.keep_rollback = opts.keep_rollback.or(cfg.keep_rollback);

    // 普通权限即可读归档：先 inspect 用于打印确认信息与提示内核不一致。
    let info = match restore::inspect(&path) {
        Ok(info) => info,
        Err(err) => {
            eprintln!("读取归档失败 / cannot read archive: {err}");
            return 1;
        }
    };
    // W7 / §5.2：`--require-verify` 在还原前强制体检（补上 C-06 校验链）。
    // `--require-verify`: integrity check before restoring (closes the C-06 gap).
    if opts.require_verify {
        eprintln!("前置校验 / pre-verify: {}", path.display());
        match verify::verify(&path) {
            Ok(report) if report.ok => {
                eprintln!("  ✓ 校验通过 / passed（{} 条目）", report.entries_total);
            }
            Ok(report) => {
                eprintln!("  ✗ 校验未通过 / FAILED");
                eprintln!("{}", verify::format_report(&report));
                return 1;
            }
            Err(err) => {
                eprintln!("  ✗ 校验失败 / failed: {err}");
                return 1;
            }
        }
    }
    let current_kver = distro::kernel_release();
    let mismatch = info.manifest.kernel_release != current_kver;
    let arch_mismatch = info.manifest.arch != distro::arch();
    // 架构不匹配需独立确认（C-32）：交互式 y/N 确认或 `--allow-arch-mismatch`。
    // Arch mismatch needs its own consent: interactive y/N or `--allow-arch-mismatch`.
    let mut allow_arch_mismatch = opts.allow_arch_mismatch;
    // 预演只读不落盘：放行全部不一致检查，任何归档都应能被体检（与 GUI dry-run 一致）。
    // A dry-run is read-only, so waive every mismatch check: any archive can be previewed.
    if opts.dry_run {
        allow_arch_mismatch = true;
    }

    if !opts.dry_run && !opts.yes {
        println!("即将还原 / about to restore:");
        println!("  归档 / archive : {}", path.display());
        println!(
            "  备份内核 / kernel: {}  当前内核 / current: {}",
            info.manifest.kernel_release, current_kver
        );
        println!(
            "  发行版 / distro: {}（{}）",
            info.manifest.distro.pretty_name,
            info.manifest.mode.label()
        );
        println!(
            "  归档格式 / format: v{}（工具 {}，压缩 {}）",
            info.manifest.format_version,
            info.manifest.tool_version,
            info.manifest.compression.as_deref().unwrap_or("unknown")
        );
        println!("  条目 / entries : {}", info.manifest.entries.len());
        if let Some(st) = opts.strategy {
            // C-48：英文 label 与中文 label_zh 并存，此处消费英文文案。
            println!("  策略 / strategy : {}（{}）", st.label(), st.label_zh());
        }
        println!("  体积 / payload : {}", human_size(info.total_bytes));
        if let Some(vm) = &info.manifest.kernel_vermagic {
            println!("  vermagic       : {vm}");
        }
        if mismatch {
            println!("  ⚠ 内核不一致：默认按当前内核重建（可加 --strategy rebuild 指定策略）");
        }
        if arch_mismatch {
            println!(
                "  ⚠ 架构不一致：归档 {} vs 当前 {}（确认即视为接受，或使用 --allow-arch-mismatch）",
                info.manifest.arch,
                distro::arch()
            );
        }
        print!("确认继续？[y/N] / continue? ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        let mut answer = String::new();
        if std::io::stdin().read_line(&mut answer).is_err() {
            eprintln!("读取标准输入失败 / cannot read stdin");
            return 1;
        }
        let answer = answer.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            println!("已取消 / cancelled");
            return 0;
        }
        // 用户在交互提示中确认 = 接受上方列出的全部不一致项。
        // Answering yes at the prompt counts as accepting every mismatch listed above.
        allow_arch_mismatch = true;
    }

    // 写 `/` 需要 root；`--root <目录>` 离线还原（救援场景）按目录自身权限判定。
    if !opts.dry_run && opts.root.is_none() && !distro::is_root() {
        eprintln!(
            "还原需要 root 权限 / restore requires root：请用 `sudo linux-driver-backup --restore …` 运行，\n\
             或改用图形界面（由 pkexec 弹出系统密码框完成单次提权）；\n\
             离线还原可加 `--root <目录>`（无需 root）。"
        );
        return 1;
    }

    // 交互确认（或 --dry-run 放行）后把架构不一致决议写回选项，再统一构造请求。
    opts.allow_arch_mismatch = allow_arch_mismatch;
    let request = opts.to_request(cli_progress(), Arc::new(AtomicBool::new(false)));

    match restore::run_restore(request) {
        Ok(report) => {
            println!("{}", format_restore_summary(&report));
            for note in &report.notes {
                println!("  - {note}");
            }
            0
        }
        Err(err) => {
            let code = exit_code(&err);
            match &err {
                AppError::Cancelled => eprintln!("已取消 / cancelled"),
                other => eprintln!("还原失败 / restore failed: {other}"),
            }
            code
        }
    }
}

/// `--rollback`：按事务日志回滚最近一次（或指定一次）还原。
/// `--rollback`: undo the most recent (or a specified) restore using its journal.
fn run_cli_rollback(journal: Option<String>, root: Option<String>) -> i32 {
    // 回滚 `/` 需要 root；`--root` 指向用户可写目录时按目录权限自行判定。
    if root.is_none() && !distro::is_root() {
        eprintln!(
            "回滚需要 root 权限 / rollback requires root：请用 `sudo linux-driver-backup --rollback …` 运行。"
        );
        return 1;
    }
    let root_path = root
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| PathBuf::from("/"));
    let journal_path = match journal.as_deref() {
        None | Some("last") => None,
        Some(p) => Some(expand_tilde(p)),
    };

    match restore::run_rollback(&root_path, journal_path.as_deref(), cli_progress()) {
        Ok(report) => {
            println!(
                "回滚完成 / rollback finished: 恢复 {} 个原文件，删除 {} 个新增文件",
                report.restored, report.removed
            );
            for note in &report.notes {
                println!("  - {note}");
            }
            0
        }
        Err(err) => {
            let code = exit_code(&err);
            match &err {
                AppError::Cancelled => eprintln!("已取消 / cancelled"),
                other => eprintln!("回滚失败 / rollback failed: {other}"),
            }
            code
        }
    }
}

/// `--helper-restore`：`pkexec` 以 root 重入的无 GUI 分支，按行协议回传。
/// `--helper-restore`: the GUI-less, root-only re-entry driven by pkexec.
#[allow(clippy::too_many_arguments)]
fn run_helper(mut opts: RestoreOptions) -> i32 {
    let sink_progress = privilege::HelperSink::new();
    let sink_result = privilege::HelperSink::new();

    // ---- C-07 helper 自证：特权入口必须自证合法性 ----
    // Helper self-attestation: the privileged entry point must prove its context.
    let euid = unsafe { geteuid() };
    if euid != 0 {
        sink_result.result(
            false,
            "helper 必须以 root 运行 / helper must run as root (euid != 0)",
        );
        return 1;
    }
    // pkexec 路径：PKEXEC_UID 应为发起提权的原始用户 uid；sudo 路径无此变量，
    // euid==0 已由上面断言，正常继续。
    // Under pkexec the caller's uid must be valid; the sudo path has no PKEXEC_UID.
    if let Ok(raw) = std::env::var("PKEXEC_UID") {
        match raw.parse::<u32>() {
            Ok(uid) => sink_progress.note(&format!("提权自调用者 / elevated from uid {uid}")),
            Err(_) => {
                sink_result.result(false, "PKEXEC_UID 非法 / invalid PKEXEC_UID");
                return 1;
            }
        }
    }

    // ---- C-04 取消传播：监听 stdin EOF（父进程取消时关闭写端）----
    // C-04 cancellation: watch stdin for EOF (the parent closes its end on cancel)。
    let cancel = Arc::new(AtomicBool::new(false));
    let restore_started = Arc::new(AtomicBool::new(false));
    {
        let cancel = Arc::clone(&cancel);
        let started = Arc::clone(&restore_started);
        std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin();
            let mut byte = [0u8; 1];
            loop {
                match stdin.read(&mut byte) {
                    // EOF：仅在还原已开始后才视为取消，避免 `--helper-restore < /dev/null`
                    // 这类手动调用在启动前就被误取消。
                    // EOF cancels only after the restore has started, so a redirected
                    // stdin (`< /dev/null`) never cancels a manual invocation.
                    Ok(0) => {
                        if started.load(Ordering::SeqCst) {
                            cancel.store(true, Ordering::SeqCst);
                        }
                        break;
                    }
                    Ok(_) => { /* 保留字节读取以便未来握手；当前父进程只保持管道打开 */
                    }
                    Err(_) => break,
                }
            }
        });
    }

    let progress: ProgressFn = Arc::new(move |value: f32, msg: String| {
        sink_progress.progress(value, &msg);
    });

    // W6/P1-5：勾选清单由 GUI 写入临时文件经参数传来（避免超长 argv）。
    opts.selected = match opts.selected_file.take() {
        Some(raw) => {
            let path = expand_tilde(&raw);
            match std::fs::read_to_string(&path) {
                Ok(text) => Some(
                    text.lines()
                        .map(str::trim)
                        .filter(|line| !line.is_empty())
                        .map(str::to_string)
                        .collect::<Vec<_>>(),
                ),
                Err(err) => {
                    sink_result.result(
                        false,
                        &format!("无法读取 --selected-file / cannot read selection: {err}"),
                    );
                    return 1;
                }
            }
        }
        None => None,
    };

    let request = opts.to_request(progress, Arc::clone(&cancel)); // C-04：与 EOF 监听共享 cancel

    restore_started.store(true, Ordering::SeqCst);
    match restore::run_restore(request) {
        Ok(report) => {
            let message = format_restore_summary(&report);
            for note in &report.notes {
                sink_result.note(note);
            }
            sink_result.result(true, &message);
            0
        }
        Err(AppError::Cancelled) => {
            // §5.3 行协议：取消以 RESULT FAIL 已取消 回传，退出码 0（用户主动取消）。
            // Protocol: cancellation reports `RESULT FAIL\t已取消`, exit 0 (W0-C33).
            sink_result.result(false, "已取消");
            0
        }
        Err(err) => {
            sink_result.result(false, &err.to_string());
            1
        }
    }
}

/// `--helper-rollback`：`pkexec` 以 root 重入的无 GUI 回滚分支（W6 回滚入口）。
/// `--helper-rollback`: the GUI-less root re-entry used to roll back the last restore.
fn run_helper_rollback(journal: Option<String>, root: Option<String>) -> i32 {
    let sink_progress = privilege::HelperSink::new();
    let sink_result = privilege::HelperSink::new();

    // C-07：特权入口必须自证合法性（与 `--helper-restore` 同一标准）。
    let euid = unsafe { geteuid() };
    if euid != 0 {
        sink_result.result(
            false,
            "helper 必须以 root 运行 / helper must run as root (euid != 0)",
        );
        return 1;
    }
    if let Ok(raw) = std::env::var("PKEXEC_UID") {
        if raw.parse::<u32>().is_err() {
            sink_result.result(false, "PKEXEC_UID 非法 / invalid PKEXEC_UID");
            return 1;
        }
    }

    let root_path = root
        .as_deref()
        .map(expand_tilde)
        .unwrap_or_else(|| PathBuf::from("/"));
    let journal_path = journal.as_deref().map(expand_tilde);
    let progress: ProgressFn = Arc::new(move |value: f32, msg: String| {
        sink_progress.progress(value, &msg);
    });

    match restore::run_rollback(&root_path, journal_path.as_deref(), progress) {
        Ok(report) => {
            for note in &report.notes {
                sink_result.note(note);
            }
            sink_result.result(
                true,
                &format!(
                    "回滚完成：恢复 {} 个文件，删除 {} 个链接",
                    report.restored, report.removed
                ),
            );
            0
        }
        Err(err) => {
            sink_result.result(false, &err.to_string());
            exit_code(&err)
        }
    }
}

// helper 自证所需的 `geteuid(2)`（裸 extern，避免为单个符号引入 libc 依赖）。
// `geteuid(2)` for helper self-attestation (bare extern; no libc dependency).
extern "C" {
    fn geteuid() -> u32;
}

// ===========================================================================
// GUI 模式 / GUI mode
// ===========================================================================

/// W6：打开“选择归档”原生对话框（需 `gui-dialogs` 特性）。
/// Open the native "pick archive" dialog (requires the `gui-dialogs` feature).
#[cfg(feature = "gui-dialogs")]
fn pick_archive(ui: &AppWindow) {
    let mut dialog = rfd::FileDialog::new().add_filter("驱动备份归档", &["gz", "tgz", "tar.gz"]);
    if let Some(home) = std::env::var_os("HOME") {
        dialog = dialog.set_directory(home);
    }
    let Some(path) = dialog.pick_file() else {
        return;
    };
    // 前置校验：归档必须存在（避免运行到一半才失败）。
    if !path.is_file() {
        ui.set_status_text(format!("所选归档不存在：{}", path.display()).into());
        return;
    }
    ui.set_archive_path(path.to_string_lossy().to_string().into());
    ui.set_status_text(format!("已选择归档：{}", path.display()).into());
}

/// 无 `gui-dialogs` 特性时的回退：提示手动输入。
#[cfg(not(feature = "gui-dialogs"))]
fn pick_archive(ui: &AppWindow) {
    ui.set_status_text("此构建未包含文件对话框，请手动输入归档路径。".into());
}

/// W6：打开“选择输出路径”原生保存对话框（需 `gui-dialogs` 特性）。
#[cfg(feature = "gui-dialogs")]
fn pick_out_path(ui: &AppWindow) {
    let kver = distro::kernel_release();
    let default_name = backup::default_out_path(&kver)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("driver-backup-{kver}.tar.gz"));
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(default_name)
        .add_filter("驱动备份归档", &["gz"])
        .save_file()
    else {
        return;
    };
    // 前置校验：父目录必须存在（可写性交给实际写入阶段报错）。
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            ui.set_status_text(format!("输出目录不存在：{}", parent.display()).into());
            return;
        }
    }
    ui.set_out_path(path.to_string_lossy().to_string().into());
    ui.set_status_text(format!("备份将输出到：{}", path.display()).into());
}

/// 无 `gui-dialogs` 特性时的回退：提示手动输入。
#[cfg(not(feature = "gui-dialogs"))]
fn pick_out_path(ui: &AppWindow) {
    ui.set_status_text("此构建未包含文件对话框，请手动输入输出路径。".into());
}

/// 启动 Slint 图形界面并绑定 4 个冻结回调。
/// Launch the Slint GUI and wire the four frozen callbacks.
fn run_gui() -> AppResult<()> {
    let app = AppWindow::new().map_err(|err| {
        AppError::Privilege(format!(
            "无法初始化图形界面（缺少显示服务器或窗口系统库？）：{err}"
        ))
    })?;

    // W7：GUI 读取配置补全固件策略 / 回滚代数（GUI 没有 CLI 旗标，配置即默认）。
    let gui_cfg = config::Config::load(None).unwrap_or_default();

    // ---- 启动时的静态信息 ----
    let kver = distro::kernel_release();
    let info = DistroInfo::detect();
    app.set_system_info(
        format!(
            "内核 / kernel {} · {} · 架构 {} · {} · 发行版 {} {}",
            kver,
            info,
            distro::arch(),
            if distro::is_root() {
                "root"
            } else {
                "普通用户"
            },
            info.id,
            info.version_id
        )
        .into(),
    );
    app.set_out_path(
        backup::default_out_path(&kver)
            .to_string_lossy()
            .to_string()
            .into(),
    );

    // ---- 跨回调共享状态 ----
    let running = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));

    // ---- 回调 1：扫描 ----
    {
        let weak = app.as_weak();
        let running = Arc::clone(&running);
        let cancel = Arc::clone(&cancel);
        app.on_refresh_scan(move || {
            let Some(ui) = weak.upgrade() else { return };
            if !begin_task(&ui, &running, &cancel, "正在扫描外置驱动模块…") {
                return;
            }
            let mode = BackupMode::from_index(ui.get_mode_index());
            let weak_thread = weak.clone();
            let running_thread = Arc::clone(&running);
            let cancel_thread = Arc::clone(&cancel);
            std::thread::spawn(move || {
                let kver = distro::kernel_release();
                let info = DistroInfo::detect();
                let options = ScanOptions {
                    kver: &kver,
                    distro: &info,
                    mode,
                    cancel: Some(&cancel_thread),
                };
                let outcome = scan::scan(&options);
                let _ = weak_thread.upgrade_in_event_loop(move |ui| {
                    running_thread.store(false, Ordering::SeqCst);
                    ui.set_busy(false);
                    match outcome {
                        Ok(report) => {
                            ui.set_warnings_text(warnings_panel_text(&report.warnings).into());
                            let (rows, truncated, total) = to_module_items(&report);
                            let modules = report
                                .entries
                                .iter()
                                .filter(|e| e.kind == EntryKind::Module)
                                .count();
                            let dkms = report
                                .entries
                                .iter()
                                .filter(|e| e.kind == EntryKind::Dkms)
                                .count();
                            let configs = report
                                .entries
                                .iter()
                                .filter(|e| e.kind == EntryKind::Config)
                                .count();
                            ui.set_modules(ModelRc::new(VecModel::from(rows)));
                            ui.set_progress(1.0);
                            let firmware = if report.firmware_bytes > 0 {
                                format!(" · 固件 {}", human_size(report.firmware_bytes))
                            } else {
                                String::new()
                            };
                            let truncated_note = if truncated {
                                format!("（列表仅显示前 500 条，共 {total} 条）")
                            } else {
                                String::new()
                            };
                            ui.set_status_text(
                                format!(
                                    "扫描完成：模块 {modules} · DKMS {dkms} · 配置 {configs}{firmware}\
                                     ；in-tree 跳过 {} 个{truncated_note}",
                                    report.skipped_in_tree
                                )
                                .into(),
                            );
                        }
                        Err(err) => {
                            ui.set_progress(0.0);
                            ui.set_warnings_text("".into());
                            ui.set_status_text(format!("扫描失败：{err}").into());
                        }
                    }
                });
            });
        });
    }

    // ---- 回调 2：备份 ----
    {
        let weak = app.as_weak();
        let running = Arc::clone(&running);
        let cancel = Arc::clone(&cancel);
        let gui_firmware = gui_cfg.firmware.clone();
        app.on_start_backup(move || {
            let Some(ui) = weak.upgrade() else { return };
            let out = ui.get_out_path().to_string();
            let kver = distro::kernel_release();
            let out_path = if out.trim().is_empty() {
                backup::default_out_path(&kver)
            } else {
                expand_tilde(out.trim())
            };
            if !begin_task(
                &ui,
                &running,
                &cancel,
                &format!("正在打包驱动到 {}…", out_path.display()),
            ) {
                return;
            }
            let mode = BackupMode::from_index(ui.get_mode_index());
            let progress = gui_progress(weak.clone());
            let weak_thread = weak.clone();
            let running_thread = Arc::clone(&running);
            let cancel_thread = Arc::clone(&cancel);
            // 内层线程 move 捕获，先克隆避免把 FnMut 闭包捕获的变量移走。
            let gui_firmware = gui_firmware.clone();
            std::thread::spawn(move || {
                let request = backup::BackupRequest {
                    out_file: out_path,
                    kver,
                    distro: DistroInfo::detect(),
                    mode,
                    progress,
                    firmware_policy: gui_firmware.clone(),
                    cancel: Arc::clone(&cancel_thread),
                };
                match backup::run_backup(request) {
                    Ok(report) => {
                        let message = format_backup_summary(&report);
                        let archive = report.out_file.to_string_lossy().to_string();
                        let running_finish = Arc::clone(&running_thread);
                        let _ = weak_thread.upgrade_in_event_loop(move |ui| {
                            ui.set_archive_path(archive.into());
                            running_finish.store(false, Ordering::SeqCst);
                            ui.set_busy(false);
                            ui.set_progress(1.0);
                            ui.set_status_text(message.into());
                        });
                    }
                    Err(AppError::Cancelled) => {
                        finish_gui(
                            &weak_thread,
                            &running_thread,
                            false,
                            "备份已取消。".to_string(),
                        );
                    }
                    Err(err) => {
                        finish_gui(
                            &weak_thread,
                            &running_thread,
                            false,
                            format!("备份失败：{err}"),
                        );
                    }
                }
            });
        });
    }

    // ---- 回调 3：还原 ----
    {
        let weak = app.as_weak();
        let running = Arc::clone(&running);
        let cancel = Arc::clone(&cancel);
        let gui_keep_rollback = gui_cfg
            .keep_rollback
            .unwrap_or(restore::DEFAULT_KEEP_ROLLBACK);
        app.on_start_restore(move || {
            let Some(ui) = weak.upgrade() else { return };
            let archive = ui.get_archive_path().to_string().trim().to_string();
            if archive.is_empty() {
                ui.set_status_text("请先填写还原归档路径。".into());
                return;
            }
            let dry_run = ui.get_dry_run();
            // W6：GUI 能力对齐 CLI —— 策略与安全开关。
            let strategy = match ui.get_strategy_index() {
                1 => Some(RestoreStrategy::Rebuild),
                2 => Some(RestoreStrategy::Reinstall),
                3 => Some(RestoreStrategy::WeakModules),
                4 => Some(RestoreStrategy::Copy),
                _ => None,
            };
            let strict_links = ui.get_strict_links();
            let no_sign = ui.get_no_sign();
            let on_immutable = ui.get_on_immutable();
            // W6/P1-5：把勾选（含依赖闭包）固化；全部选中时为 None（整档还原）。
            let gui_selected = selected_paths(&ui);
            let path = expand_tilde(&archive);

            // 真实还原（非 dry-run）且尚未确认 → 先只读 inspect，再弹确认框（C-35）。
            // A real restore (not dry-run) without acknowledgement: read-only inspect,
            // then show the confirmation dialog (C-35).
            if !dry_run && !ui.get_restore_ack() {
                if ui.get_confirm_visible() || running.swap(true, Ordering::SeqCst) {
                    ui.set_status_text("已有任务正在运行，或确认框已打开。".into());
                    return;
                }
                ui.set_status_text("正在读取归档信息…".into());
                let weak_inspect = weak.clone();
                let running_inspect = Arc::clone(&running);
                let path_inspect = path.clone();
                std::thread::spawn(move || {
                    let outcome = restore::inspect(&path_inspect).map(|info| {
                        let manifest = &info.manifest;
                        let current_kver = distro::kernel_release();
                        let mut detail = String::new();
                        detail.push_str(&format!("归档：{}\n", path_inspect.display()));
                        detail.push_str(&format!(
                            "备份内核：{}　当前内核：{}\n",
                            manifest.kernel_release, current_kver
                        ));
                        if manifest.kernel_release != current_kver {
                            detail.push_str("⚠ 跨内核：确认后将按当前内核重建（DKMS 优先）\n");
                        }
                        detail.push_str(&format!(
                            "归档架构：{}　当前架构：{}\n",
                            manifest.arch,
                            distro::arch()
                        ));
                        if manifest.arch != distro::arch() {
                            detail.push_str("⚠ 架构不一致：错误架构的模块通常无法加载！\n");
                        }
                        detail.push_str(&format!(
                            "发行版：{}（模式 {}）\n",
                            manifest.distro.pretty_name,
                            manifest.mode.label()
                        ));
                        detail.push_str(&format!(
                            "条目：{}　体积：{}\n",
                            manifest.entries.len(),
                            human_size(info.total_bytes)
                        ));
                        detail.push_str(
                            "\n⚠ 确认后将以 root 权限写入系统目录（/lib/modules 等）。\n\
                             还原可用 `--rollback last` 撤销上一次。",
                        );
                        detail
                    });
                    let _ = weak_inspect.upgrade_in_event_loop(move |ui| {
                        running_inspect.store(false, Ordering::SeqCst);
                        match outcome {
                            Ok(detail) => {
                                ui.set_confirm_detail(detail.as_str().into());
                                ui.set_confirm_visible(true);
                                ui.set_status_text("请确认还原操作。".into());
                            }
                            Err(err) => {
                                ui.set_status_text(format!("读取归档失败：{err}").as_str().into());
                            }
                        }
                    });
                });
                return;
            }
            ui.set_restore_ack(false);

            if !begin_task(
                &ui,
                &running,
                &cancel,
                if dry_run {
                    "正在预演还原（不写盘）…"
                } else {
                    "正在准备还原…"
                },
            ) {
                return;
            }
            let progress = gui_progress(weak.clone());
            let weak_thread = weak.clone();
            let running_thread = Arc::clone(&running);
            let cancel_thread = Arc::clone(&cancel);
            std::thread::spawn(move || {
                let current_kver = distro::kernel_release();

                // 先只读 inspect：普通权限即可，失败直接回写状态。
                let inspected = match restore::inspect(&path) {
                    Ok(info) => info,
                    Err(err) => {
                        finish_gui(
                            &weak_thread,
                            &running_thread,
                            false,
                            format!("读取归档失败：{err}"),
                        );
                        return;
                    }
                };
                let same_kernel = inspected.manifest.kernel_release == current_kver;

                if dry_run {
                    let request = restore::RestoreRequest {
                        archive: path.clone(),
                        kver: None,
                        dry_run: true,
                        // 预演无副作用：允许跨内核/跨架构预览，附带提示信息。
                        allow_kernel_mismatch: true,
                        no_auto_rollback_on_post: false, // GUI 不暴露该逃生口（仅 CLI）
                        allow_arch_mismatch: true,
                        with_firmware: true,
                        root: None,
                        strategy,
                        on_immutable: if on_immutable {
                            restore::ImmutablePolicy::Usroverlay
                        } else {
                            restore::ImmutablePolicy::Refuse
                        },
                        strict_links,
                        no_sign: true, // 预演不写盘、不签名
                        chroot_exec: false,
                        keep_rollback: gui_keep_rollback,
                        selected: gui_selected.clone(),
                        progress,
                        cancel: Arc::clone(&cancel_thread),
                    };
                    match restore::run_restore(request) {
                        Ok(report) => {
                            let mut message = format!(
                                "预演完成（未写盘）：将写入 {} 个文件 + {} 个链接（共 {}），跳过 {} 个",
                                report.written,
                                report.links_written,
                                human_size(inspected.total_bytes),
                                report.skipped
                            );
                            if !same_kernel {
                                message.push_str(&format!(
                                    "；⚠ 归档内核 {} 与当前 {current_kver} 不一致",
                                    inspected.manifest.kernel_release
                                ));
                            }
                            for note in report.notes.iter().take(3) {
                                message.push_str(&format!("；{note}"));
                            }
                            finish_gui(&weak_thread, &running_thread, true, message);
                        }
                        Err(err) => finish_gui(
                            &weak_thread,
                            &running_thread,
                            false,
                            format!("预演失败：{err}"),
                        ),
                    }
                    return;
                }

                // 真实还原：root 直接做；否则 pkexec 单次提权重入本二进制。
                let outcome: AppResult<String> = if distro::is_root() {
                    let request = restore::RestoreRequest {
                        archive: path.clone(),
                        kver: None,
                        dry_run: false,
                        allow_kernel_mismatch: false,
                        // 能走到这里说明用户已在确认框点"确认还原"（C-35），
                        // 架构不一致的警告已列在确认框详情里，视为已确认（C-32）。
                        no_auto_rollback_on_post: false, // GUI 不暴露该逃生口（仅 CLI）
                        allow_arch_mismatch: true,
                        with_firmware: true,
                        root: None,
                        strategy,
                        on_immutable: if on_immutable {
                            restore::ImmutablePolicy::Usroverlay
                        } else {
                            restore::ImmutablePolicy::Refuse
                        },
                        strict_links,
                        no_sign,
                        chroot_exec: false,
                        keep_rollback: gui_keep_rollback,
                        selected: gui_selected.clone(),
                        progress,
                        cancel: Arc::clone(&cancel_thread),
                    };
                    restore::run_restore(request).map(|report| {
                        format!(
                            "还原完成：写入 {} 个文件 + {} 个链接，跳过 {} 个；重建 {}，重装 {}，签名 {}；depmod={}，initramfs={}",
                            report.written,
                            report.links_written,
                            report.skipped,
                            report.rebuilt,
                            report.reinstalled,
                            report.signed,
                            report.depmod_done,
                            match report.initramfs_done {
                                Some(true) => "已更新",
                                Some(false) => "失败",
                                None => "已跳过",
                            }
                        )
                    })
                } else if !distro::pkexec_available() {
                    Err(AppError::Privilege(
                        "未找到 pkexec（polkit 未安装或不可用），无法自动提权。\
                         请在终端执行：sudo linux-driver-backup --restore --archive <归档>"
                            .to_string(),
                    ))
                } else {
                    // C-31：不再向 helper 传归档内核 —— helper（联网、root=None）会按
                    // 新默认语义"以当前内核为目标"执行重建；旧分支传的正是默认值，是死逻辑。
                    // C-31: no `--kver` here — the helper defaults to the current kernel
                    // (rebuild-first); the old branch passed the default value, i.e. dead logic.
                    let mut args = vec![
                        "--archive".to_string(),
                        path.to_string_lossy().to_string(),
                        "--with-firmware".to_string(),
                        // 确认框已展示架构差异并获得用户确认（C-32/C-35）。
                        "--allow-arch-mismatch".to_string(),
                        "--keep-rollback".to_string(),
                        gui_keep_rollback.to_string(),
                    ];
                    // W6：把 GUI 的策略与安全开关透传给提权 helper。
                    if let Some(strategy) = strategy {
                        args.push("--strategy".to_string());
                        args.push(strategy_token(strategy).to_string());
                    }
                    if strict_links {
                        args.push("--strict-links".to_string());
                    }
                    if no_sign {
                        args.push("--no-sign".to_string());
                    }
                    if on_immutable {
                        args.push("--on-immutable".to_string());
                        args.push("usroverlay".to_string());
                    }
                    // W6/P1-5：勾选清单写入临时文件，经 `--selected-file` 传给 root helper，
                    // 运行结束后删除（避免超长 argv）。
                    let selected_file = gui_selected.as_ref().map(|list| {
                        let nonce = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_nanos())
                            .unwrap_or(0);
                        let file =
                            std::env::temp_dir().join(format!(
                                "ldb-selected-{}-{nonce:x}.txt",
                                std::process::id()
                            ));
                        std::fs::write(&file, list.join("\n")).map(|_| file)
                    });
                    if let Some(Ok(file)) = &selected_file {
                        args.push("--selected-file".to_string());
                        args.push(file.to_string_lossy().into_owned());
                    }
                    let result = privilege::run_helper_via_pkexec(
                        &args,
                        progress,
                        Arc::clone(&cancel_thread),
                    );
                    if let Some(Ok(file)) = selected_file {
                        let _ = std::fs::remove_file(file);
                    }
                    result
                };

                match outcome {
                    Ok(message) => finish_gui(&weak_thread, &running_thread, true, message),
                    Err(AppError::Cancelled) => {
                        finish_gui(&weak_thread, &running_thread, false, "还原已取消。".to_string())
                    }
                    Err(err) => finish_gui(
                        &weak_thread,
                        &running_thread,
                        false,
                        format!("还原失败：{err}"),
                    ),
                }
            });
        });
    }

    // ---- 回调 3b：W6 文件对话框（rfd）/ 诊断包 / 回滚入口 ----
    {
        let weak = app.as_weak();
        app.on_pick_archive(move || {
            if let Some(ui) = weak.upgrade() {
                pick_archive(&ui);
            }
        });
    }
    {
        let weak = app.as_weak();
        app.on_pick_out_path(move || {
            if let Some(ui) = weak.upgrade() {
                pick_out_path(&ui);
            }
        });
    }
    {
        let weak = app.as_weak();
        let running = Arc::clone(&running);
        app.on_diagnose(move || {
            let Some(ui) = weak.upgrade() else { return };
            if running.swap(true, Ordering::SeqCst) {
                ui.set_status_text("已有任务正在运行。".into());
                return;
            }
            ui.set_busy(true);
            ui.set_progress(0.0);
            ui.set_status_text("正在生成脱敏诊断包…".into());
            let weak_thread = weak.clone();
            let running_thread = Arc::clone(&running);
            std::thread::spawn(move || {
                let outcome = diagnose::run(None);
                let _ = weak_thread.upgrade_in_event_loop(move |ui| {
                    running_thread.store(false, Ordering::SeqCst);
                    ui.set_busy(false);
                    ui.set_progress(1.0);
                    match outcome {
                        Ok(path) => {
                            ui.set_status_text(format!("诊断包已生成：{}", path.display()).into())
                        }
                        Err(err) => {
                            ui.set_status_text(format!("诊断收集失败：{err}").into());
                        }
                    }
                });
            });
        });
    }
    {
        let weak = app.as_weak();
        let running = Arc::clone(&running);
        let cancel = Arc::clone(&cancel);
        app.on_rollback(move || {
            let Some(ui) = weak.upgrade() else { return };
            if !begin_task(&ui, &running, &cancel, "正在回滚上一次还原…") {
                return;
            }
            let progress = gui_progress(weak.clone());
            let weak_thread = weak.clone();
            let running_thread = Arc::clone(&running);
            let cancel_thread = Arc::clone(&cancel);
            std::thread::spawn(move || {
                let outcome: AppResult<String> = if distro::is_root() {
                    restore::run_rollback(Path::new("/"), None, progress).map(|report| {
                        format!(
                            "回滚完成：恢复 {} 个文件，删除 {} 个链接",
                            report.restored, report.removed
                        )
                    })
                } else if !distro::pkexec_available() {
                    Err(AppError::Privilege(
                        "未找到 pkexec（polkit 未安装或不可用），无法自动提权。\
                         请在终端执行：sudo linux-driver-backup --rollback last"
                            .to_string(),
                    ))
                } else {
                    // W6：提权重入本二进制执行回滚（与还原同一 pkexec 机制）。
                    privilege::run_helper_via_pkexec_with(
                        privilege::ROLLBACK_FLAG,
                        &[],
                        progress,
                        Arc::clone(&cancel_thread),
                    )
                };
                match outcome {
                    Ok(message) => finish_gui(&weak_thread, &running_thread, true, message),
                    Err(AppError::Cancelled) => finish_gui(
                        &weak_thread,
                        &running_thread,
                        false,
                        "回滚已取消。".to_string(),
                    ),
                    Err(err) => finish_gui(
                        &weak_thread,
                        &running_thread,
                        false,
                        format!("回滚失败：{err}"),
                    ),
                }
            });
        });
    }

    // ---- 回调 4：确认框 —— 用户点击"确认还原"（C-35） ----
    {
        let weak = app.as_weak();
        app.on_confirm_restore(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_confirm_visible(false);
            ui.set_restore_ack(true);
            // 重新进入 start-restore：此时 restore-ack 为真，直接走真实还原分支。
            // Re-enter start-restore: with restore-ack set it proceeds to the real run.
            ui.invoke_start_restore();
        });
    }

    // ---- 回调 5：确认框 —— 用户点击"取消"（C-35） ----
    {
        let weak = app.as_weak();
        app.on_dismiss_confirm(move || {
            let Some(ui) = weak.upgrade() else { return };
            ui.set_confirm_visible(false);
            ui.set_status_text("已取消还原（未做任何改动）。".into());
        });
    }

    // ---- 回调 6：取消 ----
    {
        let weak = app.as_weak();
        let cancel = Arc::clone(&cancel);
        app.on_cancel(move || {
            let Some(ui) = weak.upgrade() else { return };
            cancel.store(true, Ordering::SeqCst);
            ui.set_status_text("正在取消，请稍候…".into());
        });
    }

    app.run()
        .map_err(|err| AppError::Privilege(format!("图形界面事件循环异常退出：{err}")))
}

// ===========================================================================
// 入口 / Entry point
// ===========================================================================

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = match parse_args(&args) {
        Ok(command) => command,
        Err(err) => {
            eprintln!("参数错误 / invalid arguments: {err}\n");
            eprintln!("{}", usage());
            std::process::exit(2);
        }
    };

    let code = match command {
        Cmd::Help => {
            println!("{}", usage());
            0
        }
        Cmd::Version => {
            println!("linux-driver-backup {}", env!("CARGO_PKG_VERSION"));
            0
        }
        Cmd::Scan { mode, json, config } => run_cli_scan(mode, json, config),
        Cmd::Backup {
            out,
            mode,
            kver,
            firmware,
            config,
        } => run_cli_backup(out, mode, kver, firmware, config),
        Cmd::Restore {
            archive,
            dry_run,
            yes,
            with_firmware,
            allow_kernel_mismatch,
            allow_arch_mismatch,
            root,
            strategy,
            on_immutable,
            strict_links,
            no_sign,
            chroot_exec,
            require_verify,
            no_auto_rollback_on_post,
            keep_rollback,
            config,
        } => run_cli_restore(RestoreOptions {
            archive,
            dry_run,
            yes,
            with_firmware,
            allow_kernel_mismatch,
            allow_arch_mismatch,
            root,
            strategy,
            on_immutable,
            strict_links,
            no_sign,
            chroot_exec,
            require_verify,
            no_auto_rollback_on_post,
            keep_rollback,
            config,
            kver: None,
            selected: None,
            selected_file: None,
        }),
        Cmd::Rollback { journal, root } => run_cli_rollback(journal, root),
        Cmd::Helper {
            archive,
            kver,
            with_firmware,
            allow_kernel_mismatch,
            allow_arch_mismatch,
            root,
            strategy,
            on_immutable,
            strict_links,
            no_sign,
            chroot_exec,
            keep_rollback,
            selected_file,
        } => run_helper(RestoreOptions {
            archive,
            kver,
            dry_run: false,
            yes: false,
            with_firmware,
            allow_kernel_mismatch,
            allow_arch_mismatch,
            root,
            strategy,
            on_immutable,
            strict_links,
            no_sign,
            chroot_exec,
            require_verify: false,
            no_auto_rollback_on_post: false,
            keep_rollback,
            config: None,
            selected: None,
            selected_file,
        }),
        Cmd::Verify { archive, json } => run_cli_verify(archive, json),
        Cmd::Diagnose { out } => run_cli_diagnose(out),
        Cmd::HelperRollback { journal, root } => run_helper_rollback(journal, root),
        Cmd::Gui => match run_gui() {
            Ok(()) => 0,
            Err(err) => {
                eprintln!("GUI 启动失败 / GUI failed: {err}");
                1
            }
        },
    };

    std::process::exit(code);
}

// ===========================================================================
// 单元测试 / Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn restore_options_to_request_maps_all_fields() {
        // C-45：CLI / helper 共用同一结构体与同一转换；此处覆盖全部字段映射。
        let opts = RestoreOptions {
            archive: "~/a.tar.gz".to_string(),
            kver: Some("6.8.0".to_string()),
            dry_run: false,
            yes: false,
            with_firmware: true,
            allow_kernel_mismatch: true,
            allow_arch_mismatch: true,
            root: Some("~/mnt".to_string()),
            strategy: Some(RestoreStrategy::Rebuild),
            on_immutable: true,
            strict_links: true,
            no_sign: true,
            chroot_exec: true,
            require_verify: false,
            no_auto_rollback_on_post: true,
            keep_rollback: Some(7),
            config: None,
            selected: Some(vec!["lib/modules/x/a.ko".to_string()]),
            selected_file: None,
        };
        let req = opts.to_request(
            Arc::new(|_v: f32, _m: String| {}),
            Arc::new(AtomicBool::new(false)),
        );
        assert!(req.archive.ends_with("a.tar.gz"));
        assert_eq!(req.kver.as_deref(), Some("6.8.0"));
        assert!(req.with_firmware && req.allow_kernel_mismatch && req.allow_arch_mismatch);
        assert!(req.root.is_some());
        assert_eq!(req.strategy, Some(RestoreStrategy::Rebuild));
        assert!(matches!(
            req.on_immutable,
            restore::ImmutablePolicy::Usroverlay
        ));
        assert!(req.strict_links && req.no_sign && req.chroot_exec);
        assert!(req.no_auto_rollback_on_post);
        assert_eq!(req.keep_rollback, 7);
        assert_eq!(
            req.selected.as_deref(),
            Some(&["lib/modules/x/a.ko".to_string()][..])
        );
    }

    #[test]
    fn no_arguments_launches_gui() {
        assert_eq!(parse_args(&args(&[])).unwrap(), Cmd::Gui);
    }

    #[test]
    fn help_and_version_are_recognised() {
        assert_eq!(parse_args(&args(&["--help"])).unwrap(), Cmd::Help);
        assert_eq!(parse_args(&args(&["-h"])).unwrap(), Cmd::Help);
        assert_eq!(parse_args(&args(&["--version"])).unwrap(), Cmd::Version);
        assert_eq!(parse_args(&args(&["-V"])).unwrap(), Cmd::Version);
    }

    #[test]
    fn scan_defaults_and_flags() {
        assert_eq!(
            parse_args(&args(&["--scan"])).unwrap(),
            Cmd::Scan {
                mode: None,
                json: false,
                config: None,
            }
        );
        assert_eq!(
            parse_args(&args(&["--scan", "--mode", "full", "--json"])).unwrap(),
            Cmd::Scan {
                mode: Some(BackupMode::Full),
                json: true,
                config: None,
            }
        );
        assert_eq!(
            parse_args(&args(&["--scan", "--mode=minimal"])).unwrap(),
            Cmd::Scan {
                mode: Some(BackupMode::Minimal),
                json: false,
                config: None,
            }
        );
    }

    #[test]
    fn backup_parses_options_and_allows_out_from_config() {
        // W7：`--backup` 不再在解析期要求 `--out`（可由配置 out_dir 补全），执行期才判空。
        assert_eq!(
            parse_args(&args(&["--backup"])).unwrap(),
            Cmd::Backup {
                out: None,
                mode: None,
                kver: None,
                firmware: None,
                config: None,
            }
        );
        assert_eq!(
            parse_args(&args(&["--backup", "--out", "/tmp/a.tar.gz"])).unwrap(),
            Cmd::Backup {
                out: Some("/tmp/a.tar.gz".to_string()),
                mode: None,
                kver: None,
                firmware: None,
                config: None,
            }
        );
        assert_eq!(
            parse_args(&args(&[
                "--backup",
                "--out=/tmp/b.tar.gz",
                "--mode",
                "minimal",
                "--kver",
                "6.8.0-45-generic",
                "--firmware",
                "needed",
                "--config",
                "/etc/ldb.toml"
            ]))
            .unwrap(),
            Cmd::Backup {
                out: Some("/tmp/b.tar.gz".to_string()),
                mode: Some(BackupMode::Minimal),
                kver: Some("6.8.0-45-generic".to_string()),
                firmware: Some("needed".to_string()),
                config: Some("/etc/ldb.toml".to_string()),
            }
        );
        assert!(parse_args(&args(&["--backup", "--firmware", "yes"])).is_err());
    }

    #[test]
    fn restore_flags_are_parsed() {
        assert!(parse_args(&args(&["--restore"])).is_err());
        assert_eq!(
            parse_args(&args(&[
                "--restore",
                "--archive",
                "/tmp/a.tar.gz",
                "--dry-run",
                "--yes",
                "--with-firmware",
                "--allow-kernel-mismatch"
            ]))
            .unwrap(),
            Cmd::Restore {
                archive: "/tmp/a.tar.gz".to_string(),
                dry_run: true,
                yes: true,
                with_firmware: true,
                allow_kernel_mismatch: true,
                allow_arch_mismatch: false,
                root: None,
                strategy: None,
                on_immutable: false,
                strict_links: false,
                no_sign: false,
                chroot_exec: false,
                require_verify: false,
                no_auto_rollback_on_post: false,
                keep_rollback: None,
                config: None
            }
        );
    }

    #[test]
    fn restore_v2_flags_are_parsed() {
        assert_eq!(
            parse_args(&args(&[
                "--restore",
                "--archive",
                "/tmp/a.tar.gz",
                "--root",
                "/mnt/target",
                "--strategy",
                "rebuild",
                "--on-immutable",
                "usroverlay",
                "--strict-links",
                "--no-sign",
                "--chroot-exec"
            ]))
            .unwrap(),
            Cmd::Restore {
                archive: "/tmp/a.tar.gz".to_string(),
                dry_run: false,
                yes: false,
                with_firmware: false,
                allow_kernel_mismatch: false,
                allow_arch_mismatch: false,
                root: Some("/mnt/target".to_string()),
                strategy: Some(RestoreStrategy::Rebuild),
                on_immutable: true,
                strict_links: true,
                no_sign: true,
                chroot_exec: true,
                require_verify: false,
                no_auto_rollback_on_post: false,
                keep_rollback: None,
                config: None
            }
        );
        // `--strategy auto` 等价于自动决策（None）
        assert_eq!(
            parse_args(&args(&["--restore", "--archive", "a", "--strategy=auto"])).unwrap(),
            Cmd::Restore {
                archive: "a".to_string(),
                dry_run: false,
                yes: false,
                with_firmware: false,
                allow_kernel_mismatch: false,
                allow_arch_mismatch: false,
                root: None,
                strategy: None,
                on_immutable: false,
                strict_links: false,
                no_sign: false,
                chroot_exec: false,
                require_verify: false,
                no_auto_rollback_on_post: false,
                keep_rollback: None,
                config: None
            }
        );
        assert!(parse_args(&args(&[
            "--restore",
            "--archive",
            "a",
            "--strategy",
            "magic"
        ]))
        .is_err());
        assert!(parse_args(&args(&[
            "--restore",
            "--archive",
            "a",
            "--on-immutable",
            "maybe"
        ]))
        .is_err());
    }

    #[test]
    fn restore_w7_flags_are_parsed() {
        assert_eq!(
            parse_args(&args(&[
                "--restore",
                "--archive",
                "a",
                "--require-verify",
                "--no-auto-rollback-on-post",
                "--keep-rollback",
                "7",
                "--config",
                "/etc/ldb.toml"
            ]))
            .unwrap(),
            Cmd::Restore {
                archive: "a".to_string(),
                dry_run: false,
                yes: false,
                with_firmware: false,
                allow_kernel_mismatch: false,
                allow_arch_mismatch: false,
                root: None,
                strategy: None,
                on_immutable: false,
                strict_links: false,
                no_sign: false,
                chroot_exec: false,
                require_verify: true,
                no_auto_rollback_on_post: true,
                keep_rollback: Some(7),
                config: Some("/etc/ldb.toml".to_string())
            }
        );
        assert!(parse_args(&args(&[
            "--restore",
            "--archive",
            "a",
            "--keep-rollback",
            "-1"
        ]))
        .is_err());
    }

    #[test]
    fn verify_and_diagnose_are_parsed() {
        assert_eq!(
            parse_args(&args(&["--verify", "--archive", "/tmp/a.tar.gz", "--json"])).unwrap(),
            Cmd::Verify {
                archive: "/tmp/a.tar.gz".to_string(),
                json: true
            }
        );
        // 位置参数写法
        assert_eq!(
            parse_args(&args(&["--verify", "/tmp/b.tar.gz"])).unwrap(),
            Cmd::Verify {
                archive: "/tmp/b.tar.gz".to_string(),
                json: false
            }
        );
        assert!(parse_args(&args(&["--verify"])).is_err());
        assert_eq!(
            parse_args(&args(&["--diagnose"])).unwrap(),
            Cmd::Diagnose { out: None }
        );
        assert_eq!(
            parse_args(&args(&["--diagnose", "--out", "/tmp/d.tar.gz"])).unwrap(),
            Cmd::Diagnose {
                out: Some("/tmp/d.tar.gz".to_string())
            }
        );
        assert!(parse_args(&args(&["--diagnose", "--wat"])).is_err());
    }

    #[test]
    fn rollback_is_parsed() {
        assert_eq!(
            parse_args(&args(&["--rollback"])).unwrap(),
            Cmd::Rollback {
                journal: None,
                root: None
            }
        );
        assert_eq!(
            parse_args(&args(&["--rollback", "last"])).unwrap(),
            Cmd::Rollback {
                journal: Some("last".to_string()),
                root: None
            }
        );
        assert_eq!(
            parse_args(&args(&[
                "--rollback",
                "/var/lib/linux-driver-backup/restore-1.json",
                "--root",
                "/mnt/t"
            ]))
            .unwrap(),
            Cmd::Rollback {
                journal: Some("/var/lib/linux-driver-backup/restore-1.json".to_string()),
                root: Some("/mnt/t".to_string())
            }
        );
    }

    #[test]
    fn strategy_parser_covers_all_values() {
        assert_eq!(parse_strategy("auto").unwrap(), None);
        assert_eq!(
            parse_strategy("rebuild").unwrap(),
            Some(RestoreStrategy::Rebuild)
        );
        assert_eq!(
            parse_strategy("reinstall").unwrap(),
            Some(RestoreStrategy::Reinstall)
        );
        assert_eq!(
            parse_strategy("weak-modules").unwrap(),
            Some(RestoreStrategy::WeakModules)
        );
        assert_eq!(parse_strategy("copy").unwrap(), Some(RestoreStrategy::Copy));
        assert!(parse_strategy("bogus").is_err());
    }

    #[test]
    fn helper_mode_is_parsed() {
        assert_eq!(
            parse_args(&args(&["--helper-restore", "--archive", "/tmp/a.tar.gz"])).unwrap(),
            Cmd::Helper {
                archive: "/tmp/a.tar.gz".to_string(),
                kver: None,
                with_firmware: false,
                allow_kernel_mismatch: false,
                allow_arch_mismatch: false,
                root: None,
                strategy: None,
                on_immutable: false,
                strict_links: false,
                no_sign: false,
                chroot_exec: false,
                keep_rollback: None,
                selected_file: None
            }
        );
        assert!(parse_args(&args(&["--helper-restore"])).is_err());
    }

    #[test]
    fn invalid_mode_and_unknown_arguments_are_rejected() {
        assert!(parse_args(&args(&["--scan", "--mode", "huge"])).is_err());
        assert!(parse_args(&args(&["--scan", "--mode"])).is_err());
        assert!(parse_args(&args(&["--unknown"])).is_err());
        assert!(parse_args(&args(&["--scan", "--out", "/tmp/x"])).is_err());
        assert!(parse_args(&args(&["--scan", "--json=true"])).is_err());
    }

    #[test]
    fn tilde_and_labels_helpers() {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        assert_eq!(
            expand_tilde("~/a.tar.gz"),
            PathBuf::from(&home).join("a.tar.gz")
        );
        assert_eq!(expand_tilde("/abs/path"), PathBuf::from("/abs/path"));
        assert_eq!(kind_label(EntryKind::Module), "模块");
        assert_eq!(kind_label(EntryKind::Firmware), "固件");
    }

    #[test]
    fn usage_mentions_every_subcommand() {
        let text = usage();
        for needle in [
            "--scan",
            "--backup",
            "--restore",
            "--rollback",
            "--helper-restore",
            "--dry-run",
            "--strategy",
            "--root",
            "--allow-arch-mismatch",
        ] {
            assert!(text.contains(needle), "用法说明缺少 {needle}");
        }
        // 退出码契约（C-33）：0 必须包含"用户主动取消"。
        assert!(text.contains("0 成功或用户主动取消"));
    }

    // ---- C-32：--allow-arch-mismatch 旗标 ----
    #[test]
    fn restore_allow_arch_mismatch_flag_is_parsed() {
        let parsed = parse_args(&args(&[
            "--restore",
            "--archive",
            "/tmp/a.tar.gz",
            "--allow-arch-mismatch",
        ]))
        .unwrap();
        match parsed {
            Cmd::Restore {
                allow_arch_mismatch,
                ..
            } => assert!(allow_arch_mismatch),
            other => panic!("unexpected command: {other:?}"),
        }
        let helper = parse_args(&args(&[
            "--helper-restore",
            "--archive",
            "/tmp/a.tar.gz",
            "--allow-arch-mismatch",
        ]))
        .unwrap();
        match helper {
            Cmd::Helper {
                allow_arch_mismatch,
                ..
            } => assert!(allow_arch_mismatch),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    // ---- C-34：helper 路径对 --on-immutable 严格校验取值 ----
    #[test]
    fn helper_on_immutable_rejects_unknown_value() {
        // 旧实现 matches!(v, "usroverlay") 把任意拼写静默当作 refuse，
        // 提权路径上可能让用户以为已启用 usroverlay 实则没有（C-34）。
        assert!(parse_args(&args(&[
            "--helper-restore",
            "--archive",
            "a",
            "--on-immutable",
            "bogus"
        ]))
        .is_err());
        assert!(parse_args(&args(&[
            "--helper-restore",
            "--archive",
            "a",
            "--on-immutable",
            "usroverlay"
        ]))
        .is_ok());
        assert!(parse_args(&args(&[
            "--helper-restore",
            "--archive",
            "a",
            "--on-immutable",
            "refuse"
        ]))
        .is_ok());
    }

    // ---- C-33：退出码映射 —— 用户取消为 0，其余失败为 1 ----
    #[test]
    fn exit_code_maps_cancelled_to_zero() {
        assert_eq!(exit_code(&AppError::Cancelled), 0);
        assert_eq!(exit_code(&AppError::Validation("x".into())), 1);
        assert_eq!(exit_code(&AppError::Format("bad".into())), 1);
    }
}
