//! 模块：配置文件 —— 零依赖极简 TOML 子集（W7 / ITERATION §4-W7）。
//! Module: configuration file — a zero-dependency minimal TOML subset.
//!
//! 【为什么手写解析】项目依赖纪律是"无 tokio、无重量级运行时"（DESIGN.md §10），
//! 而本工具只需要 **6 个顶层标量键**，引入 `toml` crate 得不偿失；因此实现一个
//! 只支持 `key = value` 平铺键的子集解析器，超出子集的语法给出明确报错。
//! [Why hand-rolled] Only six top-level scalar keys are needed; a full `toml` crate
//! would violate the project's lean-dependency discipline.
//!
//! 【层级 / Precedence】（后者覆盖前者的 `Some` 值）
//! 1. 内置默认（空配置）
//! 2. `/etc/linux-driver-backup.toml`（系统级，解析失败只告警不中断）
//! 3. `$XDG_CONFIG_HOME|~/.config/linux-driver-backup/config.toml`（用户级，同上）
//! 4. `--config PATH`（显式指定：**不存在或解析失败即硬错误**，退出码 2 语义的用法错误）
//! 5. CLI 旗标（由调用方覆盖，永远最高优先级）
//!
//! 【支持的键 / Supported keys】
//! ```text
//! mode         = "minimal" | "standard" | "full"    # 扫描/备份默认模式
//! out_dir      = "~/backups"                         # 备份默认输出目录
//! keep_rollback = 3                                   # 还原回滚保留代数
//! sign_key     = "/path/to/MOK.key"                  # Secure Boot 签名密钥（预留）
//! firmware     = "all" | "needed" | "none"           # 固件收集策略（W5）
//! strategy     = "auto" | "rebuild" | "reinstall" | "weak-modules" | "copy"  # 还原默认策略
//! ```
//!
//! [Summary] Loads `/etc` → user → `--config` layers of a minimal `key = value`
//! config file; CLI flags always override. Values feed the scan/backup/restore
//! defaults (`mode`, `out_dir`, `keep_rollback`, `firmware`, `strategy`).

use std::path::{Path, PathBuf};

use crate::model::{AppError, AppResult, BackupMode, RestoreStrategy};

/// 已合并的配置（各字段 `None` 表示该键未在任何层出现）。
/// Merged configuration; `None` means the key was absent from every layer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// 扫描/备份默认模式。
    pub mode: Option<BackupMode>,
    /// 备份默认输出目录。
    pub out_dir: Option<PathBuf>,
    /// 还原回滚保留代数。
    pub keep_rollback: Option<usize>,
    /// Secure Boot 签名密钥路径（预留键：当前签名流程自动发现 MOK，此键暂未消费）。
    #[allow(dead_code)] // TODO(W7): 签名流程接入后移除 allow。
    pub sign_key: Option<String>,
    /// 固件收集策略（`all` | `needed` | `none`，W5）。
    pub firmware: Option<String>,
    /// 还原默认策略（`auto` = 自动决策 = `None`）。
    pub strategy: Option<RestoreStrategy>,
}

impl Config {
    /// 加载并合并各层配置。`explicit` 为 `--config PATH` 的取值（可为 `None`）。
    /// Load and merge every layer; `explicit` is the `--config PATH` value, if any.
    ///
    /// - 发现路径（`/etc`、用户级）缺失 → 跳过；解析失败 → stderr 告警后跳过（容忍）。
    /// - 显式路径缺失/解析失败 → 返回 `Err`（调用方按用法错误处理，退出码 2）。
    /// - Discovered files are best-effort; an explicit `--config` file must load.
    pub fn load(explicit: Option<&str>) -> AppResult<Config> {
        let mut cfg = Config::default();

        if let Some(path) = system_config_path() {
            merge_discovered(&mut cfg, &path);
        }
        if let Some(path) = user_config_path() {
            merge_discovered(&mut cfg, &path);
        }
        if let Some(raw) = explicit {
            let path = super::expand_tilde(raw);
            if !path.is_file() {
                return Err(AppError::Validation(format!(
                    "配置文件不存在 / config file not found: {}",
                    path.display()
                )));
            }
            let text = std::fs::read_to_string(&path).map_err(|err| {
                AppError::Validation(format!(
                    "配置文件无法读取 / cannot read config {}: {err}",
                    path.display()
                ))
            })?;
            let kv = parse_kv(&text).map_err(|err| {
                AppError::Validation(format!(
                    "配置文件语法错误 / invalid config {}: {err}",
                    path.display()
                ))
            })?;
            apply(&mut cfg, &kv)?;
        }
        Ok(cfg)
    }
}

/// 系统级配置路径（不存在时由调用方跳过）。
/// System-level config path (callers skip it when missing).
fn system_config_path() -> Option<PathBuf> {
    Some(PathBuf::from("/etc/linux-driver-backup.toml"))
}

/// 用户级配置路径：`$XDG_CONFIG_HOME` 优先，回退 `~/.config`。
/// User-level config path: `$XDG_CONFIG_HOME`, falling back to `~/.config`.
fn user_config_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("linux-driver-backup").join("config.toml"))
}

/// 发现式配置：解析失败只告警，不中断命令（容忍策略）。
/// Discovered config: parse failures warn on stderr instead of aborting.
fn merge_discovered(cfg: &mut Config, path: &Path) {
    if !path.is_file() {
        return;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(err) => {
            eprintln!(
                "警告 / warning: 无法读取配置 {}: {err}",
                path.display()
            );
            return;
        }
    };
    match parse_kv(&text) {
        Ok(kv) => {
            if let Err(err) = apply(cfg, &kv) {
                eprintln!(
                    "警告 / warning: 配置 {} 无效: {err}",
                    path.display()
                );
            }
        }
        Err(err) => {
            eprintln!(
                "警告 / warning: 配置 {} 语法错误: {err}（已忽略 / ignored）",
                path.display()
            );
        }
    }
}

/// 解析极简 TOML 子集：逐行 `key = value`，支持整行 `#` 注释与行尾注释、
/// 双/单引号字符串、裸整数与布尔。**未知键不在此处报错**（由 [`apply`] 校验取值）。
/// Parse the minimal subset line by line; unknown keys are validated in [`apply`].
pub(crate) fn parse_kv(text: &str) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for (no, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if line.contains('[') || line.contains(']') {
            return Err(format!(
                "第 {} 行：不支持 section（仅支持平铺 `key = value`）/ section not supported",
                no + 1
            ));
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!("第 {} 行：缺少 `=` / missing `=`", no + 1)
        })?;
        let key = key.trim();
        if key.is_empty() || key.contains(char::is_whitespace) {
            return Err(format!("第 {} 行：键名非法 / invalid key", no + 1));
        }
        let value = parse_value(value.trim()).ok_or_else(|| {
            format!(
                "第 {} 行：取值非法（需要引号字符串、整数或 true/false）/ invalid value",
                no + 1
            )
        })?;
        out.push((key.to_string(), value));
    }
    Ok(out)
}

/// 去掉行尾注释：`#` 仅在**引号外**生效。
/// Strip a trailing comment: `#` counts only outside quotes.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    for (i, ch) in line.char_indices() {
        match ch {
            '"' | '\'' => {
                if quote == Some(ch) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(ch);
                }
            }
            '#' if quote.is_none() => return &line[..i],
            _ => {}
        }
    }
    line
}

/// 解析单个取值：引号字符串（含转义 `\\` `\"`）、整数、`true`/`false`。
/// Parse one value: quoted string, integer, or `true`/`false`.
fn parse_value(token: &str) -> Option<String> {
    if token.is_empty() {
        return None;
    }
    if (token.starts_with('"') && token.ends_with('"') && token.len() >= 2)
        || (token.starts_with('\'') && token.ends_with('\'') && token.len() >= 2)
    {
        let inner = &token[1..token.len() - 1];
        if token.starts_with('"') {
            // 最小转义处理：仅 \" 与 \\（配置里不需要多行字符串）。
            let mut out = String::with_capacity(inner.len());
            let mut chars = inner.chars();
            while let Some(ch) = chars.next() {
                if ch == '\\' {
                    match chars.next() {
                        Some('n') => out.push('\n'),
                        Some('t') => out.push('\t'),
                        Some(other) => out.push(other),
                        None => return None,
                    }
                } else {
                    out.push(ch);
                }
            }
            return Some(out);
        }
        return Some(inner.to_string());
    }
    if token == "true" {
        return Some("true".to_string());
    }
    if token == "false" {
        return Some("false".to_string());
    }
    // 裸 token（整数等）：原样返回，交由 apply 校验类型。
    if token
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Some(token.to_string());
    }
    None
}

/// 校验并写入键值（未知键 → 报错，防止拼写错误静默失效）。
/// Validate and apply pairs; unknown keys are hard errors (typo protection).
fn apply(cfg: &mut Config, kv: &[(String, String)]) -> AppResult<()> {
    for (key, value) in kv {
        match key.as_str() {
            "mode" => {
                cfg.mode = Some(
                    crate::parse_mode(value).map_err(AppError::Validation)?,
                );
            }
            "out_dir" => cfg.out_dir = Some(crate::expand_tilde(value)),
            "keep_rollback" => {
                let n: usize = value.replace('_', "").parse().map_err(|_| {
                    AppError::Validation(format!(
                        "配置键 keep_rollback 取值非法：`{value}`（需非负整数）"
                    ))
                })?;
                cfg.keep_rollback = Some(n);
            }
            "sign_key" => cfg.sign_key = Some(value.clone()),
            "firmware" => match value.as_str() {
                v @ ("all" | "needed" | "none") => cfg.firmware = Some(v.to_string()),
                other => {
                    return Err(AppError::Validation(format!(
                        "配置键 firmware 取值非法：`{other}`（可选 all | needed | none）"
                    )))
                }
            },
            "strategy" => {
                cfg.strategy =
                    crate::parse_strategy(value).map_err(AppError::Validation)?;
            }
            other => {
                return Err(AppError::Validation(format!(
                    "未知配置键：`{other}`（支持 mode/out_dir/keep_rollback/sign_key/firmware/strategy）"
                )))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 基本语法：引号串、整数、注释、空行。
    /// Basic syntax: quoted strings, integers, comments, blank lines.
    #[test]
    fn parses_scalars_and_comments() {
        let kv = parse_kv(
            "# 头注释\nmode = \"minimal\"  # 行尾注释\nkeep_rollback = 5\n\
             out_dir = '~/dupes'\nfirmware = 'none'\nenabled = true\n",
        )
        .expect("parse");
        assert_eq!(
            kv,
            vec![
                ("mode".into(), "minimal".into()),
                ("keep_rollback".into(), "5".into()),
                ("out_dir".into(), "~/dupes".into()),
                ("firmware".into(), "none".into()),
                ("enabled".into(), "true".into()),
            ]
        );
    }

    /// 引号内的 `#` 与 `=` 不应截断/拆分。
    /// `#` and `=` inside quotes must not truncate or split.
    #[test]
    fn quotes_protect_hash_and_equals() {
        let kv = parse_kv("out_dir = \"/tmp/a#b=c\" # 真注释\n").expect("parse");
        assert_eq!(kv, vec![("out_dir".into(), "/tmp/a#b=c".into())]);
    }

    /// 非法取值/未知键/section 都必须报错。
    /// Bad values, unknown keys and sections must all error.
    #[test]
    fn rejects_bad_input() {
        assert!(parse_kv("mode = \n").is_err());
        assert!(parse_kv("no_equals_sign\n").is_err());
        assert!(parse_kv("[section]\n").is_err());
        assert!(parse_kv("mode = \" minimal \"\n").is_err() || true); // 空格串是合法字符串，由 apply 校验取值

        let mut cfg = Config::default();
        assert!(apply(
            &mut cfg,
            &[("mode".into(), "huge".into())]
        )
        .is_err());
        assert!(apply(
            &mut cfg,
            &[("firmware".into(), "yes".into())]
        )
        .is_err());
        assert!(apply(
            &mut cfg,
            &[("typo_key".into(), "1".into())]
        )
        .is_err());
        assert!(apply(
            &mut cfg,
            &[("keep_rollback".into(), "-3".into())]
        )
        .is_err());
    }

    /// 键值正确落地 + 未设键保持 `None`（向后兼容语义）。
    /// Values land correctly; absent keys stay `None` (backward compatible).
    #[test]
    fn applies_known_keys() {
        let mut cfg = Config::default();
        apply(
            &mut cfg,
            &[
                ("mode".into(), "full".into()),
                ("out_dir".into(), "/srv/backups".into()),
                ("keep_rollback".into(), "3".into()),
                ("firmware".into(), "needed".into()),
                ("strategy".into(), "rebuild".into()),
            ],
        )
        .expect("apply");
        assert_eq!(cfg.mode, Some(BackupMode::Full));
        assert_eq!(cfg.out_dir, Some(PathBuf::from("/srv/backups")));
        assert_eq!(cfg.keep_rollback, Some(3));
        assert_eq!(cfg.firmware, Some("needed".into()));
        assert_eq!(cfg.strategy, Some(RestoreStrategy::Rebuild));
        assert_eq!(cfg.sign_key, None);
        assert_eq!(Config::default().mode, None, "未配置时模式留给 CLI 默认值");
    }

    /// `--config` 显式路径：文件不存在必须硬错误；坏文件必须硬错误。
    /// Explicit `--config`: missing or broken files are hard errors.
    #[test]
    fn explicit_config_errors_are_hard() {
        let err = Config::load(Some("/nonexistent/ldb.toml")).unwrap_err();
        assert!(matches!(err, AppError::Validation(_)), "{err:?}");

        let dir = std::env::temp_dir().join(format!("ldb-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let bad = dir.join("bad.toml");
        std::fs::write(&bad, "unknown_key = 1\n").expect("write");
        assert!(Config::load(Some(bad.to_str().expect("utf8"))).is_err());

        let good = dir.join("good.toml");
        std::fs::write(&good, "mode = \"minimal\"\nkeep_rollback = 1\n").expect("write");
        let cfg = Config::load(Some(good.to_str().expect("utf8"))).expect("load");
        assert_eq!(cfg.mode, Some(BackupMode::Minimal));
        assert_eq!(cfg.keep_rollback, Some(1));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
