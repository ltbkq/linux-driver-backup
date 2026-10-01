//! 模块：路径校验共享工具（W7 / C-47）。
//! Module: shared path-validation utilities (W7 / C-47).
//!
//! 原先 `restore.rs` 与 `backup.rs` 各有一份「归档相对路径」与「符号链接禁闭」
//! 校验（v0.2.1 由 W0-A 先各自实现并互相指认）。此处合并为**唯一实现**，两侧共用，
//! 避免规则漂移导致「备份放行、还原拒绝」之类的不对称（C-47）。
//! [Summary] Single source of truth for archive-relative path validation and the
//! symlink containment ("link jail") shared by `restore.rs` and `backup.rs`.

use std::path::{Component, Path, PathBuf};

use crate::model::{AppError, AppResult};

/// 受管前缀（`rel_path` 命名空间）：符号链接目标归一化后必须落在其中之一。
/// Managed prefixes in the `rel_path` namespace; a symlink target must stay within one.
const MANAGED_LINK_PREFIXES: [&str; 2] = ["lib/modules/", "usr/lib/modules/"];

/// `etc/` 下符号链接目标归一化后的**绝对路径白名单**（必须落在其中之一）。
/// C-01: whitelist of absolute prefixes an `etc/` symlink target may resolve into.
///
/// 覆盖实测合法样例（`/lib/linux-sound-base/…`）、usr-merge 的 `/usr/lib/…`，以及
/// 常见的 `/etc/…`、`/usr/share/…`、`/run/…` 别名；`/`、`/home/…` 等一律拒绝。
const ALLOWED_ETC_LINK_PREFIXES: [&str; 5] =
    ["/etc/", "/lib/", "/usr/lib/", "/usr/share/", "/run/"];

/// Normalize an archive-relative path and reject anything that could escape the target root.
/// 逐层 normalize 归档内相对路径，拒绝绝对路径、空路径与任何 `..` 分量；非法时返回 `None`。
///
/// 这是路径穿越防护的核心纯函数（可单测）：`a/./b//c` → `a/b/c`，`a/../b` → `None`。
pub(crate) fn safe_rel_path(p: &str) -> Option<PathBuf> {
    if p.is_empty() || p.starts_with('/') {
        return None;
    }
    let mut out = PathBuf::new();
    for comp in p.split('/') {
        match comp {
            "" | "." => continue,
            ".." => return None,
            other => out.push(other),
        }
    }
    if out.as_os_str().is_empty() {
        return None;
    }
    // 二次保险：normalize 之后的结果必须仍是相对路径且不含 `..`。
    let s = out.to_str()?;
    if s.starts_with('/') || s.split('/').any(|c| c == "..") {
        return None;
    }
    Some(out)
}

/// Build the canonical "illegal path" error message.
/// 构造"非法归档路径"的统一错误（绝对路径或越界 `..`）。
pub(crate) fn illegal_path(raw: &str) -> AppError {
    AppError::Format(format!(
        "归档内含非法路径（绝对路径或越界 ..），已拒绝越界写入：{}",
        raw
    ))
}

/// Split an archive path into its `data/` payload part.
/// 拆出归档路径中 `data/` 之后的负载路径：非 `data/` 条目返回 `Ok(None)`，路径非法返回 `Err(Format)`。
///
/// 返回值保证是干净的相对路径（再次经过 [`safe_rel_path`]），调用方可以安全地拼到 `/` 之下。
pub(crate) fn data_payload(raw: &str) -> AppResult<Option<PathBuf>> {
    let rel = match safe_rel_path(raw) {
        Some(r) => r,
        None => return Err(illegal_path(raw)),
    };
    let s = rel.to_string_lossy();
    let rest = match s.strip_prefix("data/") {
        Some(r) if !r.is_empty() => r,
        // `manifest.json`、`data` 目录本身等非负载条目
        _ => return Ok(None),
    };
    match safe_rel_path(rest) {
        Some(inner) => Ok(Some(inner)),
        None => Err(illegal_path(raw)),
    }
}

/// 校验归档内相对路径：拒绝 `..`、绝对路径、空路径与 NUL。
/// Validate an in-archive relative path: reject `..`, absolute paths, empties and NULs.
pub(crate) fn validate_rel_path(rel: &str) -> AppResult<()> {
    if rel.is_empty() {
        return Err(AppError::Format(
            "归档内路径为空 / empty relative path".to_string(),
        ));
    }
    if rel.starts_with('/') {
        return Err(AppError::Format(format!(
            "归档内路径不得以 / 开头 / absolute path not allowed: {rel}"
        )));
    }
    if rel.contains('\0') {
        return Err(AppError::Format(format!(
            "归档内路径含 NUL 字节 / NUL byte in path: {rel}"
        )));
    }
    // 冗余的字面 `..` 检查（DESIGN.md §4.5）：任何形态的父目录跳转都被拒绝。
    // 注意：只拒绝"作为路径组件出现"的 `..`（等价于下面 components() 的 ParentDir），
    // 文件名里内嵌两个点（如 `foo..bar`）不是越界路径，不应误伤。
    for seg in rel.split('/') {
        if seg == ".." {
            return Err(AppError::Format(format!(
                "归档内路径含 `..` 组件 / parent-directory component not allowed: {rel}"
            )));
        }
    }
    for c in Path::new(rel).components() {
        match c {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(AppError::Format(format!(
                    "归档内路径含非法组件 / unsafe path component: {rel}"
                )))
            }
        }
    }
    Ok(())
}

/// Join a symlink's target onto its own directory and normalize the result.
/// 把符号链接目标按 POSIX 语义拼到链接所在目录并逐层 normalize；越出根或不可归一化时返回 `None`。
///
/// 例：`("lib/modules/6.8/weak-updates/a.ko", "../../6.6/extra/a.ko")`
/// → `Some("lib/modules/6.6/extra/a.ko")`。
/// Pure helper shared by validation and tests.
pub(crate) fn normalize_join(link_rel: &str, target: &str) -> Option<PathBuf> {
    if target.is_empty() || target.starts_with('/') {
        return None;
    }
    let mut stack: Vec<String> = Vec::new();
    let parent = match link_rel.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => String::new(),
    };
    for part in parent.split('/').chain(target.split('/')) {
        match part {
            "" | "." => continue,
            ".." => {
                // 越出根：直接判定为非法（不允许链接逃逸受管前缀之上）。
                stack.pop()?;
            }
            other => stack.push(other.to_string()),
        }
    }
    if stack.is_empty() {
        return None;
    }
    Some(PathBuf::from(stack.join("/")))
}

/// Validate a symlink entry (pure, unit-testable).
/// 校验符号链接条目：目标必须是相对路径，归一化后仍落在受管前缀内；返回归一化后的相对路径。
///
/// RHEL/SUSE 的 `weak-updates/<m>.ko -> ../../<kver>/extra/<m>.ko` 是**合法**形态
/// （归一化后仍在 `lib/modules/` 之下），必须放行；而 `../../etc/shadow` 之类一律拒绝。
#[derive(Debug)]
pub(crate) enum LinkPlan {
    /// 按原样重建（`/etc` 下的配置别名，可含绝对目标）。
    ///
    /// C-01：目标已经过 [`resolve_link_abs`] 词法归一化与白名单校验，
    /// 因此只可能落在 `etc/` 树内或 [`ALLOWED_ETC_LINK_PREFIXES`] 之内。
    Verbatim,
    /// 归一化后落在模块目录内的模块链接（如 weak-updates）。
    Normalized(PathBuf),
}

/// Lexically resolve a symlink target to an absolute path rooted at the archive
/// root (C-01): relative targets are joined onto the link's own directory first;
/// `..` is rejected when it would climb above the archive root for relative
/// targets, and pinned at `/` for absolute ones.
/// 把符号链接目标**词法**解析为以归档根为基准的绝对路径（C-01）：
/// 相对目标先拼到链接所在目录；相对目标的 `..` 越出归档根即返回 `None`，
/// 绝对目标的 `/..` 则停在根。例：`("etc/a/b.conf", "../x")` → `Some("/etc/x")`。
fn resolve_link_abs(link_rel: &str, target: &str) -> Option<PathBuf> {
    let absolute = target.starts_with('/');
    let mut stack: Vec<&str> = Vec::new();
    if !absolute {
        if let Some((dir, _)) = link_rel.rsplit_once('/') {
            for seg in dir.split('/') {
                if !seg.is_empty() && seg != "." {
                    stack.push(seg);
                }
            }
        }
    }
    for seg in target.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if stack.pop().is_none() && !absolute {
                    // 相对目标越出归档根（`etc/x -> ../../../../..`）→ 拒绝。
                    return None;
                }
            }
            other => stack.push(other),
        }
    }
    Some(PathBuf::from(format!("/{}", stack.join("/"))))
}

/// 校验符号链接目标（C-01/C-02 禁闭），返回处置计划。`restore.rs` 与 `backup.rs` 共用。
/// Validate a symlink target (containment); the shared implementation of the link jail.
pub(crate) fn validate_link_target(link_rel: &str, target: &str) -> AppResult<LinkPlan> {
    if link_rel.starts_with("etc/") {
        // ---- C-01/C-02 符号链接禁闭 ----
        // 旧实现按原样放行（绝对路径与 `..` 全部允许），恶意归档可用
        // `data/etc/x -> /` + `data/etc/x/...` 条目以 root 任意写文件；现改为：
        // 目标必须词法解析后仍落在 `etc/` 树内，或（绝对目标）位于允许前缀白名单。
        if target.trim().is_empty() {
            return Err(AppError::Format(format!("符号链接目标为空：{link_rel}")));
        }
        let resolved = resolve_link_abs(link_rel, target).ok_or_else(|| {
            AppError::Format(format!(
                "符号链接目标越出归档根，拒绝还原：{link_rel} -> {target}"
            ))
        })?;
        let s = resolved.to_string_lossy();
        let in_etc_tree = s.as_ref() == "/etc" || s.starts_with("/etc/");
        let in_whitelist = ALLOWED_ETC_LINK_PREFIXES
            .iter()
            .any(|p| s.as_ref() == p.trim_end_matches('/') || s.starts_with(p));
        if !(in_etc_tree || in_whitelist) {
            // 消息同时含中英关键词，兼容两侧既有测试断言（`归一化` / `normalized`）。
            return Err(AppError::Format(format!(
                "符号链接目标越出允许前缀，拒绝还原 / etc link target outside allowed \
                 prefixes: {link_rel} -> {target}（归一化 / normalized: {}）",
                resolved.display()
            )));
        }
        return Ok(LinkPlan::Verbatim);
    }
    if target.is_empty() {
        return Err(AppError::Format(format!(
            "符号链接目标为空 / empty link target: {link_rel}"
        )));
    }
    if target.contains('\0') {
        return Err(AppError::Format(format!(
            "符号链接目标含 NUL 字节 / NUL byte in link target: {link_rel}"
        )));
    }
    if target.starts_with('/') {
        return Err(AppError::Format(format!(
            "模块目录下的符号链接不得使用绝对目标，拒绝还原：{link_rel} -> {target}"
        )));
    }
    let normalized = normalize_join(link_rel, target).ok_or_else(|| {
        AppError::Format(format!(
            "符号链接目标越出受管范围，拒绝还原：{link_rel} -> {target}"
        ))
    })?;
    let s = normalized.to_string_lossy();
    if MANAGED_LINK_PREFIXES.iter().any(|p| s.starts_with(p)) {
        Ok(LinkPlan::Normalized(normalized))
    } else {
        Err(AppError::Format(format!(
            "符号链接指向受管前缀之外，拒绝还原：{link_rel} -> {target}（归一化：{}）",
            normalized.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_rel_path_normalizes_and_rejects() {
        assert_eq!(safe_rel_path("a/./b//c"), Some(PathBuf::from("a/b/c")));
        assert!(safe_rel_path("a/../b").is_none());
        assert!(safe_rel_path("/abs").is_none());
        assert!(safe_rel_path("").is_none());
    }

    #[test]
    fn data_payload_splits_data_prefix() {
        assert_eq!(
            data_payload("data/etc/foo.conf").unwrap(),
            Some(PathBuf::from("etc/foo.conf"))
        );
        assert_eq!(data_payload("manifest.json").unwrap(), None);
        assert!(data_payload("data/../etc/passwd").is_err());
    }

    #[test]
    fn validate_rel_path_rejects_unsafe_components() {
        assert!(validate_rel_path("..").is_err());
        assert!(validate_rel_path("/etc/passwd").is_err());
        assert!(validate_rel_path("etc\0passwd").is_err());
        assert!(validate_rel_path("lib/modules/6.8/foo.ko").is_ok());
        assert!(validate_rel_path("var/lib/foo..bar/x").is_ok());
    }

    #[test]
    fn link_jail_is_shared_and_consistent() {
        // /etc 树内合法别名。
        assert!(matches!(
            validate_link_target("etc/modules-load.d/modules.conf", "../modules"),
            Ok(LinkPlan::Verbatim)
        ));
        // 白名单绝对目标。
        assert!(validate_link_target("etc/x", "/usr/lib/foo").is_ok());
        // 逃逸 / 白名单外一律拒绝。
        assert!(validate_link_target("etc/x", "/").is_err());
        assert!(validate_link_target("etc/x", "/home/user/pwn").is_err());
        assert!(validate_link_target("etc/x", "../../../../..").is_err());
        // 模块 weak-updates 合法、逃逸非法。
        assert!(matches!(
            validate_link_target("lib/modules/6.8/weak-updates/a.ko", "../../6.6/extra/a.ko"),
            Ok(LinkPlan::Normalized(_))
        ));
        assert!(validate_link_target("lib/modules/6.8/a.ko", "../../../etc/shadow").is_err());
        assert!(validate_link_target("lib/modules/6.8/a.ko", "/etc/shadow").is_err());
        assert!(validate_link_target("lib/modules/x/a.ko", "bad\0target").is_err());
    }
}
