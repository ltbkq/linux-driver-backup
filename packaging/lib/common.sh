#!/usr/bin/env bash
# ============================================================
# packaging/lib/common.sh —— 打包脚本共享库 / shared helpers for the packaging scripts
#
# 由 packaging/build-packages.sh 与 packaging/build-appimage.sh `source`
# （本文件只被 source，不单独执行）/ sourced only, never executed directly.
#
# 这是「版本 / 架构 / 占位符替换」的唯一事实源（C-52 + C-56）：
#   · 版本只从 Cargo.toml 解析一次          ldb_version
#   · 架构解析只有一处实现                  ldb_resolve_arch → ARCH_DEB / ARCH_PLAIN / ARCH_RPM
#   · @PLACEHOLDER@ 替换走同一条 sed 管线    ldb_render
#   · 渲染后残留占位符统一自查              ldb_assert_no_placeholders
#
# Single source of truth for version parsing, arch mapping and placeholder
# rendering, so the two packaging entry scripts can never drift apart again.
# ============================================================

# ---- 仓库根 / repository root ------------------------------
# 调用方已设置 LDB_ROOT 时优先复用；否则按本文件位置推导
# (packaging/lib/common.sh → 仓库根 = 上两级)
# Reuse LDB_ROOT when the caller already set it, else derive from this file.
if [[ -z "${LDB_ROOT:-}" ]]; then
  LDB_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fi

# 目标架构的三种命名（由 ldb_resolve_arch 填充）/ three naming flavours of the
# target arch, filled by ldb_resolve_arch:
#   ARCH_DEB   deb 的 Architecture 字段（amd64 | arm64）
#   ARCH_PLAIN uname 风格（x86_64 | aarch64），用于 tar/AppImage 文件名与 rpmbuild --target
#   ARCH_RPM   rpmbuild --target（x86_64 | aarch64）
ARCH_DEB="${ARCH_DEB:-}"
ARCH_PLAIN="${ARCH_PLAIN:-}"
ARCH_RPM="${ARCH_RPM:-}"

# 统一错误前缀 / unified error prefix（供被 source 的脚本复用）
ldb_err() { printf '[打包][错误/ERROR] %s\n' "$*" >&2; }

# ---- 版本 / version ----------------------------------------
# 版本的唯一来源：Cargo.toml 的 version 字段（C-52/C-56 合并实现）。
# Single source of version truth: the `version = "…"` field of Cargo.toml.
ldb_version() {
  local v
  v="$(grep -m1 '^version[[:space:]]*=' "$LDB_ROOT/Cargo.toml" 2>/dev/null \
        | sed 's/.*"\(.*\)".*/\1/')" || true
  if [[ -z "$v" ]]; then
    ldb_err "无法从 Cargo.toml 解析 version 字段 / failed to parse version from Cargo.toml"
    exit 1
  fi
  printf '%s' "$v"
}

# ---- 架构解析 / arch resolution ----------------------------
# 用法 / usage: ldb_resolve_arch [amd64|arm64|x86_64|aarch64]
# 不传参时按宿主推断 / defaults to the host arch. 结果写入 ARCH_DEB/ARCH_PLAIN/ARCH_RPM。
ldb_resolve_arch() {
  local wanted="${1:-}"
  if [[ -z "$wanted" ]]; then
    case "$(uname -m)" in
      aarch64|arm64) wanted=arm64 ;;
      *)             wanted=amd64 ;;
    esac
  fi
  case "$wanted" in
    amd64|x86_64)  ARCH_DEB=amd64; ARCH_PLAIN=x86_64;  ARCH_RPM=x86_64 ;;
    arm64|aarch64) ARCH_DEB=arm64; ARCH_PLAIN=aarch64; ARCH_RPM=aarch64 ;;
    *)
      ldb_err "不支持的架构 / unsupported arch: $wanted（可选 / one of: amd64 | arm64）"
      return 2
      ;;
  esac
}

# ---- 占位符替换管线 / placeholder rendering pipeline -------
# 用法 / usage: ldb_render <模板 file> <输出 out> [NAME=VALUE ...]
#
# 模板中的 @NAME@ 替换为对应 VALUE；@VERSION@ 无需列出，总是自动填充。
# @NAME@ in the template is replaced by the matching VALUE; @VERSION@ is always
# filled in automatically so no caller can forget it.
#
# 限制 / limitation：VALUE 不得含 `|`、`&` 与反斜杠（sed 分隔符/转义），
# 打包用的路径与哈希均满足该限制。
ldb_render() {
  local in="$1" out="$2" ver kv key val
  shift 2
  ver="$(ldb_version)" || return $?
  local -a exprs=(-e "s|@VERSION@|${ver}|g")
  for kv in "$@"; do
    case "$kv" in
      *=*) key="${kv%%=*}"; val="${kv#*=}" ;;
      *)
        ldb_err "ldb_render 参数须为 NAME=VALUE / expected NAME=VALUE, got: $kv"
        return 2
        ;;
    esac
    exprs+=(-e "s|@${key}@|${val}|g")
  done
  sed "${exprs[@]}" "$in" > "$out"
}

# 渲染结果自查：不允许残留 @UPPER_CASE@ 形式的占位符。
# Post-render guard: no @UPPER_CASE@ placeholder may survive rendering.
ldb_assert_no_placeholders() {
  local f="$1" hits
  hits="$(grep -nE '@[A-Z][A-Z0-9_]*@' "$f" 2>/dev/null || true)"
  if [[ -n "$hits" ]]; then
    ldb_err "文件仍含未替换的占位符 / unresolved placeholder(s) in $f:"
    printf '%s\n' "$hits" >&2
    return 1
  fi
}
