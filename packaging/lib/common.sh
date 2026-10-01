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
#   · .SRCINFO 生成（AUR / C-52）           ldb_write_srcinfo
#   · 下载 + SHA-256 校验（C-08）           ldb_fetch_verify
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
# shellcheck disable=SC2034  # 这三个变量由被 source 的调用方使用
ARCH_DEB="${ARCH_DEB:-}"
ARCH_PLAIN="${ARCH_PLAIN:-}"
ARCH_RPM="${ARCH_RPM:-}"

# ---- 统一日志 / unified logging ----------------------------
# 所有打包脚本共用同一套前缀，便于 CI grep。
ldb_info() { printf '[打包] %s\n' "$*"; }
ldb_skip() { printf '[跳过] %s\n' "$*"; }
ldb_warn() { printf '[打包][警告/WARNING] %s\n' "$*" >&2; }
ldb_err()  { printf '[打包][错误/ERROR] %s\n' "$*" >&2; }

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

# ---- 校验和 / checksums ------------------------------------
ldb_sha256_of() {
  local f="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$f" | awk '{print $1}'
  else
    shasum -a 256 "$f" | awk '{print $1}'
  fi
}

# 为产物生成同名 .sha256（记录 dist 内相对文件名，便于 sha256sum -c）
# usage: ldb_checksum <distdir> <file>
ldb_checksum() {
  local dir="$1" f="$2" base
  base="$(basename "$f")"
  ( cd "$dir" && sha256sum "$base" > "$base.sha256" )
  ldb_info "SHA-256: $(<"$dir/$base.sha256")"
}

# ---- 带校验的下载 / verified download ----------------------
# 用法 / usage: ldb_fetch_verify <url> <output> [expected-sha256]
# 返回值 / returns: 127 无下载器；非 0 下载失败；3 校验失败；0 成功。
ldb_fetch_verify() {
  local url="$1" out="$2" want="${3:-}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 20 -o "$out" "$url" || return $?
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 30 -t 2 -O "$out" "$url" || return $?
  else
    return 127
  fi
  [[ -s "$out" ]] || return 1
  if [[ -n "$want" ]]; then
    local got
    got="$(ldb_sha256_of "$out")"
    if [[ "$got" != "$want" ]]; then
      ldb_err "SHA-256 校验失败 / checksum mismatch for $(basename "$out"): 期望/expected $want 实际/actual $got"
      return 3
    fi
  fi
  return 0
}

# ---- .SRCINFO 生成 / AUR metadata generation (C-52) --------
# 用法 / usage: ldb_write_srcinfo <已渲染 PKGBUILD> <输出 .SRCINFO>
# 优先调用 makepkg --printsrcinfo（Arch 环境）；否则用内置生成器，
# 使非 Arch 的 CI（Ubuntu）也能产出与 makepkg 等价的 AUR 元数据。
ldb_write_srcinfo() {
  local pkgbuild="$1" out="$2" tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ldb-srcinfo.XXXXXX")"
  cp "$pkgbuild" "$tmp/PKGBUILD"

  if command -v makepkg >/dev/null 2>&1; then
    ldb_info ".SRCINFO: 使用 makepkg --printsrcinfo / using makepkg"
    ( cd "$tmp" && makepkg --printsrcinfo ) > "$out"
  else
    ldb_info ".SRCINFO: 未检测到 makepkg，使用内置生成器 / built-in generator"
    (
      set -eu
      cd "$tmp" || exit 1
      # PKGBUILD 顶层仅为变量赋值与函数定义；source 不执行构建（makepkg 同理）。
      # 先声明默认值，既满足 set -u，也让静态检查知道这些变量来自 PKGBUILD。
      pkgname=""; pkgbase=""; pkgdesc=""; pkgver=""; pkgrel=""; url=""
      source=(); sha256sums=(); arch=(); license=(); groups=()
      makedepends=(); depends=(); optdepends=(); checkdepends=()
      provides=(); conflicts=(); replaces=()
      # shellcheck disable=SC1090,SC1091
      source ./PKGBUILD

      emit() {
        local key="$1"; shift
        local v
        for v in "$@"; do
          printf '\t%s = %s\n' "$key" "$v"
        done
      }
      printf 'pkgbase = %s\n' "${pkgbase:-$pkgname}"
      printf '\tpkgdesc = %s\n' "$pkgdesc"
      printf '\tpkgver = %s\n' "$pkgver"
      printf '\tpkgrel = %s\n' "$pkgrel"
      printf '\turl = %s\n' "$url"
      emit source "${source[@]}"
      emit sha256sums "${sha256sums[@]}"
      emit arch "${arch[@]}"
      emit license "${license[@]}"
      emit groups "${groups[@]}"
      emit makedepends "${makedepends[@]}"
      emit depends "${depends[@]}"
      emit optdepends "${optdepends[@]}"
      emit checkdepends "${checkdepends[@]}"
      emit provides "${provides[@]}"
      emit conflicts "${conflicts[@]}"
      emit replaces "${replaces[@]}"
      printf 'pkgname = %s\n' "$pkgname"
    ) > "$out"
  fi

  rm -rf "$tmp"
}
