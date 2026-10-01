#!/usr/bin/env bash
# ============================================================
# build-appimage.sh —— 组装 AppDir 并产出 AppImage
# Assemble the AppDir and build the AppImage for linux-driver-backup.
#
# 结构说明见 packaging/appimage/README.md。
#
# 关键约定 / Key behaviours:
#   - 版本 / 架构解析统一走 packaging/lib/common.sh（C-56 唯一事实源）；
#   - 二进制来源：--bin 指定，默认 target/release/linux-driver-backup；
#   - 免 FUSE：统一用 APPIMAGE_EXTRACT_AND_RUN=1 运行 appimagetool；
#   - appimagetool 固定版本且校验 SHA-256（C-08）：下载失败按 DESIGN.md §11.4
#     降级（打印 warning 并 exit 0）；校验和不符则硬失败（exit 1），防止投毒；
#   - 产物：dist/linux-driver-backup-<版本>-linux-<架构>.AppImage
#
# 用法 / Usage:
#   bash packaging/build-appimage.sh
#   bash packaging/build-appimage.sh --bin target/release/linux-driver-backup-x86_64 --arch amd64
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export LDB_ROOT="$ROOT"
# shellcheck disable=SC1090,SC1091  # 共享库路径含变量，shellcheck 无法静态跟随
source "$SCRIPT_DIR/lib/common.sh"

# 中文进度输出（附英文关键词，便于 grep）
info() { ldb_info "$@"; }
warn() { ldb_warn "$@"; }
err()  { ldb_err "$@"; }

BIN="$ROOT/target/release/linux-driver-backup"
ARCH_WANTED=""
OUTDIR="$ROOT/dist"

# appimagetool 固定版本（C-08：不再使用可变的 continuous 标签）+ 官方 SHA-256
# （取自 GitHub Release API 的 asset digest）。
APPIMAGETOOL_VERSION="1.9.1"
APPIMAGETOOL_URL_BASE="https://github.com/AppImage/appimagetool/releases/download"

DESKTOP="$ROOT/packaging/linux-driver-backup.desktop"
ICON="$ROOT/packaging/icon.svg"

# ---- 0) 参数解析 / argument parsing ------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bin)     BIN="${2:-}";        shift 2 ;;
    --bin=*)   BIN="${1#*=}";       shift ;;
    --arch)    ARCH_WANTED="${2:-}"; shift 2 ;;
    --arch=*)  ARCH_WANTED="${1#*=}"; shift ;;
    --outdir)  OUTDIR="${2:-}";     shift 2 ;;
    --outdir=*) OUTDIR="${1#*=}";   shift ;;
    -h|--help)
      cat <<'EOF'
用法 / Usage: bash packaging/build-appimage.sh [--bin <路径>] [--arch <amd64|arm64>] [--outdir <目录>]
  --bin     要打包的二进制（默认 target/release/linux-driver-backup）
  --arch    目标架构（默认按宿主推断；amd64|arm64）
  --outdir  产物输出目录（默认 dist/）
EOF
      exit 0 ;;
    *) err "未知参数 / unknown option: $1"; exit 2 ;;
  esac
done

ldb_resolve_arch "$ARCH_WANTED" || exit 2

# ---- 1) 前置检查：二进制与静态资产 -------------------------
if [[ ! -f "$BIN" ]]; then
  warn "未找到二进制 $BIN"
  warn "请先执行 cargo build --release（或从 Release 页下载产物）后重试。"
  warn "Binary not found; run 'cargo build --release' first."
  exit 1
fi
if [[ ! -f "$DESKTOP" || ! -f "$ICON" ]]; then
  warn "缺少 packaging/linux-driver-backup.desktop 或 packaging/icon.svg，无法继续。"
  exit 1
fi

# ---- 2) 版本、架构与 appimagetool 资产 ---------------------
VERSION="$(ldb_version)"
ARCH="$ARCH_PLAIN"
OUT="$OUTDIR/linux-driver-backup-${VERSION}-linux-${ARCH}.AppImage"
case "$ARCH" in
  x86_64)  AI_ASSET="appimagetool-x86_64.AppImage"
           AI_SHA="ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0" ;;
  aarch64) AI_ASSET="appimagetool-aarch64.AppImage"
           AI_SHA="f0837e7448a0c1e4e650a93bb3e85802546e60654ef287576f46c71c126a9158" ;;
  *)       warn "appimagetool 无对应资产 / unsupported arch: $ARCH"; exit 0 ;;
esac
APPIMAGE_URL="$APPIMAGETOOL_URL_BASE/$APPIMAGETOOL_VERSION/$AI_ASSET"
info "版本/version=$VERSION 架构/arch=$ARCH 工具/appimagetool=$APPIMAGETOOL_VERSION"

# ---- 3) 临时工作目录 ---------------------------------------
WORK="$(mktemp -d "${TMPDIR:-/tmp}/ldb-appimage.XXXXXX")"
cleanup() { rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT
APPDIR="$WORK/AppDir"

# ---- 4) 组装 AppDir ----------------------------------------
mkdir -p "$APPDIR/usr/bin"

# 4.1 二进制
cp "$BIN" "$APPDIR/usr/bin/linux-driver-backup"
chmod 0755 "$APPDIR/usr/bin/linux-driver-backup"

# 4.2 桌面入口（必须在 AppDir 根部）；AppImage 中入口固定为 AppRun，
#     并去掉宿主 PATH 相关的 TryExec（C-55 的绝对路径改写只针对系统安装）。
sed -e 's|^Exec=.*|Exec=AppRun|' -e '/^TryExec=/d' \
  "$DESKTOP" > "$APPDIR/linux-driver-backup.desktop"
chmod 0644 "$APPDIR/linux-driver-backup.desktop"

# 4.3 图标：优先 SVG（可缩放，appimagetool 支持）；
#     若本机有 SVG→PNG 转换器且 appimagetool 不吃 svg，可额外产 png。
cp "$ICON" "$APPDIR/linux-driver-backup.svg"
if command -v rsvg-convert >/dev/null 2>&1; then
  info "检测到 rsvg-convert，额外生成 256px PNG 图标 / also generate a 256px PNG"
  rsvg-convert -w 256 -h 256 "$ICON" > "$APPDIR/linux-driver-backup.png" || \
    warn "SVG→PNG 转换失败，继续使用 SVG 图标（不影响打包）。"
elif command -v inkscape >/dev/null 2>&1; then
  info "检测到 inkscape，额外生成 256px PNG 图标 / also generate a 256px PNG"
  inkscape --export-type=png --export-filename="$APPDIR/linux-driver-backup.png" \
    --export-width=256 "$ICON" >/dev/null 2>&1 || \
    warn "SVG→PNG 转换失败，继续使用 SVG 图标（不影响打包）。"
else
  info "无 rsvg-convert/inkscape：直接使用 SVG 图标（appimagetool 支持）。"
fi

# 4.4 AppRun：优先使用仓库内的骨架文件 packaging/appimage/AppDir/AppRun，
#     缺失时现场生成（保持脚本自包含）；都是定位自身目录后 exec 二进制
if [[ -f "$ROOT/packaging/appimage/AppDir/AppRun" ]]; then
  install -m 0755 "$ROOT/packaging/appimage/AppDir/AppRun" "$APPDIR/AppRun"
else
  cat > "$APPDIR/AppRun" <<'APPRUN'
#!/bin/sh
# AppImage 入口 / AppImage entry point: resolve own dir, exec the real binary.
HERE="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
exec "$HERE/usr/bin/linux-driver-backup" "$@"
APPRUN
  chmod 0755 "$APPDIR/AppRun"
fi

info "AppDir 组装完成 / assembled:"
if command -v find >/dev/null 2>&1; then
  (cd "$APPDIR" && find . -type f -o -type l | sort | sed 's/^/    /')
fi

# ---- 5) 获取 appimagetool（固定版本 + SHA-256 校验）--------
TOOL="$WORK/appimagetool"
info "下载并校验 appimagetool / downloading + verifying appimagetool ..."
rc=0
ldb_fetch_verify "$APPIMAGE_URL" "$TOOL" "$AI_SHA" || rc=$?
case "$rc" in
  0) : ;;
  3)
    err "appimagetool 校验和不符，疑似供应链投毒，已中止 / checksum mismatch, aborting."
    exit 1 ;;
  127)
    warn "既无 curl 也无 wget，跳过 AppImage 构建。"
    exit 0 ;;
  *)
    warn "下载 appimagetool 失败（网络不可达）。"
    warn "Failed to download appimagetool — skipping AppImage, CI 继续产出 deb/rpm/tar。"
    exit 0 ;;
esac
chmod +x "$TOOL"

# ---- 6) 打包（APPIMAGE_EXTRACT_AND_RUN=1 免 FUSE）-----------
mkdir -p "$OUTDIR"
info "运行 appimagetool 打包 / building the AppImage (no FUSE required) ..."
if ! APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$ARCH" "$TOOL" "$APPDIR" "$OUT"; then
  warn "appimagetool 打包失败（常见原因：runner 无 FUSE、glibc 过旧、网络中断）。"
  warn "AppImage build failed — 已跳过，Release 仍会附带 deb/rpm/tar。"
  exit 0
fi

if [[ -f "$OUT" ]]; then
  chmod +x "$OUT"
  info "产物 / output: $OUT ($(du -h "$OUT" | cut -f1))"
  (cd "$OUTDIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
  info "已生成校验文件 / checksum: $(basename "$OUT").sha256"
else
  warn "appimagetool 未产出预期文件 $OUT，跳过。"
  exit 0
fi
