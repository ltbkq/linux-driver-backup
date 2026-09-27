#!/usr/bin/env bash
# ============================================================
# build-appimage.sh —— 组装 AppDir 并产出 AppImage
# Assemble the AppDir and build the AppImage for linux-driver-backup.
#
# 结构说明见 packaging/appimage/README.md。
#
# 关键约定 / Key behaviours:
#   - 二进制来源：target/release/linux-driver-backup（不存在则中文报错退出）
#   - 免 FUSE：统一用 APPIMAGE_EXTRACT_AND_RUN=1 运行 appimagetool
#   - 网络失败 / 无 FUSE / 下载超时：打印中文 warning 并 exit 0，
#     以免中断 CI（DESIGN.md §11.4：AppImage 失败只降级、不影响发布）
#   - 产物：dist/linux-driver-backup-<版本>-linux-<架构>.AppImage
#
# 用法 / Usage:
#   bash packaging/build-appimage.sh
# ============================================================
set -euo pipefail

# 中文进度输出（附英文关键词，便于 grep）
info() { printf '[appimage] %s\n' "$*"; }
warn() { printf '[appimage][警告/WARNING] %s\n' "$*" >&2; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release/linux-driver-backup"
DESKTOP="$ROOT/packaging/linux-driver-backup.desktop"
ICON="$ROOT/packaging/icon.svg"
OUTDIR="$ROOT/dist"
APPIMAGE_URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"

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

# ---- 2) 版本与架构 -----------------------------------------
VERSION="$(grep -m1 '^version' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')"
ARCH="$(uname -m)"   # x86_64 / aarch64（appimagetool 用原始 uname 架构命名）
OUT="$OUTDIR/linux-driver-backup-${VERSION}-linux-${ARCH}.AppImage"
info "版本/version=$VERSION 架构/arch=$ARCH"

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

# 4.2 桌面入口（必须在 AppDir 根部）
cp "$DESKTOP" "$APPDIR/linux-driver-backup.desktop"
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
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec "$HERE/usr/bin/linux-driver-backup" "$@"
APPRUN
  chmod 0755 "$APPDIR/AppRun"
fi

info "AppDir 组装完成 / assembled:"
if command -v find >/dev/null 2>&1; then
  (cd "$APPDIR" && find . -type f -o -type l | sort | sed 's/^/    /')
fi

# ---- 5) 获取 appimagetool（失败 => 中文 warning + exit 0）---
TOOL="$WORK/appimagetool"
download_tool() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 20 -o "$TOOL" "$APPIMAGE_URL"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 30 -t 2 -O "$TOOL" "$APPIMAGE_URL"
  else
    return 127
  fi
}

info "下载 appimagetool / downloading appimagetool ..."
if ! download_tool; then
  warn "下载 appimagetool 失败（网络不可达或无 curl/wget）。"
  warn "Failed to download appimagetool — skipping AppImage, CI 继续产出 deb/rpm/tar。"
  exit 0
fi
if [[ ! -s "$TOOL" ]]; then
  warn "appimagetool 下载内容为空，跳过 AppImage 构建。"
  exit 0
fi
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
