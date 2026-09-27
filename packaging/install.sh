#!/usr/bin/env bash
# ============================================================
# install.sh —— 通用安装/卸载脚本（不依赖任何包管理器）
# Universal installer / uninstaller for linux-driver-backup (no pkg manager).
#
# 用法 / Usage:
#   ./install.sh                      # 安装到默认前缀 /usr/local
#   ./install.sh --prefix=/opt/ldb    # 指定前缀（也支持 --prefix /opt/ldb）
#   ./install.sh --uninstall          # 卸载（可与 --prefix 连用）
#   ./install.sh --help               # 帮助
#
# 安装内容 / What gets installed:
#   $prefix/bin/linux-driver-backup                              可执行文件
#   $prefix/share/applications/linux-driver-backup.desktop       桌面入口
#   $prefix/share/icons/hicolor/scalable/apps/linux-driver-backup.svg  图标
#   $prefix/share/doc/linux-driver-backup/LICENSE                GPL-3.0 全文
#
# 二进制来源 / Where the binary comes from:
#   1) 优先 target/release/linux-driver-backup（仓库内 cargo build --release 的产物）
#   2) 其次脚本同目录的 ./linux-driver-backup（tar.gz 包解出来的布局）
#   两者都没有 => 打印中文错误并退出 1。
# ============================================================
set -euo pipefail

PROG="install.sh"
PREFIX="/usr/local"
MODE="install"

info() { printf '[%s] %s\n' "$PROG" "$*"; }
err()  { printf '[%s][错误/ERROR] %s\n' "$PROG" "$*" >&2; }

usage() {
  cat <<'EOF'
linux-driver-backup 安装脚本 / installer

用法 / Usage:
  ./install.sh [--prefix DIR]          安装到 DIR（默认 /usr/local）
  ./install.sh --uninstall [--prefix]  卸载已安装的文件
  ./install.sh --help                  显示本帮助

选项 / Options:
  --prefix DIR, --prefix=DIR   安装前缀 / installation prefix（默认 /usr/local）
  --uninstall                  卸载模式：只删除本脚本安装过的四个文件
  -h, --help                   显示帮助并退出

说明 / Notes:
  · 需要写入系统目录时请加 sudo：sudo ./install.sh
  · 二进制取自 target/release/linux-driver-backup，
    若不存在会报错退出（请先 cargo build --release）。
EOF
}

# ---- 参数解析 / argument parsing ---------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      [[ $# -ge 2 ]] || { err "--prefix 缺少取值 / missing value"; exit 2; }
      PREFIX="$2"; shift 2 ;;
    --prefix=*)
      PREFIX="${1#--prefix=}"; shift ;;
    --uninstall)
      MODE="uninstall"; shift ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      err "未知参数 / unknown option: $1"
      usage
      exit 2 ;;
  esac
done

[[ -n "$PREFIX" ]] || { err "--prefix 不能为空 / prefix must not be empty"; exit 2; }
# 去掉尾部斜杠（/usr/local/ -> /usr/local），避免出现双斜杠路径
PREFIX="${PREFIX%/}"
[[ -n "$PREFIX" ]] || PREFIX="/"

# ---- 资源定位 / locate assets -----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 在候选目录里找第一个存在的文件 / first existing file among candidates
resolve() {
  local cand
  for cand in "$@"; do
    if [[ -f "$cand" ]]; then printf '%s' "$cand"; return 0; fi
  done
  return 1
}

# 1) 二进制：优先仓库 target/release，其次脚本同目录（tar 包布局）
BIN_SRC=""
if BIN_SRC="$(resolve \
    "$SCRIPT_DIR/../target/release/linux-driver-backup" \
    "$PWD/target/release/linux-driver-backup" \
    "$SCRIPT_DIR/linux-driver-backup")"; then
  :
else
  err "未找到二进制文件，已中止安装。"
  err "找不到可执行文件：请先在仓库根目录执行 'cargo build --release'，"
  err "或使用包含二进制的 tar.gz 发行包（其中 install.sh 与二进制同级）。"
  err "Binary not found: expected target/release/linux-driver-backup."
  exit 1
fi

# 2) 桌面入口与图标：脚本在 packaging/ 下，或随 tar 包与脚本同级
DESKTOP_SRC="$(resolve \
  "$SCRIPT_DIR/linux-driver-backup.desktop" \
  "$SCRIPT_DIR/../packaging/linux-driver-backup.desktop")" \
  || { err "未找到 linux-driver-backup.desktop"; exit 1; }

ICON_SRC="$(resolve \
  "$SCRIPT_DIR/icon.svg" \
  "$SCRIPT_DIR/../packaging/icon.svg")" \
  || { err "未找到 icon.svg"; exit 1; }

LICENSE_SRC="$(resolve "$SCRIPT_DIR/LICENSE" "$SCRIPT_DIR/../LICENSE")" \
  || { err "未找到 LICENSE"; exit 1; }

# ---- 安装目标 / install targets ---------------------------
BIN_DST="$PREFIX/bin/linux-driver-backup"
DESKTOP_DST="$PREFIX/share/applications/linux-driver-backup.desktop"
ICON_DST="$PREFIX/share/icons/hicolor/scalable/apps/linux-driver-backup.svg"
DOC_DIR="$PREFIX/share/doc/linux-driver-backup"
LICENSE_DST="$DOC_DIR/LICENSE"

# ---- 卸载模式 / uninstall mode ----------------------------
if [[ "$MODE" == "uninstall" ]]; then
  removed=0
  for f in "$BIN_DST" "$DESKTOP_DST" "$ICON_DST" "$LICENSE_DST"; do
    if [[ -e "$f" ]]; then
      rm -f "$f"
      info "已删除 / removed: $f"
      removed=$((removed + 1))
    else
      info "不存在，跳过 / not installed: $f"
    fi
  done
  # 清掉空目录（失败不致命）/ prune empty dirs, ignore failures
  rmdir "$DOC_DIR" 2>/dev/null || true
  rmdir "$PREFIX/share/icons/hicolor/scalable/apps" 2>/dev/null || true
  rmdir "$PREFIX/share/icons/hicolor/scalable" 2>/dev/null || true
  info "卸载完成 / uninstall finished（共移除 $removed 个文件 / $removed files removed）。"
  exit 0
fi

# ---- 安装 / install ---------------------------------------
# 目标目录不存在则自动创建 / auto-create missing directories
mkdir -p \
  "$PREFIX/bin" \
  "$PREFIX/share/applications" \
  "$PREFIX/share/icons/hicolor/scalable/apps" \
  "$DOC_DIR"

# 覆盖安装提示 / warn when overwriting an existing install
for f in "$BIN_DST" "$DESKTOP_DST" "$ICON_DST" "$LICENSE_DST"; do
  if [[ -e "$f" ]]; then
    info "已存在，将覆盖 / overwriting existing: $f"
  fi
done

install -m 0755 "$BIN_SRC"     "$BIN_DST"
install -m 0644 "$DESKTOP_SRC" "$DESKTOP_DST"
install -m 0644 "$ICON_SRC"    "$ICON_DST"
install -m 0644 "$LICENSE_SRC" "$LICENSE_DST"

info "安装完成 / installed:"
info "  可执行文件 / binary     : $BIN_DST"
info "  桌面入口   / desktop    : $DESKTOP_DST"
info "  图标       / icon       : $ICON_DST"
info "  许可       / license    : $LICENSE_DST"
info "运行 / run  : $BIN_DST  （或直接执行 linux-driver-backup，若 \$PATH 含 $PREFIX/bin）"
info "验证 / check: linux-driver-backup --version"
info "卸载 / remove: sudo $SCRIPT_DIR/$PROG --uninstall --prefix=$PREFIX"
info "（若是 root/普通用户直接安装，去掉 sudo 即可。）"
