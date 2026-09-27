#!/usr/bin/env bash
# ============================================================
# build-packages.sh —— 统一打包入口 / one-stop packaging entry point
#
# 子命令 / subcommands:
#   deb       组装 .deb（需 dpkg-deb）
#   tar       组装通用 tar.gz + install.sh（只需 tar）
#   rpm       组装 .rpm（需 rpmbuild；本机通常没有，CI 产出）
#   appimage  组装 AppImage（需 appimagetool；CI 产出）
#   all       以上全部（本机缺少工具的格式自动跳过，不算失败）
#   --help    帮助
#
# 设计要点 / Design notes（DESIGN.md §11.3）:
#   - 版本号从 Cargo.toml 的 version = 行 grep 出来，避免多处手写；
#   - 自动探测工具：本机不具备的格式打印「[跳过]」并继续，不视为失败；
#   - deb 组装后用 dpkg-deb -I / -c 自检；
#   - 所有产物写入 dist/，并为每个产物生成同名 .sha256（供 release 复验）；
#   - 全程中文进度输出，关键英文词便于 grep。
#
# 用法 / Usage:
#   bash packaging/build-packages.sh deb tar
#   bash packaging/build-packages.sh all
# ============================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
NAME="linux-driver-backup"
BIN="$ROOT/target/release/linux-driver-backup"
CONTROL="$ROOT/packaging/deb/control"
SPEC="$ROOT/packaging/linux-driver-backup.spec"
DESKTOP="$ROOT/packaging/linux-driver-backup.desktop"
ICON="$ROOT/packaging/icon.svg"
LICENSE="$ROOT/LICENSE"
INSTALL_SH="$ROOT/packaging/install.sh"

# 临时目录统一回收 / clean up every staging dir on exit
TMPDIRS=()
# 注意：EXIT 陷阱里最后一条命令的状态会成为脚本退出码，
# 因此这里显式以 true 收尾，避免空数组/条件不成立导致 rc=1。
cleanup() {
  local d
  for d in "${TMPDIRS[@]:-}"; do
    if [[ -n "$d" && -d "$d" ]]; then
      rm -rf "$d"
    fi
  done
  true
}
trap cleanup EXIT

info() { printf '[打包] %s\n' "$*"; }
skip() { printf '[跳过] %s\n' "$*"; }
err()  { printf '[错误/ERROR] %s\n' "$*" >&2; }

usage() {
  cat <<'EOF'
linux-driver-backup 统一打包入口 / unified packaging entry

用法 / Usage:
  bash packaging/build-packages.sh <子命令...>

子命令 / Subcommands:
  deb        组装 Debian/Ubuntu 包（需 dpkg-deb）
  tar        组装通用 tar.gz（含 install.sh，任何发行版可用）
  rpm        组装 RPM 包（需 rpmbuild；本机缺失时跳过，由 CI 产出）
  appimage   组装 AppImage（需 appimagetool；本机缺失时跳过，由 CI 产出）
  all        以上全部
  -h, --help 显示本帮助

说明 / Notes:
  · 二进制取自 target/release/linux-driver-backup，不存在则报错退出，
    请先在仓库根目录执行 cargo build --release；
  · 本机缺少的工具不会导致失败，只打印「[跳过]」提示，对应格式由 CI 产出；
  · 产物与 .sha256 清单统一写入 dist/。
EOF
}

# ---- 版本与架构 / version & arch ---------------------------
version_of() {
  local v
  v="$(grep -m1 '^version[[:space:]]*=' "$ROOT/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/')" || true
  if [[ -z "$v" ]]; then
    err "无法从 Cargo.toml 解析 version 字段。"
    exit 1
  fi
  printf '%s' "$v"
}

# deb 架构名（amd64/arm64）与通用架构名（x86_64/aarch64）
deb_arch()   { case "$(uname -m)" in aarch64|arm64) echo arm64 ;; *) echo amd64 ;; esac; }
plain_arch() { uname -m; }

need_bin() {
  if [[ ! -f "$BIN" ]]; then
    err "未找到二进制 $BIN"
    err "请先执行 cargo build --release（W3 验证单元负责首次编译）。"
    err "Binary not found: build it with 'cargo build --release' first."
    exit 1
  fi
}

# 为产物生成同名 .sha256（记录 dist 内相对文件名，便于 sha256sum -c）
checksum() {
  local f="$1"
  (cd "$DIST" && sha256sum "$(basename "$f")" > "$(basename "$f").sha256")
  info "SHA-256: $(cat "$DIST/$(basename "$f").sha256")"
}

# ---- deb ---------------------------------------------------
build_deb() {
  local ver debarch out stage size_kb
  if ! command -v dpkg-deb >/dev/null 2>&1; then
    skip "deb：未安装 dpkg-deb 工具（CI 会产出）"
    return 0
  fi
  need_bin
  ver="$(version_of)"
  debarch="$(deb_arch)"
  out="$DIST/${NAME}_${ver}_${debarch}.deb"
  info "[deb 1/4] 组装数据树 / staging data tree（$ver / $debarch）"
  stage="$(mktemp -d "${TMPDIR:-/tmp}/ldb-deb.XXXXXX")"
  TMPDIRS+=("$stage")
  local root="$stage/root"
  install -Dm755 "$BIN"      "$root/usr/bin/$NAME"
  install -Dm644 "$DESKTOP"  "$root/usr/share/applications/$NAME.desktop"
  install -Dm644 "$ICON"     "$root/usr/share/icons/hicolor/scalable/apps/$NAME.svg"
  # deb 的 copyright 按 Debian 惯例放在 /usr/share/doc/<pkg>/copyright
  install -Dm644 "$LICENSE"  "$root/usr/share/doc/$NAME/copyright"

  info "[deb 2/4] 计算 Installed-Size 并渲染 control"
  size_kb="$(du -sk "$root" | cut -f1)"
  mkdir -p "$root/DEBIAN"
  # sed 替换占位符，并剥离模板里的 # 注释行（control 不接受注释）
  sed -e "s/@VERSION@/$ver/g" -e "s/@SIZE_KB@/$size_kb/g" "$CONTROL" \
    | grep -v '^#' > "$root/DEBIAN/control"
  chmod 0755 "$root/DEBIAN"

  info "[deb 3/4] dpkg-deb --build --root-owner-group"
  mkdir -p "$DIST"
  dpkg-deb --build --root-owner-group "$root" "$out"

  info "[deb 4/4] 自检 / self-check"
  dpkg-deb -I "$out"
  info "包内容 / contents:"
  dpkg-deb -c "$out" | sed 's/^/    /'
  checksum "$out"
}

# ---- tar.gz ------------------------------------------------
build_tar() {
  local ver arch stage dir out
  if ! command -v tar >/dev/null 2>&1; then
    skip "tar：未安装 tar 工具（理论上必有，CI 会产出）"
    return 0
  fi
  need_bin
  ver="$(version_of)"
  arch="$(plain_arch)"
  dir="${NAME}-${ver}-linux-${arch}"
  out="$DIST/${dir}.tar.gz"
  info "[tar 1/2] 组装目录 / staging $dir"
  stage="$(mktemp -d "${TMPDIR:-/tmp}/ldb-tar.XXXXXX")"
  TMPDIRS+=("$stage")
  local pkg="$stage/$dir"
  mkdir -p "$pkg"
  install -m 0755 "$BIN"       "$pkg/$NAME"
  install -m 0644 "$DESKTOP"   "$pkg/$NAME.desktop"
  install -m 0644 "$ICON"      "$pkg/icon.svg"
  install -m 0644 "$LICENSE"   "$pkg/LICENSE"
  install -m 0755 "$INSTALL_SH" "$pkg/install.sh"

  info "[tar 2/2] 压缩 / compress → $(basename "$out")"
  mkdir -p "$DIST"
  tar -C "$stage" -czf "$out" "$dir"
  info "内容 / members:"
  tar -tzf "$out" | sed 's/^/    /'
  checksum "$out"
}

# ---- rpm ---------------------------------------------------
build_rpm() {
  local ver top out
  if ! command -v rpmbuild >/dev/null 2>&1; then
    skip "rpm：未安装 rpmbuild 工具（CI 会产出）"
    return 0
  fi
  need_bin
  ver="$(version_of)"
  info "[rpm 1/3] 准备 rpmbuild 目录 / prepare _topdir"
  top="$(mktemp -d "${TMPDIR:-/tmp}/ldb-rpm.XXXXXX")"
  TMPDIRS+=("$top")
  mkdir -p "$top"/{SPECS,SOURCES,RPMS,SRPMS,BUILD,BUILDROOT}

  info "[rpm 2/3] 渲染 spec 并拷入预编译二进制（%build 留空）"
  sed -e "s/@VERSION@/$ver/g" "$SPEC" > "$top/SPECS/$NAME.spec"
  install -m 0755 "$BIN"     "$top/SOURCES/$NAME"
  install -m 0644 "$DESKTOP" "$top/SOURCES/$NAME.desktop"
  install -m 0644 "$ICON"    "$top/SOURCES/icon.svg"
  install -m 0644 "$LICENSE" "$top/SOURCES/LICENSE"

  info "[rpm 3/3] rpmbuild -bb"
  rpmbuild -bb --define "_topdir $top" "$top/SPECS/$NAME.spec"
  out="$(find "$top/RPMS" -name '*.rpm' -type f | head -n1)"
  if [[ -z "$out" ]]; then
    err "rpmbuild 未产出 rpm 文件。"
    return 1
  fi
  mkdir -p "$DIST"
  cp "$out" "$DIST/$(basename "$out")"
  info "产物 / output: $(basename "$out")"
  if command -v rpm >/dev/null 2>&1; then
    info "rpm 自检 / inspect:"
    rpm -qip "$DIST/$(basename "$out")" | sed 's/^/    /' || true
  fi
  checksum "$DIST/$(basename "$out")"
}

# ---- appimage ---------------------------------------------
build_appimage() {
  if ! command -v appimagetool >/dev/null 2>&1; then
    skip "appimage：未安装 appimagetool 工具（CI 会产出）"
    info "提示 / hint: 本机如需构建，可直接运行 packaging/build-appimage.sh（会自动下载 appimagetool）。"
    return 0
  fi
  need_bin
  info "[appimage] 调用 packaging/build-appimage.sh"
  bash "$ROOT/packaging/build-appimage.sh"
}

# ---- 主流程 / main ----------------------------------------
if [[ $# -eq 0 ]]; then
  usage
  exit 2
fi

mkdir -p "$DIST"
for cmd in "$@"; do
  case "$cmd" in
    deb)      build_deb ;;
    tar)      build_tar ;;
    rpm)      build_rpm ;;
    appimage) build_appimage ;;
    all)      build_deb; build_tar; build_rpm; build_appimage ;;
    -h|--help|help) usage; exit 0 ;;
    *)
      err "未知子命令 / unknown subcommand: $cmd"
      usage
      exit 2 ;;
  esac
done

info "完成 / done。产物见 / see: $DIST"
if command -v ls >/dev/null 2>&1; then
  ls -l "$DIST" | sed 's/^/    /'
fi
