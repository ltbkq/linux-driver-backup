#!/usr/bin/env bash
# ============================================================
# build-packages.sh —— 统一打包入口 / one-stop packaging entry point
#
# 子命令 / subcommands:
#   deb       组装 .deb（需 dpkg-deb）
#   tar       组装通用 tar.gz + install.sh（只需 tar）
#   rpm       组装 .rpm（需 rpmbuild；本机通常没有，CI 产出）
#   arch      渲染 PKGBUILD（AUR 源码包）+ 生成 .SRCINFO（需网络或 --sha256）
#   appimage  组装 AppImage（转调 build-appimage.sh；CI 产出）
#   all       以上全部（本机缺少工具的格式自动跳过，不算失败）
#   --help    帮助
#
# 设计要点 / Design notes（DESIGN.md §11.3）:
#   - 版本号、架构与占位符替换统一走 packaging/lib/common.sh（C-52/C-56 唯一事实源）；
#   - 自动探测工具：本机不具备的格式打印「[跳过]」并继续，不视为失败；
#   - deb 组装后用 dpkg-deb -I / -c 自检；
#   - 所有产物写入 dist/，并为每个产物生成同名 .sha256（供 release 复验）；
#   - polkit policy 随各包安装到 /usr/share/polkit-1/actions/（C-51）；
#   - RPM 目标由 --rpm-target 显式指定，不再强制 fedora（C-53）。
#
# 用法 / Usage:
#   bash packaging/build-packages.sh deb tar
#   bash packaging/build-packages.sh all
#   bash packaging/build-packages.sh rpm --rpm-target both
#   bash packaging/build-packages.sh arch
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
export LDB_ROOT="$ROOT"
# shellcheck disable=SC1090,SC1091  # 共享库路径含变量，shellcheck 无法静态跟随
source "$SCRIPT_DIR/lib/common.sh"

DIST="$ROOT/dist"
NAME="linux-driver-backup"
BIN="$ROOT/target/release/linux-driver-backup"
CONTROL="$ROOT/packaging/deb/control"
SPEC="$ROOT/packaging/linux-driver-backup.spec"
DESKTOP="$ROOT/packaging/linux-driver-backup.desktop"
ICON="$ROOT/packaging/icon.svg"
LICENSE="$ROOT/LICENSE"
INSTALL_SH="$ROOT/packaging/install.sh"
POLICY="$ROOT/packaging/polkit/linux-driver-backup.policy"
PKGBUILD_TMPL="$ROOT/packaging/arch/PKGBUILD"

# 临时目录统一回收 / clean up every staging dir on exit
TMPDIRS=()
# 注意：EXIT 陷阱里最后一条命令的状态会成为脚本退出码，
# 因此这里显式以 true 收尾，避免空数组/条件不成立导致 rc=1。
cleanup() {
  local d
  for d in "${TMPDIRS[@]}"; do
    if [[ -n "$d" && -d "$d" ]]; then
      rm -rf "$d"
    fi
  done
  true
}
trap cleanup EXIT

# 统一日志别名 / aliases onto the shared helpers in lib/common.sh
info() { ldb_info "$@"; }
skip() { ldb_skip "$@"; }
err()  { ldb_err "$@"; }

usage() {
  cat <<'EOF'
linux-driver-backup 统一打包入口 / unified packaging entry

用法 / Usage:
  bash packaging/build-packages.sh <子命令...> [选项]

子命令 / Subcommands:
  deb        组装 Debian/Ubuntu 包（需 dpkg-deb）
  tar        组装通用 tar.gz（含 install.sh，任何发行版可用）
  rpm        组装 RPM 包（需 rpmbuild；本机缺失时跳过，由 CI 产出）
  arch       渲染 AUR 的 PKGBUILD 并生成 .SRCINFO（产物在 dist/aur/）
  appimage   组装 AppImage（转调 build-appimage.sh；仅 x86_64）
  all        以上全部（arch 与 appimage 亦包含）
  -h, --help 显示本帮助

可选参数 / Options:
  --arch <amd64|arm64>   目标架构（默认按宿主推断）。deb 的 Architecture 字段、
                         rpm 的 --target 与 tar.gz 的文件名都会随之变化。
  --bin <路径>           指定要打包的二进制（默认 target/release/linux-driver-backup）。
  --rpm-target <目标>    RPM 依赖目标：fedora | suse | both | auto（默认 auto）。
                         fedora 用 Fedora/RHEL 包名；suse 用 SoName 文件依赖；
                         both 同时产出两种（文件名以 .fedora/.suse 区分），
                         不再强制 fedora（C-53）。
  --sha256 <hex>         渲染 PKGBUILD 时直接使用该 tarball 校验和（免联网）。
  --tarball <路径>       用本地发布归档计算 PKGBUILD 的 sha256sums。

说明 / Notes:
  · 本机缺少的工具不会导致失败，只打印「[跳过]」提示，对应格式由 CI 产出；
  · 产物与 .sha256 清单统一写入 dist/。
EOF
}

# deb 架构名、通用架构名、rpm 目标与渲染参数（见文件末尾参数循环）
ARCH_WANTED=""
BIN_OVERRIDE=""
RPM_TARGET="${RPM_TARGET:-auto}"
SHA256_OVERRIDE=""
TARBALL_OVERRIDE=""

# 交叉出包时给出提示：二进制 ELF 架构与目标架构不一致仍然由 rpmbuild/dpkg-deb
# 照常组装（它们不做机器码校验），但值得提醒，避免误发。
warn_arch_mismatch() {
  command -v file >/dev/null 2>&1 || return 0
  local desc
  desc="$(file -b "$BIN" 2>/dev/null || true)"
  case "$ARCH_PLAIN" in
    x86_64)  [[ "$desc" == *x86-64* ]] || info "提示 / hint: 目标架构 $ARCH_PLAIN，但二进制描述为：$desc" ;;
    aarch64) [[ "$desc" == *aarch64* || "$desc" == *ARM* ]] || info "提示 / hint: 目标架构 $ARCH_PLAIN，但二进制描述为：$desc" ;;
  esac
}

need_bin() {
  if [[ ! -f "$BIN" ]]; then
    err "未找到二进制 $BIN"
    err "请先执行 cargo build --release（W3 验证单元负责首次编译）。"
    err "Binary not found: build it with 'cargo build --release' first."
    exit 1
  fi
}

checksum() { ldb_checksum "$DIST" "$1"; }

# ---- deb ---------------------------------------------------
build_deb() {
  local ver debarch out stage size_kb
  if ! command -v dpkg-deb >/dev/null 2>&1; then
    skip "deb：未安装 dpkg-deb 工具（CI 会产出）"
    return 0
  fi
  need_bin
  ver="$(ldb_version)"
  debarch="$ARCH_DEB"
  out="$DIST/${NAME}_${ver}_${debarch}.deb"
  info "[deb 1/4] 组装数据树 / staging data tree（$ver / $debarch）"
  stage="$(mktemp -d "${TMPDIR:-/tmp}/ldb-deb.XXXXXX")"
  TMPDIRS+=("$stage")
  local root="$stage/root"
  install -Dm755 "$BIN"      "$root/usr/bin/$NAME"
  install -Dm644 "$DESKTOP"  "$root/usr/share/applications/$NAME.desktop"
  install -Dm644 "$ICON"     "$root/usr/share/icons/hicolor/scalable/apps/$NAME.svg"
  # polkit policy（C-51）：exec.path 与 /usr/bin/<name> 一致
  install -Dm644 "$POLICY"   "$root/usr/share/polkit-1/actions/$NAME.policy"
  # deb 的 copyright 按 Debian 惯例放在 /usr/share/doc/<pkg>/copyright
  install -Dm644 "$LICENSE"  "$root/usr/share/doc/$NAME/copyright"

  info "[deb 2/4] 计算 Installed-Size 并渲染 control"
  size_kb="$(du -sk "$root" | cut -f1)"
  mkdir -p "$root/DEBIAN"
  # ldb_render 负责 @VERSION@/@SIZE_KB@；Architecture 行再单独按目标替换；
  # 最后剥离模板里的 # 注释行（control 不接受注释）。
  ldb_render "$CONTROL" "$root/DEBIAN/control.render" "SIZE_KB=$size_kb"
  ldb_assert_no_placeholders "$root/DEBIAN/control.render"
  sed -e "s/^Architecture:.*/Architecture: $debarch/" "$root/DEBIAN/control.render" \
    | grep -v '^#' > "$root/DEBIAN/control"
  rm -f "$root/DEBIAN/control.render"
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
  ver="$(ldb_version)"
  arch="$ARCH_PLAIN"
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
  install -m 0644 "$POLICY"    "$pkg/$NAME.policy"
  install -m 0755 "$INSTALL_SH" "$pkg/install.sh"

  info "[tar 2/2] 压缩 / compress → $(basename "$out")"
  mkdir -p "$DIST"
  tar -C "$stage" -czf "$out" "$dir"
  info "内容 / members:"
  tar -tzf "$out" | sed 's/^/    /'
  checksum "$out"
}

# ---- rpm ---------------------------------------------------
# 单个目标 / one RPM flavour（fedora 包名 或 suse SoName）
build_rpm_one() {
  local target="$1" ver top out
  local -a defs=()
  case "$target" in
    fedora) defs+=(--define "ldb_target fedora" --define "dist .fedora") ;;
    suse)   defs+=(--define "ldb_target suse"   --define "dist .suse") ;;
    auto|"") : ;;
    *) err "未知 rpm 目标 / unknown rpm target: $target（fedora | suse | both | auto）"; return 2 ;;
  esac

  ver="$(ldb_version)"
  top="$(mktemp -d "${TMPDIR:-/tmp}/ldb-rpm.XXXXXX")"
  TMPDIRS+=("$top")
  mkdir -p "$top"/{SPECS,SOURCES,RPMS,SRPMS,BUILD,BUILDROOT}

  info "[rpm] 渲染 spec 并拷入预编译二进制（%build 留空；目标 / target=${target:-auto}）"
  ldb_render "$SPEC" "$top/SPECS/$NAME.spec"
  ldb_assert_no_placeholders "$top/SPECS/$NAME.spec"
  install -m 0755 "$BIN"     "$top/SOURCES/$NAME"
  install -m 0644 "$DESKTOP" "$top/SOURCES/$NAME.desktop"
  install -m 0644 "$ICON"    "$top/SOURCES/icon.svg"
  install -m 0644 "$LICENSE" "$top/SOURCES/LICENSE"
  install -m 0644 "$POLICY"  "$top/SOURCES/$NAME.policy"

  info "[rpm] rpmbuild -bb --target $ARCH_RPM"
  rpmbuild -bb --target "$ARCH_RPM" \
    --define "_topdir $top" \
    "${defs[@]}" \
    "$top/SPECS/$NAME.spec"
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

build_rpm() {
  if ! command -v rpmbuild >/dev/null 2>&1; then
    skip "rpm：未安装 rpmbuild 工具（CI 会产出）"
    return 0
  fi
  need_bin
  info "[rpm 1/2] 准备 rpmbuild 目录 / prepare _topdir"
  case "$RPM_TARGET" in
    both) build_rpm_one fedora; build_rpm_one suse ;;
    *)    build_rpm_one "${RPM_TARGET:-auto}" ;;
  esac
}

# ---- arch / AUR --------------------------------------------
# 渲染 PKGBUILD（@VERSION@/@SHA256@）并生成 .SRCINFO（C-52）。
build_arch() {
  local ver hash url tmp outdir
  ver="$(ldb_version)"
  outdir="$DIST/aur"
  mkdir -p "$outdir"

  info "[arch 1/3] 计算发布归档 sha256 / computing release tarball checksum（$ver）"
  hash="${SHA256_OVERRIDE:-}"
  if [[ -n "$hash" ]]; then
    info "使用 --sha256 指定的校验和 / using supplied checksum"
  elif [[ -n "$TARBALL_OVERRIDE" ]]; then
    if [[ ! -f "$TARBALL_OVERRIDE" ]]; then
      err "--tarball 指定的文件不存在 / tarball not found: $TARBALL_OVERRIDE"
      return 1
    fi
    hash="$(ldb_sha256_of "$TARBALL_OVERRIDE")"
  else
    url="https://github.com/ltbkq/linux-driver-backup/archive/refs/tags/v${ver}.tar.gz"
    tmp="$(mktemp "${TMPDIR:-/tmp}/ldb-aur-src.XXXXXX.tar.gz")"
    if ldb_fetch_verify "$url" "$tmp" ""; then
      hash="$(ldb_sha256_of "$tmp")"
    else
      ldb_warn "无法获取发布归档（$url）；PKGBUILD 的 sha256sums 保留 SKIP。"
      ldb_warn "发布后请运行 updpkgsums，或改用 --tarball/--sha256 重跑。"
      hash="SKIP"
    fi
    rm -f "$tmp"
  fi

  info "[arch 2/3] 渲染 PKGBUILD → $outdir/PKGBUILD"
  ldb_render "$PKGBUILD_TMPL" "$outdir/PKGBUILD" "SHA256=$hash"
  ldb_assert_no_placeholders "$outdir/PKGBUILD"

  info "[arch 3/3] 生成 .SRCINFO → $outdir/.SRCINFO"
  ldb_write_srcinfo "$outdir/PKGBUILD" "$outdir/.SRCINFO"
  info "产物 / output: $outdir/PKGBUILD, $outdir/.SRCINFO"
}

# ---- appimage ---------------------------------------------
build_appimage() {
  # appimagetool 官方仅提供 x86_64 / aarch64 两种宿主工具；交叉组装 AppImage 意义不大，
  # 首版仅对 x86_64 产出（DESIGN.md §11.1 架构范围）。
  if [[ "$ARCH_PLAIN" != "x86_64" ]]; then
    skip "appimage：首版仅支持 x86_64 目标（当前 $ARCH_PLAIN）"
    return 0
  fi
  need_bin
  info "[appimage] 调用 packaging/build-appimage.sh（--bin/--arch 透传）"
  bash "$ROOT/packaging/build-appimage.sh" --bin "$BIN" --arch "$ARCH_DEB"
}

# ---- 主流程 / main ----------------------------------------
# 先解析可选参数（--arch / --bin / --rpm-target / --sha256 / --tarball），
# 再逐个执行子命令。
SUBCOMMANDS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --arch)        ARCH_WANTED="${2:-}";     shift 2 ;;
    --arch=*)      ARCH_WANTED="${1#*=}";    shift ;;
    --bin)         BIN_OVERRIDE="${2:-}";    shift 2 ;;
    --bin=*)       BIN_OVERRIDE="${1#*=}";   shift ;;
    --rpm-target)  RPM_TARGET="${2:-}";      shift 2 ;;
    --rpm-target=*) RPM_TARGET="${1#*=}";    shift ;;
    --sha256)      SHA256_OVERRIDE="${2:-}"; shift 2 ;;
    --sha256=*)    SHA256_OVERRIDE="${1#*=}"; shift ;;
    --tarball)     TARBALL_OVERRIDE="${2:-}"; shift 2 ;;
    --tarball=*)   TARBALL_OVERRIDE="${1#*=}"; shift ;;
    -h|--help|help) usage; exit 0 ;;
    *)             SUBCOMMANDS+=("$1"); shift ;;
  esac
done

if [[ -n "$BIN_OVERRIDE" ]]; then
  BIN="$BIN_OVERRIDE"
fi
ldb_resolve_arch "$ARCH_WANTED" || exit 2

if [[ ${#SUBCOMMANDS[@]} -eq 0 ]]; then
  usage
  exit 2
fi

mkdir -p "$DIST"
if [[ -f "$BIN" ]]; then
  warn_arch_mismatch
fi
for cmd in "${SUBCOMMANDS[@]}"; do
  case "$cmd" in
    deb)      build_deb ;;
    tar)      build_tar ;;
    rpm)      build_rpm ;;
    arch)     build_arch ;;
    appimage) build_appimage ;;
    all)      build_deb; build_tar; build_rpm; build_arch; build_appimage ;;
    *)
      err "未知子命令 / unknown subcommand: $cmd"
      usage
      exit 2 ;;
  esac
done

info "完成 / done。产物见 / see: $DIST"
if command -v find >/dev/null 2>&1; then
  find "$DIST" -maxdepth 1 -mindepth 1 -printf '    %p\n' | sort
fi
