# ============================================================
# RPM 打包模板 / RPM spec template for linux-driver-backup
#
# 占位 / Placeholders：@VERSION@ 由 packaging/build-packages.sh 用 sed 替换
# （取自 Cargo.toml 的 version 字段）。
#
# CI 用法 / How CI uses this spec
# --------------------------------
# 1) 本 spec **不编译源码**：%build 留空，二进制由 CI 从 target/release
#    拷入 rpmbuild 的 %{_sourcedir}（或 %{_builddir}），见下方 %install。
#    The spec does not compile anything: %build is intentionally empty and the
#    pre-built binary is copied in by CI from target/release.
# 2) CI 执行 / CI steps：
#      sudo apt-get install -y rpm                    # 提供 rpmbuild
#      topdir=$(mktemp -d)
#      mkdir -p "$topdir"/{SPECS,SOURCES,RPMS,SRPMS,BUILD,BUILDROOT}
#      sed "s/@VERSION@/$VER/" packaging/linux-driver-backup.spec > "$topdir/SPECS/…"
#      cp target/release/linux-driver-backup packaging/linux-driver-backup.desktop \
#         packaging/icon.svg LICENSE "$topdir/SOURCES/"
#      rpmbuild -bb --define "_topdir $topdir" "$topdir/SPECS/linux-driver-backup.spec"
#      cp "$topdir"/RPMS/*/linux-driver-backup-*.rpm dist/
#    以上流程已由 packaging/build-packages.sh 的 `rpm` 子命令封装。
# 3) 本机无 rpmbuild 时脚本打印 [跳过]，产物交由 CI 产出（DESIGN.md §11.4）。
# ============================================================

# 关闭 debuginfo：交付物是已 strip 的预编译二进制，不产出 debug 包
# Disable debuginfo: we ship a pre-stripped binary, no debug package.
%global debug_package %{nil}

# 说明：不声明 Source0 —— 声明后 rpmbuild 会强制校验 _sourcedir 内存在同名源码包；
# 本项目直接由 CI 拷入已编译二进制与静态资产，故用注释记录来源（见文件头）。
# Source0: linux-driver-backup-@VERSION@.tar.gz   # 备选：改用 tarball 时再启用

Name:           linux-driver-backup
Version:        @VERSION@
Release:        1%{?dist}
License:        GPL-3.0-only
Summary:        Backup and restore out-of-tree (third-party) Linux kernel drivers
URL:            https://github.com/ltbkq/linux-driver-backup

# 依赖按 DESIGN.md §11.1 手写，W3 用 ldd 复核：
# glibc 运行时 + winit 运行期 dlopen 的 libxkbcommon / wayland 客户端库
Requires:       glibc >= 2.35, fontconfig, freetype, libxkbcommon, libxkbcommon-x11, wayland

# 构建依赖：无 —— 直接安装已编译产物，不在此处编译 Rust
# BuildRequires: none — pre-built binary is installed directly.

%description
Backup and restore out-of-tree (third-party) Linux kernel drivers, with both a
Slint GUI and a scriptable CLI in one self-contained binary.

备份与还原 Linux 外置（out-of-tree）驱动模块的桌面 + 命令行工具：支持
minimal / standard / full 三级备份模式，逐文件 SHA-256 校验，归档为含
manifest.json 的 tar.gz，可跨机还原；还原前支持 dry-run 预演，写入系统目录
时通过 pkexec 完成单次提权。

%prep
# 预编译交付 / pre-built delivery：无源码可解
:

%build
# 留空：二进制由 CI 从 target/release 拷入 %{_sourcedir}（见文件头说明）
# Intentionally empty — the binary is copied in by CI from target/release.
:

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_datadir}/applications
install -d %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -d %{buildroot}%{_docdir}/%{name}

# 二进制 / the pre-built binary (copied in by packaging/build-packages.sh)
install -m 0755 %{_sourcedir}/linux-driver-backup \
        %{buildroot}%{_bindir}/linux-driver-backup

# 桌面入口 / desktop entry
install -m 0644 %{_sourcedir}/linux-driver-backup.desktop \
        %{buildroot}%{_datadir}/applications/linux-driver-backup.desktop

# 可缩放图标 / scalable icon（hicolor 主题，安装后可选刷新图标缓存）
install -m 0644 %{_sourcedir}/icon.svg \
        %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/linux-driver-backup.svg

# 许可全文 / full GPL-3.0 text（与 deb 的 copyright 同源：/usr/share/common-licenses/GPL-3）
install -m 0644 %{_sourcedir}/LICENSE \
        %{buildroot}%{_docdir}/%{name}/LICENSE

%files
%{_bindir}/linux-driver-backup
%{_datadir}/applications/linux-driver-backup.desktop
%{_datadir}/icons/hicolor/scalable/apps/linux-driver-backup.svg
%{_docdir}/%{name}/LICENSE

%changelog
* Sun Sep 27 2026 ltbkq <ltbkqq@gmail.com> - @VERSION@-1
- 首个 RPM 打包版本 / Initial RPM packaging
