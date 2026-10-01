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
#         packaging/icon.svg packaging/polkit/linux-driver-backup.policy LICENSE \
#         "$topdir/SOURCES/"
#      rpmbuild -bb --define "_topdir $topdir" --define "ldb_target fedora" \
#         "$topdir/SPECS/linux-driver-backup.spec"
#      cp "$topdir"/RPMS/*/linux-driver-backup-*.rpm dist/
#    以上流程已由 packaging/build-packages.sh 的 `rpm` 子命令封装，
#    并由其 `--rpm-target fedora|suse|both|auto` 选择依赖分支（C-53）。
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

# ---------------------------------------------------------------------------
# 依赖声明 / Runtime dependencies
#
# 原则：**硬链接（DT_NEEDED）依赖交给 rpmbuild 自动生成 soname 依赖**
# （libc.so.6()(64bit)、libfontconfig.so.1()(64bit)、libfreetype.so.6()(64bit) …），
# 因为它们的提供包名在各发行版一致，自动生成比手写更准确。
#
# 只有**运行期 dlopen** 的库（自动生成抓不到）才手写，且必须用发行版真实
# 二进制包名 —— 这里曾把 `wayland` 当包名写死，导致 Fedora 报
#   「wayland 被 linux-driver-backup 需要」而无法安装；
# Fedora/RHEL 上正确的包名是 `libwayland-client`（见下方条件分支）。
#
# 双目标 / Dual target（C-53）：依赖分支由构建参数 `ldb_target` 显式选择，
# **不再强制 fedora**。CI 在 Ubuntu 上构建时 `%{?fedora}`/`%{?rhel}` 均未定义，
# 若不传 `ldb_target` 则走通用 SoName 分支（openSUSE 等正确）；
# 传 `--define "ldb_target fedora"` 才产出 Fedora/RHEL 包名依赖。
# build-packages.sh `--rpm-target fedora|suse|both|auto` 封装了该参数。
#
# Verification: `rpm -qpR <包>` 可查看最终生效的 Requires（CI 中有断言防止回退）。
# ---------------------------------------------------------------------------
AutoReqProv:    yes

# 可选依赖：pkexec 图形提权（C-50）。Fedora/RHEL 及 openSUSE 的包名均为 polkit。
Recommends:     polkit

%if 0%{?fedora} || 0%{?rhel} || "%{?ldb_target}" == "fedora"
# Fedora / RHEL / Rocky / AlmaLinux / CentOS Stream / openEuler 的真实包名。
Requires:       libwayland-client
Requires:       libxkbcommon
Requires:       libxkbcommon-x11
%else
# 其它 RPM 发行版（如 openSUSE：libwayland-client0 / libxkbcommon0 …）包名不同，
# 改用 SoName 文件依赖，避免把某一家的包名硬编码到通用 spec 里。
# x86_64 与 aarch64 在 Fedora/openSUSE 上库目录均为 /usr/lib64。
Requires:       /usr/lib64/libxkbcommon.so.0
Requires:       /usr/lib64/libxkbcommon-x11.so.0
Requires:       /usr/lib64/libwayland-client.so.0
%endif

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
install -d %{buildroot}%{_datadir}/polkit-1/actions
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

# polkit policy（C-51）：exec.path 与 %{_bindir}/linux-driver-backup 一致
install -m 0644 %{_sourcedir}/linux-driver-backup.policy \
        %{buildroot}%{_datadir}/polkit-1/actions/linux-driver-backup.policy

# 许可全文 / full GPL-3.0 text（与 deb 的 copyright 同源：/usr/share/common-licenses/GPL-3）
install -m 0644 %{_sourcedir}/LICENSE \
        %{buildroot}%{_docdir}/%{name}/LICENSE

%files
%{_bindir}/linux-driver-backup
%{_datadir}/applications/linux-driver-backup.desktop
%{_datadir}/icons/hicolor/scalable/apps/linux-driver-backup.svg
%{_datadir}/polkit-1/actions/linux-driver-backup.policy
%{_docdir}/%{name}/LICENSE

%changelog
* Sun Sep 27 2026 ltbkq <ltbkqq@gmail.com> - @VERSION@-1
- 首个 RPM 打包版本 / Initial RPM packaging
