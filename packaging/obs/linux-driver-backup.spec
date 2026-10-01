# ============================================================
# OBS spec for linux-driver-backup
# 用于 OBS（openSUSE Build Service）的 RPM spec 模板。
#
# 占位 / Placeholders：@VERSION@ 由 CI 用 sed 替换（取自 Cargo.toml）。
#
# 与主 spec（packaging/linux-driver-backup.spec）的差异：
#   - 使用 suse 目标的依赖声明（SoName 文件依赖）；
#   - 去掉 %changelog 硬编码日期（OBS 从 git log 自动生成）；
#   - 其余安装布局完全一致。
# ============================================================

%global debug_package %{nil}

Name:           linux-driver-backup
Version:        @VERSION@
Release:        1%{?dist}
License:        GPL-3.0-only
Summary:        Backup and restore out-of-tree (third-party) Linux kernel drivers
URL:            https://github.com/ltbkq/linux-driver-backup

AutoReqProv:    yes

Recommends:     polkit

# openSUSE / SLE 使用 SoName 文件依赖（与主 spec 的 suse 分支一致）
Requires:       /usr/lib64/libxkbcommon.so.0
Requires:       /usr/lib64/libxkbcommon-x11.so.0
Requires:       /usr/lib64/libwayland-client.so.0

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
# 留空：二进制由 CI 从 target/release 拷入 %{_sourcedir}
:

%install
rm -rf %{buildroot}
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_datadir}/applications
install -d %{buildroot}%{_datadir}/icons/hicolor/scalable/apps
install -d %{buildroot}%{_datadir}/polkit-1/actions
install -d %{buildroot}%{_docdir}/%{name}

install -m 0755 %{_sourcedir}/linux-driver-backup \
        %{buildroot}%{_bindir}/linux-driver-backup
install -m 0644 %{_sourcedir}/linux-driver-backup.desktop \
        %{buildroot}%{_datadir}/applications/linux-driver-backup.desktop
install -m 0644 %{_sourcedir}/icon.svg \
        %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/linux-driver-backup.svg
install -m 0644 %{_sourcedir}/linux-driver-backup.policy \
        %{buildroot}%{_datadir}/polkit-1/actions/linux-driver-backup.policy
install -m 0644 %{_sourcedir}/LICENSE \
        %{buildroot}%{_docdir}/%{name}/LICENSE

%files
%{_bindir}/linux-driver-backup
%{_datadir}/applications/linux-driver-backup.desktop
%{_datadir}/icons/hicolor/scalable/apps/linux-driver-backup.svg
%{_datadir}/polkit-1/actions/linux-driver-backup.policy
%{_docdir}/%{name}/LICENSE
