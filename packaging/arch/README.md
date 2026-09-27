# packaging/arch —— Arch Linux / AUR 打包说明

中文为主、英文补充（DESIGN.md 附录 A 文档规范）。本目录用于**源码包**方式安装
`linux-driver-backup`，产物与 [../linux-driver-backup.spec](../linux-driver-backup.spec)（RPM）、
[../deb/control](../deb/control)（deb）等价，只是走 Arch 的 `makepkg` 流程。

## 1. 适用场景 / When to use this

| 场景 / Scenario | 做法 / How |
|---|---|
| Arch / Manjaro / EndeavourOS 本机装包 | `makepkg -si`（见下） |
| 提交到 AUR 让所有人 `yay -S linux-driver-backup` | 见下「提交 AUR」 |
| 只是想跑一下，不装系统 | 用 [../build-appimage.sh](../build-appimage.sh) 产 AppImage |

> 注意：本目录是**源码包**（PKGBUILD 的 `source` 指向 GitHub Release 的 tag 归档），
> 不是二进制包。若只想用二进制，请改用 Release 页的 `.deb` / `.rpm` / `tar.gz`。

## 2. 本机构建安装 / Build & install locally

前置条件 / Prerequisites：

- 已发布对应的 GitHub Release（`source` 需要 `v<版本>` 的 tag 归档可下载）；
- 已安装 Rust 工具链 ≥ 1.83（`rustup` 或 `pacman -S rust`）；
- 编译期依赖：`sudo pacman -S --needed pkgconfig libxkbcommon wayland libx11`。

步骤 / Steps：

```bash
cd packaging/arch

# 1) 把模板里的 @VERSION@ 替换成 Cargo.toml 里的真实版本（根目录可一键生成）
VERSION=$(grep -m1 '^version' ../../Cargo.toml | sed 's/.*"\(.*\)".*/\1/')
sed "s/@VERSION@/$VERSION/g" PKGBUILD > PKGBUILD.rendered
mv PKGBUILD.rendered PKGBUILD        # 或直接手工编辑 pkgver

# 2) 生成/更新校验和（发布 release 之后执行；未发 release 前保持 SKIP）
updpkgsums                          # 或 makepkg -g

# 3) 生成 .SRCINFO（AUR 必需，改任何字段后都要重跑）
makepkg --printsrcinfo > .SRCINFO

# 4) 构建并安装（-s 自动装依赖，-i 装完直接 pacman -U）
makepkg -si
```

安装落点 / Install layout：

```
/usr/bin/linux-driver-backup
/usr/share/applications/linux-driver-backup.desktop
/usr/share/icons/hicolor/scalable/apps/linux-driver-backup.svg
/usr/share/licenses/linux-driver-backup/LICENSE
```

卸载 / Uninstall：`sudo pacman -R linux-driver-backup`

## 3. 提交 AUR / Publish to the AUR

1. 先在 GitHub 上发布 `v<版本>` tag（否则 AUR 用户下载不到 `source`）；
2. 确认 `sha256sums` 已用 `updpkgsums` 生成真实值（**AUR 不接受 `SKIP`**）；
3. `makepkg --printsrcinfo > .SRCINFO`；
4. 克隆 AUR 仓库并推送：

```bash
git clone ssh://aur@aur.archlinux.org/linux-driver-backup.git
cd linux-driver-backup
cp ../PKGBUILD ../.SRCINFO .
git add PKGBUILD .SRCINFO
git commit -m "linux-driver-backup 0.1.0"
git push
```

之后用户即可 `yay -S linux-driver-backup` 或 `paru -S linux-driver-backup`。

## 4. 常见问题 / FAQ

- **`makepkg` 提示 checksum mismatch**：上游 release 内容变了，重跑 `updpkgsums`；
- **`ERROR: deps not satisfied`**：缺少 `cargo`，装 Rust 工具链；
- **`.SRCINFO` 与 `PKGBUILD` 不一致**（AUR 机器人会报错）：任何时候改了 `PKGBUILD`
  都要重跑 `makepkg --printsrcinfo > .SRCINFO`；
- **Arch 的 `depends` 与 deb 的 `Depends` 不同名**：Arch 包名是 `wayland` /
  `libxkbcommon` / `glibc`，deb 是 `libc6` / `libwayland-client0` / `libxkbcommon0`，
  这是发行版命名差异，不是错误。
