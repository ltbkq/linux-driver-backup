# packaging/appimage —— AppImage 的 AppDir 结构说明

中文为主、英文补充。本目录**只放结构说明**；真正的 AppDir 由
[`packaging/build-appimage.sh`](../build-appimage.sh) 在临时目录里按下面的结构组装，
组装完用 `appimagetool` 打成 `linux-driver-backup-<版本>-linux-x86_64.AppImage`。

## 1. AppDir 目录树 / AppDir layout

```
packaging/appimage/
├── README.md                       # 本文件：结构说明
└── AppDir/                         # 受版本控制的骨架（只有入口脚本）
    └── AppRun                      # 可执行入口，build-appimage.sh 直接复用

<构建时生成的 AppDir>/
├── AppRun                               # ← 由上面的骨架复制而来
├── linux-driver-backup.desktop          # 桌面入口（根目录必须有一个 .desktop）
├── linux-driver-backup.svg              # 图标，Icon= 必须与文件名一致；
│                                        #   appimagetool 也用它生成 AppImage 图标
│                                        #   （若 appimagetool 版本不接受 svg，
│                                        #    build-appimage.sh 会尝试用
│                                        #    rsvg-convert / inkscape 转 256px png）
└── usr/
    └── bin/
        └── linux-driver-backup          # 真正的可执行文件（来自 target/release）
```

> `usr/bin/linux-driver-backup` 属于构建产物，**不入库**；仓库里只保留 `AppRun` 骨架。

要点 / Key points：

1. **AppRun** 不是符号链接到二进制，而是一小段 `sh`：定位自身所在目录后
   `exec usr/bin/linux-driver-backup "$@"`。这样图标、桌面文件与二进制的相对
   关系固定，也不依赖 `/usr` 挂载点。
2. **.desktop 必须位于 AppDir 根部**，`Exec=linux-driver-backup`、
   `Icon=linux-driver-backup` 两个字段会被 appimagetool 校验。
3. **免 FUSE**：CI 容器里通常没有 `/dev/fuse`，因此统一用
   `APPIMAGE_EXTRACT_AND_RUN=1 appimagetool …`，让 appimagetool 自解压运行，
   不需要 FUSE，也不需要 `--appimage-extract-and-run` 参数。
4. **供应链（C-08）**：appimagetool 固定到 `1.9.1` 并校验官方 SHA-256（见
   `build-appimage.sh` 顶部的 `APPIMAGETOOL_VERSION`/`AI_SHA`）；下载失败按
   DESIGN.md §11.4 降级（warning + exit 0），**校验和不符则硬失败**（exit 1）。
5. **网络失败不阻断 CI**：`build-appimage.sh` 下载 `appimagetool` 失败时打印中文
   warning 并 `exit 0`（DESIGN.md §11.4：AppImage 失败降级为只发 deb/rpm/tar）。

## 2. 手动运行 / Run manually

```bash
# 在仓库根目录（需先 cargo build --release 产出二进制）
bash packaging/build-appimage.sh

# 产物落在 dist/
chmod +x dist/linux-driver-backup-*.AppImage
./dist/linux-driver-backup-*.AppImage --scan --json
```

本机没有 `rpmbuild` / `appimagetool` 也没关系：这两个格式由 CI 的
`package` job 补齐（见 `.github/workflows/build.yml`）。
