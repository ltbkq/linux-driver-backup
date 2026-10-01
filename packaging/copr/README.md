# packaging/copr —— COPR 分发渠道（Fedora / RHEL）

中文为主、英文补充。COPR（Cool Other Package Repo）是 Fedora 社区的免费构建服务，
为 Fedora / RHEL / Rocky / AlmaLinux / CentOS Stream / openEuler 等 RPM 发行版提供包。

## 1. 适用场景 / When to use

| 场景 / Scenario | 做法 / How |
|---|---|
| Fedora / RHEL 用户想直接 `dnf install` | `sudo dnf copr enable ltbkq/linux-driver-backup && sudo dnf install linux-driver-backup` |
| 维护者发布新版本 | 更新 spec 文件并推送到 COPR 仓库 |

## 2. 目录内容 / Layout

```
packaging/copr/
├── README.md                    # 本文件
└── linux-driver-backup.spec    # COPR 用的 RPM spec（与主 spec 一致，去掉 %changelog 日期）
```

## 3. 发布流程 / Release process

### 3.1 首次创建 COPR 项目 / First-time setup

```bash
# 1) 安装 copr-cli（Fedora 上）
sudo dnf install copr-cli

# 2) 登录（需要 FAS 账户）
copr-cli login

# 3) 创建项目
copr-cli create ltbkq/linux-driver-backup \
  --chroot fedora-40-x86_64 \
  --chroot fedora-40-aarch64 \
  --chroot fedora-rawhide-x86_64 \
  --chroot fedora-rawhide-aarch64 \
  --description "Linux driver backup & restore tool" \
  --instructions "Install with: sudo dnf install linux-driver-backup"
```

### 3.2 每次发布 / Per-release

```bash
# 1) 从 GitHub Release 下载 tarball 并计算 sha256
curl -L -o linux-driver-backup-<版本>.tar.gz \
  https://github.com/ltbkq/linux-driver-backup/archive/refs/tags/v<版本>.tar.gz
sha256sum linux-driver-backup-<版本>.tar.gz

# 2) 更新 spec 中的 Version 与 sha256sums（或直接用主 spec 模板渲染）

# 3) 构建 SRPM
copr-cli buildscm \
  --clone-url https://github.com/ltbkq/linux-driver-backup.git \
  --commit v<版本> \
  --spec packaging/copr/linux-driver-backup.spec \
  ltbkq/linux-driver-backup
```

### 3.3 用户安装 / User installation

```bash
sudo dnf copr enable ltbkq/linux-driver-backup
sudo dnf install linux-driver-backup
```

## 4. 与主 spec 的关系 / Relationship with main spec

COPR spec 与 `packaging/linux-driver-backup.spec` 内容一致，但：
- 去掉 `%changelog` 的硬编码日期（COPR 自动从 git log 生成）；
- `Version` 字段由 CI 在渲染时替换（与主 spec 相同）；
- 依赖声明与主 spec 完全一致（fedora 目标用 Fedora/RHEL 包名）。

## 5. 注意事项 / Notes

- COPR 构建在 Fedora 基础设施上进行，**不需要本地 rpmbuild**；
- 构建日志公开可查，便于调试；
- 支持多 chroot（架构 × Fedora 版本矩阵）；
- 首次启用需要用户信任 GPG 密钥（COPR 自动处理）。
