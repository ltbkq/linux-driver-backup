# packaging/obs —— OBS 分发渠道（openSUSE / SLE）

中文为主、英文补充。OBS（openSUSE Build Service）是 SUSE 社区的免费构建服务，
为 openSUSE / SLE / Fedora / Debian / Ubuntu 等多种发行版提供包。

## 1. 适用场景 / When to use

| 场景 / Scenario | 做法 / How |
|---|---|
| openSUSE / SLE 用户想直接 `zypper install` | 添加 OBS 仓库后 `sudo zypper install linux-driver-backup` |
| 维护者发布新版本 | 更新 spec 文件并推送到 OBS 仓库 |

## 2. 目录内容 / Layout

```
packaging/obs/
├── README.md                    # 本文件
├── linux-driver-backup.spec    # OBS 用的 RPM spec（suse 目标，SoName 依赖）
└── _service                    # OBS 服务定义（从 GitHub 拉取源码）
```

## 3. 发布流程 / Release process

### 3.1 首次创建 OBS 项目 / First-time setup

```bash
# 1) 安装 osc（openSUSE 命令行工具）
sudo zypper install osc

# 2) 登录（需要 openSUSE 账户）
osc login

# 3) 创建项目
osc meta prj ltbkq/linux-driver-backup \
  -F - <<'EOF'
<project name="ltbkq:linux-driver-backup">
  <title>Linux Driver Backup</title>
  <description>Backup and restore out-of-tree Linux kernel drivers</description>
  <person userid="ltbkq" role="maintainer"/>
  <build>
    <enable/>
  </build>
  <repository name="openSUSE_Tumbleweed">
    <path project="openSUSE:Factory" repository="standard"/>
    <arch>x86_64</arch>
    <arch>aarch64</arch>
  </repository>
  <repository name="openSUSE_Leap_15.6">
    <path project="openSUSE:Leap:15.6" repository="standard"/>
    <arch>x86_64</arch>
    <arch>aarch64</arch>
  </repository>
</project>
EOF
```

### 3.2 每次发布 / Per-release

```bash
# 1) 更新 spec 中的 Version（或直接用主 spec 模板渲染）

# 2) 提交到 OBS
osc add packaging/obs/linux-driver-backup.spec packaging/obs/_service
osc commit -m "linux-driver-backup <版本>"
```

### 3.3 用户安装 / User installation

```bash
# openSUSE Tumbleweed
sudo zypper addrepo https://download.opensuse.org/repositories/ltbkq:linux-driver-backup/openSUSE_Tumbleweed/ltbkq:linux-driver-backup.repo
sudo zypper refresh
sudo zypper install linux-driver-backup

# openSUSE Leap 15.6
sudo zypper addrepo https://download.opensuse.org/repositories/ltbkq:linux-driver-backup/openSUSE_Leap_15.6/ltbkq:linux-driver-backup.repo
sudo zypper refresh
sudo zypper install linux-driver-backup
```

## 4. 与主 spec 的关系 / Relationship with main spec

OBS spec 与主 spec 的差异：
- 使用 **suse 目标**的依赖声明（SoName 文件依赖，而非 Fedora 包名）；
- 去掉 `%changelog` 硬编码日期（OBS 从 git log 自动生成）；
- 其余安装布局完全一致。

## 5. OBS 服务定义 / OBS service definition

`_service` 文件定义了 OBS 如何从 GitHub 拉取源码：

```xml
<services>
  <service name="obs_scm">
    <param name="scm">git</param>
    <param name="url">https://github.com/ltbkq/linux-driver-backup.git</param>
    <param name="versionformat">@VERSION@</param>
  </service>
  <service name="set_version">
    <param name="file">linux-driver-backup.spec</param>
  </service>
</services>
```

## 6. 注意事项 / Notes

- OBS 构建在 openSUSE 基础设施上进行，**不需要本地 rpmbuild**；
- 支持多发行版 × 多架构矩阵；
- 构建日志公开可查；
- 首次添加仓库需要用户信任 GPG 密钥（zypper 自动处理）。
