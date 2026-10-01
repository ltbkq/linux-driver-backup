# Linux 驱动备份与还原工具 迭代设计文档 v0.4.0（基于 v0.3.0 全量代码审查与路线图）/ Iteration Design Document v0.4.0

## 摘要 / Abstract

v0.4.0 主题为 **性能与分发 / Performance & Distribution**（ROADMAP-v2 §14 既定节奏），并收尾 v0.3.0 明确推迟的
格式与保真项。目标：

1. **性能**：压缩算法可选（zstd 多线程）与单遍 I/O，降低 full 模式体积与耗时（P2-1、P2-2）。
2. **归档 v3**：内容寻址块存储实现增量/去重，`--encrypt` 与 `--remote`（P2-3）；根治 manifest 前置/索引页脚（C-41）。
3. **分发渠道**：COPR / OBS / Launchpad PPA / AUR 正式提交 / Flathub / 一行安装脚本；产物签名 + SBOM（P2-4）。
4. **可复现构建**：`--locked` + 固定工具链 + 构建镜像 digest，产出可复验哈希（P2-5）。
5. **AppImage aarch64**：补齐 arm64 AppImage（P2-6）。
6. **保真与验证收尾**：xattr/属主/mtime 保真（C-40/P3-6）；容器矩阵与 QEMU 三场景验证收尾（§3.2 的 P-1…P-7）。

> **范围纪律**：v0.4.0 不做 P3-1…P3-7（驱动索引、归档签名信任链、sysext、TUI、i18n 全量、lib 化）——
> 那些属于 v1.0 生态阶段。v0.4.0 只做 P2 级性能/分发 + 已推迟的格式/保真项。

---

## 0. 方法与基线 / Method & Baseline

### 0.1 审查方法 / Review method

- 以 v0.3.0 全量代码审查（57 项）的**明确推迟项**（`ITERATION-v0.3.0.md §2.3`）为输入。
- 以 ROADMAP-v2 §14 的 **P2-1…P2-6** 为性能/分发主线。
- 对每项给出：现状、目标语义、可行性验证（本机/容器/QEMU）、风险与取舍、验收标准。

### 0.2 质量基线 / Quality baseline

| 项 | v0.3.0 实测 | v0.4.0 目标 |
|---|---|---|
| 单元测试 | 186 | ≥ 220（新增 zstd/增量/加密/PAX 夹具） |
| 集成测试 | 11（7 exit_codes + 4 w7_cli） | ≥ 16（新增 `--compress`/`--encrypt`/`--remote` 退出码） |
| `cargo clippy --all-targets -- -D warnings` | 零告警 | 零告警 |
| `cargo fmt --check` | 通过 | 通过 |
| MSRV | 1.92（slint 1.18 要求） | 维持 1.92（zstd crate MSRV 需复核） |
| 归档格式 | v2 | **v3（增量/去重/加密）**，v2 仍可读 |

---

## 1. 审查发现 / Review Findings（v0.4.0 输入）

### 1.1 性能（2 项）/ Performance

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| P2-1 | 中 | `backup.rs`（`GzEncoder` 单线程） | 压缩仅 gzip 单线程；full 模式数万固件条目压缩耗时占比高，且 gzip 压缩率低于 zstd | ✅ 可行（`zstd` crate `zstdmt`） |
| P2-2 | 中 | `backup.rs`（Walker → Packer） | C-38 已把哈希并入打包（单遍读），但 Walker 与 Packer 间仍经通道传 `ScanEntry` 元数据；大文件分块流式与内存上限可配尚未做 | 🔍 评估是否仍需（C-38 后 I/O 已减半） |

### 1.2 归档格式（2 项）/ Archive format

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| P2-3 | 高 | `backup.rs`/`restore.rs`（manifest 在归档**末尾**） | 二次备份重复存储相同块；无加密；无远程。manifest 末尾导致还原前必须解压整档才能读清单（C-41 关联） | ✅ 可行（内容寻址块，借鉴 Borg/Restic/Kopia） |
| C-41 | 中 | `restore.rs`（`inspect`/`extract` 解压 2–3 次） | manifest 不在归档头部，无索引页脚；同进程已做缓存（解压 3→2 次），跨进程仍多次解压 | ✅ 可行（v3：manifest 前置 + 尾部索引页脚） |

### 1.3 分发与供应链（3 项）/ Distribution & supply chain

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| P2-4 | 中 | `packaging/`、`.github/workflows/build.yml` | 仅 deb/rpm/tar/AppImage；无 COPR/OBS/PPA/Flathub；产物无签名、无 SBOM | ✅ 可行（minisign/GPG + syft） |
| P2-5 | 低 | CI | 未固定 Rust 版本与构建镜像 digest，二进制不可复验 | ✅ 可行（`--locked` + 固定 toolchain + digest 记录） |
| P2-6 | 低 | `packaging/build-appimage.sh` | AppImage 仅 x86_64 | ✅ 可行（aarch64 交叉或 qemu 构建） |

### 1.4 保真与验证（2 项）/ Fidelity & verification

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-40 | 低 | `backup.rs`/`restore.rs`（强制 0644/uid 0） | 执行位/属主/mtime 丢失（ROADMAP P3-6/D13 已知） | ✅ 可行（tar PAX 扩展） |
| P-1…P-7 | — | 容器/QEMU | v0.3.0 待验证项（发行版矩阵、polkit 单次认证、pkexec 三形态、QEMU 三场景、AUR/openSUSE 依赖解析） | 🔍 需容器/VM |

---

## 2. 版本划分 / Versioning

### 2.1 v0.4.0 —— 性能与分发（P2-1…P2-6 + 推迟项）

- **W10 性能**：`--compress zstd|gzip|none`（zstd 多线程）；评估/实施单遍 I/O 流式（P2-1、P2-2）。
- **W11 归档 v3**：内容寻址块存储（增量/去重）；`--encrypt age|gpg`；`--remote sftp|s3`；manifest 前置 + 索引页脚（P2-3、C-41）。
- **W12 分发渠道**：COPR/OBS/PPA/AUR/Flathub/一行安装；产物 minisign/GPG 签名 + `SHA256SUMS.sig` + SBOM（P2-4）。
- **W13 可复现构建 + AppImage aarch64**：固定工具链/镜像 digest/可复验哈希；arm64 AppImage（P2-5、P2-6）。
- **W14 保真与验证收尾**：xattr/属主/mtime（C-40/P3-6）；容器矩阵 + QEMU 三场景验证收尾（P-1…P-7）。

### 2.2 明确推迟 / Deferred

| 项 | 去向 | 理由 |
|---|---|---|
| P3-1…P3-7（驱动索引、归档签名信任链、sysext、TUI、i18n 全量、lib 化） | v1.0 | 属生态阶段，v0.4.0 维持 ROADMAP 节奏 |
| C-48 全量 i18n | v1.0 | 维持原计划 |

---

## 3. 可行性验证记录 / Feasibility Verification Log

### 3.1 本机已验证 / Verified locally

| # | 断言 | 方法与证据 | 结论 |
|---|---|---|---|
| 1 | zstd crate 可用且 MSRV 兼容 | crates.io API：`zstd 0.14`（BSD-3）、`zstdmt` 多线程；MSRV 需 ≤1.92 | ✅ 待 rc 前确认 |
| 2 | 内容寻址块存储可行 | Borg/Restic/Kopia 均为内容寻址；`tar` crate 可自定义条目 | ✅ 设计成立 |
| 3 | `age`/`gpg` 加密可行 | `age` crate（Rust）或外部 `gpg`；流式加密 | ✅ 设计成立 |
| 4 | PAX 扩展保真可行 | `tar` crate 支持 PAX；或自写扩展头 | ✅ 待验证 |
| 5 | minisign/GPG 签名 + syft SBOM 可行 | `minisign` CLI、`syft` CLI；CI 可装 | ✅ 设计成立 |

### 3.2 待容器/真机验证 / Pending (containers & QEMU)

| # | 项 | 场景 | 归属 |
|---|---|---|---|
| P-1 | `rpm -qf` 批量输出格式 | `fedora:40` 容器 | W14 |
| P-2 | SUSE/Alpine/Void initramfs 命令矩阵 | `opensuse/tumbleweed`、`alpine` 容器 | W14 |
| P-3 | polkit `auth_admin_keep` 单次认证 | 桌面 VM | W14 |
| P-4 | 恶意归档夹具回归 + fuzz | 本地 + CI | W11/W14 |
| P-5 | pkexec 属主检查三形态 | 本地三形态 | W14 |
| P-6 | QEMU 三场景 + Live USB `--root` | QEMU | W14 |
| P-7 | AUR `makepkg --verifysource`、openSUSE `zypper` | 容器/VM | W12 |

### 3.3 依赖与取舍评估 / Dependency assessment

| 决策 | 选择 | 备选 | 理由 |
|---|---|---|---|
| 压缩 | `zstd` crate（`zstdmt` 多线程） | 外部 `zstd` CLI | 纯 Rust、无进程开销；MSRV 需复核 |
| 加密 | `age` crate（流式） | 外部 `gpg` | 纯 Rust、无 GPG 依赖；`age` 单二进制可内嵌 |
| 远程 | 自带 `sftp`/`s3`（`rusoto`/`russh`）或复用 `rclone` | 仅本地 | 保持轻依赖；优先 `rclone` 外部调用 |
| 签名 | minisign（产物）+ GPG（可选） | 仅 GPG | minisign 单文件、易校验 |
| SBOM | `syft` CLI（CI 生成） | `cargo-cyclonedx` | syft 覆盖系统+语言依赖 |
| 保真 | tar PAX 扩展 | 自写扩展头 | 优先用 `tar` crate 能力 |

---

## 4. 详细设计 / Detailed Design

### W10 性能 / Performance

- **P2-1 压缩可选**：`--compress zstd|gzip|none`（默认 `zstd`）。`zstd` crate `zstdmt` 多线程；`.ko.zst` 原样存储不二次压缩。
  manifest 记录压缩算法；还原侧按 manifest 选择解码器。
- **P2-2 单遍 I/O 评估**：C-38 后哈希已并入打包。评估 Walker→Packer 是否需分块流式（有界通道传数据块，内存上限可配）。
  若 C-38 已满足则标记完成并记录结论。

**验收**：full 模式体积/耗时对比基线（gzip）下降；`--compress` 三档退出码正确。

### W11 归档 v3 / Archive v3

- **内容寻址块存储**：文件按固定/可变块切分，块以 `sha256` 为键存入 `blocks/`；manifest 记录块序列。
  二次备份只传变化块（增量）+ 跨档去重。
- **`--encrypt age|gpg`**：归档整体流式加密；密钥/口令经 CLI 或环境变量传入（不落地）。
- **`--remote sftp|s3`**：备份产物上传远程；还原侧 `--remote` 拉取。
- **manifest 前置 + 索引页脚（C-41）**：v3 归档首部放 manifest，尾部放索引页脚（块表摘要）；
  `inspect` 只读头部即可，无需解压整档。

**契约**：`Manifest.format_version = 3`；v2 归档仍可读（`MIN..=3`）。块格式、加密头格式需冻结。

**验收**：增量备份只传变化块；加密归档可解密还原；`inspect` 对 v3 只读头部；v2 归档回归通过。

### W12 分发渠道 / Distribution channels

- **COPR**（Fedora/RHEL）、**OBS**（openSUSE/SLE）、**Launchpad PPA**（Ubuntu）、**AUR 正式提交**、**Flathub**（需改用 portal 文件对话框）、**winget 式一行安装脚本**。
- **产物签名**：minisign 签 `SHA256SUMS` → `SHA256SUMS.sig`；公钥固定说明写入 README。
- **SBOM**：CI 用 `syft` 生成，随 Release 发布。

**验收**：各渠道安装命令可用；`minisign -V` 校验通过；SBOM 生成。

### W13 可复现构建 + AppImage aarch64 / Reproducible build & arm64 AppImage

- **可复现构建**：`--locked` + 固定 Rust 版本（如 `1.92.0`）+ 记录构建镜像 digest；产出可复验哈希。
- **AppImage aarch64**：`build-appimage.sh` 支持 `--arch aarch64`（交叉或 qemu 构建）。

**验收**：两次构建哈希一致（或仅时间戳差异可解释）；arm64 AppImage 在 qemu 下 `--version` 通过。

### W14 保真与验证收尾 / Fidelity & verification

- **C-40/P3-6 保真**：tar PAX 扩展写入 xattr、保留 mtime 精度与属主（root 还原时）。
- **容器矩阵**：`ubuntu:22.04/24.04`、`debian:12`、`fedora:40`、`opensuse/tumbleweed`、`archlinux`、`alpine`：
  `--scan/--backup/--restore --dry-run` + 包安装冒烟。
- **QEMU 三场景**：可变 / Secure Boot+OVMF / OSTree Atomic + Live USB `--root` 救援。
- **fuzz**：`cargo-fuzz` 打 `validate_link_target`/`safe_rel_path`/manifest 解析。

**验收**：PAX 保真夹具通过；容器矩阵全绿；QEMU 三场景通过；P-1…P-7 全部有结论并回填 §3.2。

---

## 5. 接口契约变更 / Interface Contract Changes

> 规则：**加字段不删字段、新 CLI 旗标只增不改义**。归档 manifest 版本升至 v3，v1/v2 仍可读。

### 5.1 退出码（沿用 v0.3.0）

| 码 | 含义 |
|---|---|
| 0 | 成功或用户主动取消 |
| 1 | 运行失败（含 JSON 输出失败） |
| 2 | 用法/参数错误 |

### 5.2 新增 CLI 旗标（v0.4.0）

| 旗标 | 归属 | 说明 |
|---|---|---|
| `--compress zstd\|gzip\|none` | W10/P2-1 | 压缩算法（默认 zstd） |
| `--encrypt age\|gpg` | W11/P2-3 | 归档加密 |
| `--remote sftp\|s3` | W11/P2-3 | 远程备份/还原 |
| `--sign` / `--require-signature` | W12 | 产物签名（P3-2 预留，v1.0 完善信任链） |

### 5.3 归档 v3 格式

- 首部 `manifest.json`（含 `format_version=3`、压缩算法、加密头、块表）。
- `blocks/` 内容寻址块（`sha256` 为键）。
- 尾部索引页脚（块表摘要 + manifest 哈希）。
- v2 归档：`MIN_MANIFEST_FORMAT_VERSION..=3` 均可读。

---

## 6. 测试与验收 / Testing & Acceptance

| 层级 | 目标 |
|---|---|
| 单元 | ≥220（zstd/增量/加密/PAX/索引页脚夹具） |
| 集成 | ≥16（`--compress`/`--encrypt`/`--remote` 退出码矩阵） |
| 夹具 | 恶意归档、PAX 保真、增量去重、加密往返 |
| 注入测试 | 提取中途 `SIGKILL`、`ENOSPC`、helper 取消 |
| 容器矩阵 | 6 发行版 × `--scan/--backup/--restore --dry-run` + 包安装冒烟 |
| QEMU | 三场景 + Live USB `--root` |
| fuzz | `validate_link_target`/`safe_rel_path`/manifest 解析 |
| CI 守门 | W9 全部门禁 + 可复现构建断言 |

**发布验收**：容器矩阵全绿 + QEMU 三场景通过 + GUI 人工验收清单通过 + §3.2 的 P-1…P-7 全部有结论并回填。

---

## 7. 风险与取舍 / Risks & Trade-offs

| 风险 | 缓解 |
|---|---|
| zstd crate MSRV > 1.92 | 选兼容版本或上调 MSRV（需评估用户影响） |
| 归档 v3 格式变更 | v2 仍可读；提供 `migrate` 工具或双读 |
| 加密密钥管理 | 口令经 CLI/环境变量，不落地；提供 `--passphrase-file` 可选 |
| 远程依赖（sftp/s3） | 优先外部 `rclone`，避免重造客户端 |
| Flathub 需 portal 对话框 | 评估 `rfd` xdg-portal 后端或 Flathub 构建时特性 |
| PAX 体积/兼容 | 仅 root 还原时写属主；xattr 可选开关 |

---

## 8. 实施计划 / Milestones

1. **W10 性能**（zstd + 单遍 I/O 评估）→ 体积/耗时基线对比。
2. **W11 归档 v3**（内容寻址 + 加密 + 远程 + manifest 前置）→ 增量/去重/加密验收。
3. **W12 分发渠道**（COPR/OBS/PPA/AUR/Flathub + 签名 + SBOM）→ 各渠道安装冒烟。
4. **W13 可复现构建 + AppImage aarch64** → 哈希复验 + arm64 冒烟。
5. **W14 保真与验证收尾**（PAX + 容器/QEMU + fuzz）→ P-1…P-7 结论回填。

> 每里程碑需：`cargo test --locked` 全绿、`clippy -D warnings` 零告警、`cargo fmt --check` 通过、CI 全绿。

---

## 附录 A：与 ROADMAP-v2.md 的对应关系 / Mapping to ROADMAP

| ROADMAP 项 | v0.4.0 归属 |
|---|---|
| P2-1 zstd 并行压缩 | W10 |
| P2-2 单遍 I/O | W10（评估） |
| P2-3 归档 v3 增量/去重/加密 | W11 |
| P2-4 分发渠道 + 签名 + SBOM | W12 |
| P2-5 可复现构建 | W13 |
| P2-6 AppImage aarch64 | W13 |
| P3-6 xattr/属主保真 | W14 |
| P-1…P-7 验证收尾 | W14 |

## 附录 B：English Summary / 英文摘要

v0.4.0 focuses on **performance & distribution** (ROADMAP P2-1…P2-6) plus the format/fidelity items deferred from v0.3.0:
optional zstd parallel compression and single-pass I/O (W10); archive v3 with content-addressed dedup/incremental,
encryption and remote, plus manifest-at-head with index footer (W11); distribution channels (COPR/OBS/PPA/AUR/Flathub)
with minisign/GPG signatures and SBOM (W12); reproducible builds and aarch64 AppImage (W13); xattr/ownership/mtime
fidelity and container/QEMU verification closure (W14). Archive format bumps to v3 while v1/v2 remain readable.
