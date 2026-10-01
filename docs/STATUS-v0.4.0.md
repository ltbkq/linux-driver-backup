# 阶段报告 / Stage Report — v0.4.0 迭代中

> 目的 / Purpose：在版本迭代之间提供一份**可复核的现状快照**，记录当前能力、契约、验证结果与已知缺口，
> 供后续迭代（v0.4.1、v0.5.0…）直接读取，避免重复走查与臆测。
> A verifiable snapshot between iterations: capabilities, contracts, test status and known gaps.

---

## 0. 快照信息 / Snapshot

| 项 / Item | 值 / Value |
|---|---|
| 报告日期 / Date | 2026-10-01 |
| 分支 / Branch | `main` |
| Cargo 版本 / Version | **0.4.0**（`Cargo.toml`；随 tag `v0.4.0` 发布） |
| 迭代 / Iteration | v0.4.0「性能与分发」（[docs/ITERATION-v0.4.0.md](ITERATION-v0.4.0.md)） |
| 最新提交 / HEAD | `9bc8ffa`（W10 可选压缩 + W11 顺延收尾 + COPR/OBS 渠道） |
| 最新 tag / Latest tag | `v0.3.0`（历史：v0.1.1、v0.1.2、v0.2.0、v0.2.1、v0.3.0） |
| 工具链 / Toolchain | rustc/cargo **1.98.1**；MSRV **1.92**（`Cargo.toml` `rust-version`） |
| 远端 / Remote | `github.com/ltbkq/linux-driver-backup` |

---

## 1. 质量门禁现状 / Quality Gates

| 门禁 / Gate | 命令 | 结果 |
|---|---|---|
| 单元 + 集成测试 | `cargo test --locked` | **199 通过 / 0 失败**（187 单元 + 8 `exit_codes` + 4 `w7_cli`） |
| Lint | `cargo clippy --all-targets --locked -- -D warnings` | 零告警 |
| 格式 | `cargo fmt --check` | 通过 |
| MSRV | CI `msrv` job（Rust 1.92） | 通过（本地 1.98.1 复验） |

### 1.1 测试分布 / Test distribution

| 文件 / File | `#[test]` | 备注 |
|---|---:|---|
| `src/scan.rs` | 46 | 扫描五阶段、usr-merge、配置面 |
| `src/restore.rs` | 41 | 事务/WAL/符号链接禁闭/解压读取 |
| `src/distro.rs` | 22 | 家族识别、命令矩阵 |
| `src/backup.rs` | 20 | 压缩器、路径校验、默认文件名 |
| `src/main.rs` | 18 | 参数解析、退出码 |
| `src/model.rs` | 12 | manifest 往返、版本闸 |
| `src/privilege.rs` | 11 | pkexec 属主自证 |
| `src/config.rs` | 5 | 配置层级 |
| `src/verify.rs` | 5 | 体检（gzip/zstd/裸读） |
| `src/pathutil.rs` | 4 | 路径工具 |
| `src/diagnose.rs` | 3 | 诊断包 |
| `tests/exit_codes.rs` | 8 | 退出码矩阵（含 `compress_matrix`） |
| `tests/w7_cli.rs` | 4 | `--verify`/`--diagnose`/配置发现 |

### 1.2 CI 作业 / CI jobs（`.github/workflows/build.yml`）

`test` · `lint (fmt/clippy/shellcheck/desktop)` · `audit (cargo audit)` · `msrv (1.92)` · `build` · `package` · `aur (PKGbuild + .SRCINFO)` · `release`。
第三方 action 全部 pin 到 commit SHA；appimagetool 固定版本并校验 SHA-256。

---

## 2. 代码结构 / Code Layout

| 文件 / File | 行数 | 职责 / Role |
|---|---:|---|
| `src/main.rs` | 2934 | CLI/GUI 入口、参数解析、退出码、Slint 回调绑定 |
| `src/restore.rs` | 4860 | 还原事务/WAL/回滚、归档读取（`archive_reader`）、`inspect` 缓存 |
| `src/scan.rs` | 2507 | 五阶段扫描、元数据/归属查询、告警去重 |
| `src/backup.rs` | 2061 | 扫描→哈希→打包流水线、`Compressor`、原子替换 |
| `src/distro.rs` | 1437 | 发行版家族、initramfs 命令矩阵、Secure Boot/不可变探测 |
| `src/model.rs` | 933 | `Manifest`/`ManifestEntry`、`AppError`/退出码语义、`human_size` |
| `src/verify.rs` | 763 | `--verify` 逐条 SHA-256 + 内核/架构比对、报告格式化 |
| `src/privilege.rs` | 684 | pkexec 提权、属主自证、helper 参数透传 |
| `src/config.rs` | 385 | 配置发现与层级合并 |
| `src/diagnose.rs` | 350 | 脱敏诊断包（始终 gzip） |
| `src/pathutil.rs` | 320 | 路径规范化/`safe_rel_path`/`validate_link_target` |
| **合计** | **17234** | 另有 `ui/app_window.slint`、`build.rs` |

`unsafe`：仅 5 处 `unsafe {}` 块（`src/main.rs` 2、`src/privilege.rs` 3），用于裸 `extern`（`geteuid` 等）与 pkexec 相关系统调用包装。

---

## 3. 归档格式契约 / Archive Format Contract

**当前格式版本：`MANIFEST_FORMAT_VERSION = 2`，可读下限 `MIN_MANIFEST_FORMAT_VERSION = 1`**（`src/model.rs`）。

- **布局**：`manifest.json` + `data/**`（相对路径，去前导 `/`）。v2 下 manifest 位于归档**末尾**（前置 manifest + 尾部索引页脚属 W11，顺延）。
- **压缩（v0.4.0 W10）**：整档压缩，`zstd`（默认，`zstdmt` 多线程）| `gzip` | `none`，算法写入 `manifest.compression`。
- **解压识别（读取端）**：`restore::archive_reader` 按魔数自动选择（gzip `1f 8b` / zstd `28 b5 2f fd` / 裸 tar）；`--restore` 与 `--verify` **共用**该实现。
- **写入原子性**：先写同目录临时文件 `<name>.ldb-partial-<pid>-<seq>`，成功后 `rename` 覆盖；失败/取消只删临时文件，旧备份完好。
- **保留字段（v0.4.1 W11 启用）**：`Manifest.encryption: Option<ManifestEncryption>`、`ManifestEntry.block: Option<String>` —— 当前恒为 `None`，反序列化缺省兼容。

### 3.1 `Manifest` 顶层字段

`format_version` · `tool_version` · `created_at` · `kernel_release` · `kernel_vermagic?` · `arch` · `distro` · `immutability?` · `secure_boot?` · `mode` · `compression?` · `entries[]` · `dkms[]` · `warnings[]` · `firmware_policy?` · `encryption?`

### 3.2 `ManifestEntry` 字段

`path` · `size` · `kind` · `link_target?` · `owner?` · `modinfo?` · `content_stored` · `strategy_hint?` · `block?`

### 3.3 尚未实现（v0.4.1+）

内容寻址块存储 / 跨档去重 / 增量 · `--encrypt age|gpg` · `--remote sftp|s3` · manifest 前置 + 索引页脚（C-41）。

---

## 4. 接口 / Interfaces

### 4.1 命令 / Commands（`src/main.rs` `enum Cmd`）

| 命令 / Command | 说明 |
|---|---|
| *(无参数)* | 启动 Slint GUI |
| `--help` / `-h`、`--version` / `-V` | 帮助 / 版本 |
| `--scan [--mode m] [--json] [--config f]` | 扫描；`--json` 机器可读 |
| `--backup [--out f] [--mode m] [--kver k] [--firmware p] [--compress zstd\|gzip\|none] [--config f]` | 备份；`--out` 可缺省（由配置 `out_dir` + 默认名补全） |
| `--restore --archive f [--dry-run] [--yes] [--with-firmware] [--allow-kernel-mismatch] [--allow-arch-mismatch] [--root d] [--strategy s] [--on-immutable] [--strict-links] [--no-sign] [--chroot-exec] [--require-verify] [--no-auto-rollback-on-post] [--keep-rollback n] [--config f]` | 还原 |
| `--rollback [last\|id] [--root d]` | 从 WAL 日志回滚 |
| `--verify --archive f [--json]`（或 `--verify f`） | 归档体检 |
| `--diagnose [--out f]`（或 `--diagnose f`） | 脱敏诊断包（始终 gzip） |
| `--helper-restore …` / `--helper-rollback …` | **内部**：pkexec 以 root 重入 |

### 4.2 退出码 / Exit codes

`0` 成功或用户主动取消 · `1` 运行失败（含 JSON 输出失败） · `2` 用法/参数错误。

### 4.3 配置 / Config（`src/config.rs`）

发现顺序：内置默认 < `/etc/linux-driver-backup.toml` < `$XDG_CONFIG_HOME|~/.config/linux-driver-backup/config.toml` < 显式 `--config` < CLI 旗标。
键 / Keys：`mode` · `out_dir` · `keep_rollback` · `sign_key` · `compression` · `firmware` · `strategy`（**共 7 个**）。

> ⚠️ README 仍写「6 键」，与实际 7 个不符（见 §6 技术债 D-3）。

### 4.4 环境变量 / Env vars

`HOME`、`XDG_CONFIG_HOME`（配置发现）· `PKEXEC_UID`（helper 自证）· `LDB_ALLOW_UNSAFE_ELEVATION=1`（跳过 pkexec 属主校验，仅开发用）。

---

## 5. v0.4.0 迭代进度 / Iteration Status

| 工作项 / Work | ROADMAP | 状态 | 证据 / Evidence |
|---|---|---|---|
| **W10 性能** | P2-1 | ✅ **完成（P2-1）** | `--compress zstd\|gzip\|none`（默认 zstd + `zstdmt`）、manifest 记录算法、读取端魔数识别、扩展名跟随算法、`compress_matrix` 集成测试 |
| W10 单遍 I/O | P2-2 | ⏸ **未评估** | C-38 已把哈希并入打包（单遍读）；有界通道/内存上限可配尚未评估，无结论记录 |
| **W11 归档 v3** | P2-3、C-41 | ⏸ **顺延至 v0.4.1** | 移除 `--encrypt` 与 `age` 依赖；Manifest 保留 `encryption`/`block` 字段；格式维持 v2 |
| **W12 分发渠道** | P2-4 | 🟡 **部分** | 新增 `packaging/copr`、`packaging/obs`；既有 `appimage/arch/deb/flatpak/ppa/install.sh`；**签名（minisign/GPG）与 SBOM 未做**；Flathub/PPA/AUR 正式提交未做 |
| W13 可复现 + arm64 AppImage | P2-5、P2-6 | ⛔ **未开始** | 无固定 toolchain/镜像 digest 记录；`build-appimage.sh` 仍仅 x86_64 |
| W14 保真与验证收尾 | C-40、P-1…P-7 | ⛔ **未开始** | xattr/属主/mtime（PAX）未做；容器矩阵、QEMU 三场景、fuzz 未做 |

### 5.1 明确推迟 / Deferred（`ITERATION-v0.4.0.md §2.2`）

P3-1…P3-7（驱动索引、归档签名信任链、sysext、TUI、i18n 全量、lib 化）→ v1.0；C-48 全量 i18n → v1.0。

---

## 6. 已知缺陷与技术债 / Known Gaps & Debt

| ID | 级别 | 位置 | 说明 |
|---|---|---|---|
| D-1 | 中 | `docs/ITERATION-v0.4.0.md §2.1/§4-W11` | 文档仍把 W11（内容寻址/加密/远程/manifest 前置）列为 v0.4.0 范围，与代码「顺延 v0.4.1」不一致；需在迭代文档回填状态 |
| D-2 | 中 | `src/backup.rs`（整档压缩） | 设计意图「`.ko.zst` 原样存储不二次压缩」**未实现**：整档 zstd/gzip 会再次压缩已压缩的固件/模块，浪费 CPU 与体积收益；需评估跳过二次压缩或改用内容寻址 |
| D-3 | 低 | `README.md`（配置一节） | 写「6 键」，实际 7 键（缺 `strategy` 计数）；已在 §4.3 记录，需校正 README |
| D-4 | 低 | `Cargo.toml` / `README` | 版本仍标 0.3.0、README 亮点节以 v0.3.0 为主；v0.4.0 尚未收敛前保持一致（已补 v0.4.0 更新节） |
| D-5 | 低 | `src/config.rs` | `#[allow(dead_code)] // TODO(W7): 签名流程接入后移除 allow` —— `sign_key` 未接入签名流程 |
| D-6 | 低 | `ITERATION-v0.4.0.md §6` | 集成测试目标 ≥16，现状 12（8+4）；`--compress` 矩阵已覆盖核心，其余退出码矩阵待补 |
| D-7 | 低 | P2-2 | 单遍 I/O 是否仍需分块流式，无书面结论（应标记完成或给出结论） |

> 安全性方面：v0.2.1 的 14 项热修与 v0.3.0 的 57 项审查发现均已落地；本快照未发现新增高危项。

---

## 7. 复现 / Reproduce

```bash
# 门禁三连（与 CI 一致）
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
cargo fmt --check

# 端到端冒烟：默认 zstd / gzip / 无压缩，扩展名与内容一致
D=$(mktemp -d); mkdir -p "$D/out"
printf 'out_dir = "%s"\nmode = "minimal"\n' "$D/out" > "$D/cfg.toml"
cargo run --quiet -- --backup --config "$D/cfg.toml"            # -> driver-backup-<kver>.tar.zst
cargo run --quiet -- --backup --config "$D/cfg.toml" --compress gzip  # -> .tar.gz
cargo run --quiet -- --backup --config "$D/cfg.toml" --compress none  # -> .tar
cargo run --quiet -- --verify --archive "$D/out"/*.tar.zst      # 体检 zstd 归档
tar --zstd -tf "$D/out"/*.tar.zst                              # 外部工具可解
```

---

## 8. 后续迭代建议 / Next Steps

**v0.4.0 收敛（发布前）**
1. 回填 `ITERATION-v0.4.0.md` 的 W11 顺延与 W10 完成状态（D-1）；校正 README 键数（D-3）。
2. ✅ 已完成：版本号提升至 `0.4.0`、README 亮点切换到 v0.4.0、本阶段报告随 tag `v0.4.0` 发布。
3. 记录 P2-2 单遍 I/O 结论（D-7）；补 `.ko.zst` 二次压缩的取舍结论（D-2）。
4. 补齐集成测试矩阵至 ≥16（D-6）。

**v0.4.1（承接 W11）**
5. 内容寻址块存储 + 增量/去重；`--encrypt age|gpg`；`--remote sftp|s3`；manifest 前置 + 索引页脚（`inspect` 只读头部）。
6. 启用已保留的 `encryption`/`block` 字段，格式版本升 v3，保持 v1/v2 可读。

**v0.4.x（W12–W14 收尾）**
7. 产物 minisign/GPG 签名 + `SHA256SUMS.sig` + `syft` SBOM；完成 PPA/AUR 正式提交与 Flathub（需 portal 对话框）。
8. 可复现构建（`--locked` + 固定 toolchain/镜像 digest）；`build-appimage.sh --arch aarch64`。
9. PAX 保真（xattr/属主/mtime）；容器矩阵与 QEMU 三场景；`cargo-fuzz` 打 `validate_link_target`/`safe_rel_path`/manifest 解析。

---

## 9. 关键文件索引 / Key Files

| 关注点 | 位置 |
|---|---|
| 归档写入与压缩器 | `src/backup.rs`（`Compressor`、`packer_main`、`archive_ext`、`default_out_path`） |
| 归档读取与恢复 | `src/restore.rs`（`archive_reader`、`open_archive`、`run_restore`、`inspect`） |
| 归档体检 | `src/verify.rs`（`open`、`verify`） |
| 数据契约 | `src/model.rs`（`Manifest`、`ManifestEntry`、版本常量、`AppError`） |
| CLI/GUI | `src/main.rs`、`ui/app_window.slint` |
| 打包与分发 | `packaging/**`（`copr`、`obs`、`appimage`、`arch`、`deb`、`ppa`、`flatpak`、`install.sh`） |
| CI | `.github/workflows/build.yml` |
| 设计与路线 | `DESIGN.md`、`docs/ROADMAP-v2.md`、`docs/ITERATION-v0.4.0.md` |

---

## 附录 A：与 `ITERATION-v0.4.0.md` 的偏差 / Divergence

| 迭代文档 | 代码现状 | 处理 |
|---|---|---|
| §2.1 W11 属 v0.4.0 | 顺延 v0.4.1 | 待回填文档（D-1） |
| §4-W10 默认 zstd；未提扩展名 | 扩展名跟随算法（`.tar.zst` 等） | 本报告 §3、README v0.4.0 节已记录 |
| §5.3 归档 v3 契约 | 仍为 v2，保留字段 | 顺延 v0.4.1 |
| §3.1 断言 zstd crate MSRV 待确认 | rustc 1.98.1 / MSRV 1.92 下编译通过 | 已验证 |
