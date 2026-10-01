# v0.4.0 — 性能与分发（W10 完成，W11 顺延）

本版本聚焦 **压缩性能**，并起步 **分发渠道**；归档格式维持 **v2**。详细现状见
[docs/STATUS-v0.4.0.md](STATUS-v0.4.0.md)，迭代计划见 [docs/ITERATION-v0.4.0.md](ITERATION-v0.4.0.md)。

## 亮点 / Highlights

- **压缩算法可选（W10 / P2-1）**：`--backup --compress zstd|gzip|none`，默认 **zstd**（`zstdmt` 多线程）。
  压缩算法写入 `manifest.json`，还原端据此解码。
- **读取端按魔数识别**：`--restore` 与 `--verify` 共用同一读取路径，自动识别 gzip / zstd / 裸 tar。
  修复了 `--verify` 将**默认 zstd** 归档误判为「归档条目损坏」的缺陷。
- **扩展名跟随算法**：自动生成的文件名与内容一致 —— `zstd → .tar.zst`、`gzip → .tar.gz`、`none → .tar`；
  CLI 与 GUI 文件对话框/过滤器同步。
- **分发渠道起步（W12）**：新增 COPR（Fedora / RHEL）与 OBS（openSUSE / SLE）打包模板与说明。

## 兼容性与推迟项 / Compatibility & deferred

- **归档格式仍为 v2**，v1/v2 归档继续可读；manifest 新增压缩算法字段。
- 内容寻址/去重/增量、`--encrypt age|gpg`、`--remote sftp|s3`、manifest 前置 + 索引页脚（W11）
  **顺延至 v0.4.1**；Manifest 已保留 `encryption` / `block` 字段（当前恒为 `None`）。
- 签名（minisign/GPG）、SBOM、可复现构建、aarch64 AppImage、PAX 保真与容器/QEMU 验证仍未完成。

## 验证 / Verification

- `cargo test --locked` → **199 通过 / 0 失败**（187 单元 + 8 退出码 + 4 集成）
- `cargo clippy --all-targets -- -D warnings` 零告警；`cargo fmt --check` 通过；MSRV 1.92 通过
- 新增 `--compress` 三档退出码矩阵测试；端到端确认 `tar --zstd -tf` 可解默认归档

## 安装 / Install

参见 [README → 安装](https://github.com/ltbkq/linux-driver-backup#安装--installation)。
本 Release 附带的各发行版包/AppImage 与 `SHA256SUMS` 由 CI 构建并校验。
