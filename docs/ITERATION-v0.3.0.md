# linux-driver-backup 迭代设计文档 v0.2.1 / v0.3.0（基于全量代码审查）/ Iteration Design Document

> 基线 / Baseline：`v0.2.0`（commit `8c4841e`，tag `v0.2.0`）
> 上游文档 / Parent documents：[`DESIGN.md`](../DESIGN.md)（架构与冻结契约）、[`ROADMAP-v2.md`](ROADMAP-v2.md)（P0–P3 分级建议）
> 状态 / Status：草案 v1，待评审 / Draft for review
> 文档规范 / Policy：DESIGN.md 附录 A（中英双语，中文为主）

---

## 摘要 / Abstract

本文档记录对 v0.2.0 全量源码（7 个模块、9,406 行 Rust + Slint UI + 打包/CI 脚本）的系统性审查结果，并据此给出下一迭代的范围划分、模块级设计与可行性验证记录。

审查共发现 **57 项问题**（高 8 / 中 26 / 低 23），其中若干为 ROADMAP-v2 尚未收录的安全与正确性缺陷（最严重者：符号链接写穿逃逸、pkexec 执行用户可写二进制、事务日志"写后不写前"、usr-merge 系统来源包查询全部失效）。据此将迭代划分为两个版本：

- **v0.2.1（安全与正确性热修）**：14 项，改动半径小、可快速发版；
- **v0.3.0（兼容性与体验 + 审查强化）**：吸收 ROADMAP 的 P1-1…P1-8 全部条目，并落入 9 个工作包（W1–W9），同时修复其余 40 项审查发现。

关键可行性均已在本机实测（见 §3），包括：`dpkg-query -S` 非零退出仍输出匹配、usr-merge 路径归属查询差异、efivars 免 root 读取 Secure Boot、`/proc/config.gz` 可读、候选依赖许可证兼容等。基线质量：`cargo test --locked` **103 项全绿**、`cargo clippy --all-targets -- -D warnings` **零告警**。

---

## 0. 方法与基线 / Method & Baseline

### 0.1 审查方法 / Review method

| 范围 | 文件 | 行数 | 审查方式 |
|---|---|---|---|
| 入口与数据模型 | `src/main.rs`, `src/model.rs`, `ui/app_window.slint` | 1,668 + 747 + 233 | 全量走读（CLI/GUI 两条路径、契约结构体） |
| 扫描与发行版 | `src/scan.rs`, `src/distro.rs` | 1,447 + 910 | 全量走读（五阶段扫描、家族识别、命令矩阵） |
| 备份与还原 | `src/backup.rs`, `src/restore.rs` | 1,700 + 2,453 | 全量走读（归档 v2、事务回滚、符号链接、SB 签名） |
| 提权/构建/打包/CI | `src/privilege.rs`, `build.rs`, `packaging/**`, `.github/workflows/build.yml` | 418 + ~2,000 | 全量走读（pkexec 链路、4 个打包器、4 个 CI job） |
| 事实核验 | — | — | 对最高严重度结论逐条**亲自复核源码** + 本机命令实测（§3.1） |

严重度定义 / Severity：**高**＝可被利用或导致数据不可恢复；**中**＝功能错误、静默降级或发行版兼容缺口；**低**＝体验/一致性/技术债。
核实标记 / Verification：✅＝源码亲核或本机实测；🔍＝代码路径推演（待容器/真机复验）。

### 0.2 质量基线 / Quality baseline

| 项 | 结果 | 备注 |
|---|---|---|
| 工具链 | rustc/cargo **1.98.1** ≥ MSRV 1.92（`Cargo.toml:13`；slint 1.18 要求 1.92） | 本机 rustup stable |
| 系统依赖 | `fontconfig`/`freetype2`/`gtk3 3.24`/`wayland-client` 齐备 | Slint winit 后端可链接 |
| `cargo test --no-fail-fast --locked` | **103 passed / 0 failed**（0.34s） | 比 ROADMAP §17 记录的 102 项多 1（期间新增） |
| `cargo clippy --all-targets -- -D warnings` | **零告警**（基线复验） | README:363 承诺的 lint 门槛 |
| 网络 | crates.io / api.github.com 可达 | 依赖与 action SHA 查询可行 |

---

## 1. 审查发现 / Review Findings（57 项）

### 1.1 安全（10 项）/ Security

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-01 | 高 | `restore.rs:386-392`、`backup.rs:1047-1055`、`restore.rs:913-931` | `etc/` 前缀符号链接目标按 `Verbatim` 原样放行（允许绝对路径与 `..`），提取时 `root.join(inner)` + `create_dir_all(parent)` 逐段跟随符号链接且无 `O_NOFOLLOW`/逐段校验 → 恶意归档可用 `data/etc/x -> /` 加后续 `data/etc/x/...` 条目**以 root 任意写文件** | ✅ |
| C-02 | 高 | `restore.rs:239-260` | `safe_rel_path` 只做词法检查；`--root` 模式下目标根内**预先存在**的符号链接组件（如 `<root>/etc -> /etc`）会把写入重定向到根外 | ✅ |
| C-03 | 高 | `privilege.rs:159-162`、`210-217` | `self_exe()` canonicalize 后直接交给 pkexec，**不检查属主与写权限**；开发构建或 AppImage（位于用户可写目录）会被 pkexec 以 root 执行，且 canonicalize→spawn 之间存在 TOCTOU | ✅ |
| C-04 | 中 | `privilege.rs:270-301`、`main.rs:1283-1284` | 取消只 `child.kill()` 杀掉 pkexec，**root helper 不受影响**，继续以 root 写 `/lib/modules`，GUI 却报告"已取消" | ✅ |
| C-05 | 中 | `backup.rs:564-565`、`921-923` | 扫描→哈希→打包三次打开同一路径，无 `O_NOFOLLOW`/类型复核；扫描后被换成符号链接则**把链接目标内容（可能含敏感文件）打进归档** | 🔍 |
| C-06 | 中 | `model.rs:231` | manifest 携带 sha256，但**还原全程从不校验**（仅测试夹具出现），传输损坏不可检测 | ✅ |
| C-07 | 中 | `main.rs:871-908` | `--helper-restore` 不复核 `geteuid()==0`，也不校验 `PKEXEC_UID` 来源，特权路径缺少自证 | 🔍 |
| C-08 | 中 | `build-appimage.sh:29,117-141`、`build.yml:298,315-318` | appimagetool 从可变的 `releases/download/continuous` 下载且**无哈希校验**，随后执行其产物；叠加脚本三处 `exit 0` + CI `continue-on-error` + 校验跳过缺失文件 → 失败静默 | ✅ |
| C-09 | 低 | `build.yml:52,55,68,140,223,245,252,344,365,406` | 全部第三方 action 按可变 tag 引用（release job 持 `contents: write`），供应链可被投毒 | ✅ |
| C-10 | 中 | `restore.rs:700-703,741,913` | manifest 不是权威：路径不合法的条目从查找表**静默丢弃**，不在 manifest 的 tar 条目**照样写入** | 🔍 |

### 1.2 正确性（30 项）/ Correctness

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-11 | 高 | `restore.rs:969-990,993` | 事务日志**成功后才落盘**；提取中途失败/进程崩溃时回滚区只有内存日志 → 原文件躺在 `rollback-<id>/` 却**无 journal 可 `--rollback`**，不可恢复 | ✅ |
| C-12 | 中 | `restore.rs:918-928,1044-1054` | 写分支失败时 `.ldb-staging-*` 暂存文件不清理，残留在 `/lib/modules/...` | 🔍 |
| C-13 | 低 | `restore.rs:842-844,915-917,802-804` | `MakeDir` 与父目录 `create_dir_all` 不入日志，回滚后残留空目录 | 🔍 |
| C-14 | 高 | `restore.rs:1755-1774,1861-1867` | 文件已提交后 `depmod` 失败 / `sig_enforce` 拒绝 → 返回 `Err` 但**不自动回滚**，仅留一句"本次还原无效" | 🔍 |
| C-15 | 中 | `restore.rs:1589-1680` | 回滚只覆盖文件，**不撤销** `dkms install`/`akmods`/包重装/`weak-modules` 的状态变更 | 🔍 |
| C-16 | 低 | `restore.rs:576-588` | `rollback_file_name` 把 `a/b` 压平成 `a__b`，与真实 `a__b` 路径冲突并被 `remove_any` 静默覆盖 | 🔍 |
| C-17 | 中 | `restore.rs:561-572,1018,1187-1199` | `run_id` 秒级精度（同秒互相覆盖）、`state_dir` 无锁；`copy_entries` 生成的新 id 目录**永不被 prune** | 🔍 |
| C-18 | 高 | `restore.rs:1430-1445` vs `1479` | 不可变门控在 dry-run 分支**之前**执行 `rpm-ostree usroverlay` → 预演也会**变更系统状态**（且在非 root 下必然失败） | ✅ |
| C-19 | 中 | `restore.rs:1509-1520` | dry-run 忽略 `content_stored=false` 跳过与策略降级，统计与真实执行不一致 | 🔍 |
| C-20 | 中 | `restore.rs:1386-1406,1582,694/1485/1581` | 离线 `--root` 模式仍读**宿主机**的 vermagic/Secure Boot/os-release（且 detect 三次），救援场景结论错误 | ✅ |
| C-21 | 低 | `restore.rs:1409` | `--root --chroot-exec` 需要 root 却跳过权限预检，写完文件才在 `depmod` 处失败 | 🔍 |
| C-22 | 中 | `scan.rs:572-576,674-680` | `run_command` 非零退出即返回 `None`；`dpkg-query -S` 只要批内有**一个**未归属路径就 exit 1（stdout 仍有其余匹配）→ 整批来源信息丢失 | ✅ 实测 |
| C-23 | 高 | `distro.rs:242-269` + `scan.rs:735-741` | usr-merge 系统（`/lib`→`/usr/lib`）下归属查询用 `/lib/...` 路径，dpkg/rpm 数据库记的是 `/usr/lib/...` → **owner 全部为 None**，连带固件 `content_stored=false` 优化失效 | ✅ 实测 |
| C-24 | 中 | `scan.rs:646-669` | `rpm -qf` **每路径 fork 一次**，full 模式数万固件条目＝数万进程（小时级）；且 `%{FILENAMES}` 输出数 MB 只取首行 | 🔍 |
| C-25 | 低 | `scan.rs:228-231` vs `244-248` | 符号链接处理先于 in-tree 判定 → `kernel/` 内的链接被误判为外置模块 | 🔍 |
| C-26 | 低 | `scan.rs:296-317,74` | `/lib/modules/<kver>/build`、`source` 这两个**必然存在**的目录链接每次扫描都告警；`report.warnings` 无去重与上限 | 🔍 |
| C-27 | 中 | `scan.rs:52-57` | 备份的配置目录缺 `/etc/initramfs-tools`、`/etc/dracut.conf{,.d}`、`/etc/mkinitcpio{,.d}`、`/etc/modules` —— 恰是控制还原期 initramfs 行为的文件 | ✅ |
| C-28 | 低 | `scan.rs:66,744-751` | 固件只扫 `/lib/firmware`（无 `/usr/lib/firmware` 回退）；`firmware_bytes` 把不存内容的包提供文件也计入，UI 体积虚高 | 🔍 |
| C-29 | 中 | `scan.rs:380-392` | `/usr/src` 目录名启发式漏检（不带 `-dkms`、命名不一致的包），应读 `dkms.conf` 的 `PACKAGE_NAME` | 🔍 |
| C-30 | 中 | `distro.rs:470-482,444,551` | `mokutil` 缺失 → Secure Boot 记为 `false`（与"关闭"不可区分，写入 manifest）；文档称查 `CONFIG_MODULE_SIG_FORCE` 实际未查；文档称优先 `kmodsign` 实际优先 `sign-file` | ✅ 可行性 |
| C-31 | 低 | `main.rs:1270-1273` | 归档内核≠当前内核时传 `--kver <归档内核>`，而该值正是还原默认值 → **死逻辑**；跨内核警告（`main.rs:1204`）实际从未生效 | ✅ |
| C-32 | 中 | `restore.rs:1359-1376` | `--allow-kernel-mismatch` 同时压制**架构**不匹配检查：x86_64 归档可被强制写入 aarch64 | 🔍 |
| C-33 | 中 | `main.rs:592,632,754` vs `670-671` | JSON 序列化失败仍 exit 0；用户拒绝 y/N 返回 0 而 `AppError::Cancelled` 返回 1 → 脚本无法依赖退出码 | ✅ |
| C-34 | 低 | `main.rs:343` vs `247-258` | `--helper-restore` 的 `--on-immutable` 用 `matches!` 把任何拼写错误静默当成 `refuse`，与 `--restore` 的严格校验不一致 | ✅ |
| C-35 | 高 | `main.rs:1132-1160` | GUI 真实还原**无确认对话框**（唯一防线是默认勾选的 dry-run 复选框），一次误点即以 root 改写系统 | ✅ |
| C-36 | 低 | `main.rs:1037-1044` | GUI 忽略 `report.warnings`（CLI 会打印），扫描告警对 GUI 用户不可见 | 🔍 |
| C-37 | 低 | `backup.rs:554-557,921,629,435-439` | 单个不可读文件使**整个备份中止**；输出文件先被 `File::create` 截断、失败又删除 → 覆盖同路径时**连旧备份一起毁掉** | 🔍 |
| C-38 | 低 | `backup.rs:564,921,951-956` | 哈希与打包双读，内容变化仅告警 → manifest 的 sha256 描述的**不是归档内内容** | 🔍 |
| C-39 | 低 | `restore.rs:707-712` | journal `created_at` 写成 `"epoch:<id>"`（非 RFC3339），`target_kver` 恒为空，与文档（`restore.rs:83-86`）不符 | 🔍 |
| C-40 | 低 | `backup.rs:927-931`、`restore.rs:920-927` | 强制 0644/uid 0、还原不 `chown` → 执行位/属主/mtime 丢失（ROADMAP **P3-6/D13** 已知） | ✅ |

### 1.3 性能（4 项）/ Performance

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-41 | 中 | `restore.rs:1324,717,1022` | 一次还原把归档**解压遍历 3 次**（inspect / extract / copy_entries）；manifest 追加在末尾导致 inspect 必须全量扫描 | ✅ |
| C-42 | 低 | `restore.rs:1510,1034` | dry-run 线性 `find`（O(n²)）、`copy_entries` `wanted.iter().any`（O(n·m)），已有 HashMap 却不用 | 🔍 |
| C-43 | 中 | `scan.rs:475-515,320-343,172-191` | 每模块 fork 一次 `modinfo`、`has_cmd` 每次重扫 `$PATH`、第 5 阶段（归属+元数据）**不可取消** | ✅ |
| C-44 | 低 | `backup.rs:197-208` vs `restore.rs:957` | 进度节流语义不一致（"或" vs "与"），且持锁回调 → 慢回调阻塞流水线线程 | 🔍 |

### 1.4 可维护性（5 项）/ Maintainability

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-45 | 中 | `main.rs:207-289,309-375,682-694,870-882,1365-1387` | `--restore`/`--helper-restore` 参数解析重复约 65 行；`RestoreCli` 再重复 11 个字段；`run_helper` 10 个位置参数 —— 合计约 200 行可收敛为一个 `RestoreOptions` | ✅ |
| C-46 | 低 | `main.rs:794-809,912-927,1242-1256` | 还原摘要在 CLI/helper/GUI 三处各自格式化，措辞已漂移（"跳过/skipped" vs "已跳过（未知发行版）" vs 漏 `unsigned_left`） | ✅ |
| C-47 | 低 | `backup.rs:1042,1099`、`restore.rs:239,341` | 路径归一化/校验函数在两模块重复两套（且语义不完全一致，与 C-01 同源） | ✅ |
| C-48 | 低 | `app_window.slint` 全部、`main.rs` 多处、`model.rs:63,153` | GUI/CLI 文案硬编码中文，无 `@tr()`；`BackupMode::label()` 英文而 `RestoreStrategy::label_zh()` 中文（ROADMAP **P3-5** 已知） | ✅ |
| C-49 | 低 | `model.rs:338-340`、`main.rs:519,1033`、`model.rs:147` | 注释过期（"恒为 1"实为 2）；`MAX_ROWS=500` 与状态栏字面量"前 500 条"重复；`RestoreStrategy::Skip` CLI 不可达 | ✅ |

### 1.5 打包与 CI（8 项）/ Packaging & CI

| ID | 严重度 | 位置 | 问题 | 核实 |
|---|---|---|---|---|
| C-50 | 中 | `deb/control:30`、`spec:63-65`、`PKGBUILD:30` | GUI 还原强依赖 pkexec（`main.rs:1258`），**四个打包器都没声明 polkit/pkexec 依赖** | ✅ |
| C-51 | 中 | 全部打包器 | 无 polkit policy 文件 → 通用"以 root 运行？"对话框、每次还原重新认证（无 `auth_admin_keep`） | ✅ |
| C-52 | 中 | `packaging/arch/PKGBUILD:23,45,30` | `@VERSION@` 占位符**原样提交**（无替换管线）、缺 AUR 必需的 `.SRCINFO`、`sha256sums=('SKIP')` 不被 AUR 接受、缺 `fontconfig`/`freetype` 运行依赖 | ✅ |
| C-53 | 中 | `build-packages.sh:247-250`、`spec:66-73` | RPM 强制 `ldb_target_fedora=1` → openSUSE 用户拿到 `Requires: libwayland-client`（该发行版不存在的包名），spec 的 openSUSE 分支成死代码 | ✅ |
| C-54 | 中 | `build.yml` | 缺 `clippy`/`fmt --check`/`cargo audit`/`shellcheck`/`desktop-file-validate`/MSRV job/`--locked`/tag==`Cargo.toml` 版本门禁（README:389 承诺了 clippy 却未入 CI） | ✅ |
| C-55 | 低 | `linux-driver-backup.desktop:11-13` vs `install.sh:8` | `Exec=linux-driver-backup` 依赖 PATH，与 `--prefix=/opt/ldb`（通常不在 PATH）矛盾 → 菜单项失效 | ✅ |
| C-56 | 低 | `build-appimage.sh:25,44` vs `build-packages.sh:89,291-302` | AppImage 脚本硬编码 `target/release` 路径、不接 `--bin/--arch`，两套版本解析正则不一致，CI 只能 `cp` 绕过 | ✅ |
| C-57 | 低 | `build.yml:279-280,304-341` | aarch64 产物**从未被执行**；无 `dpkg -i`/`rpm -ivh`/`install.sh` 安装冒烟 | ✅ |

---

## 2. 版本划分 / Versioning

### 2.1 v0.2.1 —— 安全与正确性热修（14 项）

原则：只做**改动半径小、有测试守护、不新增功能**的修复，尽快发版。

| ID | 修复方案 | 涉及文件 | 验收 |
|---|---|---|---|
| C-01 | `etc/` 链接目标拒绝绝对路径与 `..`（保留"绝对目标须落在受管前缀内"的归一化校验，替代 `Verbatim`）；提取时对每个路径组件做 `symlink_metadata` 逐段校验（见 §4-W1 方案 A） | `backup.rs`, `restore.rs` | 恶意归档夹具（`etc/x -> /`、`etc/x -> ../../..`）必须被拒；原有合法绝对目标（`/lib/...`）仍通过 |
| C-02 | 写入路径逐段校验同样覆盖 `--root` 模式；`create_dir_all` 前确认每段非链接 | `restore.rs` | 夹具：`<root>/etc -> /tmp/evil` 时写入被拒 |
| C-03 | pkexec 提权前校验 `self_exe()`：`st_uid==0` 且 `mode & 022 == 0`；不满足则报错并指引"请先安装到 /usr"（AppImage 显式拒绝提权） | `privilege.rs` | dev 构建/模拟可写路径下提权被拒；安装到 `/usr/bin` 后正常 |
| C-10 | manifest 路径非法 → 硬错误（不再静默丢弃）；tar 条目不在 manifest → 拒绝写入 | `restore.rs` | 夹具：多余条目/非法路径归档被拒 |
| C-11 | **写前日志（WAL）**：每条 `JournalEntry` 先以 JSONL 追加 + `fsync` 到 `journal.jsonl.tmp`，成功后原子重命名为正式 JSON；失败/崩溃后 `--rollback` 可读 JSONL 恢复 | `restore.rs` | 杀进程注入测试：提取中途 `SIGKILL` → `--rollback last` 可恢复 |
| C-12 | 所有退出路径（含 `?` 提前返回）清理 `.ldb-staging-*`；新增 `sweep_staging(root)` | `restore.rs` | 失败注入后 `find` 无残留 |
| C-18 | 把不可变门控移到 dry-run 分支**之后**；dry-run 永不执行任何变更命令 | `restore.rs` | 单测：dry-run 路径不含 `run_command` 调用 |
| C-22 | 读取子进程 stdout **不看退出码**（dpkg/rpm 均适用）；仅在完全无输出时回退 | `scan.rs` | 单测：模拟 exit 1 + 有 stdout → 匹配仍入库（已实测支撑，§3.1-4） |
| C-23 | 查询前做 **usr-merge 归一化**（`/lib`→`/usr/lib`，`/bin`、`/sbin` 同理）；命中后映射回原路径 | `scan.rs`, `distro.rs` | 本机回归：`/lib/x86_64-linux-gnu/libc.so.6` 查得 `libc6`（当前为 None） |
| C-31 | 删除死分支；跨内核时把 `--kver` 明确设为**当前内核**或直接移除该参数并更新提示文案 | `main.rs` | 单测断言 helper 参数；提示与行为一致 |
| C-32 | 架构不匹配独立为硬错误，仅 `--allow-arch-mismatch`（新旗标）可越过 | `restore.rs`, `main.rs` | 单测：`--allow-kernel-mismatch` 不影响架构检查 |
| C-33 | 统一退出码：**0**＝成功或用户主动取消；**1**＝运行失败；**2**＝用法/参数错误；JSON 写失败返回 1 | `main.rs` | 集成测试覆盖 4 条路径 |
| C-34 | helper 模式复用 `--restore` 的严格取值校验 | `main.rs` | 单测：非法值被拒 |
| C-35 | GUI 真实还原前弹确认框：列出归档、内核差异、条目数与"将写入系统目录"警告，需二次确认 | `main.rs`, `ui/app_window.slint` | 人工验收：取消不产生任何写入 |

### 2.2 v0.3.0 —— 兼容性与体验 + 审查强化（9 个工作包）

| 包 | 名称 | 吸收的审查项 | 对应 ROADMAP | 验收摘要 |
|---|---|---|---|---|
| W1 | 还原事务完备化 | C-13,C-14,C-15,C-16,C-17,C-19,C-41(部分),C-42 | P0-6 延伸 | 任意失败点均可 `--rollback`；dry-run 与实跑同源 |
| W2 | 提权、取消与 polkit | C-04,C-07,C-50,C-51 | **P1-4** | 取消可终止 root helper；装 policy 后仅认证一次 |
| W3 | 扫描与元数据修复 | C-05,C-24,C-25,C-26,C-27,C-28,C-29,C-30,C-37,C-38,C-43,C-44,C-49 | P0-5 延伸 | fedora 容器 full 扫描分钟级；SB 检测不误报 |
| W4 | 离线还原与 initramfs 矩阵 | C-20,C-21,C-36 | **P1-1 收尾、P1-2** | `--root` 只读目标根探测；SUSE/Alpine/Void/Gentoo 命令矩阵入册 |
| W5 | 固件按需收集 | C-28(体积修正) | **P1-3** | full 体积显著下降；包提供者只记名 |
| W6 | GUI/UX 强化 | C-46,C-48(部分) | **P1-5、P1-6（GUI 面板）** | 勾选还原、策略展示、告警可见、rfd 文件对话框 |
| W7 | CLI 与配置 | C-45,C-47,C-46 | **P1-7、P1-8、P1-6（--diagnose）** | `--verify` 出体检报告；配置文件生效；`RestoreOptions` 收敛 |
| W8 | 打包修复 | C-52,C-53,C-55,C-56 | P2-4 前置 | AUR 源可构建；openSUSE 依赖名正确 |
| W9 | CI 加固 | C-09,C-08,C-54,C-57 | P2-4/P2-5 前置 | clippy/fmt/audit/--locked/SHA-pin/安装冒烟全绿 |

### 2.3 明确推迟 / Deferred

| 项 | 去向 | 理由 |
|---|---|---|
| C-40（xattr/属主/mtime 保真） | v0.4.0（P3-6） | tar PAX 扩展涉及格式与体积权衡，维持原计划 |
| C-48 全量 i18n（`@tr()` 目录） | v1.0（P3-5） | 本次仅统一 label API 与关键文案，不动消息目录 |
| C-41 根治（manifest 前置/索引页脚） | v0.4.0（归档 v3 / P2-3） | 属格式变更；v0.3.0 只做同进程 manifest 缓存（解压 3 次→2 次） |
| C-47 合并 `pathutil` | 并入 W7（随 C-45 一起） | 与 `RestoreOptions` 收敛同批重构，避免两次扰动 |
| P2-1 zstd、P2-2 单遍 I/O、P2-4 渠道分发 | v0.4.0 | 维持 ROADMAP 既定节奏 |

---

## 3. 可行性验证记录 / Feasibility Verification Log

### 3.1 本机已验证 / Verified locally

环境：Linux Mint 22.3（Ubuntu 24.04 系）、内核 `7.3.0-rc5-ryzen5500u`、usr-merge、rustc 1.98.1。

| # | 断言 | 方法与证据 | 结论 |
|---|---|---|---|
| 1 | 工具链满足 MSRV | `rustc --version` → 1.98.1 ≥ 1.92 | ✅ 构建基线成立 |
| 2 | 现有测试不被破坏 | `cargo test --no-fail-fast --locked` → **103 passed / 0 failed** | ✅ 重构有回归护栏 |
| 3 | lint 门槛可达 | `cargo clippy --all-targets -- -D warnings` → **零告警** | ✅ 可直接入 CI（W9） |
| 4 | **C-22 修复方案可行** | `dpkg-query -S <存在的路径> <不存在的路径>` → `exit=1`，但 stdout 仍输出 `coreutils: /usr/bin/env` | ✅ "无视退出码读 stdout"即可挽回整批数据 |
| 5 | **C-23 修复方案可行** | 同一个 libc：`dpkg-query -S /lib/.../libc.so.6` → exit 1 无匹配；`dpkg-query -S /usr/lib/.../libc.so.6` → `libc6:amd64` exit 0 | ✅ 归一化 `/lib`→`/usr/lib` 后查询命中 |
| 6 | **C-30 方案一可行** | `od /sys/firmware/efi/efivars/SecureBoot-*` 存在且**无需 root** 可读（末字节 0=关闭） | ✅ 可去掉 mokutil 依赖、消除"缺失即 false"误报 |
| 7 | **C-30 方案二可行** | `zcat /proc/config.gz \| grep MODULE_SIG` → 本机可读，输出 `# CONFIG_MODULE_SIG_FORCE is not set` | ✅ 可实现文档承诺的强制签名判定 |
| 8 | 候选依赖存在且许可证兼容 | crates.io API：`rfd 0.17.2`(MIT)、`ashpd 0.13.13`、`zstd 0.14.0`(BSD-3)、`rayon 1.12.0`(MIT/Apache-2.0)、`rustix 1.1.5` | ✅ 均与 GPL-3.0-only 兼容；不引入 tokio（ROADMAP 禁令） |
| 9 | GUI 文件对话框构建依赖就绪 | `pkg-config gtk+-3.0` → 3.24.41 存在 | ✅ rfd GTK 后端可构建（CI 需补 `libgtk-3-dev`） |
| 10 | C-01/C-03/C-11/C-18/C-31/C-33/C-35 等结论 | 逐条复核源码（§1 标 ✅ 项） | ✅ 结论成立，纳入设计 |

### 3.1.1 v0.3.0 实施结果 / Implementation result (v0.3.0)

57 项审查发现全部落地（v0.2.1 热修 14 项 + W1–W9）：

| 门禁 / Gate | 结果（本机 rustc 1.98.1） |
|---|---|
| `cargo test --no-fail-fast` | **197 passed / 0 failed**（186 单元 + 7 `exit_codes` + 4 `w7_cli`） |
| `cargo clippy --all-targets -- -D warnings` | 零告警 |
| `cargo fmt --check` | 通过（仓库已全量重排） |
| 打包脚本 | `bash -n` + `shellcheck -x` 零告警；`.deb`/`tar`/PKGBUILD 渲染实测通过 |
| 版本 | `Cargo.toml` = `0.3.0`；归档格式仍为 v2 |

> 待容器/真机复核项见 §3.2（P-1…P-7）；其中 P-3/P-7 依赖桌面 VM / Arch / openSUSE 环境。

### 3.2 待容器/真机验证 / Pending (containers & QEMU)

| # | 项 | 场景 | 归属 |
|---|---|---|---|
| P-1 | `rpm -qf` 批量（多路径一次调用）的输出格式与耗时对比 | `fedora:40` 容器（本机无 rpm 系工具） | W3 |
| P-2 | SUSE `mkinitrd`/`dracut -f`、Alpine `mkinitfs`、Void/Gentoo 命令矩阵 | `opensuse/tumbleweed`、`alpine` 容器 | W4 |
| P-3 | polkit policy 安装、`auth_admin_keep` 只认证一次 | Fedora/Ubuntu 桌面 VM | W2 |
| P-4 | 恶意归档（C-01/C-02/C-10 夹具）回归 + `cargo-fuzz` 路径模糊 | 本地 + CI | W1 |
| P-5 | pkexec 属主检查在**安装版 / AppImage / dev 构建**三种形态下的行为 | 本地三形态 | W2 |
| P-6 | QEMU 三场景（可变 / Secure Boot+OVMF / OSTree Atomic）与 Live USB `--root` 救援 | QEMU | W4 + ROADMAP §13 |
| P-7 | AUR `makepkg --verifysource`、openSUSE `zypper in` 依赖解析 | 容器/VM | W8 |

### 3.3 依赖与取舍评估 / Dependency assessment

| 决策 | 选择 | 备选 | 理由 |
|---|---|---|---|
| 写入路径防穿越 | **方案 A：逐段 `symlink_metadata` 校验**（纯 std） | 方案 B：`openat2(RESOLVE_BENEATH\|NO_SYMLINKS)`（rustix 1.1.5，Linux ≥5.6） | A 零依赖、全内核可用、易测试；B 作 v0.4.0 增强（需 `ENOSYS` 回退，Ubuntu 20.04 内核 5.4 不满足） |
| 事务日志 | JSONL 追加 + fsync + 原子收尾（纯 std） | SQLite / sled | 日志量小（单次还原 ≤ 数千条），引数据库不成比例 |
| 取消传播 | helper 侧轮询 **stdin EOF**（父进程关闭写端即取消）+ 进程组终止兜底 | D-Bus / 信号 | 行协议已有 stdin 管道，改动最小 |
| GUI 文件对话框 | `rfd`（GTK 后端，本机 3.24 可用） | `ashpd`（xdg-portal） | rfd 简单成熟；无父窗口句柄时为非模态对话框（Slint 不暴露 winit 窗口指针）——风险见 §7 |
| 性能并行 | 沿用 `std::thread` 流水线；`rayon` 仅作 W3 可选 | 引入 rayon 到核心路径 | 保持"无 tokio、轻依赖"定位；rayon 需先评估二进制体积 |

---

## 4. 详细设计 / Detailed Design

### W0（v0.2.1 热修）/ Hotfix package

内容见 §2.1，此处补充两个关键设计：

**W0-A 符号链接禁闭（C-01/C-02）**
1. `validate_link_target` 取消 `Verbatim` 分支：`etc/` 目标也必须通过 `normalize_join` 归一化，且结果仍落在 `lib/modules/`、`usr/lib/modules/` 或 `etc/` 前缀内；绝对目标仅当其解析后位于受管前缀（现有合法样例：`/lib/linux-sound-base/…`、`/lib/modules/…`）。
2. 提取侧新增 `safe_join(root, rel)`：逐组件 `symlink_metadata`，任何组件为符号链接即拒绝（目录组件永不跟随）；`create_dir_all` 改为逐段创建 + 校验。
3. 备份侧同规则复用（与 C-47 一并收敛到共享函数，v0.2.1 先复制、v0.3.0 合并）。

**W0-B 写前日志（C-11）**
- 状态目录：`/var/lib/linux-driver-backup/`（写 `/` 时）或 `<root>/var/lib/...`。
- 每条目变更顺序：`journal.append(entry, fsync)` → move aside → rename 落位；任何一步失败，已 append 的条目足以逆序回滚。
- 提取成功 → 重写为正式 `restore-<id>.json` 并 `rename`；提取失败 → 保留 `.jsonl`，`--rollback` 优先读 JSON、回退读 JSONL。

### W1 还原事务完备化 / Transactional restore completion

- **失败即回滚的边界（C-14）**：`depmod`、签名、initramfs 失败改为两段式——先提交事务（journal 正式化），后进入"系统阶段"；系统阶段失败默认**自动回滚文件**再报错（新增 `--no-auto-rollback-on-post` 逃生口），错误文案不再说"本次还原无效"却不回滚。
- **非文件效应（C-15）**：journal 增加 `CommandEntry{program, args, undone_by}`；回滚逆序执行补偿命令（`dkms remove`、记录的包状态等）。无法精确补偿的（包重装为新版本）记录为"已尽力补偿"并入 `RestoreReport.notes`。
- **目录与暂存（C-13/C-16/C-17）**：`MakeDir`/父目录入 journal；回滚文件名改为 `path` 的 **URL 编码式转义**（保留 `/`→`%2F` 风格，杜绝碰撞）；`run_id` 改为 `秒级时间戳 + 4 位随机`；`state_dir` 加 `flock` 排他锁（并发还原直接报错）；prune 扫描**目录与 journal 双向配对**，清理孤儿。
- **dry-run 与实跑同源（C-19）**：抽出 `plan_restore(archive, opts) -> RestorePlan`，dry-run 只打印 plan，实跑执行 plan；两者共享 `content_stored` 跳过、策略降级与固件开关。
- **性能（C-41/C-42/C-44）**：manifest 解析结果在进程内缓存（inspect→extract 复用，3 次解压→2 次）；dry-run 用 `HashMap` 直查、`copy_entries` 用 `HashSet`；节流统一为"间隔 **或** 进度差"且回调前释放锁。

**验收**：任意注入点（写入中/提交后/系统阶段）失败 → `--rollback last` 均可恢复；dry-run 与实跑统计一致（同夹具逐字段相等）。

### W2 提权、取消与 polkit / Privilege, cancellation & polkit

- **取消传播（C-04）**：pkexec 的 stdin 改为 `piped`；helper 每步检查 stdin EOF（父进程取消 → drop 写端 → EOF → helper 置位本地 cancel → 回滚已做部分 → 输出 `RESULT FAIL 已取消`）。兜底：spawn 时 `setsid`，超时后 `kill(-pgid)`。
- **helper 自证（C-07）**：入口断言 `geteuid()==0`；存在 `PKEXEC_UID` 时校验其为调用者；否则（`sudo` 路径）提示使用 sudo。
- **polkit policy（P1-4/C-51）**：新增 `packaging/polkit/linux-driver-backup.policy`，action id `io.github.ltbkq.linux-driver-backup`，`auth_admin_keep`，`org.freedesktop.policykit.exec.path` 指向安装二进制；四个打包器 + `install.sh` 统一安装到 `/usr/share/polkit-1/actions/`。
- **依赖声明（C-50）**：deb `Recommends: polkit | pkexec`（deb/control）、rpm `Recommends:`、PKGBUILD `optdepends`。

**验收**：取消后 2s 内 helper 停止且已改文件回滚；桌面 VM 连续两次还原只认证一次（P-3）。

### W3 扫描与元数据修复 / Scan & metadata fixes

- 归属查询：stdout 无视退出码（C-22 已在 W0）+ usr-merge 归一化（C-23 已在 W0）+ **rpm 批量**（C-24：`rpm -qf` 一次多路径、默认输出、超时 30s、按 256 分片，输出解析容错；格式在 P-1 验证后定稿）。
- 扫描顺序（C-25）：先 in-tree 判定再处理符号链接；抑制 `build`/`source` 目录链接告警（C-26），`report.warnings` 全局去重 + 上限 200 条 + 溢出计数。
- 配置目录扩展（C-27）：`/etc/initramfs-tools`、`/etc/dracut.conf`、`/etc/dracut.conf.d`、`/etc/mkinitcpio.conf`、`/etc/mkinitcpio.d`、`/etc/modules`、`/etc/sysconfig/modules`。
- 固件（C-28）：`/lib/firmware` 缺失或为符号链接时回退 `/usr/lib/firmware`；`firmware_bytes` 只累计 `content_stored=true` 的条目。
- DKMS（C-29）：`/usr/src/<dir>/dkms.conf` 解析 `PACKAGE_NAME=`，取代目录名启发式；扫描与 manifest 复用同一枚举结果（消除 `scan.rs:151/189` 双遍历）。
- Secure Boot（C-30）：① 直读 efivars（§3.1-6），`mokutil` 仅作回退；② 解析 `/proc/config.gz`（回退 `/boot/config-<kver>`）判 `CONFIG_MODULE_SIG_FORCE`；③ 修正文档与实现不一致的两处注释。
- 稳健性（C-37/C-38）：单文件不可读 → 跳过 + 计入 `warnings`（不中止）；输出改写 `.partial` 后原子 `rename`（不毁旧备份）；哈希与打包合并为单次读（见 W3-性能）。
- 性能（C-43/C-44）：`modinfo` 批量（一次多文件）+ `has_cmd` 结果缓存（`OnceLock<HashMap>`）+ 第 5 阶段接入取消检查；备份哈希阶段把数据块经有界通道直送打包（ROADMAP P2-2 的最小版，顺带消除双读 C-38）。

**验收**：fedora 容器 full 扫描 ≤ 2 分钟（基线先测）；usr-merge 本机 owner 命中率与 `dpkg -S` 对账一致。

### W4 离线还原收尾与 initramfs 矩阵 / Offline root & initramfs matrix

- **目标根本地化探测（C-20/C-21）**：`--root` 模式下 os-release、`reference_vermagic`、Secure Boot、不可变标记**全部读 `<root>` 下对应路径**；`DistroInfo::detect()` 只探测一次并向下传递（消除 3 次重复探测）。`--chroot-exec` 需要 root 时提前预检（C-21）。
- **initramfs 命令矩阵（P1-2，实现 ROADMAP §3 表格）**：SUSE `mkinitrd`/`dracut -f`、Alpine `mkinitfs <kver>`、Void/Gentoo `dracut -f`、Slackware 检测不到则明确提示、UKI 系统 `ukify build` + 重签（P-2 场景验证）。
- **告警可见性（C-36）**：GUI 状态区展示 `report.warnings`（截断 + 计数），与 CLI 对齐。
- 跨内核语义定稿：配合 W0-C31，明确"归档内核 ≠ 当前内核 → 默认按**当前内核**安装并重建（DKMS），`--kver` 显式指定时按目标内核"，dry-run 警告与真实行为一致。

**验收**：P-2 容器矩阵全绿；Live USB `--root /mnt/target` 实测（P-6）。

### W5 固件按需收集 / On-demand firmware (P1-3)

- 备份：解析模块 `modinfo.firmware` 标签 → 只收集命中的 `/lib/firmware/**`（含 `.zst/.xz` 变体与同目录版本族）；`--firmware all|needed|none` 三态（`standard` 默认 `needed`，兼容 v2 归档语义）。
- 还原：固件条目独立开关；包提供者仍走 `content_stored=false`（W3 修正统计口径）。
- **验收**：同机 full→needed 体积对比写入验证记录；缺固件设备回插可加载（实机项，P-6）。

### W6 GUI/UX 强化 / GUI enhancements

- **P1-5 勾选还原**：`ModuleItem` 增加 `selected` 布尔列（默认按策略建议预选），按 `modinfo.depends` 计算**依赖闭包**（勾 nvidia 自动带 nvidia-uvm）；仅选中项进入 `RestorePlan`（W1 的 plan 天然支持子集）。
- **能力对齐 CLI**：暴露策略选择（rebuild/reinstall/weak/copy）、`--strict-links`、`--no-sign`、`--on-immutable`、回滚入口（CLI `main.rs:207-308` 已有，Slint 仅 4 个回调）。
- **信息完整**：行内显示 `path`/`owner`/`vermagic`（`ModuleItem.path` 已填充但未渲染，`main.rs:537`）；扫描 warnings 常驻面板（P1-6 日志面板）；`--diagnose` 输出在 GUI 一键生成（P1-6）。
- **文件对话框**：`rfd` 打开归档/输出目录选择（替代纯 LineEdit），并加**前置校验**（目录存在且可写、归档存在）。
- 摘要统一（C-46）：单一 `format_restore_summary()` / `format_backup_summary()` 供 CLI/helper/GUI 共用。
- label API 统一（C-49/C-48 部分）：`RestoreStrategy::label()`（英）与 `label_zh()` 并存，CLI 文案策略定稿。

**验收**：人工验收清单（勾选/闭包/告警/对话框/回滚入口 5 项）。

### W7 CLI 与配置 / CLI & configuration

- **`RestoreOptions` 收敛（C-45/C-47）**：一个结构体 + 一个解析器服务 `--restore`/`--helper-restore`/GUI 三路径；`run_helper` 由 10 位置参数改传结构体；路径校验函数合并为 `pathutil`（C-47）。预期 `main.rs` 净减 ~250 行。
- **P1-7 `--verify`**：读归档 → 校验 manifest 版本、逐条 sha256、vermagic/架构/签名状态、条目数与体积 → 输出文本或 `--json` 报告；`--restore --require-verify` 可强制先体检。
- **P1-8 配置文件**：`/etc/linux-driver-backup.toml` + `~/.config/linux-driver-backup/config.toml`（层级覆盖：内置 < 系统 < 用户 < CLI）；键：默认模式、输出目录、`keep_rollback`、签名密钥、固件策略。**TOML 解析器选型**：优先零依赖的极简解析（仅需 6 个键）或 `toml` crate（MIT/Apache-2.0，无传递风险）——rc 前做二进制体积对比后定稿。
- **P1-6 `--diagnose`**：一键收集内核/发行版/SB/不可变状态/工具链存在性/最近 journal，输出脱敏 zip 目录结构。
- 退出码与 JSON 输出遵循 W0-C33 规范；`MAX_ROWS` 字面量由常量插值（C-49）。

**验收**：`RestoreOptions` 单测覆盖三路径等价；`--verify` 对完好/损坏/v1 三类归档输出正确。

### W8 打包修复 / Packaging fixes

- **PKGBUILD（C-52）**：`@VERSION@` 替换纳入 `build-packages.sh` 统一管线（与 C-56 的"单一版本解析"合并实现）；生成 `.SRCINFO`；`sha256sums` 用真实 tarball 哈希；补 `fontconfig`/`freetype` 依赖；示例文案更新。
- **RPM 双目标（C-53）**：`ldb_target_fedora` 改为构建参数（CI 产 `fedora`/`suse` 两个 spec 分支产物或在 Release 标注目标），删除"强制 fedora"默认。
- **desktop/PATH（C-55）**：`install.sh` 按 `--prefix` 生成 `Exec=` 绝对路径（或安装时改写 `.desktop`）；补 `TryExec`。
- **AppImage 脚本（C-56）**：接 `--bin/--arch`，与 `build-packages.sh` 共享 `lib/common.sh`（版本/架构解析唯一来源）。
- **C-51/C-50**：policy 文件与依赖声明随 W2 落地。

**验收**：P-7 全绿；`desktop-file-validate`、`shellcheck` 零告警入 CI（W9）。

### W9 CI 加固 / CI hardening

- 门禁：`cargo fmt --check`、`clippy -D warnings`（README 已承诺）、`cargo audit`、`shellcheck`、`desktop-file-validate`、MSRV 1.92 job、全部构建 `--locked`、release 前 **tag == Cargo.toml version** 断言。
- 供应链：第三方 action 全部 pin 到 commit SHA（C-09）；appimagetool 下载加 SHA-256 校验，删除一层 `exit 0`/`continue-on-error`（C-08）。
- 冒烟：`dpkg -i`/`rpm -ivh`/`tar+install.sh` 安装后跑 `--version`/`--scan --format json`；aarch64 用 `qemu-user` 执行（C-57）。

**验收**：P-9 全绿后才允许打 tag。

---

## 5. 接口契约变更 / Interface Contract Changes

DESIGN.md §5 冻结契约的变更按以下规则：**加字段不删字段、新 CLI 旗标只增不改义、归档 manifest 版本不变（仍为 v2）**。

### 5.1 退出码（C-33，v0.2.1 起生效）

| 码 | 含义 | 场景 |
|---|---|---|
| 0 | 成功，或用户主动取消 | 扫描/备份/还原成功；y/N 选"否" |
| 1 | 运行失败 | 任何 `AppError`、JSON 输出失败 |
| 2 | 用法错误 | 未知参数、非法取值 |

### 5.2 新增 CLI 旗标（v0.3.0）

| 旗标 | 归属 | 说明 |
|---|---|---|
| `--allow-arch-mismatch` | W0/C-32 | 与 `--allow-kernel-mismatch` 解耦 |
| `--verify [ARCHIVE]`、`--json` | W7/P1-7 | 归档体检 |
| `--require-verify` | W7 | 还原前强制体检 |
| `--firmware all\|needed\|none` | W5/P1-3 | 固件收集策略 |
| `--diagnose [OUT]` | W7/P1-6 | 一键诊断包 |
| `--config PATH` | W7/P1-8 | 指定配置文件 |

### 5.3 行协议与数据结构

- helper 行协议追加：`RESULT FAIL\t已取消`（区分取消与失败）；stdin 由 `null` 改为 `piped`（W2）。
- `model.rs` 新增：`RestorePlan`（W1）、`ModuleItem.selected`（W6）、journal 的 `CommandEntry`（W1）、`Manifest.firmware_policy`（W5，**可选字段，缺省=现有行为，v2 向后兼容**）。
- polkit action id：`io.github.ltbkq.linux-driver-backup`；policy 文件路径 `/usr/share/polkit-1/actions/`。

---

## 6. 测试与验收 / Testing & Acceptance

| 层级 | 新增/强化 | 覆盖 |
|---|---|---|
| 单元（现有 103 → 目标 ≥170） | 恶意归档夹具（`etc/x -> /`、`..`、超长、非法 manifest）、WAL 崩溃恢复、退出码矩阵、usr-merge 归属、plan 与实跑等价、`RestoreOptions` 三路径等价、依赖闭包计算 | 纯函数与状态机 |
| 夹具 | 伪内核树扩展：`kernel/` 内链接、`build`/`source` 链接、initramfs-tools/dracut 配置目录、`dkms.conf` 命名不一致样例 | 扫描/备份/dry-run 免真机 |
| 注入测试 | 提取中途 `SIGKILL`、磁盘满（`ENOSPC` 模拟）、helper 取消 | W0/W1 验收核心 |
| 容器矩阵 | `ubuntu:22.04/24.04`、`debian:12`、`fedora:40`、`opensuse/tumbleweed`、`archlinux`、`alpine`：`--scan/--backup/--restore --dry-run` + 包安装冒烟（P-1、P-2、P-7） | 发行版差异 |
| QEMU | ROADMAP §13 三场景 + Live USB `--root` 救援（P-6） | 端到端 |
| 模糊 | `cargo-fuzz` 打 `validate_link_target`/`safe_join`/manifest 解析 | 路径穿越与 panic |
| CI 守门 | W9 全部门禁 | 防回归 |

发布验收（v0.3.0）：容器矩阵全绿 + QEMU 三场景通过 + GUI 人工验收清单通过 + 本文档 §3.2 的 P-1…P-7 全部有结论并回填"验证记录"。

---

## 7. 风险与取舍 / Risks & Trade-offs

| 风险 | 影响 | 缓解 |
|---|---|---|
| C-01 收紧后**拒绝历史合法归档中的绝对目标链接** | 旧归档还原报错 | 归一化后仍接受受管前缀内的绝对目标（v0.2.0 实测样例 `/lib/linux-sound-base/…` 保持通过）；拒绝信息给出替代命令 |
| WAL 使每次还原多 N 次 fsync | 还原耗时上升 | 条目级批量 fsync（每 32 条或 4ms），仅日志受损风险换恢复能力 |
| helper 取消改 stdin 语义 | 与 sudo/旧协议不兼容 | 协议版本字段放首行 `HELPER\t1`，缺省按旧行为 |
| `rfd` 对话框非模态（Slint 不暴露窗口句柄） | 体验略降 | 文档说明；后续评估 ashpd/portal（Flatpak 需要时一并做） |
| 配置文件解析器选择 | 体积或依赖增加 | rc 前二进制体积对比；核心保持"无 tokio、轻依赖" |
| 57 项一次修复的回归面 | v0.2.1 质量 | 热修只取 14 项小半径改动；每项带夹具测试；clippy/测试基线先行（§0.2） |
| W3 rpm 批量格式未实测 | fedora 行为偏差 | P-1 前置到 W3 开工第一周 |
| 与 ROADMAP 节奏的偏差 | 文档分叉 | 附录 A 显式映射；ROADMAP 保持"建议源"，本文档为"实施蓝图"，实施后回填 §17 |

---

## 8. 实施计划 / Milestones

| 里程碑 | 内容 | 出口条件 |
|---|---|---|
| **M0** | 本文档评审（重点：§2 版本划分、§7 风险） | 评审通过、C 编号冻结 |
| **M1**（v0.2.1-rc） | W0 十四项 + 夹具测试 | `cargo test`/`clippy` 全绿；P-4 恶意归档回归通过 |
| **M2**（v0.2.1） | 打 tag、发版（含 deb/rpm/tar/AppImage） | CI 全绿 + 安装冒烟 |
| **M3**（v0.3.0-rc1） | W1、W2、W3、W8、W9 | P-1/P-3/P-5/P-7 有结论；注入测试通过 |
| **M4**（v0.3.0-rc2） | W4、W5、W6、W7 | P-2 通过；GUI 人工验收清单通过 |
| **M5**（v0.3.0） | QEMU 三场景 + 容器矩阵 + 文档回填（ROADMAP §17、验证记录） | 发布验收全项通过 |

依赖关系：W0 → W1（同一文件）；W2 与 W8 依赖 policy 文件（并行）；W9 随 M3 起全量生效；W6 依赖 W1 的 `RestorePlan`。

---

## 附录 A：与 ROADMAP-v2.md 的对应关系 / Mapping to ROADMAP

| ROADMAP 条目 | 本文档处理 | 说明 |
|---|---|---|
| P1-1 离线 `--root` | **已在 v0.2.0 提前落地**（§17 调整 1）；本文档 W4 收尾（C-20/C-21） | — |
| P1-2 initramfs 矩阵 | W4 原样吸收 | 实现级补充：UKI 重签细节 |
| P1-3 固件按需收集 | W5 原样吸收 | `content_stored` 机制已就位 |
| P1-4 polkit + headless | W2 原样吸收 | 与 C-50/C-51 合并 |
| P1-5 per-module 选择 | W6 原样吸收 | 增补依赖闭包（`depends=`） |
| P1-6 诊断与可观测性 | W6/W7 拆分吸收 | GUI 日志面板 + `--diagnose` |
| P1-7 `--verify` | W7 原样吸收 | 增补 `--require-verify` |
| P1-8 配置与保留 | W7 原样吸收 | 保留策略复用 W1 的 prune |
| P2-1…P2-6 | **推迟**（§2.3） | 仅 C-41 的 manifest 缓存提前 |
| P3-5/P3-6/P3-7 | **推迟** | i18n、xattr、lib 化维持原计划；lib 化可在 v0.4.0 一并考虑 |
| 新增（ROADMAP 未收录） | C-01…C-57 中除已收录外的全部 | 本文档 §1 为唯一事实源，实施后回填 ROADMAP §16/§17 |

## 附录 B：English Summary

This document records a full-source review of v0.2.0 (7 modules, 9,406 lines of Rust plus Slint UI, packaging and CI) and turns the results into a two-stage iteration plan: **v0.2.1** (14 small-radius security/correctness hotfixes — symlink write-through escape, unguarded pkexec elevation, write-last transaction journal, usr-merge provenance queries, exit-code semantics, GUI restore confirmation) and **v0.3.0** (nine work packages absorbing all ROADMAP P1 items plus 40 further review findings).

Key claims were verified on the reference machine: `cargo test --locked` is green (103 tests), clippy is clean, `dpkg-query -S` still prints matches on non-zero exit, `/lib` vs `/usr/lib` provenance lookups differ on usr-merged systems, Secure Boot state and `CONFIG_MODULE_SIG_FORCE` are readable without extra tooling, and all candidate dependencies are license-compatible. Remaining items are scheduled for container and QEMU verification (§3.2). Contracts stay backward compatible: manifest format remains v2, CLI flags are additive, and exit codes are formalised (0 success/cancel, 1 failure, 2 usage).
