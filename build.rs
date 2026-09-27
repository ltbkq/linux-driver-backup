// 模块：Slint UI 编译脚本（W1-A 工程骨架）。
// Module: Slint UI build script (W1-A skeleton).
//
// 职责：把 ui/app_window.slint 编译为 Rust 代码并嵌入二进制；
//       .slint 语法错误会在 cargo build 的构建期直接暴露。
// Duty: compile ui/app_window.slint into Rust code embedded in the binary;
//       any syntax error surfaces at build time.

fn main() {
    // 编译声明式界面（失败即中止构建，避免带着坏 UI 往下编译）。
    // Compile the declarative UI; abort the build on failure.
    slint_build::compile("ui/app_window.slint").unwrap();
}
