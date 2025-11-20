#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
use axstd::println;

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    // 输出红色的 Hello, Arceos!
    // 颜色代码：\x1b[31m   重置：\x1b[0m
    println!("\x1b[31mHello, Arceos!\x1b[0m");
}
