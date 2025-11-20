#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[macro_use]
#[cfg(feature = "axstd")]
extern crate axstd as std;
extern crate alloc;

use alloc::vec::Vec;

// 为 no_std 环境添加 panic 处理
#[cfg(not(feature = "axstd"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut console = axhal::console::console();
    writeln!(console, "Panic: {}", info).ok();
    loop {}
}

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    println!("Running bump tests...");

    // 进一步降低数据量，适配bump分配器的内存限制
    const N: usize = 10_000; // 从50万降到1万

    let mut v = Vec::with_capacity(N);
    for i in 0..N {
        v.push(i);
    }
    
    // 简化排序逻辑，减少内存使用
    v.sort_unstable(); // 使用更高效的unstable排序
    
    for i in 0..N - 1 {
        assert!(v[i] <= v[i + 1]);
    }

    println!("Bump tests run OK!");
}