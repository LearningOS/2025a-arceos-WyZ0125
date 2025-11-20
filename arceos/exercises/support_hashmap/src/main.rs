#![no_std]
#![no_main]

#[macro_use]
extern crate alloc; // 添加 alloc 依赖以支持 HashMap

#[cfg(feature = "axstd")]
#[macro_use]
extern crate axstd as std;

// 为 no_std 环境提供 panic 处理
#[cfg(not(feature = "axstd"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    let mut console = axhal::console::console();
    writeln!(console, "Panic: {}", info).ok();
    loop {}
}

// 为 no_std 环境提供入口点
#[cfg(not(feature = "axstd"))]
#[no_mangle]
fn main() {
    real_main();
}

#[cfg(feature = "axstd")]
#[no_mangle]
fn main() {
    real_main();
}

fn real_main() {
    println!("Running memory tests...");
    test_hashmap();
    println!("Memory tests run OK!");
}

fn test_hashmap() {
    use alloc::collections::BTreeMap; // 若 HashMap 未实现，可先用 BTreeMap 替代（或确保 HashMap 可用）
    const N: u32 = 50_000;
    let mut m = BTreeMap::new(); // 或 HashMap::new()，需确保 alloc 特性启用
    for value in 0..N {
        let key = alloc::format!("key_{value}");
        m.insert(key, value);
    }
    for (k, v) in m.iter() {
        if let Some(k) = k.strip_prefix("key_") {
            assert_eq!(k.parse::<u32>().unwrap(), *v);
        }
    }
    println!("test_hashmap() OK!");
}
