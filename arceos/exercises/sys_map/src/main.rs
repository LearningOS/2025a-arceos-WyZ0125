#![cfg_attr(feature = "axstd", no_std)]
#![cfg_attr(feature = "axstd", no_main)]

#[cfg(feature = "axstd")]
extern crate axstd as std;
extern crate alloc;

#[macro_use]
extern crate axlog;

mod task;
mod syscall;
mod loader;

use axstd::io;
use axhal::paging::MappingFlags;
use axhal::arch::UspaceContext;
use axhal::mem::VirtAddr;
use axsync::Mutex;
use alloc::sync::Arc;
use alloc::string::String;
use alloc::collections::BTreeMap;
use axmm::AddrSpace;
use loader::load_user_app;

const USER_STACK_SIZE: usize = 0x10000;
const KERNEL_STACK_SIZE: usize = 0x40000; // 256 KiB

#[cfg_attr(feature = "axstd", no_mangle)]
fn main() {
    // A new address space for user app.
    let mut uspace = axmm::new_user_aspace().unwrap();

     // 将 pre-map 改为更保守的策略（只占用第一页，且不设 EXEC）
// 这样既能避免 NULL deref 崩溃，又降低与 loader 的可执行段冲突概率。
{
    use axhal::paging::MappingFlags;
    use axhal::mem::VirtAddr;

    // map 0..4KB (只占第一页)。如果你真的需要更多再改成 8KB/16KB，但建议越小越安全。
    let low_start = VirtAddr::from(0usize);
    let low_size: usize = 0x1000; // 4KiB

    // mapping flags: make it user / read / write (不要 EXEC)
    let flags = MappingFlags::USER | MappingFlags::READ | MappingFlags::WRITE;

    // map and populate pages (populate = true zeros pages so reads are valid)
    if let Err(e) = uspace.map_alloc(low_start, low_size, flags, true) {
        // 只记录警告，继续；多数情况下不会有冲突
        ax_println!("Warning: pre-map low memory failed: {:?}", e);
    } else {
        ax_println!("Pre-mapped low memory: {:#x}..{:#x}", low_start.as_usize(), low_start.as_usize() + low_size);
    }
}

    
    // Load user app binary file into address space.
    // Load user app binary file into address space.
let entry = match load_user_app("/sbin/mapfile", &mut uspace) {
    Ok(e) => e,
    Err(err) => {
        // 如果是 AlreadyExists，尝试在现有地址空间中找 ELF header 并解析 e_entry
        if err == axerrno::AxError::AlreadyExists {
            ax_println!("Warning: app memory already exists, trying to detect entry from memory...");
            // 扫描低地址空间 —— 这里扫描 0x0..0x10000（64KiB），按需扩大
            let scan_start = 0x0usize;
            let scan_end = 0x10000usize;
            if let Some(found_entry) = find_elf_entry_in_uspace(&mut uspace, scan_start, scan_end) {
                ax_println!("Detected ELF entry at {:#x}, continuing...", found_entry);
                found_entry
            } else {
                // 如果没找到，再尝试更保守的行为：打印更多调试信息并 panic（或按你项目策略处理）
                ax_println!("Failed to detect ELF entry in memory (AlreadyExists). Dumping diagnostics...");
                // 尝试打印低地址几个页的前 16 字节，帮助定位
                let mut d = [0u8; 16];
                for probe in (0usize..0x2000).step_by(0x1000) {
                    let va = axhal::mem::VirtAddr::from_usize(probe);
                    if uspace.read(va, &mut d).is_ok() {
                        ax_println!("mem@{:#x}: {:02x?}", probe, &d);
                    } else {
                        ax_println!("mem@{:#x}: read err", probe);
                    }
                }
                panic!("Cannot load app and cannot detect existing ELF entry: {:?}", err);
            }
        } else {
            panic!("Cannot load app! {:?}", err);
        }
    }
};


    ax_println!("entry: {:#x}", entry);

    // Init user stack.
    let ustack_top = init_user_stack(&mut uspace, true).unwrap();
    ax_println!("New user address space: {:#x?}", uspace);

    // Let's kick off the user process.
    let user_task = task::spawn_user_task(
        Arc::new(Mutex::new(uspace)),
        UspaceContext::new(entry, ustack_top),
    );

    // Wait for user process to exit ...
    let exit_code = user_task.join();
    ax_println!("monolithic kernel exit [{:?}] normally!", exit_code);
}

// helper: 在用户地址空间里扫描 ELF magic 并返回 e_entry（如果找到）
fn find_elf_entry_in_uspace(uspace: &mut AddrSpace, scan_start: usize, scan_end: usize) -> Option<usize> {
    use axhal::mem::VirtAddr;
    use core::convert::TryInto;

    let page_sz = axhal::mem::PAGE_SIZE_4K as usize;
    let mut buf = [0u8; 64]; // 足够读取 ELF header 的前 64 字节
    let mut addr = scan_start;

    while addr < scan_end {
        let va = VirtAddr::from_usize(addr);
        if uspace.read(va, &mut buf).is_ok() {
            if buf[0] == 0x7f && buf[1] == b'E' && buf[2] == b'L' && buf[3] == b'F' {
                // ELF64 little-endian: e_entry 在 offset 24, 长度 8
                let entry_bytes: [u8; 8] = buf[24..32].try_into().unwrap();
                let entry = u64::from_le_bytes(entry_bytes) as usize;
                return Some(entry);
            }
        }
        addr += page_sz;
    }
    None
}


fn init_user_stack(uspace: &mut AddrSpace, populating: bool) -> io::Result<VirtAddr> {
    let ustack_top = uspace.end();
    let ustack_vaddr = ustack_top - crate::USER_STACK_SIZE;
    ax_println!(
        "Mapping user stack: {:#x?} -> {:#x?}",
        ustack_vaddr, ustack_top
    );
    uspace.map_alloc(
        ustack_vaddr,
        crate::USER_STACK_SIZE,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
        populating,
    ).unwrap();

    let app_name = "hello";
    let av = BTreeMap::new();
    let (stack_data, ustack_pointer) = kernel_elf_parser::get_app_stack_region(
        &[String::from(app_name)],
        &[],
        &av,
        ustack_vaddr,
        crate::USER_STACK_SIZE,
    );
    uspace.write(VirtAddr::from_usize(ustack_pointer), stack_data.as_slice())?;

    Ok(ustack_pointer.into())
}
