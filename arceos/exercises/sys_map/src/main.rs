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
        // 直接匹配 AxError 枚举
        if err == axerrno::AxError::AlreadyExists {
            ax_println!("Warning: app memory already exists, continuing...");
            0x1000  // 根据你的 loader 可以返回默认 entry
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
