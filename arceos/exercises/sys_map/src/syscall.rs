#![allow(dead_code)]

use core::ffi::{c_void, c_char, c_int};
use axhal::arch::TrapFrame;
use axhal::trap::{register_trap_handler, SYSCALL};
use axerrno::LinuxError;
use axtask::current;
use axhal::paging::MappingFlags;
use arceos_posix_api as api;
use axhal::mem::{VirtAddr};
use memory_addr::VirtAddrRange;

use axmm::AddrSpace;
use alloc::sync::Arc;
use axsync::Mutex;
use axhal::mem::MemoryAddr;

use axtask::TaskExtRef;
// 系统调用号定义
const SYS_IOCTL: usize = 29;
const SYS_OPENAT: usize = 56;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_WRITEV: usize = 66;
const SYS_EXIT: usize = 93;
const SYS_EXIT_GROUP: usize = 94;
const SYS_SET_TID_ADDRESS: usize = 96;
const SYS_MMAP: usize = 222;
const SYS_GETUID: usize = 174;
const SYS_GETGID: usize = 175;
const SYS_GETEUID: usize = 176;
const SYS_GETEGID: usize = 177;
const SYS_PRCTL: usize = 157;
const SYS_FSTAT: usize = 80;
const SYS_ARCH_PRCTL: usize = 214;

const AT_FDCWD: i32 = -100;

/// 在用户程序启动时预映射低地址空间
fn pre_map_low_memory() {
    let curr = current();
    let aspace_arc: Arc<Mutex<AddrSpace>> = curr.task_ext().aspace.clone();
    let mut aspace = aspace_arc.lock();
    
    // 映射0x0-0x100000（1MB）的低地址空间
    let start = VirtAddr::from(0x0);
    let size = 0x100000; // 1MB
    let flags = MappingFlags::USER | MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE;
    
    // 忽略已存在的错误，只关心是否成功映射
    let _ = aspace.map_alloc(start, size, flags, true);
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct MmapProt: i32 {
        const PROT_READ = 1 << 0;
        const PROT_WRITE = 1 << 1;
        const PROT_EXEC = 1 << 2;
    }
}

impl From<MmapProt> for MappingFlags {
    fn from(value: MmapProt) -> Self {
        let mut flags = MappingFlags::USER;
        if value.contains(MmapProt::PROT_READ) {
            flags |= MappingFlags::READ;
        }
        if value.contains(MmapProt::PROT_WRITE) {
            flags |= MappingFlags::WRITE;
        }
        if value.contains(MmapProt::PROT_EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        flags
    }
}

bitflags::bitflags! {
    #[derive(Debug)]
    struct MmapFlags: i32 {
        const MAP_SHARED = 1 << 0;
        const MAP_PRIVATE = 1 << 1;
        const MAP_FIXED = 1 << 4;
        const MAP_ANONYMOUS = 1 << 5;
        const MAP_NORESERVE = 1 << 14;
        const MAP_STACK = 0x20000;
    }
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
    // 在第一个系统调用时预映射低地址
    static mut FIRST_CALL: bool = true;
    unsafe {
        if FIRST_CALL {
            pre_map_low_memory();
            FIRST_CALL = false;
        }
    }
    
    ax_println!("handle_syscall [{}] ...", syscall_num);
    let ret = match syscall_num {
         SYS_IOCTL => sys_ioctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _) as _,
        SYS_SET_TID_ADDRESS => sys_set_tid_address(tf.arg0() as _),
        SYS_OPENAT => sys_openat(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _, tf.arg3() as _),
        SYS_CLOSE => sys_close(tf.arg0() as _),
        SYS_READ => sys_read(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITE => sys_write(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_WRITEV => sys_writev(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _),
        SYS_EXIT_GROUP => {
            ax_println!("[SYS_EXIT_GROUP]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        },
        SYS_EXIT => {
            ax_println!("[SYS_EXIT]: system is exiting ..");
            axtask::exit(tf.arg0() as _)
        },
        SYS_MMAP => sys_mmap(
            tf.arg0() as _,
            tf.arg1() as _,
            tf.arg2() as _,
            tf.arg3() as _,
            tf.arg4() as _,
            tf.arg5() as _,
        ),
        SYS_GETUID => sys_getuid(),
        SYS_GETGID => sys_getgid(),
        SYS_GETEUID => sys_geteuid(),
        SYS_GETEGID => sys_getegid(),
        SYS_PRCTL => sys_prctl(tf.arg0() as _, tf.arg1() as _, tf.arg2() as _, tf.arg3() as _, tf.arg4() as _),
        SYS_FSTAT => sys_fstat(tf.arg0() as _, tf.arg1() as _),
        SYS_ARCH_PRCTL => sys_arch_prctl(tf.arg0() as _, tf.arg1() as _),
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as isize
        }
    };
    ret
}

#[allow(unused_variables)]
fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    _offset: isize,
) -> isize {
    // quick validations
    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    // 解析标志
    let mmap_flags = MmapFlags::from_bits(flags).unwrap_or_else(|| MmapFlags::empty());
    let is_anonymous = mmap_flags.contains(MmapFlags::MAP_ANONYMOUS);
    let is_fixed = mmap_flags.contains(MmapFlags::MAP_FIXED);
    
    // 只支持匿名映射
    if !is_anonymous {
        return -LinuxError::ENOSYS.code() as isize;
    }
    
    // 不支持文件映射
    if fd >= 0 {
        return -LinuxError::EBADF.code() as isize;
    }

    // 转换保护标志
    let prot_flags = match MmapProt::from_bits(prot) {
        Some(p) => MappingFlags::from(p),
        None => return -LinuxError::EINVAL.code() as isize,
    };

    // 页面对齐
    let page_size = axhal::mem::PAGE_SIZE_4K;
    let len_aligned = ((length + page_size - 1) / page_size) * page_size;
    
    // 获取地址空间
    let curr = current();
    let aspace_arc: Arc<Mutex<AddrSpace>> = curr.task_ext().aspace.clone();
    let mut aspace = aspace_arc.lock();

    // 确定映射地址
    let base_vaddr = if !addr.is_null() && (addr as usize) != 0 {
        // 用户指定的地址（按页对齐）
        VirtAddr::from_usize(addr as usize).align_down_4k()
    } else if is_fixed {
        return -LinuxError::EINVAL.code() as isize;
    } else {
        // 自动分配地址
        let hint = VirtAddr::from(0x200000); // 2MB
        let limit = VirtAddrRange::from_start_size(hint, 0x10000000); // 256MB
        
        match aspace.find_free_area(hint, len_aligned, limit) {
            Some(addr) => addr,
            None => return -LinuxError::ENOMEM.code() as isize,
        }
    };

    // 检查地址范围
    if !aspace.contains_range(base_vaddr, len_aligned) {
        return -LinuxError::EINVAL.code() as isize;
    }

    // 执行映射
    let map_res = aspace.map_alloc(base_vaddr, len_aligned, prot_flags, true);
    if map_res.is_err() {
        return -LinuxError::ENOMEM.code() as isize;
    }

    // 返回结果地址
    let result_addr = if !addr.is_null() && (addr as usize) != 0 {
        addr as usize
    } else {
        base_vaddr.as_usize()
    };

    ax_println!("mmap: addr={:p} -> {:#x}, size={:#x}", 
               addr, result_addr, len_aligned);
    
    result_addr as isize
}

// 系统调用实现
fn sys_getuid() -> isize {
    0
}

fn sys_getgid() -> isize {
    0
}

fn sys_geteuid() -> isize {
    0
}

fn sys_getegid() -> isize {
    0
}

fn sys_prctl(_option: c_int, _arg2: usize, _arg3: usize, _arg4: usize, _arg5: usize) -> isize {
    0
}

fn sys_arch_prctl(_code: c_int, _addr: *mut c_void) -> isize {
    0
}

fn sys_fstat(_fd: c_int, statbuf: *mut api::ctypes::stat) -> isize {
    unsafe {
        if !statbuf.is_null() {
            core::ptr::write_bytes(statbuf, 0, 1);
        }
    }
    0
}

fn sys_openat(dfd: c_int, fname: *const c_char, flags: c_int, mode: api::ctypes::mode_t) -> isize {
    assert_eq!(dfd, AT_FDCWD);
    api::sys_open(fname, flags, mode) as isize
}

fn sys_close(fd: i32) -> isize {
    api::sys_close(fd) as isize
}

fn sys_read(fd: i32, buf: *mut c_void, count: usize) -> isize {
    api::sys_read(fd, buf, count)
}

fn sys_write(fd: i32, buf: *const c_void, count: usize) -> isize {
    api::sys_write(fd, buf, count)
}

fn sys_writev(fd: i32, iov: *const api::ctypes::iovec, iocnt: i32) -> isize {
    unsafe { api::sys_writev(fd, iov, iocnt) }
}

fn sys_set_tid_address(tid_ptd: *const i32) -> isize {
    let curr = current();
    curr.task_ext().set_clear_child_tid(tid_ptd as _);
    curr.id().as_u64() as isize
}

fn sys_ioctl(_fd: i32, _op: usize, _argp: *mut c_void) -> i32 {
    0
}