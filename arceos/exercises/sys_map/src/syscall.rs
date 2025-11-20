#![allow(dead_code)]

use core::ffi::{c_void, c_char, c_int};
use axhal::arch::TrapFrame;
use axhal::trap::{register_trap_handler, SYSCALL};
use axerrno::LinuxError;
use axtask::current;
use axtask::TaskExtRef;
use axhal::paging::MappingFlags;
use arceos_posix_api as api;
use axhal::mem::MemoryAddr;

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

const AT_FDCWD: i32 = -100;

/// Macro to generate syscall body
///
/// It will receive a function which return Result<_, LinuxError> and convert it to
/// the type which is specified by the caller.
#[macro_export]
macro_rules! syscall_body {
    ($fn: ident, $($stmt: tt)*) => {{
        #[allow(clippy::redundant_closure_call)]
        let res = (|| -> axerrno::LinuxResult<_> { $($stmt)* })();
        match res {
            Ok(_) | Err(axerrno::LinuxError::EAGAIN) => debug!(concat!(stringify!($fn), " => {:?}"),  res),
            Err(_) => info!(concat!(stringify!($fn), " => {:?}"), res),
        }
        match res {
            Ok(v) => v as _,
            Err(e) => {
                -e.code() as _
            }
        }
    }};
}

bitflags::bitflags! {
    #[derive(Debug)]
    /// permissions for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapProt: i32 {
        /// Page can be read.
        const PROT_READ = 1 << 0;
        /// Page can be written.
        const PROT_WRITE = 1 << 1;
        /// Page can be executed.
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
    /// flags for sys_mmap
    ///
    /// See <https://github.com/bminor/glibc/blob/master/bits/mman.h>
    struct MmapFlags: i32 {
        /// Share changes
        const MAP_SHARED = 1 << 0;
        /// Changes private; copy pages on write.
        const MAP_PRIVATE = 1 << 1;
        /// Map address must be exactly as requested, no matter whether it is available.
        const MAP_FIXED = 1 << 4;
        /// Don't use a file.
        const MAP_ANONYMOUS = 1 << 5;
        /// Don't check for reservations.
        const MAP_NORESERVE = 1 << 14;
        /// Allocation is for a stack.
        const MAP_STACK = 0x20000;
    }
}

#[register_trap_handler(SYSCALL)]
fn handle_syscall(tf: &TrapFrame, syscall_num: usize) -> isize {
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
        _ => {
            ax_println!("Unimplemented syscall: {}", syscall_num);
            -LinuxError::ENOSYS.code() as _
        }
    };
    ret
}

#[allow(unused_variables)]
#[allow(unused_variables)]
fn sys_mmap(
    addr: *mut usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    _offset: isize,
) -> isize {
    use core::ffi::c_void;
    use axhal::mem::VirtAddr;
    use axhal::paging::MappingFlags;
    use axerrno::LinuxError;
    use axtask::current;
    use axmm::AddrSpace;
    use alloc::sync::Arc;
    use axsync::Mutex;

    // quick validations
    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    // convert prot -> MappingFlags (we already have `From<MmapProt> for MappingFlags`)
    let prot_flags = match MmapProt::from_bits(prot) {
        Some(p) => MappingFlags::from(p),
        None => {
            return -LinuxError::EINVAL.code() as isize;
        }
    };

    // parse flags
    let mmap_flags = MmapFlags::from_bits(flags).unwrap_or_else(|| MmapFlags::empty());
    let is_anonymous = mmap_flags.contains(MmapFlags::MAP_ANONYMOUS);
    let is_fixed = mmap_flags.contains(MmapFlags::MAP_FIXED);

    // page-align length up to 4K
    let page_size = axhal::mem::PAGE_SIZE_4K;
    let len_aligned = ((length + page_size - 1) / page_size) * page_size;

    // get current task and its aspace
    let curr = current();
    let aspace_arc: Arc<Mutex<AddrSpace>> = curr.task_ext().aspace.clone();
    let mut aspace = aspace_arc.lock();

    // decide mapping address
    let base_vaddr = if addr.is_null() || (!is_fixed && (addr as usize) == 0) {
        // choose a spot near aspace.end() (grow upward: allocate just below end)
        let end = aspace.end();
        // align down
        let candidate = end.checked_sub(len_aligned).unwrap_or(0.into());
        VirtAddr::from_usize(candidate.into()).align_down_4k()
    } else {
        // use requested addr (align down)
        VirtAddr::from_usize(addr as usize).align_down_4k()
    };

    // perform mapping: map_alloc(vstart, size, flags, populating)
    // choose "populating" = true so physical pages are allocated and zeroed (for anonymous)
    let map_res = aspace.map_alloc(base_vaddr, len_aligned, prot_flags, true);
    if map_res.is_err() {
        return -LinuxError::ENOMEM.code() as isize;
    }

    // If mapping a file (not anonymous) -> fill pages by reading fd into that buffer.
    if !is_anonymous && fd >= 0 {
        // We'll read repeatedly until length bytes read or EOF.
        // Use api::sys_read(fd, ptr, chunk_len) which expects user-space buffer pointer.
        let mut off = 0usize;
        while off < len_aligned {
            let to_read = core::cmp::min(len_aligned - off, 4096);
            let user_ptr = (base_vaddr.as_usize() + off) as *mut c_void;
            // call api::sys_read -> returns isize: >=0 bytes read, negative errno
            let r = api::sys_read(fd, user_ptr, to_read);
            if r < 0 {
                // read error -> unmap the region and return error
                // TODO: if AddrSpace provides a remove/unmap API, call it; else leave mapping.
                return r;
            }
            let nr = r as usize;
            if nr == 0 {
                break; // EOF
            }
            off += nr;
        }
    }

    // success: return mapped address
    base_vaddr.as_usize() as isize
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
    ax_println!("Ignore SYS_IOCTL");
    0
}
