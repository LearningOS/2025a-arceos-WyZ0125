/*#![no_std]

use allocator::{BaseAllocator, ByteAllocator, PageAllocator};

/// Early memory allocator
/// Use it before formal bytes-allocator and pages-allocator can work!
/// This is a double-end memory range:
/// - Alloc bytes forward
/// - Alloc pages backward
///
/// [ bytes-used | avail-area | pages-used ]
/// |            | -->    <-- |            |
/// start       b_pos        p_pos       end
///
/// For bytes area, 'count' records number of allocations.
/// When it goes down to ZERO, free bytes-used area.
/// For pages area, it will never be freed!
///
pub struct EarlyAllocator<const SIZE: usize> {}

impl<const SIZE: usize> EarlyAllocator<SIZE> {
    pub const fn new() -> Self {
        Self {}
    }
}

impl<const SIZE: usize> BaseAllocator for EarlyAllocator<SIZE> {
    fn init(&mut self, start: usize, size: usize) {
        todo!()
    }

    fn add_memory(&mut self, start: usize, size: usize) -> allocator::AllocResult {
        todo!()
    }
}

impl<const SIZE: usize> ByteAllocator for EarlyAllocator<SIZE> {
    fn alloc(
        &mut self,
        layout: core::alloc::Layout,
    ) -> allocator::AllocResult<core::ptr::NonNull<u8>> {
        todo!()
    }

    fn dealloc(&mut self, pos: core::ptr::NonNull<u8>, layout: core::alloc::Layout) {
        todo!()
    }

    fn total_bytes(&self) -> usize {
        todo!()
    }

    fn used_bytes(&self) -> usize {
        todo!()
    }

    fn available_bytes(&self) -> usize {
        todo!()
    }
}

impl<const SIZE: usize> PageAllocator for EarlyAllocator<SIZE> {
    const PAGE_SIZE: usize = SIZE;

    fn alloc_pages(
        &mut self,
        num_pages: usize,
        align_pow2: usize,
    ) -> allocator::AllocResult<usize> {
        todo!()
    }

    fn dealloc_pages(&mut self, pos: usize, num_pages: usize) {
        todo!()
    }

    fn total_pages(&self) -> usize {
        todo!()
    }

    fn used_pages(&self) -> usize {
        todo!()
    }

    fn available_pages(&self) -> usize {
        todo!()
    }
}*/
#![no_std]

use allocator::{BaseAllocator, ByteAllocator, AllocResult, PageAllocator};
use core::ptr::NonNull;
use core::alloc::Layout;

/// Early memory allocator
/// Use it before formal bytes-allocator and pages-allocator can work!
/// This is a double-end memory range:
/// - Alloc bytes forward
/// - Alloc pages backward
///
/// [ bytes-used | avail-area | pages-used ]
/// |            | -->    <-- |            |
/// start       b_pos        p_pos       end
///
/// For bytes area, 'count' records number of allocations.
/// When it goes down to ZERO, free bytes-used area.
/// For pages area, it will never be freed!
///
pub struct EarlyAllocator<const SIZE: usize> {
    start: usize,
    end: usize,
    b_pos: usize, // 字节分配指针（向前）
    p_pos: usize, // 页面分配指针（向后）
    count: usize, // 字节分配计数
}

impl<const SIZE: usize> EarlyAllocator<SIZE> {
    pub const fn new() -> Self {
        Self {
            start: 0,
            end: 0,
            b_pos: 0,
            p_pos: 0,
            count: 0,
        }
    }
}

impl<const SIZE: usize> BaseAllocator for EarlyAllocator<SIZE> {
    fn init(&mut self, start: usize, size: usize) {
        self.start = start;
        self.end = start + size;
        self.b_pos = start;
        self.p_pos = self.end;
        self.count = 0;
    }

    fn add_memory(&mut self, start: usize, size: usize) -> AllocResult {
        // 简单实现：只支持初始化一次内存
        if self.start == 0 {
            self.init(start, size);
            Ok(())
        } else {
            Err(allocator::AllocError::InvalidParam)
        }
    }
}

impl<const SIZE: usize> ByteAllocator for EarlyAllocator<SIZE> {
    fn alloc(
        &mut self,
        layout: Layout,
    ) -> AllocResult<NonNull<u8>> {
        // 检查内存是否已初始化
        if self.start == 0 {
            return Err(allocator::AllocError::NoMemory);
        }

        // 计算对齐后的地址
        let align = layout.align();
        let size = layout.size();
        
        // 对齐当前字节指针
        let align_mask = align - 1;
        let alloc_start = (self.b_pos + align_mask) & !align_mask;
        
        // 检查是否有足够空间（保留至少1页给页面分配器）
        if alloc_start + size >= self.p_pos - SIZE {
            return Err(allocator::AllocError::NoMemory);
        }

        // 更新字节指针和计数
        self.b_pos = alloc_start + size;
        self.count += 1;

        // 返回分配的内存指针
        Ok(NonNull::new(alloc_start as *mut u8).unwrap())
    }

    fn dealloc(&mut self, _pos: NonNull<u8>, _layout: Layout) {
        // 简单实现：只有当所有字节分配都释放后才重置
        self.count = self.count.saturating_sub(1);
        if self.count == 0 {
            self.b_pos = self.start;
        }
    }

    fn total_bytes(&self) -> usize {
        if self.start == 0 {
            0
        } else {
            self.end - self.start
        }
    }

    fn used_bytes(&self) -> usize {
        self.b_pos - self.start + (self.end - self.p_pos)
    }

    fn available_bytes(&self) -> usize {
        if self.start == 0 {
            0
        } else {
            self.p_pos - self.b_pos
        }
    }
}

impl<const SIZE: usize> PageAllocator for EarlyAllocator<SIZE> {
    const PAGE_SIZE: usize = SIZE;

    fn alloc_pages(
        &mut self,
        num_pages: usize,
        align_pow2: usize,
    ) -> AllocResult<usize> {
        // 检查内存是否已初始化
        if self.start == 0 {
            return Err(allocator::AllocError::NoMemory);
        }

        // 计算需要的总大小
        let total_size = num_pages * SIZE;
        
        // 计算对齐后的结束地址
        let align = if align_pow2 > 0 { 1 << align_pow2 } else { SIZE };
        let align_mask = align - 1;
        let alloc_end = self.p_pos & !align_mask;
        let alloc_start = alloc_end - total_size;

        // 检查是否有足够空间
        if alloc_start <= self.b_pos {
            return Err(allocator::AllocError::NoMemory);
        }

        // 更新页面指针
        self.p_pos = alloc_start;

        Ok(alloc_start)
    }

    fn dealloc_pages(&mut self, _pos: usize, _num_pages: usize) {
        // 页面分配器不支持释放（按注释要求）
    }

    fn total_pages(&self) -> usize {
        if self.start == 0 {
            0
        } else {
            (self.end - self.start) / SIZE
        }
    }

    fn used_pages(&self) -> usize {
        (self.b_pos - self.start + SIZE - 1) / SIZE + 
        (self.end - self.p_pos) / SIZE
    }

    fn available_pages(&self) -> usize {
        if self.start == 0 {
            0
        } else {
            (self.p_pos - self.b_pos) / SIZE
        }
    }
}