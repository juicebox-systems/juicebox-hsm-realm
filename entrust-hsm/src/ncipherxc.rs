use core::{alloc::GlobalAlloc, panic::PanicInfo};

#[lang = "eh_personality"]
extern "C" fn eh_personality() {}

#[global_allocator]
static A: Alloc = Alloc;

extern "C" {
    // from librtusr.a
    fn malloc(n: usize) -> *mut u8;
    fn free(ptr: *mut u8);
    // from stdlib.h
    fn abort();
}

struct Alloc;
unsafe impl GlobalAlloc for Alloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        malloc(layout.size())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: core::alloc::Layout) {
        free(ptr);
    }
}

#[panic_handler]
fn apanic(_info: &PanicInfo) -> ! {
    // We're not allowed to return from this function. In the extremely unlikely
    // event that abort doesn't actually abort we sit in a infinite loop. Which
    // is annoying but safe (from a security POV).
    unsafe {
        abort();
    }
    loop {}
}
