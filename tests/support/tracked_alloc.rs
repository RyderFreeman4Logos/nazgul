//! Per-thread allocation probe for the streaming protocol's hot path.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

std::thread_local! {
    static TRACKING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

pub struct TrackingAllocator;

fn record_allocation() {
    if TRACKING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get().saturating_add(1)));
    }
}

// SAFETY: every operation forwards the original pointer/layout to System. The
// counters use const-initialized thread-local cells and never allocate.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: caller supplies the valid allocation layout unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        // SAFETY: caller supplies the valid allocation layout unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: pointer and its original allocation layout are unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record_allocation();
        // SAFETY: pointer, original layout and requested new size are unchanged.
        unsafe { System.realloc(pointer, layout, size) }
    }
}

struct Probe;

impl Drop for Probe {
    fn drop(&mut self) {
        TRACKING.with(|tracking| tracking.set(false));
    }
}

pub fn assert_no_allocations(operation: impl FnOnce()) {
    // Initialize both TLS cells before enabling tracking. Other test threads
    // remain untracked; panic unwinding also disables this thread's probe.
    assert!(!TRACKING.with(Cell::get), "allocation probes cannot nest");
    ALLOCATIONS.with(|count| count.set(0));
    TRACKING.with(|tracking| tracking.set(true));
    let probe = Probe;
    operation();
    let allocations = ALLOCATIONS.with(Cell::get);
    drop(probe);
    assert_eq!(allocations, 0, "streaming path allocated from the heap");
}
