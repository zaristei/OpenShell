// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Monotonic UID allocator for workflow isolation.
//!
//! Each forked workflow gets a unique UID starting at 100000. UIDs are never
//! recycled — the 4-billion range is effectively inexhaustible for a single
//! sandbox lifetime.

use std::sync::atomic::{AtomicU32, Ordering};

/// Starting UID for workflow processes.
const BASE_UID: u32 = 100_000;

/// Thread-safe monotonic UID allocator.
#[derive(Debug)]
pub struct UidAllocator {
    next: AtomicU32,
}

impl UidAllocator {
    /// Create a new allocator starting at `BASE_UID`.
    pub fn new() -> Self {
        Self {
            next: AtomicU32::new(BASE_UID),
        }
    }

    /// Allocate the next UID. Never returns a previously issued UID.
    pub fn allocate(&self) -> u32 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }

    /// Return the next UID that would be allocated (without consuming it).
    pub fn peek(&self) -> u32 {
        self.next.load(Ordering::Relaxed)
    }
}

impl Default for UidAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_monotonically() {
        let alloc = UidAllocator::new();
        assert_eq!(alloc.allocate(), 100_000);
        assert_eq!(alloc.allocate(), 100_001);
        assert_eq!(alloc.allocate(), 100_002);
    }

    #[test]
    fn peek_does_not_consume() {
        let alloc = UidAllocator::new();
        assert_eq!(alloc.peek(), 100_000);
        assert_eq!(alloc.peek(), 100_000);
        assert_eq!(alloc.allocate(), 100_000);
        assert_eq!(alloc.peek(), 100_001);
    }

    #[test]
    fn thread_safe() {
        use std::sync::Arc;
        let alloc = Arc::new(UidAllocator::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let a = Arc::clone(&alloc);
            handles.push(std::thread::spawn(move || a.allocate()));
        }

        let mut uids: Vec<u32> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        uids.sort();
        uids.dedup();
        // All 10 UIDs should be unique.
        assert_eq!(uids.len(), 10);
    }
}
