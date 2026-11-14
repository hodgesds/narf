//! FIFO bucket queue with reusable, generation-checked waiter slots.
//!
//! Links are slot indexes, so growing the arena cannot invalidate them.
//! The owning futex bucket lock serializes every operation. A saved handle
//! cannot remove a later waiter that reused its slot.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Handle {
    index: usize,
    generation: u64,
}

struct Slot<T> {
    generation: u64,
    prev: Option<usize>,
    // Queue successor while occupied, free-list successor otherwise.
    next: Option<usize>,
    value: Option<T>,
}

pub(super) struct Queue<T> {
    slots: Vec<Slot<T>>,
    head: Option<usize>,
    tail: Option<usize>,
    free: Option<usize>,
}

impl<T> Queue<T> {
    pub(super) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            head: None,
            tail: None,
            free: None,
        }
    }

    fn handle(&self, index: usize) -> Handle {
        Handle {
            index,
            generation: self.slots[index].generation,
        }
    }

    pub(super) fn front(&self) -> Option<Handle> {
        self.head.map(|i| self.handle(i))
    }

    pub(super) fn next(&self, handle: Handle) -> Option<Handle> {
        self.get(handle)?;
        self.slots[handle.index].next.map(|i| self.handle(i))
    }

    pub(super) fn get(&self, handle: Handle) -> Option<&T> {
        let slot = self.slots.get(handle.index)?;
        (slot.generation == handle.generation)
            .then_some(slot.value.as_ref())
            .flatten()
    }

    pub(super) fn get_mut(&mut self, handle: Handle) -> Option<&mut T> {
        let slot = self.slots.get_mut(handle.index)?;
        (slot.generation == handle.generation)
            .then_some(slot.value.as_mut())
            .flatten()
    }

    pub(super) fn push_back(&mut self, value: T) -> Handle {
        let index = if let Some(index) = self.free {
            let slot = &mut self.slots[index];
            self.free = slot.next;
            slot.generation = slot
                .generation
                .checked_add(1)
                .expect("futex slot generation exhausted");
            slot.prev = self.tail;
            slot.next = None;
            slot.value = Some(value);
            index
        } else {
            let index = self.slots.len();
            self.slots.push(Slot {
                generation: 1,
                prev: self.tail,
                next: None,
                value: Some(value),
            });
            index
        };
        if let Some(tail) = self.tail {
            self.slots[tail].next = Some(index);
        } else {
            self.head = Some(index);
        }
        self.tail = Some(index);
        self.handle(index)
    }

    pub(super) fn remove(&mut self, handle: Handle) -> Option<T> {
        let slot = self.slots.get_mut(handle.index)?;
        if slot.generation != handle.generation {
            return None;
        }
        let value = slot.value.take()?;
        let (prev, next) = (slot.prev, slot.next);
        slot.prev = None;
        slot.next = self.free;
        self.free = Some(handle.index);
        if let Some(prev) = prev {
            self.slots[prev].next = next;
        } else {
            self.head = next;
        }
        if let Some(next) = next {
            self.slots[next].prev = prev;
        } else {
            self.tail = prev;
        }
        Some(value)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (Handle, &T)> {
        let mut next = self.head;
        core::iter::from_fn(move || {
            let index = next?;
            let slot = &self.slots[index];
            next = slot.next;
            Some((
                self.handle(index),
                slot.value.as_ref().expect("futex queue link"),
            ))
        })
    }

    pub(super) fn retain(&mut self, mut keep: impl FnMut(&T) -> bool) {
        let mut next = self.front();
        while let Some(handle) = next {
            next = self.next(handle);
            if !keep(self.get(handle).expect("futex queue link")) {
                self.remove(handle);
            }
        }
    }
}
