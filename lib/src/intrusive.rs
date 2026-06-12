//! Intrusive doubly-linked list. Caller provides node storage; `lib/` never
//! allocates.
//!
//! Spec: `lib/specification/spec.md` §3.2. Shape-compatible with
//! `scheduler/`'s run-queues and `time/`'s timer wheel once those lands.
//!
//! Safety model: a `Node<T>` is pinned in memory for the duration of its
//! membership in a list. Moving a linked node is UB. The public API below
//! accepts `Pin<&mut Node<T>>` to make this non-negotiable at the type
//! level.

use core::cell::Cell;
use core::fmt;
use core::marker::{PhantomData, PhantomPinned};
use core::pin::Pin;
use core::ptr::NonNull;

/// Intrusive list link. Embed one of these in a `T` to let it live in a list.
#[derive(Default)]
pub struct ListLink<T> {
    prev: Cell<Option<NonNull<Node<T>>>>,
    next: Cell<Option<NonNull<Node<T>>>>,
    _pinned: PhantomPinned,
}

impl<T> ListLink<T> {
    pub const fn new() -> Self {
        Self {
            prev: Cell::new(None),
            next: Cell::new(None),
            _pinned: PhantomPinned,
        }
    }

    /// Is this link currently a member of some list?
    #[inline]
    pub fn is_linked(&self) -> bool {
        self.prev.get().is_some() || self.next.get().is_some()
    }
}

impl<T> fmt::Debug for ListLink<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListLink")
            .field("linked", &self.is_linked())
            .finish()
    }
}

/// A node storing a value plus its intrusive link.
///
/// Typical usage:
/// ```ignore
/// let mut n = core::pin::pin!(Node::new(42u32));
/// list.push_back(n.as_mut());
/// ```
pub struct Node<T> {
    pub value: T,
    pub link: ListLink<T>,
}

impl<T> Node<T> {
    pub const fn new(value: T) -> Self {
        Self {
            value,
            link: ListLink::new(),
        }
    }
}

impl<T: fmt::Debug> fmt::Debug for Node<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node").field("value", &self.value).finish()
    }
}

/// Doubly-linked intrusive list.
///
/// `Send` follows `T: Send`; the list is `!Sync` — callers serialise access
/// externally via whichever `SpinLock` / `Mutex` their subsystem uses.
pub struct IntrusiveList<T> {
    head: Cell<Option<NonNull<Node<T>>>>,
    tail: Cell<Option<NonNull<Node<T>>>>,
    len: Cell<usize>,
    _marker: PhantomData<*mut T>,
}

// SAFETY: the list only holds raw pointers to pinned `Node<T>`. Ownership
// stays with the caller; `T: Send` is enough to move the list across threads.
unsafe impl<T: Send> Send for IntrusiveList<T> {}

impl<T> IntrusiveList<T> {
    pub const fn new() -> Self {
        Self {
            head: Cell::new(None),
            tail: Cell::new(None),
            len: Cell::new(0),
            _marker: PhantomData,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.get().is_none()
    }

    pub fn len(&self) -> usize {
        self.len.get()
    }

    /// Append a pinned node at the tail.
    pub fn push_back(&self, node: Pin<&mut Node<T>>) {
        // SAFETY: the pin projection for `link` is sound because `Node<T>`
        // and `ListLink<T>` are `!Unpin` and we never move out of `link`.
        // SAFETY: Valid memory or trusted environment
        let node_ptr: NonNull<Node<T>> = NonNull::from(unsafe { node.get_unchecked_mut() });
        // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
        let link = unsafe { &node_ptr.as_ref().link };
        debug_assert!(!link.is_linked(), "IntrusiveList: node already linked");

        link.prev.set(self.tail.get());
        link.next.set(None);

        match self.tail.get() {
            Some(tail) => {
                // SAFETY: the caller holds the list (external sync); the tail
                // node is still pinned and alive.
                // SAFETY: Valid memory or trusted environment
                unsafe {
                    tail.as_ref().link.next.set(Some(node_ptr));
                }
            }
            None => self.head.set(Some(node_ptr)),
        }
        self.tail.set(Some(node_ptr));
        self.len.set(self.len.get() + 1);
    }

    /// Prepend a pinned node at the head.
    pub fn push_front(&self, node: Pin<&mut Node<T>>) {
        // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
        let node_ptr: NonNull<Node<T>> = NonNull::from(unsafe { node.get_unchecked_mut() });
        // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
        let link = unsafe { &node_ptr.as_ref().link };
        debug_assert!(!link.is_linked(), "IntrusiveList: node already linked");

        link.prev.set(None);
        link.next.set(self.head.get());

        match self.head.get() {
            // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
            Some(head) => unsafe {
                head.as_ref().link.prev.set(Some(node_ptr));
            },
            None => self.tail.set(Some(node_ptr)),
        }
        self.head.set(Some(node_ptr));
        self.len.set(self.len.get() + 1);
    }

    /// Pop the front node. Returns a raw pointer; the caller re-wraps into
    /// `Pin<&mut Node<T>>` if they still hold the original pin.
    pub fn pop_front(&self) -> Option<NonNull<Node<T>>> {
        let node_ptr = self.head.get()?;
        // SAFETY: head is live until we unlink it.
        let link = unsafe { &node_ptr.as_ref().link };
        let next = link.next.get();
        link.prev.set(None);
        link.next.set(None);
        self.head.set(next);
        match next {
            // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
            Some(n) => unsafe {
                n.as_ref().link.prev.set(None);
            },
            None => self.tail.set(None),
        }
        self.len.set(self.len.get() - 1);
        Some(node_ptr)
    }

    /// Unlink an arbitrary node that is known to be in this list. O(1).
    ///
    /// # Safety
    /// - `node` must currently be linked into *this* list (calling this on a
    ///   node that belongs to a different list is UB — the list's len counter
    ///   will desynchronise from the link chain, and subsequent reads may
    ///   dereference freed memory).
    pub unsafe fn unlink(&self, node: NonNull<Node<T>>) {
        // SAFETY: caller guarantees `node` is live and in this list.
        let link = unsafe { &node.as_ref().link };
        let prev = link.prev.get();
        let next = link.next.get();
        match prev {
            // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
            Some(p) => unsafe {
                p.as_ref().link.next.set(next);
            },
            None => self.head.set(next),
        }
        match next {
            // SAFETY: the node pointer is live and owned by this list (caller holds external sync); the intrusive invariant rules out aliasing.
            Some(n) => unsafe {
                n.as_ref().link.prev.set(prev);
            },
            None => self.tail.set(prev),
        }
        link.prev.set(None);
        link.next.set(None);
        self.len.set(self.len.get() - 1);
    }
}

impl<T> Default for IntrusiveList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> fmt::Debug for IntrusiveList<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntrusiveList")
            .field("len", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::pin::pin;

    #[test]
    fn push_pop_back() {
        let list: IntrusiveList<u32> = IntrusiveList::new();
        let mut a = pin!(Node::new(1));
        let mut b = pin!(Node::new(2));
        let mut c = pin!(Node::new(3));
        list.push_back(a.as_mut());
        list.push_back(b.as_mut());
        list.push_back(c.as_mut());
        assert_eq!(list.len(), 3);

        let h = list.pop_front().unwrap();
        // SAFETY: h was just unlinked, original pin still alive.
        assert_eq!(unsafe { h.as_ref().value }, 1);
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn push_front_then_pop_front() {
        let list: IntrusiveList<u32> = IntrusiveList::new();
        let mut a = pin!(Node::new(10));
        let mut b = pin!(Node::new(20));
        list.push_front(a.as_mut());
        list.push_front(b.as_mut());
        let h = list.pop_front().unwrap();
        // SAFETY: Valid memory or trusted environment
        assert_eq!(unsafe { h.as_ref().value }, 20);
    }

    #[test]
    fn unlink_middle() {
        let list: IntrusiveList<u32> = IntrusiveList::new();
        let mut a = pin!(Node::new(1));
        let mut b = pin!(Node::new(2));
        let mut c = pin!(Node::new(3));
        list.push_back(a.as_mut());
        list.push_back(b.as_mut());
        list.push_back(c.as_mut());
        // SAFETY: b is linked into `list`.
        let b_ptr = NonNull::from(unsafe { b.as_mut().get_unchecked_mut() });
        // SAFETY: Valid memory or trusted environment
        unsafe {
            list.unlink(b_ptr);
        }
        assert_eq!(list.len(), 2);
        let h = list.pop_front().unwrap();
        // SAFETY: Valid memory or trusted environment
        assert_eq!(unsafe { h.as_ref().value }, 1);
        let h = list.pop_front().unwrap();
        // SAFETY: Valid memory or trusted environment
        assert_eq!(unsafe { h.as_ref().value }, 3);
        assert!(list.is_empty());
    }
}
