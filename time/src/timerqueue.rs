//! Intrusive time-ordered queue — Linux `lib/timerqueue.c`.
//!
//! A red-black tree keyed by `expires`, with the leftmost (earliest) node
//! cached (`rb_root_cached`). Nodes live inside the objects that own them
//! (`HrTimer`), so enqueue and dequeue never allocate or free: both run from
//! hard-IRQ context. Equal keys insert to the right, so timers with the same
//! expiry fire in enqueue order (`timerqueue_less` uses `<`).
//!
//! The queue holds raw pointers. Every function is `unsafe` and requires the
//! caller to hold the lock that guards the queue and every node linked into
//! it, and to keep each linked node at a stable address until it is removed.

use core::ptr;

/// One link in a [`TimerQueueHead`] (Linux `struct timerqueue_node`).
#[derive(Debug)]
pub struct TimerQueueNode {
    parent: *mut TimerQueueNode,
    left: *mut TimerQueueNode,
    right: *mut TimerQueueNode,
    red: bool,
    /// Ordering key. Written only while the node is not linked.
    pub expires: u64,
}

impl TimerQueueNode {
    pub const fn new() -> Self {
        Self {
            parent: ptr::null_mut(),
            left: ptr::null_mut(),
            right: ptr::null_mut(),
            red: false,
            expires: 0,
        }
    }
}

impl Default for TimerQueueNode {
    fn default() -> Self {
        Self::new()
    }
}

/// Root of a timer queue (Linux `struct timerqueue_head`).
#[derive(Debug)]
pub struct TimerQueueHead {
    root: *mut TimerQueueNode,
    leftmost: *mut TimerQueueNode,
}

// SAFETY: the head is only touched under the owning lock (module contract).
unsafe impl Send for TimerQueueHead {}

impl TimerQueueHead {
    pub const fn new() -> Self {
        Self {
            root: ptr::null_mut(),
            leftmost: ptr::null_mut(),
        }
    }

    /// Earliest node, or null when empty (`timerqueue_getnext`).
    #[inline]
    pub fn first(&self) -> *mut TimerQueueNode {
        self.leftmost
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.root.is_null()
    }

    /// Link `node`. Returns `true` when it became the earliest node
    /// (`timerqueue_add`).
    ///
    /// # Safety
    /// `node` is valid, not linked into any queue, and stays at its address
    /// until [`Self::remove`]; the caller holds the queue's lock.
    pub unsafe fn add(&mut self, node: *mut TimerQueueNode) -> bool {
        // SAFETY: caller contract; every pointer followed is a linked node.
        unsafe {
            let key = (*node).expires;
            let mut parent = ptr::null_mut();
            let mut link = self.root;
            let mut leftmost = true;
            while !link.is_null() {
                parent = link;
                if key < (*link).expires {
                    link = (*link).left;
                } else {
                    link = (*link).right;
                    leftmost = false;
                }
            }
            (*node).parent = parent;
            (*node).left = ptr::null_mut();
            (*node).right = ptr::null_mut();
            (*node).red = true;
            if parent.is_null() {
                self.root = node;
            } else if key < (*parent).expires {
                (*parent).left = node;
            } else {
                (*parent).right = node;
            }
            if leftmost {
                self.leftmost = node;
            }
            self.insert_fixup(node);
            leftmost
        }
    }

    /// Unlink `node`. Returns `true` when the queue still has nodes
    /// (`timerqueue_del`).
    ///
    /// # Safety
    /// `node` is linked into this queue; the caller holds the queue's lock.
    pub unsafe fn remove(&mut self, node: *mut TimerQueueNode) -> bool {
        // SAFETY: caller contract.
        unsafe {
            if self.leftmost == node {
                self.leftmost = next(node);
            }
            let z = node;
            let mut y_red = (*z).red;
            let x;
            let x_parent;
            if (*z).left.is_null() {
                x = (*z).right;
                x_parent = (*z).parent;
                self.transplant(z, x);
            } else if (*z).right.is_null() {
                x = (*z).left;
                x_parent = (*z).parent;
                self.transplant(z, x);
            } else {
                let y = minimum((*z).right);
                y_red = (*y).red;
                x = (*y).right;
                if (*y).parent == z {
                    x_parent = y;
                } else {
                    x_parent = (*y).parent;
                    self.transplant(y, x);
                    (*y).right = (*z).right;
                    (*(*y).right).parent = y;
                }
                self.transplant(z, y);
                (*y).left = (*z).left;
                (*(*y).left).parent = y;
                (*y).red = (*z).red;
            }
            if !y_red {
                self.delete_fixup(x, x_parent);
            }
            (*z).parent = ptr::null_mut();
            (*z).left = ptr::null_mut();
            (*z).right = ptr::null_mut();
            !self.root.is_null()
        }
    }

    unsafe fn transplant(&mut self, u: *mut TimerQueueNode, v: *mut TimerQueueNode) {
        // SAFETY: `u` is linked; `v` is linked or null (caller contract).
        unsafe {
            let p = (*u).parent;
            if p.is_null() {
                self.root = v;
            } else if (*p).left == u {
                (*p).left = v;
            } else {
                (*p).right = v;
            }
            if !v.is_null() {
                (*v).parent = p;
            }
        }
    }

    unsafe fn rotate_left(&mut self, x: *mut TimerQueueNode) {
        // SAFETY: `x` and its right child are linked (callers' tree shape).
        unsafe {
            let y = (*x).right;
            (*x).right = (*y).left;
            if !(*y).left.is_null() {
                (*(*y).left).parent = x;
            }
            self.transplant(x, y);
            (*y).left = x;
            (*x).parent = y;
        }
    }

    unsafe fn rotate_right(&mut self, x: *mut TimerQueueNode) {
        // SAFETY: `x` and its left child are linked (callers' tree shape).
        unsafe {
            let y = (*x).left;
            (*x).left = (*y).right;
            if !(*y).right.is_null() {
                (*(*y).right).parent = x;
            }
            self.transplant(x, y);
            (*y).right = x;
            (*x).parent = y;
        }
    }

    unsafe fn insert_fixup(&mut self, mut z: *mut TimerQueueNode) {
        // SAFETY: a red parent is never the root, so the grandparent exists.
        unsafe {
            while is_red((*z).parent) {
                let p = (*z).parent;
                let g = (*p).parent;
                if p == (*g).left {
                    let u = (*g).right;
                    if is_red(u) {
                        (*p).red = false;
                        (*u).red = false;
                        (*g).red = true;
                        z = g;
                    } else {
                        if z == (*p).right {
                            z = p;
                            self.rotate_left(z);
                        }
                        let p = (*z).parent;
                        let g = (*p).parent;
                        (*p).red = false;
                        (*g).red = true;
                        self.rotate_right(g);
                    }
                } else {
                    let u = (*g).left;
                    if is_red(u) {
                        (*p).red = false;
                        (*u).red = false;
                        (*g).red = true;
                        z = g;
                    } else {
                        if z == (*p).left {
                            z = p;
                            self.rotate_right(z);
                        }
                        let p = (*z).parent;
                        let g = (*p).parent;
                        (*p).red = false;
                        (*g).red = true;
                        self.rotate_left(g);
                    }
                }
            }
            (*self.root).red = false;
        }
    }

    unsafe fn delete_fixup(&mut self, mut x: *mut TimerQueueNode, mut xp: *mut TimerQueueNode) {
        // SAFETY: a doubly-black `x` always has a non-null sibling (red-black
        // height invariant), so every dereferenced `w` exists.
        unsafe {
            while x != self.root && !is_red(x) {
                if x == (*xp).left {
                    let mut w = (*xp).right;
                    if is_red(w) {
                        (*w).red = false;
                        (*xp).red = true;
                        self.rotate_left(xp);
                        w = (*xp).right;
                    }
                    if !is_red((*w).left) && !is_red((*w).right) {
                        (*w).red = true;
                        x = xp;
                        xp = (*x).parent;
                    } else {
                        if !is_red((*w).right) {
                            (*(*w).left).red = false;
                            (*w).red = true;
                            self.rotate_right(w);
                            w = (*xp).right;
                        }
                        (*w).red = (*xp).red;
                        (*xp).red = false;
                        if !(*w).right.is_null() {
                            (*(*w).right).red = false;
                        }
                        self.rotate_left(xp);
                        x = self.root;
                        break;
                    }
                } else {
                    let mut w = (*xp).left;
                    if is_red(w) {
                        (*w).red = false;
                        (*xp).red = true;
                        self.rotate_right(xp);
                        w = (*xp).left;
                    }
                    if !is_red((*w).right) && !is_red((*w).left) {
                        (*w).red = true;
                        x = xp;
                        xp = (*x).parent;
                    } else {
                        if !is_red((*w).left) {
                            (*(*w).right).red = false;
                            (*w).red = true;
                            self.rotate_left(w);
                            w = (*xp).left;
                        }
                        (*w).red = (*xp).red;
                        (*xp).red = false;
                        if !(*w).left.is_null() {
                            (*(*w).left).red = false;
                        }
                        self.rotate_right(xp);
                        x = self.root;
                        break;
                    }
                }
            }
            if !x.is_null() {
                (*x).red = false;
            }
        }
    }

    /// Check the red-black invariants and return the node count. Test-only.
    ///
    /// # Safety
    /// As for [`Self::remove`].
    #[doc(hidden)]
    pub unsafe fn __validate(&self) -> Result<usize, &'static str> {
        // SAFETY: caller contract.
        unsafe {
            if is_red(self.root) {
                return Err("red root");
            }
            let mut count = 0;
            check(self.root, ptr::null_mut(), &mut count)?;
            let min = if self.root.is_null() {
                ptr::null_mut()
            } else {
                minimum(self.root)
            };
            if min != self.leftmost {
                return Err("stale leftmost cache");
            }
            Ok(count)
        }
    }
}

impl Default for TimerQueueHead {
    fn default() -> Self {
        Self::new()
    }
}

#[inline]
fn is_red(n: *mut TimerQueueNode) -> bool {
    // SAFETY: a non-null link points at a live linked node (module contract).
    !n.is_null() && unsafe { (*n).red }
}

unsafe fn minimum(mut n: *mut TimerQueueNode) -> *mut TimerQueueNode {
    // SAFETY: `n` is a linked node (caller contract).
    unsafe {
        while !(*n).left.is_null() {
            n = (*n).left;
        }
    }
    n
}

/// In-order successor (`rb_next`).
unsafe fn next(mut n: *mut TimerQueueNode) -> *mut TimerQueueNode {
    // SAFETY: `n` is a linked node (caller contract).
    unsafe {
        if !(*n).right.is_null() {
            return minimum((*n).right);
        }
        let mut p = (*n).parent;
        while !p.is_null() && n == (*p).right {
            n = p;
            p = (*p).parent;
        }
        p
    }
}

unsafe fn check(
    n: *mut TimerQueueNode,
    parent: *mut TimerQueueNode,
    count: &mut usize,
) -> Result<usize, &'static str> {
    if n.is_null() {
        return Ok(1);
    }
    // SAFETY: linked node (caller contract).
    unsafe {
        if (*n).parent != parent {
            return Err("bad parent link");
        }
        if (*n).red && (is_red((*n).left) || is_red((*n).right)) {
            return Err("red node with red child");
        }
        if !(*n).left.is_null() && (*(*n).left).expires > (*n).expires {
            return Err("left child orders after its parent");
        }
        if !(*n).right.is_null() && (*(*n).right).expires < (*n).expires {
            return Err("right child orders before its parent");
        }
        *count += 1;
        let l = check((*n).left, n, count)?;
        let r = check((*n).right, n, count)?;
        if l != r {
            return Err("unequal black height");
        }
        Ok(l + usize::from(!(*n).red))
    }
}
