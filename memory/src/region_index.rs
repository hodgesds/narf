//! Fallible ordered index used by the base-page VMA table.
//!
//! `alloc::collections::BTreeMap` has no API for reserving the nodes an
//! insertion may allocate.  That is unsuitable for Linux-compatible fixed
//! VMA transactions: all metadata allocation must finish before an existing
//! target is retired.  This AVL tree stores nodes in a movable arena and uses
//! indices rather than pointers, so one `Vec::try_reserve` prepares an exact
//! number of later insertions without sacrificing logarithmic operations.

use alloc::vec::Vec;
use core::cmp::Ordering;

type Link = Option<usize>;

const MAX_AVL_HEIGHT: usize = 96;

#[derive(Clone, Debug)]
struct Node<V> {
    key: u64,
    value: V,
    left: Link,
    right: Link,
    height: u8,
}

impl<V> Node<V> {
    fn new(key: u64, value: V) -> Self {
        Self {
            key,
            value,
            left: None,
            right: None,
            height: 1,
        }
    }
}

#[derive(Clone, Debug)]
enum Slot<V> {
    Occupied(Node<V>),
    Vacant { next: Link },
}

/// Allocation failure while preparing space for future index insertions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReserveError;

/// Ordered `u64` map with fallibly preparable insertion capacity.
///
/// Removed arena slots form an intrusive free list, so removal and reuse do
/// not allocate. Tree links are arena indices and therefore survive a `Vec`
/// reallocation. Callers may reserve several nodes and then perform that many
/// distinct-key insertions with [`Self::insert_reserved`] without allocation.
#[derive(Clone, Debug)]
pub(crate) struct RegionIndex<V> {
    slots: Vec<Slot<V>>,
    root: Link,
    free_head: Link,
    free_len: usize,
    len: usize,
    #[cfg(any(test, feature = "kernel-test"))]
    fail_reserve_after: usize,
}

impl<V> Default for RegionIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V> RegionIndex<V> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: Vec::new(),
            root: None,
            free_head: None,
            free_len: 0,
            len: 0,
            #[cfg(any(test, feature = "kernel-test"))]
            fail_reserve_after: 0,
        }
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    /// Prepare capacity for `additional` distinct-key insertions.
    ///
    /// Holding the containing RegionTable lock between this call and the
    /// corresponding `insert_reserved` calls makes the guarantee stable.
    pub(crate) fn try_reserve_nodes(&mut self, additional: usize) -> Result<(), ReserveError> {
        #[cfg(any(test, feature = "kernel-test"))]
        if additional != 0 && self.fail_reserve_after != 0 {
            self.fail_reserve_after -= 1;
            if self.fail_reserve_after == 0 {
                return Err(ReserveError);
            }
        }

        let new_slots = additional.saturating_sub(self.free_len);
        self.slots
            .try_reserve_exact(new_slots)
            .map_err(|_| ReserveError)
    }

    #[cfg(any(test, feature = "kernel-test"))]
    #[allow(dead_code)]
    pub(crate) fn fail_next_reserve_for_test(&mut self) {
        self.fail_reserve_after = 1;
    }

    #[cfg(any(test, feature = "kernel-test"))]
    #[allow(dead_code)]
    pub(crate) fn fail_reserve_after_for_test(&mut self, calls: usize) {
        assert!(calls != 0);
        self.fail_reserve_after = calls;
    }

    #[inline]
    pub(crate) fn get(&self, key: u64) -> Option<&V> {
        self.find_index(key).map(|index| &self.node(index).value)
    }

    #[inline]
    pub(crate) fn get_mut(&mut self, key: u64) -> Option<&mut V> {
        let index = self.find_index(key)?;
        Some(&mut self.node_mut(index).value)
    }

    pub(crate) fn predecessor(&self, key: u64) -> Option<(u64, &V)> {
        let mut cursor = self.root;
        let mut result = None;
        while let Some(index) = cursor {
            let node = self.node(index);
            if node.key < key {
                result = Some((node.key, &node.value));
                cursor = node.right;
            } else {
                cursor = node.left;
            }
        }
        result
    }

    pub(crate) fn predecessor_or_equal(&self, key: u64) -> Option<(u64, &V)> {
        let mut cursor = self.root;
        let mut result = None;
        while let Some(index) = cursor {
            let node = self.node(index);
            if node.key <= key {
                result = Some((node.key, &node.value));
                cursor = node.right;
            } else {
                cursor = node.left;
            }
        }
        result
    }

    pub(crate) fn successor_or_equal(&self, key: u64) -> Option<(u64, &V)> {
        let mut cursor = self.root;
        let mut result = None;
        while let Some(index) = cursor {
            let node = self.node(index);
            if node.key >= key {
                result = Some((node.key, &node.value));
                cursor = node.left;
            } else {
                cursor = node.right;
            }
        }
        result
    }

    pub(crate) fn iter(&self) -> Iter<'_, V> {
        Iter::new(self)
    }

    pub(crate) fn range(&self, lo: u64, hi: u64) -> Range<'_, V> {
        Range::new(self, lo, hi)
    }

    pub(crate) fn for_each_mut(&mut self, mut visit: impl FnMut(&mut V)) {
        Self::visit_mut(self, self.root, &mut visit);
    }

    pub(crate) fn for_each_range_mut(&mut self, lo: u64, hi: u64, mut visit: impl FnMut(&mut V)) {
        Self::visit_range_mut(self, self.root, lo, hi, &mut visit);
    }

    /// Insert using capacity established by `try_reserve_nodes`.
    ///
    /// Replacing an existing value never consumes a reserved slot. A new key
    /// consumes either one vacant arena slot or one previously-reserved Vec
    /// position, and cannot allocate.
    pub(crate) fn insert_reserved(&mut self, key: u64, value: V) -> Option<V> {
        if let Some(existing) = self.get_mut(key) {
            return Some(core::mem::replace(existing, value));
        }

        assert!(
            self.free_head.is_some() || self.slots.len() < self.slots.capacity(),
            "RegionIndex insertion was not prepared"
        );
        let inserted = self.allocate_slot(Node::new(key, value));
        self.root = Some(self.insert_index(self.root, inserted));
        self.len += 1;
        None
    }

    pub(crate) fn remove(&mut self, key: u64) -> Option<V> {
        let (root, removed) = self.remove_index(self.root, key);
        self.root = root;
        if removed.is_some() {
            self.len -= 1;
        }
        removed
    }

    fn find_index(&self, key: u64) -> Link {
        let mut cursor = self.root;
        while let Some(index) = cursor {
            let node = self.node(index);
            match key.cmp(&node.key) {
                Ordering::Less => cursor = node.left,
                Ordering::Greater => cursor = node.right,
                Ordering::Equal => return Some(index),
            }
        }
        None
    }

    fn allocate_slot(&mut self, node: Node<V>) -> usize {
        if let Some(index) = self.free_head {
            let next = match &self.slots[index] {
                Slot::Vacant { next } => *next,
                Slot::Occupied(_) => unreachable!("free-list points at occupied region node"),
            };
            self.free_head = next;
            self.free_len -= 1;
            self.slots[index] = Slot::Occupied(node);
            index
        } else {
            let index = self.slots.len();
            self.slots.push(Slot::Occupied(node));
            index
        }
    }

    fn retire_slot(&mut self, index: usize) -> V {
        let old = core::mem::replace(
            &mut self.slots[index],
            Slot::Vacant {
                next: self.free_head,
            },
        );
        self.free_head = Some(index);
        self.free_len += 1;
        match old {
            Slot::Occupied(node) => node.value,
            Slot::Vacant { .. } => unreachable!("retired vacant region node"),
        }
    }

    #[inline]
    fn node(&self, index: usize) -> &Node<V> {
        match &self.slots[index] {
            Slot::Occupied(node) => node,
            Slot::Vacant { .. } => unreachable!("tree link points at vacant region node"),
        }
    }

    #[inline]
    fn node_mut(&mut self, index: usize) -> &mut Node<V> {
        match &mut self.slots[index] {
            Slot::Occupied(node) => node,
            Slot::Vacant { .. } => unreachable!("tree link points at vacant region node"),
        }
    }

    #[inline]
    fn height(&self, link: Link) -> i16 {
        link.map_or(0, |index| i16::from(self.node(index).height))
    }

    fn update_height(&mut self, index: usize) {
        let (left, right) = {
            let node = self.node(index);
            (node.left, node.right)
        };
        let height = 1 + self.height(left).max(self.height(right));
        self.node_mut(index).height = u8::try_from(height).expect("AVL height exceeds u8");
    }

    fn balance_factor(&self, index: usize) -> i16 {
        let node = self.node(index);
        self.height(node.left) - self.height(node.right)
    }

    fn rotate_left(&mut self, root: usize) -> usize {
        let pivot = self
            .node(root)
            .right
            .expect("left rotation requires right child");
        let middle = self.node(pivot).left;
        self.node_mut(root).right = middle;
        self.update_height(root);
        self.node_mut(pivot).left = Some(root);
        self.update_height(pivot);
        pivot
    }

    fn rotate_right(&mut self, root: usize) -> usize {
        let pivot = self
            .node(root)
            .left
            .expect("right rotation requires left child");
        let middle = self.node(pivot).right;
        self.node_mut(root).left = middle;
        self.update_height(root);
        self.node_mut(pivot).right = Some(root);
        self.update_height(pivot);
        pivot
    }

    fn rebalance(&mut self, root: usize) -> usize {
        self.update_height(root);
        let balance = self.balance_factor(root);
        if balance > 1 {
            let left = self
                .node(root)
                .left
                .expect("left-heavy AVL has no left child");
            if self.balance_factor(left) < 0 {
                let rotated = self.rotate_left(left);
                self.node_mut(root).left = Some(rotated);
            }
            self.rotate_right(root)
        } else if balance < -1 {
            let right = self
                .node(root)
                .right
                .expect("right-heavy AVL has no right child");
            if self.balance_factor(right) > 0 {
                let rotated = self.rotate_right(right);
                self.node_mut(root).right = Some(rotated);
            }
            self.rotate_left(root)
        } else {
            root
        }
    }

    fn insert_index(&mut self, root: Link, inserted: usize) -> usize {
        let Some(root) = root else {
            return inserted;
        };
        let inserted_key = self.node(inserted).key;
        if inserted_key < self.node(root).key {
            let child = self.insert_index(self.node(root).left, inserted);
            self.node_mut(root).left = Some(child);
        } else {
            let child = self.insert_index(self.node(root).right, inserted);
            self.node_mut(root).right = Some(child);
        }
        self.rebalance(root)
    }

    fn remove_index(&mut self, root: Link, key: u64) -> (Link, Option<V>) {
        let Some(root) = root else {
            return (None, None);
        };
        match key.cmp(&self.node(root).key) {
            Ordering::Less => {
                let (left, removed) = self.remove_index(self.node(root).left, key);
                if removed.is_none() {
                    return (Some(root), None);
                }
                self.node_mut(root).left = left;
                (Some(self.rebalance(root)), removed)
            }
            Ordering::Greater => {
                let (right, removed) = self.remove_index(self.node(root).right, key);
                if removed.is_none() {
                    return (Some(root), None);
                }
                self.node_mut(root).right = right;
                (Some(self.rebalance(root)), removed)
            }
            Ordering::Equal => {
                let (left, right) = {
                    let node = self.node(root);
                    (node.left, node.right)
                };
                match (left, right) {
                    (None, child) | (child, None) => {
                        let value = self.retire_slot(root);
                        (child, Some(value))
                    }
                    (Some(_), Some(right)) => {
                        let successor = self.leftmost(right);
                        self.swap_key_value(root, successor);
                        let (new_right, removed) = self.remove_index(Some(right), key);
                        self.node_mut(root).right = new_right;
                        (Some(self.rebalance(root)), removed)
                    }
                }
            }
        }
    }

    fn leftmost(&self, mut index: usize) -> usize {
        while let Some(left) = self.node(index).left {
            index = left;
        }
        index
    }

    fn swap_key_value(&mut self, first: usize, second: usize) {
        debug_assert_ne!(first, second);
        let (first_slot, second_slot) = if first < second {
            let (before, after) = self.slots.split_at_mut(second);
            (&mut before[first], &mut after[0])
        } else {
            let (before, after) = self.slots.split_at_mut(first);
            (&mut after[0], &mut before[second])
        };
        match (first_slot, second_slot) {
            (Slot::Occupied(first), Slot::Occupied(second)) => {
                core::mem::swap(&mut first.key, &mut second.key);
                core::mem::swap(&mut first.value, &mut second.value);
            }
            _ => unreachable!("AVL payload swap reached vacant slot"),
        }
    }

    fn visit_mut(map: &mut Self, link: Link, visit: &mut impl FnMut(&mut V)) {
        let Some(index) = link else { return };
        let left = map.node(index).left;
        Self::visit_mut(map, left, visit);
        visit(&mut map.node_mut(index).value);
        let right = map.node(index).right;
        Self::visit_mut(map, right, visit);
    }

    fn visit_range_mut(
        map: &mut Self,
        link: Link,
        lo: u64,
        hi: u64,
        visit: &mut impl FnMut(&mut V),
    ) {
        let Some(index) = link else { return };
        let (key, left, right) = {
            let node = map.node(index);
            (node.key, node.left, node.right)
        };
        if key > lo {
            Self::visit_range_mut(map, left, lo, hi, visit);
        }
        if key >= lo && key < hi {
            visit(&mut map.node_mut(index).value);
        }
        if key < hi {
            Self::visit_range_mut(map, right, lo, hi, visit);
        }
    }
}

pub(crate) struct Iter<'a, V> {
    map: &'a RegionIndex<V>,
    stack: [usize; MAX_AVL_HEIGHT],
    depth: usize,
}

impl<'a, V> Iter<'a, V> {
    fn new(map: &'a RegionIndex<V>) -> Self {
        let mut iter = Self {
            map,
            stack: [0; MAX_AVL_HEIGHT],
            depth: 0,
        };
        iter.push_left(map.root);
        iter
    }

    fn push_left(&mut self, mut link: Link) {
        while let Some(index) = link {
            assert!(
                self.depth < MAX_AVL_HEIGHT,
                "RegionIndex AVL height overflow"
            );
            self.stack[self.depth] = index;
            self.depth += 1;
            link = self.map.node(index).left;
        }
    }
}

impl<'a, V> Iterator for Iter<'a, V> {
    type Item = (u64, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        let index = self.stack[self.depth];
        let node = self.map.node(index);
        self.push_left(node.right);
        Some((node.key, &node.value))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.map.len))
    }
}

pub(crate) struct Range<'a, V> {
    map: &'a RegionIndex<V>,
    hi: u64,
    stack: [usize; MAX_AVL_HEIGHT],
    depth: usize,
}

impl<'a, V> Range<'a, V> {
    fn new(map: &'a RegionIndex<V>, lo: u64, hi: u64) -> Self {
        let mut range = Self {
            map,
            hi,
            stack: [0; MAX_AVL_HEIGHT],
            depth: 0,
        };
        let mut link = map.root;
        while let Some(index) = link {
            let node = map.node(index);
            if node.key >= lo {
                assert!(
                    range.depth < MAX_AVL_HEIGHT,
                    "RegionIndex AVL height overflow"
                );
                range.stack[range.depth] = index;
                range.depth += 1;
                link = node.left;
            } else {
                link = node.right;
            }
        }
        range
    }

    fn push_left(&mut self, mut link: Link) {
        while let Some(index) = link {
            assert!(
                self.depth < MAX_AVL_HEIGHT,
                "RegionIndex AVL height overflow"
            );
            self.stack[self.depth] = index;
            self.depth += 1;
            link = self.map.node(index).left;
        }
    }
}

impl<'a, V> Iterator for Range<'a, V> {
    type Item = (u64, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        let index = self.stack[self.depth];
        let node = self.map.node(index);
        if node.key >= self.hi {
            self.depth = 0;
            return None;
        }
        self.push_left(node.right);
        Some((node.key, &node.value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec;

    fn assert_invariants<V>(map: &RegionIndex<V>) {
        fn walk<V>(map: &RegionIndex<V>, link: Link) -> (usize, i16, Option<u64>, Option<u64>) {
            let Some(index) = link else {
                return (0, 0, None, None);
            };
            let node = map.node(index);
            let (left_count, left_height, left_min, left_max) = walk(map, node.left);
            let (right_count, right_height, right_min, right_max) = walk(map, node.right);
            assert!(left_max.is_none_or(|key| key < node.key));
            assert!(right_min.is_none_or(|key| key > node.key));
            assert!((left_height - right_height).abs() <= 1);
            let height = 1 + left_height.max(right_height);
            assert_eq!(i16::from(node.height), height);
            (
                left_count + right_count + 1,
                height,
                left_min.or(Some(node.key)),
                right_max.or(Some(node.key)),
            )
        }

        let (count, _, _, _) = walk(map, map.root);
        assert_eq!(count, map.len);
        assert_eq!(map.len + map.free_len, map.slots.len());
        let mut seen = vec![false; map.slots.len()];
        let mut free = map.free_head;
        let mut free_count = 0;
        while let Some(index) = free {
            assert!(!seen[index], "free-list cycle");
            seen[index] = true;
            free_count += 1;
            free = match map.slots[index] {
                Slot::Vacant { next } => next,
                Slot::Occupied(_) => panic!("free-list contains occupied slot"),
            };
        }
        assert_eq!(free_count, map.free_len);
    }

    #[test]
    fn randomized_operations_match_btree_model() {
        let mut avl = RegionIndex::new();
        let mut model = BTreeMap::new();
        let mut state = 0xBADC_0FFE_EE01_2345u64;
        for step in 0..20_000u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let key = (state >> 17) & 0x7FF;
            if state & 3 == 0 {
                assert_eq!(avl.remove(key), model.remove(&key));
            } else {
                avl.try_reserve_nodes(1).unwrap();
                assert_eq!(avl.insert_reserved(key, step), model.insert(key, step));
            }
            assert_eq!(avl.get(key), model.get(&key));
            let actual: Vec<_> = avl.iter().map(|(key, value)| (key, *value)).collect();
            let expected: Vec<_> = model.iter().map(|(&key, &value)| (key, value)).collect();
            assert_eq!(actual, expected);
            if step % 127 == 0 {
                assert_invariants(&avl);
                let lo = (state >> 33) & 0x3FF;
                let hi = lo + 256;
                let actual: Vec<_> = avl.range(lo, hi).map(|(k, v)| (k, *v)).collect();
                let expected: Vec<_> = model.range(lo..hi).map(|(&k, &v)| (k, v)).collect();
                assert_eq!(actual, expected);
                assert_eq!(
                    avl.predecessor(lo).map(|(key, value)| (key, *value)),
                    model
                        .range(..lo)
                        .next_back()
                        .map(|(&key, &value)| (key, value))
                );
                assert_eq!(
                    avl.predecessor_or_equal(lo)
                        .map(|(key, value)| (key, *value)),
                    model
                        .range(..=lo)
                        .next_back()
                        .map(|(&key, &value)| (key, value))
                );
                assert_eq!(
                    avl.successor_or_equal(lo).map(|(key, value)| (key, *value)),
                    model.range(lo..).next().map(|(&key, &value)| (key, value))
                );
            }
        }
        assert_invariants(&avl);
    }

    #[test]
    fn reservation_failure_and_free_slot_reuse_are_failure_atomic() {
        let mut map = RegionIndex::new();
        map.try_reserve_nodes(3).unwrap();
        map.insert_reserved(10, 1);
        map.insert_reserved(20, 2);
        map.insert_reserved(30, 3);
        let slots = map.slots.len();
        assert_eq!(map.remove(20), Some(2));
        map.fail_next_reserve_for_test();
        assert_eq!(map.try_reserve_nodes(1), Err(ReserveError));
        assert_eq!(
            map.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            vec![10, 30]
        );
        map.try_reserve_nodes(1).unwrap();
        map.insert_reserved(25, 4);
        assert_eq!(map.slots.len(), slots);
        assert_invariants(&map);
    }

    #[test]
    fn prepared_batch_commits_without_growing_arena_capacity() {
        let mut map = RegionIndex::new();
        map.try_reserve_nodes(4).unwrap();
        let capacity = map.slots.capacity();
        for key in [40, 10, 30, 20] {
            map.insert_reserved(key, key);
            assert_eq!(map.slots.capacity(), capacity);
        }
        map.for_each_range_mut(15, 35, |value| *value += 1);
        assert_eq!(map.get(10), Some(&10));
        assert_eq!(map.get(20), Some(&21));
        assert_eq!(map.get(30), Some(&31));
        assert_eq!(map.get(40), Some(&40));
        assert_invariants(&map);
    }
}
