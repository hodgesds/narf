//! Page-buffer ring. Payload ranges become immutable when published; only
//! the owning, mergeable tail may append beyond its published end.
const PIPE_BUF: usize = 4096;
const PIPE_DEFAULT_BYTES: usize = 65536;
use alloc::{collections::VecDeque, sync::Arc};

/// A file's retained page fragment, ready for zero-copy pipe publication.
#[derive(Debug)]
pub struct SplicePage {
    pin: narf_memory::address_space::UserPagePin,
    offset: usize,
    len: usize,
}

impl SplicePage {
    pub fn byte_len(&self) -> usize {
        self.len
    }

    pub fn new(pin: narf_memory::address_space::UserPagePin, offset: usize, len: usize) -> Self {
        assert!(offset < PIPE_BUF && len != 0 && len <= PIPE_BUF - offset);
        Self { pin, offset, len }
    }
}

#[derive(Debug)]
struct OwnedPage {
    frame: narf_memory::PhysFrame,
}

impl OwnedPage {
    fn allocate() -> Result<Arc<Self>, ()> {
        let frame = narf_memory::alloc_frame().map_err(|_| ())?;
        // SAFETY: exclusive fresh allocator page. Actors receive initialized
        // mutable slices, including on short reads and copy failures.
        unsafe {
            core::ptr::write_bytes(frame.start_address().kernel_mut_ptr::<u8>(), 0, PIPE_BUF);
        }
        Arc::try_new(Self { frame }).map_err(|_| ())
    }

    fn pointer(&self) -> *mut u8 {
        self.frame.start_address().kernel_mut_ptr()
    }
}

impl Drop for OwnedPage {
    fn drop(&mut self) {
        narf_memory::free_frame(self.frame);
    }
}

// SAFETY: published ranges are immutable. Only a mergeable buffer owns the
// right to append after its end, serialized by its pipe queue lock. Duplicate
// references never inherit that right; a split move leaves it with the source.
// No whole-page mutable reference is formed after the page is shared.
unsafe impl Sync for OwnedPage {}

#[derive(Clone, Debug)]
enum Page {
    Owned(Arc<OwnedPage>),
    Pinned(Arc<narf_memory::address_space::UserPagePin>),
}

#[inline(never)]
fn with_pinned_bytes<R>(
    pin: &narf_memory::address_space::UserPagePin,
    offset: usize,
    len: usize,
    read: impl FnOnce(&[u8]) -> R,
) -> R {
    let mut staging = [0u8; PIPE_BUF];
    pin.copy_into(offset, &mut staging[..len]);
    read(&staging[..len])
}

#[derive(Debug)]
struct PipeFrame {
    page: Page,
    offset: usize,
    len: usize,
    packet: bool,
    mergeable: bool,
}

impl PipeFrame {
    fn with_data<R>(&self, max: usize, read: impl FnOnce(&[u8]) -> R) -> R {
        let len = self.len.min(max);
        match &self.page {
            Page::Owned(page) => {
                // SAFETY: the retained page's published range is immutable.
                read(unsafe { core::slice::from_raw_parts(page.pointer().add(self.offset), len) })
            }
            Page::Pinned(pin) => with_pinned_bytes(pin, self.offset, len, read),
        }
    }

    fn reference(&self, len: usize) -> Self {
        Self {
            page: self.page.clone(),
            offset: self.offset,
            len,
            packet: self.packet,
            mergeable: false,
        }
    }

    fn append(
        &mut self,
        len: usize,
        copy: impl FnOnce(&mut [u8]) -> Result<(), u64>,
    ) -> Result<(), u64> {
        assert!(self.mergeable && self.offset + self.len + len <= PIPE_BUF);
        // SAFETY: this buffer exclusively owns the unpublished tail. Readers
        // (including tee references) can only observe previously published
        // ranges, which do not overlap this mutable slice. The pipe lock
        // serializes writers. On failure the new range stays unpublished.
        let Page::Owned(page) = &self.page else {
            unreachable!("pinned buffers never merge")
        };
        // SAFETY: the unpublished tail is exclusively owned as described above.
        let dst = unsafe {
            core::slice::from_raw_parts_mut(page.pointer().add(self.offset + self.len), len)
        };
        copy(dst)?;
        self.len += len;
        Ok(())
    }
}

#[derive(Debug)]
pub struct PipeBufs {
    frames: VecDeque<PipeFrame>,
    slots: usize,
    bytes: usize,
    // Like Linux's tmp_page cache, retain one exclusively owned drained page.
    spare: Option<Arc<OwnedPage>>,
}

impl Default for PipeBufs {
    fn default() -> Self {
        Self::new()
    }
}

impl PipeBufs {
    pub fn new() -> Self {
        let slots = PIPE_DEFAULT_BYTES / PIPE_BUF;
        Self {
            frames: VecDeque::with_capacity(slots),
            slots,
            bytes: 0,
            spare: None,
        }
    }
    pub fn len(&self) -> usize {
        self.bytes
    }
    /// Length and packet marker of the first published buffer.
    pub fn front_info(&self) -> Option<(usize, bool)> {
        self.frames.front().map(|frame| (frame.len, frame.packet))
    }
    pub fn reset(&mut self) {
        self.frames.clear();
        self.spare = None;
        self.bytes = 0;
        self.slots = PIPE_DEFAULT_BYTES / PIPE_BUF;
    }
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
    pub fn capacity(&self) -> usize {
        self.slots * PIPE_BUF
    }
    pub fn is_full(&self) -> bool {
        self.frames.len() >= self.slots
    }

    pub fn resize(&mut self, slots: usize) -> Result<(), u64> {
        if slots < self.frames.len() {
            return Err(16u64);
        }
        if slots > self.frames.capacity() {
            self.frames
                .try_reserve_exact(slots - self.frames.len())
                .map_err(|_| 12u64)?;
        }
        self.slots = slots;
        Ok(())
    }

    /// Linux merges only the write's page remainder, and only when it fits
    /// completely in the last mergeable buffer. Free bytes in earlier buffers
    /// cannot be reused until those buffers are retired.
    fn merge_len(&self, len: usize) -> usize {
        let remainder = len % PIPE_BUF;
        self.frames
            .back()
            .filter(|tail| tail.mergeable && tail.offset + tail.len + remainder <= PIPE_BUF)
            .map_or(0, |_| remainder)
    }

    pub fn write_with(
        &mut self,
        len: usize,
        packet: bool,
        copy: impl FnMut(usize, &mut [u8]) -> Result<(), u64>,
    ) -> Result<usize, u64> {
        self.write_internal(len, packet, true, copy)
    }

    /// Buffered-provider fallback for a nonmergeable imported pipe buffer.
    pub fn write_unmerged(
        &mut self,
        len: usize,
        copy: impl FnMut(usize, &mut [u8]) -> Result<(), u64>,
    ) -> Result<usize, u64> {
        self.write_internal(len, false, false, copy)
    }

    /// Read a buffered provider directly into fresh, nonmergeable pipe pages.
    /// The actor may return a short prefix or EOF; only accepted bytes publish.
    pub fn fill_from(
        &mut self,
        len: usize,
        mut read: impl FnMut(usize, &mut [u8]) -> Result<usize, u64>,
    ) -> Result<usize, u64> {
        let mut total = 0;
        while total < len && !self.is_full() {
            let count = (len - total).min(PIPE_BUF);
            let page = match self.spare.take() {
                Some(page) => page,
                None => match OwnedPage::allocate() {
                    Ok(page) => page,
                    Err(_) if total != 0 => break,
                    Err(_) => return Err(12),
                },
            };
            let mut frame = PipeFrame {
                page: Page::Owned(page),
                offset: 0,
                len: 0,
                packet: false,
                mergeable: true,
            };
            let mut accepted = 0;
            let result = frame.append(count, |bytes| {
                accepted = read(total, bytes)?;
                if accepted > bytes.len() {
                    return Err(5);
                }
                Ok(())
            });
            if result.is_err() || accepted == 0 {
                if let Page::Owned(page) = frame.page {
                    self.spare = Some(page);
                }
                if total == 0 {
                    result?;
                }
                break;
            }
            frame.len = accepted;
            frame.mergeable = false;
            self.frames.push_back(frame);
            self.bytes += accepted;
            total += accepted;
            if accepted < count {
                break;
            }
        }
        Ok(total)
    }

    fn write_internal(
        &mut self,
        len: usize,
        packet: bool,
        merge: bool,
        mut copy: impl FnMut(usize, &mut [u8]) -> Result<(), u64>,
    ) -> Result<usize, u64> {
        let mut written = if merge { self.merge_len(len) } else { 0 };
        if written != 0 {
            self.frames
                .back_mut()
                .unwrap()
                .append(written, |dst| copy(0, dst))?;
            self.bytes += written;
        }
        while written < len && !self.is_full() {
            let count = (len - written).min(PIPE_BUF);
            let page = match self.spare.take() {
                Some(page) => page,
                None => match OwnedPage::allocate() {
                    Ok(page) => page,
                    Err(_) if written != 0 => break,
                    Err(_) => return Err(12u64),
                },
            };
            let mut frame = PipeFrame {
                page: Page::Owned(page),
                offset: 0,
                len: 0,
                packet,
                mergeable: true,
            };
            if let Err(errno) = frame.append(count, |dst| copy(written, dst)) {
                if let Page::Owned(page) = frame.page {
                    self.spare = Some(page);
                }
                if written != 0 {
                    break;
                }
                return Err(errno);
            }
            frame.mergeable = merge && !packet;
            self.frames.push_back(frame);
            self.bytes += count;
            written += count;
        }
        Ok(written)
    }

    pub fn front_len(&self, max: usize) -> usize {
        self.frames.front().map_or(0, |frame| frame.len.min(max))
    }
    pub fn with_front<R>(&self, max: usize, read: impl FnOnce(&[u8]) -> R) -> R {
        match self.frames.front() {
            Some(frame) => frame.with_data(max, read),
            None => read(&[]),
        }
    }
    /// Expose retained bytes only as a raw pointer: a user pin may be modified
    /// concurrently, so callers must use guarded assembly, never a Rust slice.
    /// The pointer is valid only during the callback and must not be written.
    pub fn with_front_raw<R>(&self, max: usize, read: impl FnOnce(*const u8, usize) -> R) -> R {
        let Some(frame) = self.frames.front() else {
            return read(core::ptr::null(), 0);
        };
        let pointer = match &frame.page {
            Page::Owned(page) => page.pointer().cast_const(),
            Page::Pinned(pin) => pin.kernel_pointer(),
        };
        // SAFETY: frame offsets and lengths are bounded by the retained page.
        read(unsafe { pointer.add(frame.offset) }, frame.len.min(max))
    }
    pub fn push_pinned(
        &mut self,
        pin: narf_memory::address_space::UserPagePin,
        offset: usize,
        len: usize,
    ) -> Result<(), u64> {
        assert!(offset < PIPE_BUF && len != 0 && len <= PIPE_BUF - offset);
        if self.is_full() {
            return Err(11);
        }
        let pin = Arc::try_new(pin).map_err(|_| 12u64)?;
        self.frames.push_back(PipeFrame {
            page: Page::Pinned(pin),
            offset,
            len,
            packet: false,
            mergeable: false,
        });
        self.bytes += len;
        Ok(())
    }

    pub fn push_file_page(&mut self, page: SplicePage) -> Result<usize, u64> {
        let len = page.len;
        self.push_pinned(page.pin, page.offset, len)?;
        Ok(len)
    }

    pub fn copy_out(&self, mut offset: usize, mut dst: &mut [u8]) {
        for frame in &self.frames {
            if offset >= frame.len {
                offset -= frame.len;
                continue;
            }
            let count = dst.len().min(frame.len - offset);
            match &frame.page {
                Page::Pinned(pin) => pin.copy_into(frame.offset + offset, &mut dst[..count]),
                Page::Owned(_) => frame.with_data(frame.len, |bytes| {
                    dst[..count].copy_from_slice(&bytes[offset..offset + count])
                }),
            }
            dst = &mut dst[count..];
            offset = 0;
            if dst.is_empty() {
                return;
            }
        }
        assert!(dst.is_empty());
    }

    pub fn read_span(&self, max: usize) -> (usize, usize) {
        let mut copied = 0;
        for frame in &self.frames {
            if copied == max {
                break;
            }
            let take = (max - copied).min(frame.len);
            if frame.packet {
                return (copied + take, copied + frame.len);
            }
            copied += take;
        }
        (copied, copied)
    }

    pub fn commit(&mut self, mut count: usize) {
        assert!(count <= self.bytes);
        self.bytes -= count;
        while count != 0 {
            let front = self.frames.front_mut().unwrap();
            if count < front.len {
                front.offset += count;
                front.len -= count;
                break;
            }
            count -= front.len;
            let retired = self.frames.pop_front().unwrap();
            if let Page::Owned(page) = retired.page {
                if self.spare.is_none() && Arc::strong_count(&page) == 1 {
                    self.spare = Some(page);
                }
            }
        }
    }

    pub fn copy_prefix_to(&self, dst: &mut Self, max: usize) -> usize {
        let mut copied = 0;
        for frame in &self.frames {
            if copied == max || dst.is_full() {
                break;
            }
            let count = (max - copied).min(frame.len);
            dst.frames.push_back(frame.reference(count));
            dst.bytes += count;
            copied += count;
        }
        copied
    }

    pub fn move_prefix_to(&mut self, dst: &mut Self, max: usize) -> usize {
        let mut moved = 0;
        while moved < max && !dst.is_full() && !self.is_empty() {
            let front = self.frames.front_mut().unwrap();
            let count = (max - moved).min(front.len);
            if count == front.len {
                dst.frames.push_back(self.frames.pop_front().unwrap());
            } else {
                // Only the source retains append rights, beyond its original
                // end. The new destination view is immutable and nonmergeable.
                dst.frames.push_back(front.reference(count));
                front.offset += count;
                front.len -= count;
            }
            self.bytes -= count;
            dst.bytes += count;
            moved += count;
        }
        moved
    }
}
