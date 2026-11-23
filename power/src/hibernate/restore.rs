//! The boot kernel's half of a resume (S4 lane 8): Linux's
//! `load_image_and_restore`. The image's pages come into frames the image
//! does not use, as `get_buffer` places them, and are listed for the copy
//! loop (`restore_pblist`).
//!
//! [`load_payload`] streams the verified image one chunk at a time:
//! 1. the payload header;
//! 2. the frame table, which marks every image frame as forbidden;
//! 3. each page into a safe frame.
//!
//! A frame the allocator hands out that the image needs is held, so it is
//! never handed out again, and the next one is tried. The restore list's
//! pages and the arch code's frames come from the same safe allocator.

use alloc::vec::Vec;

use narf_memory::frame::{self, PhysFrame, PAGE_SHIFT, PAGE_SIZE};
use narf_memory::PhysAddr;

use super::arch::SafeFrames;
use super::payload::{self, PayloadHeader};
use crate::suspend_service::{ImageStore, ServiceError, VerifiedResume};

/// Pairs one restore-list page holds.
pub const PB_PAIRS: usize = 255;

/// One page of the restore list, in the layout the copy loop reads: the
/// next page's physical address (0 ends the chain), a count, and (copy,
/// original) physical frame addresses.
#[repr(C)]
struct PbPage {
    next: u64,
    count: u64,
    pairs: [[u64; 2]; PB_PAIRS],
}

const _: () = assert!(core::mem::size_of::<PbPage>() == PAGE_SIZE as usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestoreError {
    /// No frame outside the image's own.
    NoMemory,
    /// The payload's layout does not hold together.
    Malformed,
    Payload(payload::PayloadError),
    Service(ServiceError),
}

/// The image's pages, staged in safe frames, and the restore list.
#[derive(Debug)]
pub struct Loader {
    /// One bit per frame: an image frame, which nothing staged may use.
    forbidden: Vec<u64>,
    /// Frames the allocator gave out that the image needs: kept, so they
    /// are not handed out again.
    held: Vec<PhysFrame>,
    first_pb: u64,
    current_pb: u64,
    loaded: u64,
}

impl Loader {
    /// A loader for an image whose frames are `pfns`.
    pub fn new(pfns: &[u64]) -> Result<Self, RestoreError> {
        let top = pfns.iter().max().map_or(0, |&p| p + 1);
        let mut forbidden = Vec::new();
        forbidden
            .try_reserve_exact(top.div_ceil(64) as usize)
            .map_err(|_| RestoreError::NoMemory)?;
        forbidden.resize(top.div_ceil(64) as usize, 0u64);
        for &pfn in pfns {
            forbidden[(pfn / 64) as usize] |= 1 << (pfn % 64);
        }
        Ok(Self {
            forbidden,
            held: Vec::new(),
            first_pb: 0,
            current_pb: 0,
            loaded: 0,
        })
    }

    fn is_forbidden(&self, pfn: u64) -> bool {
        self.forbidden
            .get((pfn / 64) as usize)
            .is_some_and(|word| word & (1 << (pfn % 64)) != 0)
    }

    /// A zeroed frame no image page is copied to.
    fn safe(&mut self) -> Result<u64, RestoreError> {
        loop {
            let frame = frame::alloc_frame().map_err(|_| RestoreError::NoMemory)?;
            let phys = frame.start_address().raw();
            if self.is_forbidden(phys >> PAGE_SHIFT) {
                self.held.push(frame);
                continue;
            }
            // SAFETY: a fresh frame this loader owns, through the direct map.
            unsafe {
                core::ptr::write_bytes(
                    frame.start_address().kernel_mut_ptr::<u8>(),
                    0,
                    PAGE_SIZE as usize,
                )
            };
            return Ok(phys);
        }
    }

    /// Stage the image page for frame `pfn`.
    pub fn load(&mut self, pfn: u64, page: &[u8]) -> Result<(), RestoreError> {
        if page.len() != PAGE_SIZE as usize || !self.is_forbidden(pfn) {
            return Err(RestoreError::Malformed);
        }
        let copy = self.safe()?;
        // SAFETY: a safe frame this loader owns.
        unsafe {
            core::ptr::copy_nonoverlapping(
                page.as_ptr(),
                PhysAddr::new(copy).kernel_mut_ptr::<u8>(),
                page.len(),
            )
        };
        let full = self.current_pb == 0 || {
            // SAFETY: the current restore-list page, which this loader owns.
            unsafe {
                (*PhysAddr::new(self.current_pb).kernel_ptr::<PbPage>()).count as usize == PB_PAIRS
            }
        };
        if full {
            let next = self.safe()?;
            if self.current_pb == 0 {
                self.first_pb = next;
            } else {
                // SAFETY: as above.
                unsafe { (*PhysAddr::new(self.current_pb).kernel_mut_ptr::<PbPage>()).next = next };
            }
            self.current_pb = next;
        }
        // SAFETY: as above.
        let pb = unsafe { &mut *PhysAddr::new(self.current_pb).kernel_mut_ptr::<PbPage>() };
        pb.pairs[pb.count as usize] = [copy, pfn << PAGE_SHIFT];
        pb.count += 1;
        self.loaded += 1;
        Ok(())
    }

    /// Pages staged.
    pub fn loaded(&self) -> u64 {
        self.loaded
    }

    /// The first restore-list page, for the copy loop (0 when nothing is
    /// staged).
    pub fn first_pb(&self) -> u64 {
        self.first_pb
    }

    /// Give everything back: the resume was refused and the boot goes on.
    /// The arch code's frames, if it took any, stay taken.
    pub fn abandon(mut self) {
        let mut pb = self.first_pb;
        while pb != 0 {
            // SAFETY: a restore-list page this loader owns.
            let page = unsafe { &*PhysAddr::new(pb).kernel_ptr::<PbPage>() };
            for &[copy, _] in &page.pairs[..page.count as usize] {
                frame::free_frame(PhysFrame::new(PhysAddr::new(copy)));
            }
            let next = page.next;
            frame::free_frame(PhysFrame::new(PhysAddr::new(pb)));
            pb = next;
        }
        frame::free_frame_batch(&self.held);
        self.held.clear();
    }
}

impl SafeFrames for Loader {
    fn safe_frame(&mut self) -> Option<u64> {
        self.safe().ok()
    }
}

/// Stream a verified image's payload into a [`Loader`]: the header, the
/// frame table, then every page. Each chunk is authenticated again as it
/// is read.
pub fn load_payload(
    verified: &VerifiedResume,
    store: &dyn ImageStore,
) -> Result<(PayloadHeader, Loader), RestoreError> {
    let page = PAGE_SIZE as usize;
    let mut header: Option<PayloadHeader> = None;
    let mut table: Vec<u8> = Vec::new();
    let mut pfns: Vec<u64> = Vec::new();
    let mut loader: Option<Loader> = None;
    let mut next_page = 0u64;
    let mut chunk = Vec::new();
    for index in 0..verified.chunk_count() {
        chunk.clear();
        verified
            .read_chunk(store, index, &mut chunk)
            .map_err(RestoreError::Service)?;
        if chunk.len() % page != 0 {
            return Err(RestoreError::Malformed);
        }
        for bytes in chunk.chunks_exact(page) {
            let i = next_page;
            next_page += 1;
            let Some(h) = header.as_ref() else {
                header = Some(PayloadHeader::decode(bytes).map_err(RestoreError::Payload)?);
                continue;
            };
            let table_pages =
                (payload::pages_offset(h.page_count) - payload::frame_table_offset()) / PAGE_SIZE;
            if i <= table_pages {
                table.extend_from_slice(bytes);
                if i == table_pages {
                    pfns = payload::decode_frame_table(&table, h.page_count);
                    if pfns.len() as u64 != h.page_count {
                        return Err(RestoreError::Malformed);
                    }
                    table = Vec::new();
                    loader = Some(Loader::new(&pfns)?);
                }
                continue;
            }
            let data = (i - 1 - table_pages) as usize;
            let (Some(l), Some(&pfn)) = (loader.as_mut(), pfns.get(data)) else {
                return Err(RestoreError::Malformed);
            };
            l.load(pfn, bytes)?;
        }
    }
    match (header, loader) {
        (Some(h), Some(l)) if l.loaded() == h.page_count => Ok((h, l)),
        _ => Err(RestoreError::Malformed),
    }
}

#[cfg(feature = "kernel-test")]
#[path = "restore_tests.rs"]
mod tests;
