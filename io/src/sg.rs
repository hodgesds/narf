//! Scatter-gather DMA payloads: a list of page frames under one capability
//! (Linux `struct bio` + `bio_vec` as the device sees them after
//! `blk_rq_map_sg`).
//!
//! A [`PageList`] names order-0 frames a caller already owns (page-cache
//! pages, a filesystem's node buffers); registering it mints a
//! `Cap<PageList, Write>` exactly as [`crate::register_with_cap`] does for a
//! [`DmaBuffer`](crate::DmaBuffer), and a device resolves the `Read`
//! derivative back to the list through the same epoch-gated registry. In
//! per-domain IOMMU mode every page is mapped into the device's domain when
//! the list is bound to a device ([`PageList::map_into`]) and unmapped when
//! the list drops; in identity / disabled mode the device address is the
//! frame address. [`PageList::segments`] merges physically adjacent pages so
//! a driver builds the fewest descriptors (`blk_rq_map_sg`'s coalescing).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_capabilities::{CapKind, CapType};
use narf_lib::id::DomainId;
use narf_memory::{PhysAddr, PAGE_SIZE};

use crate::{iommu, IoError};

/// A physically contiguous run of a [`PageList`] as a device sees it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Device address (IOVA in per-domain mode, else physical).
    pub dma: u64,
    /// Length in bytes.
    pub len: u32,
}

/// A list of page frames that together carry `len` bytes of payload: page
/// `i` holds bytes `i * PAGE_SIZE ..`, the last page possibly partially.
pub struct PageList {
    pages: Vec<PhysAddr>,
    len: usize,
    domain: DomainId,
    /// Per-domain IOMMU mapping: the domain and one IOVA per page.
    iommu: Option<Box<(Arc<iommu::IommuDomain>, Vec<u64>)>>,
    /// What keeps the frames allocated, dropped with the list (a bio's page
    /// references: the pages go only after the last command over them).
    owner: Option<Box<dyn core::any::Any + Send + Sync>>,
}

impl core::fmt::Debug for PageList {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PageList")
            .field("pages", &self.pages.len())
            .field("len", &self.len)
            .field("mapped", &self.iommu.is_some())
            .finish()
    }
}

impl CapType for PageList {
    const KIND: CapKind = CapKind::DmaPageList;
}

impl PageList {
    /// `len` bytes over `pages`: every frame page aligned, enough of them
    /// to hold `len` (`InvalidLength` otherwise). The caller keeps the
    /// frames allocated for as long as the list — and any device command
    /// naming it — lives.
    pub fn new(pages: Vec<PhysAddr>, len: usize, domain: DomainId) -> Result<Self, IoError> {
        let page = PAGE_SIZE as usize;
        if pages.is_empty() || len == 0 || len > pages.len() * page {
            return Err(IoError::InvalidPageList);
        }
        if pages.iter().any(|p| p.raw() as usize % page != 0) {
            return Err(IoError::InvalidPageList);
        }
        Ok(Self {
            pages,
            len,
            domain,
            iommu: None,
            owner: None,
        })
    }

    /// Give the list ownership of what keeps its frames allocated: `owner`
    /// drops with the list, i.e. after the last command naming it completed.
    /// A caller whose wait may end early (a killable read) parks the frames
    /// here instead of freeing them under a device still writing them.
    pub fn with_owner(mut self, owner: Box<dyn core::any::Any + Send + Sync>) -> Self {
        self.owner = Some(owner);
        self
    }

    /// Payload bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Frames in the list.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Frame `i`.
    pub fn page(&self, i: usize) -> Option<PhysAddr> {
        self.pages.get(i).copied()
    }

    pub fn domain(&self) -> DomainId {
        self.domain
    }

    /// Device address of frame `i`.
    pub fn dma_addr(&self, i: usize) -> Option<u64> {
        match &self.iommu {
            Some(m) => m.1.get(i).copied(),
            None => self.pages.get(i).map(|p| p.raw()),
        }
    }

    /// CPU pointer to frame `i`'s bytes (identity / kernel map).
    pub fn cpu_ptr(&self, i: usize) -> Option<*mut u8> {
        self.pages.get(i).map(|p| p.kernel_mut_ptr::<u8>())
    }

    /// The segments covering bytes `offset .. offset + len` of the payload,
    /// adjacent frames merged. `None` when the range is outside the list.
    pub fn segments_in(&self, offset: usize, len: usize) -> Option<Vec<Segment>> {
        let end = offset.checked_add(len)?;
        if end > self.len || len == 0 {
            return None;
        }
        let page = PAGE_SIZE as usize;
        let mut out: Vec<Segment> = Vec::new();
        let mut at = offset;
        while at < end {
            let i = at / page;
            let in_page = at % page;
            let take = (page - in_page).min(end - at);
            let dma = self.dma_addr(i)? + in_page as u64;
            match out.last_mut() {
                Some(last) if last.dma + last.len as u64 == dma => last.len += take as u32,
                _ => out.push(Segment {
                    dma,
                    len: take as u32,
                }),
            }
            at += take;
        }
        Some(out)
    }

    /// Every segment of the payload.
    pub fn segments(&self) -> Vec<Segment> {
        self.segments_in(0, self.len).unwrap_or_default()
    }

    /// Map every frame into `domain` (read/write) so the device addresses
    /// become IOVAs. Identity / disabled IOMMU modes need no mapping.
    pub fn map_into(&mut self, domain: &Arc<iommu::IommuDomain>, pci: bool) -> Result<(), IoError> {
        if self.iommu.is_some() {
            return Err(IoError::DomainMismatch);
        }
        let mut iovas = Vec::with_capacity(self.pages.len());
        for p in &self.pages {
            match domain.map_below(
                p.raw(),
                PAGE_SIZE,
                iommu::IommuPerms::READ_WRITE,
                u64::MAX,
                pci,
            ) {
                Ok(iova) => iovas.push(iova),
                Err(e) => {
                    for iova in iovas {
                        let _ = domain.unmap(iova, PAGE_SIZE);
                    }
                    return Err(e);
                }
            }
        }
        self.iommu = Some(Box::new((Arc::clone(domain), iovas)));
        Ok(())
    }
}

impl Drop for PageList {
    fn drop(&mut self) {
        if let Some(m) = self.iommu.take() {
            let (domain, iovas) = *m;
            for iova in iovas {
                // A failed invalidation leaks the IOVA; the frames are the
                // caller's and are not freed here either way.
                let _ = domain.unmap(iova, PAGE_SIZE);
            }
        }
    }
}
