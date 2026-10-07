//! Regular-file data I/O between an inode's page-cache mapping and the
//! device — the ext2 `address_space_operations` (`->read_folio`,
//! `->writepage`). The page cache, not this file, decides when these run.
//!
//! File data never goes through the block-device mapping: a file page is
//! read straight from its blocks into the inode's folio and written straight
//! from that folio to its blocks (Linux `mpage_read_folio` /
//! `block_write_full_folio`), so one byte of a file is cached exactly once.

use alloc::vec;

use narf_block::BlockDevice;
use narf_filesystem::{FileFolio, FsError, PAGE_SIZE};

use super::super::inode::Inode;
use super::Ext2Volume;

impl<B: BlockDevice + 'static> Ext2Volume<B> {
    /// `->read_folio`: fill `dst` (one zeroed page) with file page `page` of
    /// `inode`. Holes and every byte at or past `i_size` read as zero
    /// (Linux zeroes the post-EOF tail of the last folio so a mapping of it
    /// never exposes stale block contents). Physically contiguous blocks of
    /// the page are read with one device request.
    pub(crate) async fn read_file_page(
        &self,
        inode: &Inode,
        page: u64,
        dst: &mut [u8],
    ) -> Result<(), FsError> {
        debug_assert_eq!(dst.len(), PAGE_SIZE);
        let bs = self.block_size() as u64;
        let size = inode.size;
        let start = page * PAGE_SIZE as u64;
        if start >= size {
            dst.fill(0);
            return Ok(());
        }
        let valid = (size - start).min(PAGE_SIZE as u64) as usize;
        // Pending device run: (device byte offset, page offset, length).
        let mut run: Option<(u64, usize, usize)> = None;
        let mut cursor = 0usize;
        while cursor < valid {
            let abs = start + cursor as u64;
            let logical = abs / bs;
            let in_block = abs % bs;
            let chunk = ((bs - in_block) as usize).min(valid - cursor);
            let phys = self.map_block(inode, logical).await?;
            if phys == 0 {
                if let Some((dev, at, len)) = run.take() {
                    self.read_byte_range(dev, &mut dst[at..at + len]).await?;
                }
                dst[cursor..cursor + chunk].fill(0);
            } else {
                let dev = phys * bs + in_block;
                run = match run {
                    Some((run_dev, at, len)) if run_dev + len as u64 == dev => {
                        Some((run_dev, at, len + chunk))
                    }
                    Some((run_dev, at, len)) => {
                        self.read_byte_range(run_dev, &mut dst[at..at + len])
                            .await?;
                        Some((dev, cursor, chunk))
                    }
                    None => Some((dev, cursor, chunk)),
                };
            }
            cursor += chunk;
        }
        if let Some((dev, at, len)) = run {
            self.read_byte_range(dev, &mut dst[at..at + len]).await?;
        }
        dst[valid..].fill(0);
        Ok(())
    }

    /// `->writepage` for the byte range `[lo, hi)` of file page `page`:
    /// write every filesystem block that range touches, block-granular, from
    /// the cached `folio` (which holds the block's other bytes too, so no
    /// read-modify-write is needed). With `allocate`, holes are allocated
    /// (`inode` gains the blocks; the caller persists it); without, a hole
    /// is skipped — there is nothing on disk to update.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn write_file_page(
        &self,
        inode_no: u32,
        inode: &mut Inode,
        page: u64,
        folio: &FileFolio,
        lo: usize,
        hi: usize,
        allocate: bool,
    ) -> Result<(), FsError> {
        debug_assert!(lo <= hi && hi <= PAGE_SIZE);
        let bs = self.block_size() as u64;
        let page_start = page * PAGE_SIZE as u64;
        let page_end = page_start + PAGE_SIZE as u64;
        let mut pos = page_start + lo as u64;
        let end = page_start + hi as u64;
        while pos < end {
            let logical = pos / bs;
            let block_start = logical * bs;
            let seg_lo = block_start.max(page_start);
            let seg_hi = (block_start + bs).min(page_end);
            let phys = if allocate {
                self.map_block_alloc(inode_no, inode, logical).await?
            } else {
                self.map_block(inode, logical).await?
            };
            if phys != 0 {
                let mut bytes = vec![0u8; (seg_hi - seg_lo) as usize];
                folio.read((seg_lo - page_start) as usize, &mut bytes);
                self.write_byte_range(phys * bs + (seg_lo - block_start), &bytes)
                    .await?;
            }
            pos = seg_hi;
        }
        Ok(())
    }
}
