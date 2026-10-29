//! Qualcomm MDT/MBN split-firmware loader.
//!
//! Linux `drivers/soc/qcom/mdt_loader.c`. An `.mdt` file is an ELF32
//! header + program headers (and, for a non-split image, the segments
//! themselves). Program header 0 covers the ELF header + phdrs; the
//! segment whose `p_flags & QCOM_MDT_TYPE_MASK == QCOM_MDT_TYPE_HASH`
//! carries the signature/hash blob. A split image stores segment `n` in a
//! sibling file `<name>.bNN`. `QCOM_MDT_RELOCATABLE` (bit 27) segments
//! are placed relative to the lowest segment address.
//!
//! The loader reads the header from a borrowed slice, pulls split
//! segments through [`SegmentSource`] straight into the destination
//! (Linux `request_firmware_into_buf`), and never copies the whole image.

use alloc::string::String;
use alloc::vec::Vec;

use crate::io::Delay;
use crate::scm::{Scm, ScmAlloc, ScmBuffer, ScmError, SmcConduit};

pub const PT_LOAD: u32 = 1;
pub const QCOM_MDT_TYPE_MASK: u32 = 7 << 24;
pub const QCOM_MDT_TYPE_HASH: u32 = 2 << 24;
pub const QCOM_MDT_RELOCATABLE: u32 = 1 << 27;

const EHDR_SIZE: usize = 52;
const PHDR_SIZE: usize = 32;
const SZ_4K: u64 = 0x1000;

/// Loader failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MdtError {
    /// Not an ELF32 little-endian image, or a header out of bounds.
    BadHeader,
    /// Fewer than two phdrs, phdr 0 is `PT_LOAD`, or no hash segment.
    NoHashSegment,
    /// No loadable segment (`qcom_mdt_get_size` -EINVAL).
    NoSegments,
    /// A segment lies outside the carve-out.
    SegmentOutOfRange(usize),
    /// `p_filesz > p_memsz`.
    FileszExceedsMemsz(usize),
    /// A non-split segment is truncated in the `.mdt`.
    Truncated(usize),
    /// A split `.bNN` file is missing or of the wrong size.
    SplitSegment(usize),
    /// The firmware name is shorter than 4 bytes (no `.mdt` suffix).
    BadName,
    /// The PAS call failed.
    Scm(ScmError),
}

impl From<ScmError> for MdtError {
    fn from(e: ScmError) -> Self {
        MdtError::Scm(e)
    }
}

/// `struct elf32_phdr`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Phdr {
    pub p_type: u32,
    pub p_offset: u32,
    pub p_vaddr: u32,
    pub p_paddr: u32,
    pub p_filesz: u32,
    pub p_memsz: u32,
    pub p_flags: u32,
    pub p_align: u32,
}

impl Phdr {
    /// `mdt_phdr_valid`.
    pub fn loadable(&self) -> bool {
        self.p_type == PT_LOAD
            && (self.p_flags & QCOM_MDT_TYPE_MASK) != QCOM_MDT_TYPE_HASH
            && self.p_memsz != 0
    }
    pub fn relocatable(&self) -> bool {
        self.p_flags & QCOM_MDT_RELOCATABLE != 0
    }
}

/// Source of split segments: `request_firmware_into_buf(name, dst)`.
/// Returns the file size written into `dst`, or `None` if absent or
/// larger than `dst`.
pub trait SegmentSource {
    fn read_into(&self, name: &str, dst: &mut [u8]) -> Option<usize>;
}

/// `sprintf(name + len - 3, "b%02d", segment)`.
pub fn segment_name(fw_name: &str, segment: usize) -> Result<String, MdtError> {
    if fw_name.len() < 4 || !fw_name.is_char_boundary(fw_name.len() - 3) {
        return Err(MdtError::BadName);
    }
    let mut s = String::from(&fw_name[..fw_name.len() - 3]);
    s.push('b');
    s.push(char::from(b'0' + ((segment / 10) % 10) as u8));
    s.push(char::from(b'0' + (segment % 10) as u8));
    Ok(s)
}

/// A parsed MDT header over the `.mdt` (or a whole `.mbn`) file.
#[derive(Clone, Copy, Debug)]
pub struct Mdt<'a> {
    data: &'a [u8],
    entry: u32,
    phoff: usize,
    phnum: usize,
}

fn le32(b: &[u8], o: usize) -> Option<u32> {
    let s = b.get(o..o + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le16(b: &[u8], o: usize) -> Option<u16> {
    let s = b.get(o..o + 2)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

impl<'a> Mdt<'a> {
    /// Validate the ELF32 header and the phdr table bounds.
    pub fn parse(data: &'a [u8]) -> Result<Self, MdtError> {
        if data.len() < EHDR_SIZE || &data[..4] != b"\x7fELF" || data[4] != 1 || data[5] != 1 {
            return Err(MdtError::BadHeader);
        }
        let entry = le32(data, 24).ok_or(MdtError::BadHeader)?;
        let phoff = le32(data, 28).ok_or(MdtError::BadHeader)? as usize;
        let phentsize = le16(data, 42).ok_or(MdtError::BadHeader)? as usize;
        let phnum = le16(data, 44).ok_or(MdtError::BadHeader)? as usize;
        if phentsize != PHDR_SIZE
            || phoff
                .checked_add(phnum * PHDR_SIZE)
                .is_none_or(|end| end > data.len())
        {
            return Err(MdtError::BadHeader);
        }
        Ok(Self {
            data,
            entry,
            phoff,
            phnum,
        })
    }

    /// `e_entry` (`rproc_elf_get_boot_addr`).
    pub fn entry(&self) -> u32 {
        self.entry
    }

    pub fn phnum(&self) -> usize {
        self.phnum
    }

    pub fn phdr(&self, i: usize) -> Option<Phdr> {
        if i >= self.phnum {
            return None;
        }
        let o = self.phoff + i * PHDR_SIZE;
        let d = self.data;
        Some(Phdr {
            p_type: le32(d, o)?,
            p_offset: le32(d, o + 4)?,
            p_vaddr: le32(d, o + 8)?,
            p_paddr: le32(d, o + 12)?,
            p_filesz: le32(d, o + 16)?,
            p_memsz: le32(d, o + 20)?,
            p_flags: le32(d, o + 24)?,
            p_align: le32(d, o + 28)?,
        })
    }

    fn phdrs(&self) -> impl Iterator<Item = (usize, Phdr)> + '_ {
        (0..self.phnum).filter_map(move |i| self.phdr(i).map(|p| (i, p)))
    }

    /// (min p_paddr, 4K-aligned max end, any relocatable) over loadable
    /// segments.
    fn span(&self) -> Option<(u64, u64, bool)> {
        let mut min = u64::MAX;
        let mut max = 0u64;
        let mut reloc = false;
        for (_, p) in self.phdrs().filter(|(_, p)| p.loadable()) {
            reloc |= p.relocatable();
            min = min.min(p.p_paddr as u64);
            let end = p.p_paddr as u64 + p.p_memsz as u64;
            if end > max {
                max = (end + SZ_4K - 1) & !(SZ_4K - 1);
            }
        }
        (min < max).then_some((min, max, reloc))
    }

    /// `qcom_mdt_get_size`.
    pub fn size(&self) -> Result<u64, MdtError> {
        self.span()
            .map(|(min, max, _)| max - min)
            .ok_or(MdtError::NoSegments)
    }

    /// `qcom_mdt_bins_are_split`.
    pub fn is_split(&self) -> bool {
        let n = self.data.len() as u64;
        self.phdrs().any(|(_, p)| {
            p.p_filesz != 0 && (p.p_offset as u64 > n || p.p_offset as u64 + p.p_filesz as u64 > n)
        })
    }

    /// `qcom_mdt_read_metadata`: the ELF header (phdr 0) immediately
    /// followed by the hash segment, written into `out` (resized).
    pub fn read_metadata(
        &self,
        fw_name: &str,
        src: &(dyn SegmentSource + Sync),
        out: &mut Vec<u8>,
    ) -> Result<(), MdtError> {
        if self.phnum < 2 {
            return Err(MdtError::NoHashSegment);
        }
        let p0 = self.phdr(0).ok_or(MdtError::BadHeader)?;
        if p0.p_type == PT_LOAD {
            return Err(MdtError::NoHashSegment);
        }
        let (hi, hash) = self
            .phdrs()
            .skip(1)
            .find(|(_, p)| p.p_flags & QCOM_MDT_TYPE_MASK == QCOM_MDT_TYPE_HASH)
            .ok_or(MdtError::NoHashSegment)?;
        let ehdr_size = p0.p_filesz as usize;
        let hash_size = hash.p_filesz as usize;
        if ehdr_size > self.data.len() {
            return Err(MdtError::Truncated(0));
        }
        out.clear();
        out.resize(ehdr_size + hash_size, 0);
        out[..ehdr_size].copy_from_slice(&self.data[..ehdr_size]);
        let n = self.data.len();
        if ehdr_size + hash_size == n {
            // Split image: the hash is packed right after the header.
            out[ehdr_size..].copy_from_slice(&self.data[ehdr_size..]);
        } else if hash.p_offset as usize + hash_size <= n {
            let o = hash.p_offset as usize;
            out[ehdr_size..].copy_from_slice(&self.data[o..o + hash_size]);
        } else {
            let name = segment_name(fw_name, hi)?;
            match src.read_into(&name, &mut out[ehdr_size..]) {
                Some(got) if got == hash_size => {}
                _ => return Err(MdtError::SplitSegment(hi)),
            }
        }
        Ok(())
    }

    /// `__qcom_mdt_load` (the `_no_init` body): copy/zero every loadable
    /// segment into `mem` (the carve-out mapped at `mem_phys`). Returns
    /// the relocation base (`mem_reloc`).
    pub fn load(
        &self,
        fw_name: &str,
        src: &(dyn SegmentSource + Sync),
        mem: &mut [u8],
        mem_phys: u64,
    ) -> Result<u64, MdtError> {
        if mem.is_empty() || mem_phys == 0 {
            return Err(MdtError::NoSegments);
        }
        let split = self.is_split();
        let (min, _, reloc) = self.span().ok_or(MdtError::NoSegments)?;
        let mem_reloc = if reloc { min } else { mem_phys };
        for (i, p) in self.phdrs().filter(|(_, p)| p.loadable()) {
            let offset = p.p_paddr as i64 - mem_reloc as i64;
            if offset < 0 || offset as u64 + p.p_memsz as u64 > mem.len() as u64 {
                return Err(MdtError::SegmentOutOfRange(i));
            }
            if p.p_filesz > p.p_memsz {
                return Err(MdtError::FileszExceedsMemsz(i));
            }
            let off = offset as usize;
            let filesz = p.p_filesz as usize;
            let dst = &mut mem[off..off + p.p_memsz as usize];
            if filesz != 0 && !split {
                let so = p.p_offset as usize;
                let seg = self
                    .data
                    .get(so..so + filesz)
                    .ok_or(MdtError::Truncated(i))?;
                dst[..filesz].copy_from_slice(seg);
            } else if filesz != 0 {
                let name = segment_name(fw_name, i)?;
                match src.read_into(&name, &mut dst[..filesz]) {
                    Some(got) if got == filesz => {}
                    _ => return Err(MdtError::SplitSegment(i)),
                }
            }
            dst[filesz..].fill(0);
        }
        Ok(mem_reloc)
    }

    /// `qcom_mdt_pas_init`: hand the metadata to TrustZone
    /// (`pas_init_image`) and, for a relocatable image, declare the
    /// carve-out (`pas_mem_setup`). The metadata buffer is returned so the
    /// caller releases it only after `auth_and_reset`
    /// (`qcom_scm_pas_metadata_release`).
    #[allow(clippy::too_many_arguments)]
    pub async fn pas_init<C: SmcConduit, A: ScmAlloc, D: Delay + ?Sized>(
        &self,
        fw_name: &str,
        src: &(dyn SegmentSource + Sync),
        scm: &mut Scm<C>,
        alloc: &mut A,
        pas_id: u32,
        mem_phys: u64,
        delay: &D,
    ) -> Result<A::Buf, MdtError> {
        let (min, max, reloc) = self.span().ok_or(MdtError::NoSegments)?;
        let mut meta = Vec::new();
        self.read_metadata(fw_name, src, &mut meta)?;
        let mut buf = alloc
            .alloc(meta.len())
            .ok_or(MdtError::Scm(ScmError::Alloc))?;
        buf.as_mut_slice()[..meta.len()].copy_from_slice(&meta);
        scm.pas_init_image(pas_id, buf.phys(), delay).await?;
        if reloc {
            scm.pas_mem_setup(pas_id, mem_phys, max - min, delay)
                .await?;
        }
        Ok(buf)
    }
}
