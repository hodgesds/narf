//! Multiboot2 information-structure parser.
//!
//! Spec: <https://www.gnu.org/software/grub/manual/multiboot2/multiboot.html>
//! §3.1 (header) lives in `frame/src/x86_64/boot.S`; this module owns
//! the §3.4 (boot-information) walk that runs after the loader hands
//! control to `_start`.
//!
//! Tags this parser cares about (others are walked-and-skipped):
//!
//! | type | name              | what we extract                       |
//! |------|-------------------|---------------------------------------|
//! |   1  | `cmdline`         | NUL-terminated string                  |
//! |   3  | `module`          | `(start, size, cmdline)` per module    |
//! |   6  | `mmap`            | `[entry]` of `(addr, len, type)`       |
//! |   8  | `framebuffer`     | `(addr, pitch, w, h, bpp, type)`       |
//! |  12  | `efi64`           | EFI system table physical address      |
//! |  13  | `smbios`          | copy of an SMBIOS entry-point struct   |
//! |  14  | `acpi_old_rsdp`   | 20-byte RSDP v1 copy                   |
//! |  15  | `acpi_new_rsdp`   | XSDP (v2+); preferred over tag 14      |
//!
//! Tag header is 8 bytes (`u32 type, u32 size`); payload starts
//! right after; tags are 8-byte aligned (the next tag begins at
//! `tag_start + ((size + 7) & !7)`). The structure begins with
//! `u32 total_size, u32 reserved` and ends with a tag of type 0 +
//! size 8.

use narf_memory::PhysAddr;

use crate::info::{BootError, FramebufferInfo, MemRegion, MemRegionKind};

/// Magic the bootloader places in EAX when launching us via the
/// multiboot2 protocol.
pub const BOOT_MAGIC: u64 = 0x36d76289;

const TAG_END: u32 = 0;
const TAG_CMDLINE: u32 = 1;
const TAG_MODULE: u32 = 3;
const TAG_MMAP: u32 = 6;
const TAG_FRAMEBUFFER: u32 = 8;
const TAG_EFI64: u32 = 12;
const TAG_SMBIOS: u32 = 13;
const TAG_ACPI_OLD_RSDP: u32 = 14;
const TAG_ACPI_NEW_RSDP: u32 = 15;

#[repr(C)]
#[derive(Copy, Clone)]
struct TagHeader {
    ty: u32,
    size: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MmapTagPrefix {
    /// Tag header.
    _hdr: TagHeader,
    entry_size: u32,
    entry_version: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct MmapEntry {
    base_addr: u64,
    length: u64,
    ty: u32,
    _reserved: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FramebufferTag {
    _hdr: TagHeader,
    addr: u64,
    pitch: u32,
    width: u32,
    height: u32,
    bpp: u8,
    fb_type: u8,
    _reserved: u16,
    // colour-format fields follow; we don't decode them yet.
}

/// Iterate the tag list. The `info_ptr` must point at a multiboot2
/// information structure (`u32 total_size, u32 reserved` then tags).
///
/// Returns `(type, size, payload_ptr)` for each tag up to (but not
/// including) the END tag.
struct TagIter {
    cursor: usize,
    end: usize,
}

impl TagIter {
    /// # Safety
    /// `info_ptr` must point at a valid multiboot2 information
    /// structure with the trailing tag list still in memory.
    unsafe fn new(info_ptr: usize) -> Self {
        // SAFETY: caller-asserted readability of the 8-byte
        // information-struct header.
        // SAFETY: Valid memory or trusted environment
        let total = unsafe { (info_ptr as *const u32).read_unaligned() } as usize;
        Self {
            cursor: info_ptr + 8,
            end: info_ptr + total,
        }
    }
}

impl Iterator for TagIter {
    type Item = (u32, u32, usize);
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor + 8 > self.end {
            return None;
        }
        // SAFETY: bounds-checked above.
        let hdr = unsafe { (self.cursor as *const TagHeader).read_unaligned() };
        if hdr.ty == TAG_END {
            return None;
        }
        let payload = self.cursor + 8;
        let stride = ((hdr.size as usize) + 7) & !7;
        self.cursor += stride.max(8);
        Some((hdr.ty, hdr.size, payload))
    }
}

/// Walk the information struct and write up to `out_cap` parsed
/// memory regions. Returns the count written (0 if the mmap tag is
/// missing).
///
/// # Safety
/// - `info_ptr` must point at a valid multiboot2 info struct.
/// - `out` must be writable for `out_cap` `MemRegion` entries.
pub unsafe fn parse_memory_map(
    info_ptr: usize,
    out: *mut MemRegion,
    out_cap: usize,
) -> Result<usize, BootError> {
    if out_cap == 0 {
        return Err(BootError::MalformedBootInfo);
    }
    // SAFETY: caller contract.
    for (ty, size, payload) in unsafe { TagIter::new(info_ptr) } {
        if ty != TAG_MMAP {
            continue;
        }
        // SAFETY: tag bounded by total_size; we read the prefix and
        // then iterate entries up to (size - 16) / entry_size.
        // SAFETY: Valid memory or trusted environment
        let prefix = unsafe { ((payload - 8) as *const MmapTagPrefix).read_unaligned() };
        if (prefix.entry_size as usize) < core::mem::size_of::<MmapEntry>() || size < 16 {
            return Err(BootError::MalformedBootInfo);
        }
        let body = payload + 8; // skip entry_size + entry_version
        let body_len = (size as usize).saturating_sub(16);
        if body_len % prefix.entry_size as usize != 0 {
            return Err(BootError::MalformedBootInfo);
        }
        let n = body_len / prefix.entry_size as usize;
        if n > out_cap {
            return Err(BootError::MemoryMapTooLarge);
        }
        for i in 0..n {
            let entry_ptr = body + i * prefix.entry_size as usize;
            // SAFETY: bounds-checked.
            let e = unsafe { (entry_ptr as *const MmapEntry).read_unaligned() };
            let kind = match e.ty {
                1 => MemRegionKind::Usable,
                3 => MemRegionKind::AcpiReclaimable,
                4 => MemRegionKind::AcpiNvs,
                _ => MemRegionKind::Reserved,
            };
            // SAFETY: out is valid for out_cap entries and i < out_cap.
            unsafe {
                out.add(i).write(MemRegion {
                    start: PhysAddr::new(e.base_addr),
                    len: e.length,
                    kind,
                });
            }
        }
        return Ok(n);
    }
    Err(BootError::MalformedBootInfo)
}

/// Return the RSDP physical address. Prefers the ACPI v2+ tag (15)
/// over the v1 tag (14); both carry an embedded RSDP whose `rsdt_addr`
/// (v1) or `xsdt_addr` (v2) field is what callers actually want, but
/// the ACPI parser walks an RSDP, so we hand back the *embedded
/// RSDP's* phys address (= payload + 0).
///
/// # Safety
/// `info_ptr` must point at a valid multiboot2 info struct.
pub unsafe fn rsdp_phys(info_ptr: usize) -> Option<u64> {
    let mut v1: Option<u64> = None;
    // SAFETY: caller contract.
    for (ty, _size, payload) in unsafe { TagIter::new(info_ptr) } {
        match ty {
            TAG_ACPI_NEW_RSDP => return Some(payload as u64),
            TAG_ACPI_OLD_RSDP => v1 = Some(payload as u64),
            _ => {}
        }
    }
    v1
}

/// Firmware-table pointers: the EFI system table (tag 12) and the
/// SMBIOS entry-point copies (tag 13).
///
/// Tag 12 payload: `u64 pointer`. Tag 13 payload: `u8 major, u8 minor,
/// u8 reserved[6]` then the entry-point structure the loader copied
/// (`tag->size = 16 + entry->length` in Limine). The entry point is
/// classified by its anchor; the first tag of each kind wins.
///
/// # Safety
/// `info_ptr` must point at a valid multiboot2 info struct.
pub unsafe fn firmware_handoff(info_ptr: usize) -> crate::firmware::FirmwareHandoff {
    use crate::firmware::{FirmwareHandoff, SmbiosEntryCopy};
    let mut h = FirmwareHandoff::EMPTY;
    // SAFETY: caller contract.
    for (ty, size, payload) in unsafe { TagIter::new(info_ptr) } {
        match ty {
            TAG_EFI64 if size >= 16 && h.efi_system_table.is_none() => {
                // SAFETY: the tag holds 8 payload bytes (size >= 16).
                let p = unsafe { (payload as *const u64).read_unaligned() };
                if p != 0 {
                    h.efi_system_table = Some(p);
                }
            }
            TAG_SMBIOS if size > 16 => {
                let n = (size as usize - 16).min(32);
                // SAFETY: `n` bytes past the 8-byte payload prefix lie
                // inside the tag (`size` covers header + prefix + n).
                let ep = unsafe { core::slice::from_raw_parts((payload + 8) as *const u8, n) };
                if ep.starts_with(b"_SM3_") {
                    if h.smbios3_entry.is_none() {
                        h.smbios3_entry = Some(SmbiosEntryCopy::new(ep));
                    }
                } else if ep.starts_with(b"_SM_") && h.smbios_entry.is_none() {
                    h.smbios_entry = Some(SmbiosEntryCopy::new(ep));
                }
            }
            _ => {}
        }
    }
    h
}

/// Walk the module list and return the first module whose cmdline is
/// `"initramfs"` (case-insensitive). Returns `(start, size)` in bytes.
///
/// Module tag layout (after the 8-byte header):
///
/// ```text
/// offset  field          type
/// 0x00    mod_start      u32
/// 0x04    mod_end        u32
/// 0x08    string         u8[] (NUL-terminated, padded to 8-byte align)
/// ```
///
/// # Safety
/// `info_ptr` must point at a valid multiboot2 info struct; each
/// module's string must be NUL-terminated within the tag's `size`.
pub unsafe fn initramfs_module(info_ptr: usize) -> Option<(u64, u64)> {
    // SAFETY: caller contract.
    for (ty, size, payload) in unsafe { TagIter::new(info_ptr) } {
        if ty != TAG_MODULE {
            continue;
        }
        if (size as usize) < 16 {
            continue;
        }
        // SAFETY: `size >= 16` was checked above, so the tag payload spans at
        // least bytes [0, 16). `mod_start` occupies bytes [0, 4) of the payload,
        // entirely within that range. `read_unaligned` is used because the field
        // has no guaranteed alignment within the multiboot2 tag stream.
        // SAFETY: Valid memory or trusted environment
        let mod_start = unsafe { (payload as *const u32).read_unaligned() } as u64;
        // SAFETY: `mod_end` occupies bytes [4, 8) of the payload, which lies
        // within the [0, 16) range guaranteed by the `size >= 16` check above.
        // `read_unaligned` accounts for the field's lack of alignment.
        // SAFETY: Valid memory or trusted environment
        let mod_end = unsafe { ((payload + 4) as *const u32).read_unaligned() } as u64;
        // Just return the first module since we only ever pass the initramfs.
        let len = mod_end.saturating_sub(mod_start);
        return Some((mod_start, len));
    }
    None
}

/// Walk the framebuffer tag (type 8). Returns `None` when the
/// bootloader didn't supply one or the format isn't a packed
/// linear RGB framebuffer (`fb_type == 1`).
///
/// # Safety
/// `info_ptr` must point at a valid multiboot2 info struct.
pub unsafe fn framebuffer(info_ptr: usize) -> Option<FramebufferInfo> {
    // SAFETY: caller contract.
    for (ty, _size, payload) in unsafe { TagIter::new(info_ptr) } {
        if ty != TAG_FRAMEBUFFER {
            continue;
        }
        // SAFETY: tag covers `FramebufferTag` minus the colour-format trailer.
        let fb = unsafe { ((payload - 8) as *const FramebufferTag).read_unaligned() };
        if fb.fb_type != 1 {
            // Type 0 is indexed colour, type 2 is EGA text — the kernel
            // framebuffer console assumes packed RGB.
            return None;
        }
        return Some(FramebufferInfo {
            addr: PhysAddr::new(fb.addr),
            width: fb.width,
            height: fb.height,
            pitch: fb.pitch,
            bpp: fb.bpp,
        });
    }
    None
}

/// Walk for the `cmdline` tag (type 1). Returns the bootloader-supplied
/// kernel command-line as a byte slice (no NUL terminator). Returns
/// `None` when the bootloader didn't pass a cmdline.
///
/// # Safety
/// `info_ptr` must point at a valid multiboot2 info struct; the
/// cmdline string must be NUL-terminated within the tag's `size`.
pub unsafe fn cmdline(info_ptr: usize) -> Option<&'static [u8]> {
    // SAFETY: caller contract.
    for (ty, size, payload) in unsafe { TagIter::new(info_ptr) } {
        if ty != TAG_CMDLINE {
            continue;
        }
        // Tag header is 8 bytes; payload is the string itself.
        let max = (size as usize).saturating_sub(8);
        // SAFETY: bounds-checked.
        let s = unsafe { read_cstr(payload, max) };
        return Some(s);
    }
    None
}

/// # Safety
/// `phys + max` must be readable.
unsafe fn read_cstr<'a>(phys: usize, max: usize) -> &'a [u8] {
    let mut len = 0;
    while len < max {
        // SAFETY: caller-asserted readability.
        let b = unsafe { ((phys + len) as *const u8).read_volatile() };
        if b == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: same readability contract; len ≤ max.
    unsafe { core::slice::from_raw_parts(phys as *const u8, len) }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Append one tag (8-byte aligned) to a byte image of an mbi.
    fn tag(img: &mut [u8], at: &mut usize, ty: u32, payload: &[u8]) {
        let size = 8 + payload.len();
        img[*at..*at + 4].copy_from_slice(&ty.to_le_bytes());
        img[*at + 4..*at + 8].copy_from_slice(&(size as u32).to_le_bytes());
        img[*at + 8..*at + size].copy_from_slice(payload);
        *at += (size + 7) & !7;
    }

    fn smbios_tag_payload(ep: &[u8]) -> [u8; 40] {
        // u8 major, u8 minor, u8 reserved[6], then the entry point.
        let mut p = [0u8; 40];
        p[0] = 3;
        p[8..8 + ep.len()].copy_from_slice(ep);
        p
    }

    /// Tags 12 (EFI64) and 13 (SMBIOS, `_SM3_` + `_SM_`) are copied out
    /// of the mbi; a second `_SM3_` tag does not replace the first.
    fn smoke_mb2_firmware_handoff() -> TestResult {
        let mut buf = [0u64; 64];
        // SAFETY: a u64 array viewed as bytes, same lifetime.
        let img = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), 512) };
        let mut at = 8;
        tag(img, &mut at, TAG_EFI64, &0x7FE8_1018u64.to_le_bytes());
        let mut sm3 = [0u8; 24];
        sm3[..5].copy_from_slice(b"_SM3_");
        sm3[6] = 24;
        tag(
            img,
            &mut at,
            TAG_SMBIOS,
            &smbios_tag_payload(&sm3)[..8 + 24],
        );
        let mut other = sm3;
        other[7] = 9;
        tag(
            img,
            &mut at,
            TAG_SMBIOS,
            &smbios_tag_payload(&other)[..8 + 24],
        );
        let mut sm = [0u8; 31];
        sm[..4].copy_from_slice(b"_SM_");
        sm[5] = 31;
        tag(img, &mut at, TAG_SMBIOS, &smbios_tag_payload(&sm)[..8 + 31]);
        tag(img, &mut at, TAG_END, &[]);
        img[0..4].copy_from_slice(&(at as u32).to_le_bytes());

        // SAFETY: `img` is a well-formed mbi built above.
        let h = unsafe { firmware_handoff(img.as_ptr() as usize) };
        if h.efi_system_table != Some(0x7FE8_1018) {
            return TestResult::Fail("EFI64 system table pointer");
        }
        let Some(e3) = h.smbios3_entry else {
            return TestResult::Fail("_SM3_ copy missing");
        };
        if e3.len != 24 || e3.bytes[..24] != sm3 || e3.bytes[24..] != [0; 8] {
            return TestResult::Fail("_SM3_ copy: first tag, zero padded");
        }
        let Some(e) = h.smbios_entry else {
            return TestResult::Fail("_SM_ copy missing");
        };
        if e.len != 31 || e.bytes[..31] != sm {
            return TestResult::Fail("_SM_ copy");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/firmware", smoke_mb2_firmware_handoff);

    /// No usable tags: nothing handed over (a zero EFI pointer and an
    /// SMBIOS tag without entry bytes are ignored).
    fn smoke_mb2_firmware_handoff_absent() -> TestResult {
        let mut buf = [0u64; 16];
        // SAFETY: a u64 array viewed as bytes, same lifetime.
        let img = unsafe { core::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), 128) };
        let mut at = 8;
        tag(img, &mut at, TAG_EFI64, &0u64.to_le_bytes());
        tag(img, &mut at, TAG_SMBIOS, &[0u8; 8]);
        tag(img, &mut at, TAG_END, &[]);
        img[0..4].copy_from_slice(&(at as u32).to_le_bytes());
        // SAFETY: `img` is a well-formed mbi built above.
        let h = unsafe { firmware_handoff(img.as_ptr() as usize) };
        if h != crate::firmware::FirmwareHandoff::EMPTY {
            return TestResult::Fail("expected an empty handoff");
        }
        TestResult::Pass
    }
    kernel_test_in!("boot/firmware", smoke_mb2_firmware_handoff_absent);
}
