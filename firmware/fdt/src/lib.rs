//! Flattened Device Tree (FDT / DTB v17) parser.
//!
//! Spec: `firmware/fdt/specification/spec.md`.
//!
//! The parser is pure-data — it operates over a `&[u8]` slice
//! covering the blob. Callers (boot path on aarch64, fw_cfg
//! on x86_64-virt-with-FDT, etc.) hand the slice in.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![deny(missing_debug_implementations)]
#![allow(dead_code)]

pub const FDT_MAGIC:        u32 = 0xD00D_FEED;
pub const FDT_BEGIN_NODE:   u32 = 0x0000_0001;
pub const FDT_END_NODE:     u32 = 0x0000_0002;
pub const FDT_PROP:         u32 = 0x0000_0003;
pub const FDT_NOP:          u32 = 0x0000_0004;
pub const FDT_END:          u32 = 0x0000_0009;

const HEADER_LEN: usize = 40;

#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub magic:             u32,
    pub totalsize:         u32,
    pub off_dt_struct:     u32,
    pub off_dt_strings:    u32,
    pub off_mem_rsvmap:    u32,
    pub version:           u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys:   u32,
    pub size_dt_strings:   u32,
    pub size_dt_struct:    u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Reservation {
    pub addr: u64,
    pub size: u64,
}

mod tests;

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() { return None; }
    Some(u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
    if off + 8 > b.len() { return None; }
    Some(u64::from_be_bytes([
        b[off],     b[off + 1], b[off + 2], b[off + 3],
        b[off + 4], b[off + 5], b[off + 6], b[off + 7],
    ]))
}

pub fn parse_header(blob: &[u8]) -> Option<Header> {
    if blob.len() < HEADER_LEN { return None; }
    let magic = be_u32(blob, 0)?;
    if magic != FDT_MAGIC { return None; }
    let totalsize         = be_u32(blob, 4)?;
    let off_dt_struct     = be_u32(blob, 8)?;
    let off_dt_strings    = be_u32(blob, 12)?;
    let off_mem_rsvmap    = be_u32(blob, 16)?;
    let version           = be_u32(blob, 20)?;
    let last_comp_version = be_u32(blob, 24)?;
    let boot_cpuid_phys   = be_u32(blob, 28)?;
    let size_dt_strings   = be_u32(blob, 32)?;
    let size_dt_struct    = be_u32(blob, 36)?;
    if (totalsize as usize) > blob.len() { return None; }
    Some(Header {
        magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap,
        version, last_comp_version, boot_cpuid_phys,
        size_dt_strings, size_dt_struct,
    })
}

/// Decode the memory-reserve map. Returns the number of
/// non-terminator entries copied.
pub fn copy_reservations(blob: &[u8], out: &mut [Reservation]) -> usize {
    let hdr = match parse_header(blob) { Some(h) => h, None => return 0 };
    let mut cur = hdr.off_mem_rsvmap as usize;
    let mut n = 0;
    loop {
        if cur + 16 > blob.len() { break; }
        let addr = match be_u64(blob, cur)     { Some(v) => v, None => break };
        let size = match be_u64(blob, cur + 8) { Some(v) => v, None => break };
        if addr == 0 && size == 0 { break; }
        if n < out.len() {
            out[n] = Reservation { addr, size };
            n += 1;
        }
        cur += 16;
    }
    n
}

// ───────────────────────────────────────────────────────────────────
// Struct-block walker
// ───────────────────────────────────────────────────────────────────

/// Path tracker — small fixed-depth stack so we never allocate.
/// Segments are stored back-to-back in `slab`; `seg_lens[i]` is
/// segment `i`'s byte length. The root is `depth = 0`.
pub const MAX_PATH_DEPTH: usize = 16;
pub const MAX_PATH_BYTES: usize = 256;

#[derive(Copy, Clone, Debug)]
pub struct Path<'a> {
    pub(crate) slab:     &'a [u8],
    pub(crate) seg_lens: &'a [u16],
}

impl<'a> Path<'a> {
    pub fn depth(&self) -> u8 { self.seg_lens.len() as u8 }

    pub fn last_segment(&self) -> &'a str {
        let depth = self.seg_lens.len();
        if depth == 0 { return "/"; }
        let mut start = 0usize;
        for &len in &self.seg_lens[..depth - 1] {
            start += len as usize;
        }
        let end = start + self.seg_lens[depth - 1] as usize;
        core::str::from_utf8(&self.slab[start..end]).unwrap_or("")
    }

    /// `path` is a slice of expected segment names —
    /// `["memory@0"]` matches the depth-1 child `/memory@0`,
    /// `["cpus", "cpu@0"]` matches `/cpus/cpu@0`. The root
    /// (depth 0) only matches an empty `path`.
    pub fn matches(&self, path: &[&str]) -> bool {
        if path.len() != self.seg_lens.len() { return false; }
        let mut off = 0usize;
        for (i, want) in path.iter().enumerate() {
            let len = self.seg_lens[i] as usize;
            if &self.slab[off..off + len] != want.as_bytes() {
                return false;
            }
            off += len;
        }
        true
    }
}

#[derive(Copy, Clone, Debug)]
pub struct PropIter<'a> {
    blob:    &'a [u8],
    cur:     usize,
    strings: &'a [u8],
}

impl<'a> Iterator for PropIter<'a> {
    type Item = (&'a str, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let token = be_u32(self.blob, self.cur)?;
            match token {
                FDT_NOP => { self.cur += 4; continue; }
                FDT_PROP => {
                    let len = be_u32(self.blob, self.cur + 4)? as usize;
                    let nameoff = be_u32(self.blob, self.cur + 8)? as usize;
                    let payload_start = self.cur + 12;
                    let payload_end = payload_start + len;
                    if payload_end > self.blob.len() { return None; }
                    // Pad to 4 bytes.
                    let next = (payload_end + 3) & !3;
                    self.cur = next;
                    let name = read_cstr(self.strings, nameoff)?;
                    return Some((name, &self.blob[payload_start..payload_end]));
                }
                _ => return None,    // BEGIN/END handled by walker
            }
        }
    }
}

fn read_cstr(buf: &[u8], off: usize) -> Option<&str> {
    if off >= buf.len() { return None; }
    let end = buf[off..].iter().position(|&b| b == 0)? + off;
    core::str::from_utf8(&buf[off..end]).ok()
}

/// Walk every node in the struct block. `f` is called for each
/// FDT_BEGIN_NODE; the path is the path to *that* node, and the
/// `PropIter` walks only its immediate properties (children
/// continue once the iterator is exhausted; FDT_END_NODE pops).
pub fn walk_nodes<F>(blob: &[u8], mut f: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>),
{
    let hdr = match parse_header(blob) { Some(h) => h, None => return };
    let struct_start = hdr.off_dt_struct as usize;
    let struct_end = struct_start + hdr.size_dt_struct as usize;
    let strings_start = hdr.off_dt_strings as usize;
    let strings_end = strings_start + hdr.size_dt_strings as usize;
    if struct_end > blob.len() || strings_end > blob.len() { return; }
    let strings = &blob[strings_start..strings_end];

    let mut slab = [0u8; MAX_PATH_BYTES];
    let mut seg_lens = [0u16; MAX_PATH_DEPTH];
    let mut total_len = 0u16;
    let mut depth = 0u8;

    let mut cur = struct_start;
    while cur + 4 <= struct_end {
        let token = match be_u32(blob, cur) { Some(t) => t, None => return };
        match token {
            FDT_BEGIN_NODE => {
                cur += 4;
                let name_start = cur;
                let mut end = name_start;
                while end < blob.len() && blob[end] != 0 { end += 1; }
                let name = &blob[name_start..end];
                cur = (end + 1 + 3) & !3;

                let is_root = name.is_empty() && depth == 0;
                if !is_root {
                    if (depth as usize) >= MAX_PATH_DEPTH { return; }
                    let n = name.len().min(slab.len() - total_len as usize);
                    slab[total_len as usize..total_len as usize + n]
                        .copy_from_slice(&name[..n]);
                    seg_lens[depth as usize] = n as u16;
                    total_len += n as u16;
                    depth += 1;
                }

                let path = Path {
                    slab:     &slab[..total_len as usize],
                    seg_lens: &seg_lens[..depth as usize],
                };
                let prop_iter = PropIter { blob, cur, strings };
                f(&path, prop_iter);
                // Skip past this node's properties to the next BEGIN/END.
                cur = skip_props(blob, cur, struct_end);
            }
            FDT_END_NODE => {
                cur += 4;
                if depth == 0 { continue; }
                depth -= 1;
                total_len -= seg_lens[depth as usize];
                seg_lens[depth as usize] = 0;
            }
            FDT_NOP => { cur += 4; }
            FDT_END => break,
            _ => return,    // bad token
        }
    }
}

fn skip_props(blob: &[u8], mut cur: usize, end: usize) -> usize {
    while cur + 4 <= end {
        let token = match be_u32(blob, cur) { Some(t) => t, None => return cur };
        match token {
            FDT_PROP => {
                let len = match be_u32(blob, cur + 4) { Some(v) => v as usize, None => return cur };
                let payload_end = cur + 12 + len;
                cur = (payload_end + 3) & !3;
            }
            FDT_NOP => cur += 4,
            _ => return cur,
        }
    }
    cur
}

// ───────────────────────────────────────────────────────────────────
// Convenience helpers
// ───────────────────────────────────────────────────────────────────

pub fn chosen_bootargs(blob: &[u8]) -> Option<heapless_str::Bytes<256>> {
    let mut found: Option<heapless_str::Bytes<256>> = None;
    walk_nodes(blob, |path, props| {
        if path.matches(&["chosen"]) {
            for (name, value) in props {
                if name == "bootargs" {
                    let mut out = heapless_str::Bytes::<256>::new();
                    let n = value.len().min(out.cap()).saturating_sub(0);
                    // strip trailing NUL if present
                    let n = if n > 0 && value[n - 1] == 0 { n - 1 } else { n };
                    out.extend(&value[..n]);
                    found = Some(out);
                }
            }
        }
    });
    found
}

pub fn copy_memory_ranges(blob: &[u8], out: &mut [Reservation]) -> usize {
    let mut n_out = 0;
    walk_nodes(blob, |path, props| {
        if path.depth() != 1 { return; }
        let last = path.last_segment();
        if !last.starts_with("memory") { return; }
        for (name, value) in props {
            if name == "reg" && value.len() >= 16 {
                // Default: address-cells = 2, size-cells = 2 for /memory.
                let mut off = 0;
                while off + 16 <= value.len() && n_out < out.len() {
                    let addr = u64::from_be_bytes([
                        value[off],     value[off + 1],
                        value[off + 2], value[off + 3],
                        value[off + 4], value[off + 5],
                        value[off + 6], value[off + 7],
                    ]);
                    let size = u64::from_be_bytes([
                        value[off + 8],  value[off + 9],
                        value[off + 10], value[off + 11],
                        value[off + 12], value[off + 13],
                        value[off + 14], value[off + 15],
                    ]);
                    out[n_out] = Reservation { addr, size };
                    n_out += 1;
                    off += 16;
                }
            }
        }
    });
    n_out
}

/// Force-link hook (matches the convention used by `firmware/fw_cfg`
/// and `firmware/smbios`).
pub fn register_initcalls() {}

mod heapless_str {
    /// Tiny owned-byte buffer for returning short null-terminated FDT
    /// payloads from a `&[u8]` parser without allocating.
    #[derive(Copy, Clone)]
    pub struct Bytes<const N: usize> {
        data: [u8; N],
        len:  usize,
    }

    impl<const N: usize> core::fmt::Debug for Bytes<N> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Bytes")
                .field("len", &self.len)
                .field("as_str", &self.as_str())
                .finish()
        }
    }

    impl<const N: usize> Bytes<N> {
        pub const fn new() -> Self { Self { data: [0; N], len: 0 } }
        pub const fn cap(&self) -> usize { N }
        pub fn len(&self) -> usize { self.len }
        pub fn extend(&mut self, src: &[u8]) {
            let n = src.len().min(N - self.len);
            self.data[self.len..self.len + n].copy_from_slice(&src[..n]);
            self.len += n;
        }
        pub fn as_bytes(&self) -> &[u8] { &self.data[..self.len] }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(self.as_bytes()).unwrap_or("")
        }
    }
}

pub use heapless_str::Bytes;
