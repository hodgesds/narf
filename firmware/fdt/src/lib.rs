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

pub const FDT_MAGIC: u32 = 0xD00D_FEED;
pub const FDT_BEGIN_NODE: u32 = 0x0000_0001;
pub const FDT_END_NODE: u32 = 0x0000_0002;
pub const FDT_PROP: u32 = 0x0000_0003;
pub const FDT_NOP: u32 = 0x0000_0004;
pub const FDT_END: u32 = 0x0000_0009;

const HEADER_LEN: usize = 40;

#[derive(Copy, Clone, Debug)]
pub struct Header {
    pub magic: u32,
    pub totalsize: u32,
    pub off_dt_struct: u32,
    pub off_dt_strings: u32,
    pub off_mem_rsvmap: u32,
    pub version: u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys: u32,
    pub size_dt_strings: u32,
    pub size_dt_struct: u32,
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Reservation {
    pub addr: u64,
    pub size: u64,
}

/// One statically addressed `/reserved-memory` range.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ReservedRegion {
    pub addr: u64,
    pub size: u64,
    /// The OS must not create a standard virtual mapping for this range.
    pub no_map: bool,
    /// The range may be reclaimed when its owning driver is not using it.
    pub reusable: bool,
}

mod tests;

fn be_u32(b: &[u8], off: usize) -> Option<u32> {
    if off + 4 > b.len() {
        return None;
    }
    Some(u32::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
    ]))
}

fn be_u64(b: &[u8], off: usize) -> Option<u64> {
    if off + 8 > b.len() {
        return None;
    }
    Some(u64::from_be_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ]))
}

pub fn parse_header(blob: &[u8]) -> Option<Header> {
    if blob.len() < HEADER_LEN {
        return None;
    }
    let magic = be_u32(blob, 0)?;
    if magic != FDT_MAGIC {
        return None;
    }
    let totalsize = be_u32(blob, 4)?;
    let off_dt_struct = be_u32(blob, 8)?;
    let off_dt_strings = be_u32(blob, 12)?;
    let off_mem_rsvmap = be_u32(blob, 16)?;
    let version = be_u32(blob, 20)?;
    let last_comp_version = be_u32(blob, 24)?;
    let boot_cpuid_phys = be_u32(blob, 28)?;
    let size_dt_strings = be_u32(blob, 32)?;
    let size_dt_struct = be_u32(blob, 36)?;

    if version < 17 || last_comp_version > 17 || totalsize < HEADER_LEN as u32 {
        return None;
    }
    // `discover()` first parses a header-only slice. Once the whole
    // blob is available, validate every v17 block before any walker
    // trusts offsets from firmware.
    if blob.len() > HEADER_LEN {
        let total = totalsize as usize;
        let struct_start = off_dt_struct as usize;
        let strings_start = off_dt_strings as usize;
        let reserve_start = off_mem_rsvmap as usize;
        let struct_end = struct_start.checked_add(size_dt_struct as usize)?;
        let strings_end = strings_start.checked_add(size_dt_strings as usize)?;
        if total > blob.len()
            || struct_start % 4 != 0
            || strings_start % 4 != 0
            || reserve_start % 8 != 0
            || struct_start < HEADER_LEN
            || strings_start < HEADER_LEN
            || reserve_start < HEADER_LEN
            || struct_end > total
            || strings_end > total
        {
            return None;
        }
    }

    Some(Header {
        magic,
        totalsize,
        off_dt_struct,
        off_dt_strings,
        off_mem_rsvmap,
        version,
        last_comp_version,
        boot_cpuid_phys,
        size_dt_strings,
        size_dt_struct,
    })
}

/// Decode the memory-reserve map. Returns the number of
/// non-terminator entries copied.
pub fn copy_reservations(blob: &[u8], out: &mut [Reservation]) -> usize {
    let hdr = match parse_header(blob) {
        Some(h) => h,
        None => return 0,
    };
    let mut cur = hdr.off_mem_rsvmap as usize;
    let mut n = 0;
    loop {
        if cur + 16 > blob.len() {
            break;
        }
        let addr = match be_u64(blob, cur) {
            Some(v) => v,
            None => break,
        };
        let size = match be_u64(blob, cur + 8) {
            Some(v) => v,
            None => break,
        };
        if addr == 0 && size == 0 {
            break;
        }
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
    pub(crate) slab: &'a [u8],
    pub(crate) seg_lens: &'a [u16],
}

impl<'a> Path<'a> {
    pub fn depth(&self) -> u8 {
        self.seg_lens.len() as u8
    }

    pub fn last_segment(&self) -> &'a str {
        let depth = self.seg_lens.len();
        if depth == 0 {
            return "/";
        }
        let mut start = 0usize;
        for &len in &self.seg_lens[..depth - 1] {
            start += len as usize;
        }
        let end = start + self.seg_lens[depth - 1] as usize;
        core::str::from_utf8(&self.slab[start..end]).unwrap_or("")
    }

    /// Return one zero-based path segment.
    pub fn segment(&self, index: usize) -> Option<&'a str> {
        if index >= self.seg_lens.len() {
            return None;
        }
        let start = self.seg_lens[..index]
            .iter()
            .fold(0usize, |sum, len| sum + *len as usize);
        let end = start + self.seg_lens[index] as usize;
        core::str::from_utf8(&self.slab[start..end]).ok()
    }

    /// `path` is a slice of expected segment names —
    /// `["memory@0"]` matches the depth-1 child `/memory@0`,
    /// `["cpus", "cpu@0"]` matches `/cpus/cpu@0`. The root
    /// (depth 0) only matches an empty `path`.
    pub fn matches(&self, path: &[&str]) -> bool {
        if path.len() != self.seg_lens.len() {
            return false;
        }
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
    blob: &'a [u8],
    cur: usize,
    strings: &'a [u8],
}

impl<'a> Iterator for PropIter<'a> {
    type Item = (&'a str, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let token = be_u32(self.blob, self.cur)?;
            match token {
                FDT_NOP => {
                    self.cur += 4;
                    continue;
                }
                FDT_PROP => {
                    let len = be_u32(self.blob, self.cur + 4)? as usize;
                    let nameoff = be_u32(self.blob, self.cur + 8)? as usize;
                    let payload_start = self.cur + 12;
                    let payload_end = payload_start + len;
                    if payload_end > self.blob.len() {
                        return None;
                    }
                    // Pad to 4 bytes.
                    let next = (payload_end + 3) & !3;
                    self.cur = next;
                    let name = read_cstr(self.strings, nameoff)?;
                    return Some((name, &self.blob[payload_start..payload_end]));
                }
                _ => return None, // BEGIN/END handled by walker
            }
        }
    }
}

fn read_cstr(buf: &[u8], off: usize) -> Option<&str> {
    if off >= buf.len() {
        return None;
    }
    let end = buf[off..].iter().position(|&b| b == 0)? + off;
    core::str::from_utf8(&buf[off..end]).ok()
}

/// `#address-cells` / `#size-cells` for decoding a `reg` property.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Cells {
    pub address: u32,
    pub size: u32,
}

impl Cells {
    /// DTSpec 2.3.5: when missing, `#address-cells` defaults to 2
    /// and `#size-cells` defaults to 1.
    pub const DEFAULT: Self = Self {
        address: 2,
        size: 1,
    };

    pub fn read_one_reg(self, value: &[u8], off: usize) -> Option<(u64, u64)> {
        let addr_bytes = self.address as usize * 4;
        let size_bytes = self.size as usize * 4;
        if off + addr_bytes + size_bytes > value.len() {
            return None;
        }
        let mut addr = 0u64;
        for i in 0..addr_bytes {
            addr = (addr << 8) | value[off + i] as u64;
        }
        let mut size = 0u64;
        for i in 0..size_bytes {
            size = (size << 8) | value[off + addr_bytes + i] as u64;
        }
        Some((addr, size))
    }

    pub fn entry_bytes(self) -> usize {
        (self.address as usize + self.size as usize) * 4
    }
}

/// Walk every node in the struct block. `f` is called for each
/// FDT_BEGIN_NODE except the root; the path is the path to *that*
/// node, and the `PropIter` walks only its immediate properties.
/// FDT_END_NODE pops.
pub fn walk_nodes<F>(blob: &[u8], mut f: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>),
{
    walk_with_cells(blob, |path, props, _| f(path, props));
}

/// Like `walk_nodes`, but also passes the **parent's** `Cells`
/// — the `#address-cells` / `#size-cells` that govern how the
/// current node's `reg` property is laid out. Inheritance follows
/// the conventional libfdt rule: a node that doesn't declare its
/// own cells reuses its parent's.
pub fn walk_with_cells<F>(blob: &[u8], mut f: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>, Cells),
{
    let hdr = match parse_header(blob) {
        Some(h) => h,
        None => return,
    };
    let struct_start = hdr.off_dt_struct as usize;
    let struct_end = struct_start + hdr.size_dt_struct as usize;
    let strings_start = hdr.off_dt_strings as usize;
    let strings_end = strings_start + hdr.size_dt_strings as usize;
    if struct_end > blob.len() || strings_end > blob.len() {
        return;
    }
    let strings = &blob[strings_start..strings_end];

    let mut slab = [0u8; MAX_PATH_BYTES];
    let mut seg_lens = [0u16; MAX_PATH_DEPTH];
    let mut total_len = 0u16;
    let mut depth = 0u8;

    // cells_stack[depth] stores the cells defined by the node at current depth
    // for use by its children. Index 0 is reserved for Root's children.
    let mut cells_stack = [Cells::DEFAULT; MAX_PATH_DEPTH + 1];

    let mut cur = struct_start;
    while cur + 4 <= struct_end {
        let token = match be_u32(blob, cur) {
            Some(t) => t,
            None => return,
        };
        match token {
            FDT_BEGIN_NODE => {
                cur += 4;
                let name_start = cur;
                let mut end = name_start;
                while end < blob.len() && blob[end] != 0 {
                    end += 1;
                }
                let name = &blob[name_start..end];
                cur = (end + 1 + 3) & !3;

                let is_root = name.is_empty() && depth == 0;
                if !is_root && (depth as usize) >= MAX_PATH_DEPTH {
                    return;
                }

                // The cells governing THIS node's 'reg' are defined by its parent.
                let parent_cells = cells_stack[depth as usize];

                // The cells governing THIS node's children. Spec says NOT inherited.
                let mut my_cells = Cells::DEFAULT;
                let prop_scan = PropIter { blob, cur, strings };
                for (pname, pval) in prop_scan {
                    if pname == "#address-cells" && pval.len() >= 4 {
                        my_cells.address = u32::from_be_bytes([pval[0], pval[1], pval[2], pval[3]]);
                    } else if pname == "#size-cells" && pval.len() >= 4 {
                        my_cells.size = u32::from_be_bytes([pval[0], pval[1], pval[2], pval[3]]);
                    }
                }

                if is_root {
                    cells_stack[0] = my_cells;
                } else {
                    cells_stack[depth as usize + 1] = my_cells;

                    let n = name.len().min(slab.len() - total_len as usize);
                    slab[total_len as usize..total_len as usize + n].copy_from_slice(&name[..n]);
                    seg_lens[depth as usize] = n as u16;
                    total_len += n as u16;

                    let path = Path {
                        slab: &slab[..total_len as usize],
                        seg_lens: &seg_lens[..depth as usize + 1],
                    };
                    let prop_iter = PropIter { blob, cur, strings };
                    f(&path, prop_iter, parent_cells);
                    depth += 1;
                }

                cur = skip_props(blob, cur, struct_end);
            }
            FDT_END_NODE => {
                cur += 4;
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                total_len -= seg_lens[depth as usize];
                seg_lens[depth as usize] = 0;
            }
            FDT_NOP => {
                cur += 4;
            }
            FDT_END => break,
            _ => return, // bad token
        }
    }
}

fn skip_props(blob: &[u8], mut cur: usize, end: usize) -> usize {
    while cur + 4 <= end {
        let token = match be_u32(blob, cur) {
            Some(t) => t,
            None => return cur,
        };
        match token {
            FDT_PROP => {
                let len = match be_u32(blob, cur + 4) {
                    Some(v) => v as usize,
                    None => return cur,
                };
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

/// Read Linux's `/chosen/linux,initrd-start` and
/// `/chosen/linux,initrd-end` properties. Both 32-bit and 64-bit
/// encodings are accepted, matching Linux's early FDT scanner.
pub fn chosen_initrd_range(blob: &[u8]) -> Option<Reservation> {
    fn read_addr(value: &[u8]) -> Option<u64> {
        match value.len() {
            4 => Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as u64),
            8 => Some(u64::from_be_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ])),
            _ => None,
        }
    }

    let mut start = None;
    let mut end = None;
    walk_nodes(blob, |path, props| {
        if !path.matches(&["chosen"]) {
            return;
        }
        for (name, value) in props {
            match name {
                "linux,initrd-start" => start = read_addr(value),
                "linux,initrd-end" => end = read_addr(value),
                _ => {}
            }
        }
    });
    match (start, end) {
        (Some(addr), Some(limit)) if limit > addr => Some(Reservation {
            addr,
            size: limit - addr,
        }),
        _ => None,
    }
}

pub fn copy_memory_ranges(blob: &[u8], out: &mut [Reservation]) -> usize {
    let mut n_out = 0;
    walk_with_cells(blob, |path, props, parent_cells| {
        if path.depth() != 1 {
            return;
        }
        let last = path.last_segment();
        if !last.starts_with("memory") {
            return;
        }
        for (name, value) in props {
            if name != "reg" {
                continue;
            }
            let stride = parent_cells.entry_bytes();
            if stride == 0 {
                continue;
            }
            let mut off = 0;
            while off + stride <= value.len() && n_out < out.len() {
                if let Some((addr, size)) = parent_cells.read_one_reg(value, off) {
                    out[n_out] = Reservation { addr, size };
                    n_out += 1;
                }
                off += stride;
            }
        }
    });
    n_out
}

/// Copy statically addressed children of `/reserved-memory`.
///
/// Dynamic reservations described with `size` but no `reg` require
/// boot-allocator policy and are intentionally not allocated by this
/// pure parser. `reg` takes precedence when both are present, as
/// required by the Devicetree specification.
pub fn copy_reserved_memory_ranges(blob: &[u8], out: &mut [ReservedRegion]) -> usize {
    let mut n_out = 0;
    walk_with_cells(blob, |path, props, parent_cells| {
        if path.depth() != 2 || path.segment(0) != Some("reserved-memory") {
            return;
        }
        let snapshot = props;
        if node_status(snapshot) != Status::Okay {
            return;
        }
        let mut reg = None;
        let mut no_map = false;
        let mut reusable = false;
        for (name, value) in props {
            match name {
                "reg" => reg = Some(value),
                "no-map" => no_map = true,
                "reusable" => reusable = true,
                _ => {}
            }
        }
        // The properties are mutually exclusive. Reject malformed
        // firmware rather than guessing which memory semantics wins.
        if no_map && reusable {
            return;
        }
        let Some(value) = reg else {
            return;
        };
        let stride = parent_cells.entry_bytes();
        if stride == 0 {
            return;
        }
        let mut off = 0;
        while off + stride <= value.len() && n_out < out.len() {
            if let Some((addr, size)) = parent_cells.read_one_reg(value, off) {
                out[n_out] = ReservedRegion {
                    addr,
                    size,
                    no_map,
                    reusable,
                };
                n_out += 1;
            }
            off += stride;
        }
    });
    n_out
}

// ───────────────────────────────────────────────────────────────────
// `compatible` matching
// ───────────────────────────────────────────────────────────────────

/// `true` iff the `compatible` payload (NUL-separated string list)
/// contains an exact match for `compat`.
pub fn compatible_matches(value: &[u8], compat: &str) -> bool {
    let target = compat.as_bytes();
    let mut start = 0;
    while start < value.len() {
        let end = value[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(value.len());
        if &value[start..end] == target {
            return true;
        }
        start = end + 1;
    }
    false
}

/// Iterate the `compatible` payload as a sequence of NUL-terminated
/// `&str` slices, calling `f` for each entry.
pub fn for_each_compatible_string<F: FnMut(&str)>(value: &[u8], mut f: F) {
    let mut start = 0;
    while start < value.len() {
        let end = value[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(value.len());
        if let Ok(s) = core::str::from_utf8(&value[start..end]) {
            f(s);
        }
        if end == value.len() {
            break;
        }
        start = end + 1;
    }
}

/// Walk every node, calling `f` once per node whose `compatible`
/// list contains an exact match for `compat`.
pub fn for_each_compatible<F>(blob: &[u8], compat: &str, mut f: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>, Cells),
{
    walk_with_cells(blob, |path, props, parent_cells| {
        let snapshot = props;
        let mut found = false;
        for (name, value) in snapshot {
            if name == "compatible" && compatible_matches(value, compat) {
                found = true;
                break;
            }
        }
        if found {
            f(path, props, parent_cells);
        }
    });
}

// ───────────────────────────────────────────────────────────────────
// `phandle` resolution
// ───────────────────────────────────────────────────────────────────

/// Read a `phandle` (or legacy `linux,phandle`) property out of a
/// node's prop iterator.
pub fn prop_phandle(props: PropIter<'_>) -> Option<u32> {
    for (name, value) in props {
        if (name == "phandle" || name == "linux,phandle") && value.len() >= 4 {
            return Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
        }
    }
    None
}

/// Walk every node looking for one whose `phandle` matches `target`.
/// Calls `f` and stops on the first hit.
pub fn for_phandle<F>(blob: &[u8], target: u32, mut f: F)
where
    F: FnMut(&Path<'_>, PropIter<'_>, Cells),
{
    let mut done = false;
    walk_with_cells(blob, |path, props, parent_cells| {
        if done {
            return;
        }
        if let Some(ph) = prop_phandle(props) {
            if ph == target {
                f(path, props, parent_cells);
                done = true;
            }
        }
    });
}

// ───────────────────────────────────────────────────────────────────
// `/aliases` lookup + `/chosen` helpers
// ───────────────────────────────────────────────────────────────────

/// Look up `/aliases/<name>` and copy its NUL-stripped value into
/// `out`. Returns the number of bytes written (0 if not found).
pub fn alias_path(blob: &[u8], name: &str, out: &mut [u8]) -> usize {
    let mut n = 0;
    walk_nodes(blob, |path, props| {
        if !path.matches(&["aliases"]) {
            return;
        }
        for (pname, pval) in props {
            if pname == name {
                let strip = if !pval.is_empty() && *pval.last().unwrap() == 0 {
                    pval.len() - 1
                } else {
                    pval.len()
                };
                let copy = strip.min(out.len());
                out[..copy].copy_from_slice(&pval[..copy]);
                n = copy;
            }
        }
    });
    n
}

/// `chosen.stdout-path` → caller-supplied buffer.
pub fn chosen_stdout_path(blob: &[u8], out: &mut [u8]) -> usize {
    let mut n = 0;
    walk_nodes(blob, |path, props| {
        if !path.matches(&["chosen"]) {
            return;
        }
        for (pname, pval) in props {
            if pname == "stdout-path" || pname == "linux,stdout-path" {
                let strip = if !pval.is_empty() && *pval.last().unwrap() == 0 {
                    pval.len() - 1
                } else {
                    pval.len()
                };
                let copy = strip.min(out.len());
                out[..copy].copy_from_slice(&pval[..copy]);
                n = copy;
            }
        }
    });
    n
}

// ───────────────────────────────────────────────────────────────────
// `status` filter
// ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Okay,
    Disabled,
    Reserved,
    Fail,
    Other,
}

pub fn node_status(props: PropIter<'_>) -> Status {
    for (name, value) in props {
        if name != "status" {
            continue;
        }
        // NUL-terminated string.
        let strip = if !value.is_empty() && *value.last().unwrap() == 0 {
            &value[..value.len() - 1]
        } else {
            value
        };
        return match strip {
            b"okay" | b"ok" => Status::Okay,
            b"disabled" => Status::Disabled,
            b"reserved" => Status::Reserved,
            b"fail" => Status::Fail,
            _ => Status::Other,
        };
    }
    // No `status` property ⇒ okay.
    Status::Okay
}

// ───────────────────────────────────────────────────────────────────
// Typed property accessors
// ───────────────────────────────────────────────────────────────────

pub fn prop_u32(props: PropIter<'_>, name: &str) -> Option<u32> {
    for (n, v) in props {
        if n == name && v.len() >= 4 {
            return Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        }
    }
    None
}

pub fn prop_u64(props: PropIter<'_>, name: &str) -> Option<u64> {
    for (n, v) in props {
        if n == name && v.len() >= 8 {
            return Some(u64::from_be_bytes([
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
            ]));
        }
    }
    None
}

pub fn prop_str<'a>(props: PropIter<'a>, name: &str) -> Option<&'a str> {
    for (n, v) in props {
        if n == name {
            let strip = if !v.is_empty() && *v.last().unwrap() == 0 {
                &v[..v.len() - 1]
            } else {
                v
            };
            return core::str::from_utf8(strip).ok();
        }
    }
    None
}

pub fn prop_string_list<'a, F: FnMut(&'a str)>(props: PropIter<'a>, name: &str, mut f: F) {
    for (n, v) in props {
        if n != name {
            continue;
        }
        let mut start = 0;
        while start < v.len() {
            let end = v[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(v.len());
            if let Ok(s) = core::str::from_utf8(&v[start..end]) {
                f(s);
            }
            if end == v.len() {
                break;
            }
            start = end + 1;
        }
        return;
    }
}

// ───────────────────────────────────────────────────────────────────
// Interrupt parsing helpers
// ───────────────────────────────────────────────────────────────────

/// Read a node's `interrupt-parent` (a `phandle`). If absent,
/// returns `None`; the caller should then walk up through
/// ancestors looking for the closest declaration.
pub fn prop_interrupt_parent(props: PropIter<'_>) -> Option<u32> {
    for (n, v) in props {
        if n == "interrupt-parent" && v.len() >= 4 {
            return Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        }
    }
    None
}

/// Read a node's `#interrupt-cells` declaration.
pub fn prop_interrupt_cells(props: PropIter<'_>) -> Option<u32> {
    for (n, v) in props {
        if n == "#interrupt-cells" && v.len() >= 4 {
            return Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]));
        }
    }
    None
}

/// Resolve interrupt-cells for a node: chase its `interrupt-parent`
/// phandle (or fall back to the global parent in the tree, which we
/// approximate by walking) and return that controller's
/// `#interrupt-cells`. Returns `None` when the chain cannot be
/// resolved without re-walking the tree (callers can do their own
/// phandle chase via `for_phandle`).
pub fn interrupt_cells_for(blob: &[u8], parent_phandle: u32) -> Option<u32> {
    let mut out = None;
    for_phandle(blob, parent_phandle, |_path, props, _| {
        if let Some(c) = prop_interrupt_cells(props) {
            out = Some(c);
        }
    });
    out
}

/// Walk a device's interrupt specifiers.
///
/// `interrupts-extended` takes precedence over `interrupts`, matching
/// Linux and DTSpec. For legacy `interrupts`, callers pass the
/// inherited interrupt-parent phandle resolved while walking the
/// node's ancestors.
pub fn for_each_interrupt<F>(
    blob: &[u8],
    props: PropIter<'_>,
    inherited_parent: Option<u32>,
    mut f: F,
) where
    F: FnMut(u32, &[u32]),
{
    const MAX_INTERRUPT_CELLS: usize = 16;
    let mut extended = None;
    let mut legacy = None;
    let mut explicit_parent = None;
    for (name, value) in props {
        match name {
            "interrupts-extended" => extended = Some(value),
            "interrupts" => legacy = Some(value),
            "interrupt-parent" if value.len() >= 4 => {
                explicit_parent =
                    Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            _ => {}
        }
    }

    if let Some(value) = extended {
        let mut off = 0;
        while off + 4 <= value.len() {
            let parent =
                u32::from_be_bytes([value[off], value[off + 1], value[off + 2], value[off + 3]]);
            off += 4;
            let Some(count) = interrupt_cells_for(blob, parent).map(|n| n as usize) else {
                return;
            };
            if count > MAX_INTERRUPT_CELLS || off + count * 4 > value.len() {
                return;
            }
            let mut cells = [0u32; MAX_INTERRUPT_CELLS];
            for (i, cell) in cells[..count].iter_mut().enumerate() {
                let pos = off + i * 4;
                *cell = u32::from_be_bytes([
                    value[pos],
                    value[pos + 1],
                    value[pos + 2],
                    value[pos + 3],
                ]);
            }
            f(parent, &cells[..count]);
            off += count * 4;
        }
        return;
    }

    let Some(parent) = explicit_parent.or(inherited_parent) else {
        return;
    };
    let Some(count) = interrupt_cells_for(blob, parent).map(|n| n as usize) else {
        return;
    };
    if count == 0 || count > MAX_INTERRUPT_CELLS {
        return;
    }
    let Some(value) = legacy else {
        return;
    };
    let stride = count * 4;
    let mut off = 0;
    while off + stride <= value.len() {
        let mut cells = [0u32; MAX_INTERRUPT_CELLS];
        for (i, cell) in cells[..count].iter_mut().enumerate() {
            let pos = off + i * 4;
            *cell =
                u32::from_be_bytes([value[pos], value[pos + 1], value[pos + 2], value[pos + 3]]);
        }
        f(parent, &cells[..count]);
        off += stride;
    }
}

// ───────────────────────────────────────────────────────────────────
// Live entry-point discovery
// ───────────────────────────────────────────────────────────────────

/// Read an FDT blob from `phys`. Validates the 40-byte header,
/// confirms the magic, and returns a slice covering `totalsize`
/// bytes. `max_len` is the upper bound the caller is willing to
/// accept (typically the size of the identity-mapped low-memory
/// window).
///
/// # Safety
/// `phys` is identity-mapped readable memory of at least
/// `min(totalsize, max_len)` bytes. The returned slice has the
/// `'static` lifetime in the boot path; callers that map / unmap
/// FDT memory must not let the slice outlive its mapping.
pub unsafe fn discover(phys: usize, max_len: usize) -> Option<&'static [u8]> {
    if max_len < HEADER_LEN {
        return None;
    }
    // SAFETY: caller-asserted identity-mapped readable at least HEADER_LEN.
    let head = unsafe { core::slice::from_raw_parts(phys as *const u8, HEADER_LEN) };
    let hdr = parse_header(head)?;
    let total = hdr.totalsize as usize;
    if total < HEADER_LEN || total > max_len {
        return None;
    }
    // SAFETY: caller-asserted identity-mapped readable for the entire totalsize.
    Some(unsafe { core::slice::from_raw_parts(phys as *const u8, total) })
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
        len: usize,
    }

    impl<const N: usize> core::fmt::Debug for Bytes<N> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("Bytes")
                .field("len", &self.len)
                .field("as_str", &self.as_str())
                .finish()
        }
    }

    impl<const N: usize> Default for Bytes<N> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<const N: usize> Bytes<N> {
        pub const fn new() -> Self {
            Self {
                data: [0; N],
                len: 0,
            }
        }
        pub const fn cap(&self) -> usize {
            N
        }
        pub fn len(&self) -> usize {
            self.len
        }
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }
        pub fn extend(&mut self, src: &[u8]) {
            let n = src.len().min(N - self.len);
            self.data[self.len..self.len + n].copy_from_slice(&src[..n]);
            self.len += n;
        }
        pub fn as_bytes(&self) -> &[u8] {
            &self.data[..self.len]
        }
        pub fn as_str(&self) -> &str {
            core::str::from_utf8(self.as_bytes()).unwrap_or("")
        }
    }
}

pub use heapless_str::Bytes;
