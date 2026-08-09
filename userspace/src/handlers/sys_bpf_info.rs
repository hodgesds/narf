//! `bpf(2)` introspection — `BPF_OBJ_GET_INFO_BY_FD` and the id family.
//!
//! Split out of `sys_bpf.rs` rather than bolted onto it: this is the half of
//! the syscall that answers questions about objects, and it shares nothing with
//! the half that creates them except the attribute buffer shape.
//!
//! Implemented here:
//!
//! * `BPF_OBJ_GET_INFO_BY_FD` (15) — `struct bpf_prog_info` / `struct
//!   bpf_map_info` / `struct bpf_link_info` / `struct bpf_btf_info`, for the
//!   fields NARF genuinely knows.
//! * `BPF_PROG_GET_NEXT_ID` (11) / `BPF_MAP_GET_NEXT_ID` (12) /
//!   `BPF_BTF_GET_NEXT_ID` (23) / `BPF_LINK_GET_NEXT_ID` (33) — walk the id
//!   tables in [`narf_bpf::idreg`] (BTF's lives in `sys_bpf_btf.rs`; see that
//!   file's header for why).
//! * `BPF_PROG_GET_FD_BY_ID` (13) / `BPF_MAP_GET_FD_BY_ID` (14) /
//!   `BPF_BTF_GET_FD_BY_ID` (19) / `BPF_LINK_GET_FD_BY_ID` (32) — reopen an
//!   object by id, with a *fresh* reference.
//!
//! ## The `info_len` contract
//!
//! `union bpf_attr`'s `info` member carries the size of the info struct the
//! caller was compiled against. Both directions have to work, and Linux's rule
//! (`kernel/bpf/syscall.c`) is the whole of it:
//!
//! * caller's struct **smaller** than the kernel's — write the leading
//!   `info_len` bytes and report `info_len` back, so an old binary sees exactly
//!   the prefix it understands;
//! * caller's struct **larger** — every byte past what this kernel knows must
//!   already be zero (`bpf_check_uarg_tail_zero`, `E2BIG` otherwise), then
//!   write `sizeof` bytes and report `sizeof` back, so a new binary can tell
//!   which suffix the kernel did not fill.
//!
//! Getting that backwards — writing `sizeof` into a caller's smaller buffer, or
//! reporting the caller's length back unchanged — is a buffer overrun in one
//! direction and an undetectable "field is zero because the kernel is old"
//! ambiguity in the other. It is the single most load-bearing rule in this file
//! and `smoke_abi_bpf_info_len_*` pins both directions.
//!
//! ## What is deliberately zero
//!
//! Every field NARF has no answer for is written as zero, never guessed. The
//! `// LINUX-GAP` notes at each group say which and why. A zero `btf_id` means
//! "no BTF", a zero `load_time` means "not recorded"; neither is a plausible
//! fabricated value, which is the point.

#[allow(unused_imports)]
use super::*;

use narf_bpf::link::{LinkFile, LinkTarget};
use narf_bpf::map::MapFile;
use narf_bpf::prog::ProgFile;
use narf_bpf_verifier::kfunc::Context;

// Errnos this module returns. Spelled out locally rather than widening
// `handlers/mod.rs`'s set or reaching into `sys_bpf.rs`'s private ones — the
// two files are edited by different agents and a shared private constant is a
// merge conflict waiting for a reason.
const EBADF_: i64 = 9;
const ENOENT: i64 = 2;
const E2BIG: i64 = 7;
const ENOMEM: i64 = 12;
const EFAULT: i64 = 14;
const EINVAL: i64 = 22;
const EMFILE: i64 = 24;
/// Linux's userspace-visible `EOPNOTSUPP`, which equals `ENOTSUP` (95).
const ENOTSUP: i64 = 95;

/// As `sys_bpf.rs`: `union bpf_attr` grows every release and Linux accepts any
/// size, zero-extending. Copy what the caller supplied into a zeroed buffer.
const ATTR_BUF: usize = 256;

// ── `struct { … } info` field offsets within `union bpf_attr` ───────
const AI_BPF_FD: usize = 0;
const AI_INFO_LEN: usize = 4;
const AI_INFO: usize = 8;
/// `CHECK_ATTR(BPF_OBJ_GET_INFO_BY_FD)`'s last field is `info`, so everything
/// past it must be zero.
const AI_END: usize = 16;

// ── the anonymous `BPF_*_GET_*_ID` struct ───────────────────────────
const GI_START_ID: usize = 0;
const GI_NEXT_ID: usize = 4;
const GI_OPEN_FLAGS: usize = 8;
/// `BPF_*_GET_NEXT_ID_LAST_FIELD` is `next_id`.
const GI_NEXT_ID_END: usize = 8;
/// `BPF_PROG_GET_FD_BY_ID_LAST_FIELD` is `prog_id` — a prog fd takes no flags.
///
/// The same 4 bytes cover `BPF_BTF_GET_FD_BY_ID_LAST_FIELD` (`btf_id`) and
/// `BPF_LINK_GET_FD_BY_ID_LAST_FIELD` (`link_id`): all three are the bare id at
/// offset 0 of the same anonymous struct, and only the *map* command has an
/// `open_flags`.
const GI_PROG_FD_END: usize = 4;
/// `BPF_MAP_GET_FD_BY_ID_LAST_FIELD` is `open_flags`.
const GI_MAP_FD_END: usize = 12;

/// `enum bpf_prog_type` values `sys_bpf.rs`'s `prog_load` accepts, reported
/// back here. The mapping is one-to-one in both directions, which is why it can
/// be a `match` and not a stored field.
const BPF_PROG_TYPE_TRACING: u32 = 26;
const BPF_PROG_TYPE_SYSCALL: u32 = 31;

/// `BPF_OBJ_NAME_LEN`.
const OBJ_NAME_LEN: usize = 16;

/// Largest info buffer a caller may claim, matching Linux's `PAGE_SIZE` guard
/// in `bpf_check_uarg_tail_zero` — "silly large" is `E2BIG`, not an allocation.
const MAX_INFO_LEN: usize = 4096;

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn u64_at(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// Copy the caller's `union bpf_attr` into a zeroed buffer of our own.
fn read_attr(attr_uptr: u64, size: usize) -> Result<[u8; ATTR_BUF], i64> {
    if attr_uptr == 0 || size == 0 || size > ATTR_BUF {
        return Err(-EINVAL);
    }
    let mut buf = [0u8; ATTR_BUF];
    // SAFETY: caller-supplied pointer, range-validated inside `copy_from_user`,
    // which opens and closes the SMAP window and converts a fault into
    // `Err(EFAULT)` rather than a kernel panic.
    unsafe { copy_from_user(&mut buf[..size], attr_uptr) }.map_err(|e| -(e as i64))?;
    Ok(buf)
}

/// Linux's `CHECK_ATTR`: every `bpf_attr` byte past the command's last field
/// must be zero.
///
/// Not pedantry — it is the only thing that lets a *future* kernel add a field
/// to this command and know that a caller which sent garbage there was not
/// silently given the old behaviour. `read_attr` already zero-filled beyond
/// `size`, so only the bytes the caller actually supplied are examined.
fn check_attr_tail(attr: &[u8; ATTR_BUF], last_field_end: usize, size: usize) -> Result<(), i64> {
    if size <= last_field_end {
        return Ok(());
    }
    if attr[last_field_end..size].iter().any(|b| *b != 0) {
        return Err(-EINVAL);
    }
    Ok(())
}

// ── BPF_OBJ_GET_INFO_BY_FD ──────────────────────────────────────────

// `struct bpf_prog_info` offsets. Verified against
// include/uapi/linux/bpf.h — every `__aligned_u64` forces 8-byte alignment,
// which is where the two implicit pad words (after `ifindex`+bitfield, and the
// tail) come from.
const PI_TYPE: usize = 0;
const PI_ID: usize = 4;
const PI_JITED_PROG_LEN: usize = 16;
const PI_XLATED_PROG_LEN: usize = 20;
const PI_JITED_PROG_INSNS: usize = 24;
const PI_XLATED_PROG_INSNS: usize = 32;
const PI_NR_MAP_IDS: usize = 52;
const PI_MAP_IDS: usize = 56;
const PI_NAME: usize = 64;
const PI_RUN_TIME_NS: usize = 192;
const PI_RUN_CNT: usize = 200;
/// `sizeof(struct bpf_prog_info)`.
const PROG_INFO_LEN: usize = 232;

// `struct bpf_map_info` offsets.
const MI_TYPE: usize = 0;
const MI_ID: usize = 4;
const MI_KEY_SIZE: usize = 8;
const MI_VALUE_SIZE: usize = 12;
const MI_MAX_ENTRIES: usize = 16;
const MI_NAME: usize = 24;
/// `sizeof(struct bpf_map_info)` through `map_extra`.
///
/// Stops there deliberately. Linux has since appended `btf_vmlinux_id` (over
/// the old pad word) and a `hash`/`hash_size` pair; NARF fills neither, and the
/// truncation contract above means a caller compiled against the longer struct
/// gets `88` reported back and knows the tail is unfilled — which is more
/// honest than claiming a size whose extra bytes are all zero anyway.
const MAP_INFO_LEN: usize = 88;

// `struct bpf_link_info` offsets. The three common fields, then an 8-aligned
// union whose largest member (`uprobe_multi`) makes Linux's `sizeof` 64.
const LI_TYPE: usize = 0;
const LI_ID: usize = 4;
const LI_PROG_ID: usize = 8;
/// `tracing.attach_type`, and `xdp.ifindex` — the union starts here.
const LI_UNION: usize = 16;
/// `tracing.target_obj_id`.
const LI_TRACING_TARGET_OBJ_ID: usize = 20;
/// `tracing.target_btf_id`.
const LI_TRACING_TARGET_BTF_ID: usize = 24;
/// How much of `struct bpf_link_info` NARF fills.
///
/// Short of Linux's 64, and deliberately so — the same call the `MAP_INFO_LEN`
/// note above makes. Every union member NARF can produce (`tracing`'s three
/// `__u32`s, `xdp`'s one) ends by offset 28; the rest of the union describes
/// link types NARF has no surface for, and a caller told "64 bytes filled"
/// would read a `cookie` or a `kprobe_multi.count` that was never written.
/// Reporting 32 says exactly which prefix is real.
const LINK_INFO_LEN: usize = 32;

/// `enum bpf_link_type`. Only the two NARF has surfaces for.
const BPF_LINK_TYPE_TRACING: u32 = 2;
const BPF_LINK_TYPE_XDP: u32 = 6;
/// `enum bpf_attach_type`'s `BPF_TRACE_FENTRY`, echoed into
/// `bpf_link_info.tracing.attach_type`. Spelled here rather than imported from
/// `sys_bpf_attach.rs`, whose copy is a private constant of a file another
/// agent edits.
const BPF_TRACE_FENTRY: u32 = 24;

// `struct bpf_btf_info` offsets. `sizeof` is 32 and NARF fills all of it.
const BI_BTF: usize = 0;
const BI_BTF_SIZE: usize = 8;
const BI_ID: usize = 12;
const BI_NAME: usize = 16;
const BI_NAME_LEN: usize = 24;
const BI_KERNEL_BTF: usize = 28;
/// `sizeof(struct bpf_btf_info)`.
const BTF_INFO_LEN: usize = 32;

/// Copy `name` into a fixed `BPF_OBJ_NAME_LEN` NUL-padded field.
///
/// Truncating rather than rejecting: the name was already capped at 16 bytes
/// when the object was created, so a longer one cannot occur — and if it ever
/// could, a truncated name is a better answer than a failed `info` call.
fn put_name(buf: &mut [u8], off: usize, name: &str) {
    let n = name.len().min(OBJ_NAME_LEN);
    buf[off..off + n].copy_from_slice(&name.as_bytes()[..n]);
}

/// Apply the `info_len` in/out truncation contract and write the result back.
///
/// `filled` is the kernel's full struct; `kernel_len` its `sizeof`. Returns the
/// number of bytes written, which is also what lands in `attr.info.info_len`.
fn write_info(
    attr_uptr: u64,
    uinfo: u64,
    user_len: usize,
    filled: &[u8],
    kernel_len: usize,
) -> i64 {
    debug_assert!(filled.len() >= kernel_len);
    // "Silly large" first, exactly as Linux: this bounds the tail scan below
    // before it can be asked to walk an arbitrary length.
    if user_len > MAX_INFO_LEN {
        return -E2BIG;
    }
    // Forward compatibility: a caller with a *bigger* struct than this kernel
    // knows must have zeroed the part we cannot fill. If it did not, it is
    // relying on a field this kernel does not implement, and telling it so
    // (`E2BIG`) is the only answer that is not a silent wrong result.
    if user_len > kernel_len {
        // Scanned in small chunks rather than into one `MAX_INFO_LEN` buffer:
        // that would put a 4 KiB array on the kernel stack for a call whose
        // whole job is to copy 88 bytes out, and the kernel stack is the one
        // budget a syscall handler cannot grow.
        let mut probe = [0u8; 128];
        let mut off = kernel_len;
        while off < user_len {
            let n = (user_len - off).min(probe.len());
            // SAFETY: range-validated inside `copy_from_user`, which brackets
            // SMAP and turns a fault into `Err(EFAULT)`. `n` is bounded by
            // `probe.len()`, so the slice is always in range.
            if let Err(e) = unsafe { copy_from_user(&mut probe[..n], uinfo + off as u64) } {
                return -(e as i64);
            }
            if probe[..n].iter().any(|b| *b != 0) {
                return -E2BIG;
            }
            off += n;
        }
    }
    let n = user_len.min(kernel_len);
    if n > 0 {
        // SAFETY: range-validated inside `copy_to_user`, which brackets SMAP.
        // `n` never exceeds the caller's own declared buffer length, which is
        // the whole point of the `min`.
        if let Err(e) = unsafe { copy_to_user(uinfo, &filled[..n]) } {
            return -(e as i64);
        }
    }
    // Report what was actually filled, not what was asked for. A caller with a
    // newer struct learns the suffix is untouched; a caller with an older one
    // sees its own length echoed.
    // SAFETY: as above.
    match unsafe { copy_to_user(attr_uptr + AI_INFO_LEN as u64, &(n as u32).to_le_bytes()) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

/// Read back the caller's current info struct.
///
/// Needed because several `bpf_prog_info` fields are **in/out**: the caller
/// puts a buffer pointer and a capacity in, and the kernel fills the buffer and
/// replaces the capacity with the true count. Linux does the same
/// `copy_from_user(&info, uinfo, info_len)` before it fills anything.
fn read_user_info(uinfo: u64, user_len: usize, out: &mut [u8]) -> Result<(), i64> {
    let n = user_len.min(out.len());
    if n == 0 {
        return Ok(());
    }
    if uinfo == 0 {
        return Err(-EFAULT);
    }
    // SAFETY: range-validated inside `copy_from_user`.
    unsafe { copy_from_user(&mut out[..n], uinfo) }.map_err(|e| -(e as i64))
}

pub(crate) fn bpf_obj_get_info_by_fd(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < AI_END {
        return -EINVAL;
    }
    if let Err(e) = check_attr_tail(&attr, AI_END, size) {
        return e;
    }
    let fd = u32_at(&attr, AI_BPF_FD);
    let user_len = u32_at(&attr, AI_INFO_LEN) as usize;
    let uinfo = u64_at(&attr, AI_INFO);

    // The fd is resolved *before* the info pointer is validated, matching
    // Linux's order (`fdget` in `bpf_obj_get_info_by_fd`, then the per-object
    // handler's `copy_from_user`). A caller probing with a bad fd and a NULL
    // buffer must hear about the fd.
    let ops = match fd::with_table(current_task_id(), |t| t.get(fd).map(|e| e.ops.clone())) {
        Some(Some(o)) => o,
        _ => return -EBADF_,
    };
    if uinfo == 0 && user_len != 0 {
        return -EFAULT;
    }
    let any = match ops.as_any() {
        Some(a) => a,
        // An fd whose file has no `as_any` cannot be a BPF object, so this is
        // the same answer as the downcasts below failing.
        None => return -EINVAL,
    };
    if let Some(f) = any.downcast_ref::<ProgFile>() {
        return prog_info(attr_uptr, uinfo, user_len, &f.prog());
    }
    if let Some(f) = any.downcast_ref::<MapFile>() {
        return map_info(attr_uptr, uinfo, user_len, &f.map());
    }
    if let Some(f) = any.downcast_ref::<LinkFile>() {
        return link_info(attr_uptr, uinfo, user_len, &f.link());
    }
    if let Some(f) = any.downcast_ref::<super::BtfFile>() {
        return btf_info(attr_uptr, uinfo, user_len, f);
    }
    // An fd that is none of the four is not a BPF object at all — `EINVAL`,
    // matching what Linux returns for a non-BPF fd. It is *not* `ENOTSUP`,
    // because that would claim the kernel understood the object and declined;
    // it did not recognise one.
    -EINVAL
}

fn prog_info(
    attr_uptr: u64,
    uinfo: u64,
    user_len: usize,
    prog: &alloc::sync::Arc<narf_bpf::prog::BpfProg>,
) -> i64 {
    let mut uin = [0u8; PROG_INFO_LEN];
    if let Err(e) = read_user_info(uinfo, user_len, &mut uin) {
        return e;
    }

    // LINUX-GAP: the instruction-dump fields. Linux lets a privileged caller
    // pass a buffer in `xlated_prog_insns` / `jited_prog_insns` and copies the
    // program image into it; NARF has no dump path. Refusing loudly rather than
    // reporting a length and writing nothing — a caller that asked for the
    // image and got a silently untouched buffer would disassemble whatever was
    // already there. `bpftool prog list` (which never sets these) is
    // unaffected; `bpftool prog dump` gets a clean "this kernel does not do
    // that".
    // `>=`, not `>`: a field spanning bytes `[off, off+8)` is fully supplied
    // once `user_len` reaches `off + 8`. Off by one here silently ignores a
    // dump request from a caller whose struct ends exactly at the field.
    let wants_xlated =
        user_len >= PI_XLATED_PROG_INSNS + 8 && u64_at(&uin, PI_XLATED_PROG_INSNS) != 0;
    let wants_jited =
        user_len >= PI_JITED_PROG_INSNS + 8 && u64_at(&uin, PI_JITED_PROG_INSNS) != 0;
    if wants_xlated || wants_jited {
        return -ENOTSUP;
    }

    // The in-value of `nr_map_ids` is the caller's array capacity; the
    // out-value is the true count. Both halves matter: a caller sizing its
    // buffer does one call with capacity 0 to learn the count, then a second.
    let cap = if user_len >= PI_NR_MAP_IDS + 4 {
        u32_at(&uin, PI_NR_MAP_IDS) as usize
    } else {
        0
    };
    let map_ids_uptr = if user_len >= PI_MAP_IDS + 8 {
        u64_at(&uin, PI_MAP_IDS)
    } else {
        0
    };
    let map_ids = match prog.used_map_ids() {
        Ok(ids) => ids,
        Err(narf_bpf::prog::BindError::NoMemory) => return -ENOMEM,
    };
    let nr_maps = map_ids.len();
    if cap > 0 && map_ids_uptr != 0 {
        for (i, id) in map_ids.iter().take(cap).enumerate() {
            // SAFETY: range-validated inside `copy_to_user`, which brackets
            // SMAP and converts a fault into `Err(EFAULT)`. The loop is bounded
            // by the capacity the caller itself declared in `nr_map_ids`, so
            // the write never runs past the array it described.
            let r = unsafe { copy_to_user(map_ids_uptr + (i * 4) as u64, &id.to_le_bytes()) };
            if let Err(e) = r {
                return -(e as i64);
            }
        }
    }

    let mut out = [0u8; PROG_INFO_LEN];
    put_u32(
        &mut out,
        PI_TYPE,
        match prog.context() {
            Context::Atomic => BPF_PROG_TYPE_TRACING,
            Context::Sleepable => BPF_PROG_TYPE_SYSCALL,
        },
    );
    put_u32(&mut out, PI_ID, prog.id);
    put_u32(&mut out, PI_JITED_PROG_LEN, prog.jited_len() as u32);
    // NARF does not rewrite instructions (spec §1.7), so the "translated"
    // program *is* the loaded one and its length is exact rather than an
    // approximation of a rewritten image.
    put_u32(
        &mut out,
        PI_XLATED_PROG_LEN,
        (prog.len() * core::mem::size_of::<narf_bpf_isa::Insn>()) as u32,
    );
    put_u32(&mut out, PI_NR_MAP_IDS, nr_maps as u32);
    put_name(&mut out, PI_NAME, &prog.name);
    put_u64(&mut out, PI_RUN_TIME_NS, prog.run_time_ns());
    put_u64(&mut out, PI_RUN_CNT, prog.stats_runs());
    // Everything else stays zero, and each is a deliberate absence:
    //
    // LINUX-GAP: `tag` — Linux's SHA-1 over the instruction image. NARF
    // computes no program tag, and a fabricated one would collide across
    // distinct programs, which is exactly what a tag exists to rule out.
    // LINUX-GAP: `load_time`, `created_by_uid` — not recorded on `BpfProg`, and
    // recording them is new bookkeeping on the load path rather than reporting
    // of something already known.
    // LINUX-GAP: `gpl_compatible` — NARF's load ABI carries no license field,
    // so there is nothing to be compatible with; 0 is "unknown", not "no".
    // LINUX-GAP: `ifindex`, `netns_dev`, `netns_ino` — no offload, no netns
    // binding for programs.
    // LINUX-GAP: `nr_jited_ksyms`, `nr_jited_func_lens`, `jited_ksyms`,
    // `jited_func_lens`, `nr_prog_tags`, `prog_tags` — per-subprogram symbol
    // and tag tables the JIT does not publish. Zero counts are truthful: there
    // are none to enumerate.
    // LINUX-GAP: `btf_id`, `func_info*`, `line_info*`, `attach_btf_obj_id`,
    // `attach_btf_id` — BTF is a separate stream; zero means "no BTF".
    // LINUX-GAP: `recursion_misses` — `run_atomic` declines a nested invocation
    // (spec §1.5) but does not count the refusal, so this would under-report
    // rather than be absent. Zero says "not counted"; a partial count would say
    // "counted, and it was low".
    // LINUX-GAP: `verified_insns` — Linux reports instructions the verifier
    // *processed*, which is a path count, not the image size already in
    // `xlated_prog_len`. NARF's verifier does not report one.
    write_info(attr_uptr, uinfo, user_len, &out, PROG_INFO_LEN)
}

fn map_info(
    attr_uptr: u64,
    uinfo: u64,
    user_len: usize,
    map: &alloc::sync::Arc<narf_bpf::map::BpfMap>,
) -> i64 {
    let a = map.attr();
    let mut out = [0u8; MAP_INFO_LEN];
    // `MapKind`'s discriminants *are* Linux's `enum bpf_map_type` values
    // (`map.rs` says so and the `#[repr(u32)]` enforces it), so this needs no
    // translation table that could drift from `MapKind::from_linux`.
    put_u32(&mut out, MI_TYPE, a.kind as u32);
    put_u32(&mut out, MI_ID, map.id);
    put_u32(&mut out, MI_KEY_SIZE, a.key_size);
    put_u32(&mut out, MI_VALUE_SIZE, a.value_size);
    put_u32(&mut out, MI_MAX_ENTRIES, a.max_entries);
    put_name(&mut out, MI_NAME, &map.name);
    // Deliberately zero:
    //
    // LINUX-GAP: persistent `map_flags`. `BPF_F_RDONLY` / `BPF_F_WRONLY` are
    // descriptor-local and Linux strips them from map info too. The two
    // object flags NARF accepts (`BPF_F_NO_PREALLOC`, `BPF_F_ZERO_SEED`) change
    // nothing about the map that exists — see `sys_bpf.rs` — so echoing them
    // would describe behaviour NARF did not build. Zero describes the object.
    // LINUX-GAP: `ifindex`, `netns_dev`, `netns_ino` — no map offload.
    // LINUX-GAP: `btf_id`, `btf_key_type_id`, `btf_value_type_id`,
    // `btf_vmlinux_value_type_id` — no BTF.
    // LINUX-GAP: `map_extra` — only meaningful for map types NARF does not have
    // (bloom filter hash count, ringbuf flags).
    write_info(attr_uptr, uinfo, user_len, &out, MAP_INFO_LEN)
}

fn link_info(
    attr_uptr: u64,
    uinfo: u64,
    user_len: usize,
    link: &alloc::sync::Arc<narf_bpf::link::BpfLink>,
) -> i64 {
    let mut out = [0u8; LINK_INFO_LEN];
    put_u32(&mut out, LI_ID, link.id());
    // `prog_id` is 0 once the link has been detached — `BPF_LINK_DETACH` leaves
    // the fd valid and the link dead, and reporting the last program it held
    // would say the attach is still in place. Linux's dead links report 0 for
    // the same reason.
    if let Some(p) = link.prog() {
        put_u32(&mut out, LI_PROG_ID, p.id);
    }
    match link.target() {
        LinkTarget::Probe(_) => {
            put_u32(&mut out, LI_TYPE, BPF_LINK_TYPE_TRACING);
            put_u32(&mut out, LI_UNION, BPF_TRACE_FENTRY);
            // LINUX-GAP: `tracing.target_obj_id` / `tracing.target_btf_id`.
            // Linux names an fentry target by BTF id; NARF names it by
            // `narf_tracing::dispatch` probe id, and nothing joins the two
            // (see `sys_bpf_attach.rs`'s header). Writing the probe id into a
            // field documented as a BTF type id would be a value that looks
            // resolvable and is not, so both stay 0 — which for
            // `target_btf_id` already means "none".
            put_u32(&mut out, LI_TRACING_TARGET_OBJ_ID, 0);
            put_u32(&mut out, LI_TRACING_TARGET_BTF_ID, 0);
        }
        LinkTarget::Xdp(iface) => {
            put_u32(&mut out, LI_TYPE, BPF_LINK_TYPE_XDP);
            // 0 for an interface that has since been unregistered: `ifindex`
            // has no "unknown" encoding other than 0, and a stale index would
            // name whichever interface now sits at that position.
            put_u32(
                &mut out,
                LI_UNION,
                super::ifindex_for_iface(iface).unwrap_or(0),
            );
        }
    }
    write_info(attr_uptr, uinfo, user_len, &out, LINK_INFO_LEN)
}

fn btf_info(attr_uptr: u64, uinfo: u64, user_len: usize, file: &super::BtfFile) -> i64 {
    let mut uin = [0u8; BTF_INFO_LEN];
    if let Err(e) = read_user_info(uinfo, user_len, &mut uin) {
        return e;
    }
    let btf = file.btf();
    let raw = btf.raw();

    // `btf` / `btf_size` are the in/out pair `bpftool btf dump` uses: in, a
    // buffer and its capacity; out, the blob's true size. A caller sizing its
    // buffer calls once with capacity 0 to learn the size, then again.
    let ubtf = if user_len >= BI_BTF + 8 {
        u64_at(&uin, BI_BTF)
    } else {
        0
    };
    let cap = if user_len >= BI_BTF_SIZE + 4 {
        u32_at(&uin, BI_BTF_SIZE) as usize
    } else {
        0
    };
    if ubtf != 0 && cap > 0 {
        let n = cap.min(raw.len());
        // SAFETY: range-validated inside `copy_to_user`, which brackets SMAP
        // and turns a fault into `Err(EFAULT)`. `n` never exceeds the capacity
        // the caller itself declared in `btf_size`.
        if let Err(e) = unsafe { copy_to_user(ubtf, &raw[..n]) } {
            return -(e as i64);
        }
    }

    let mut out = [0u8; BTF_INFO_LEN];
    // Echoed back unchanged: it is the caller's own pointer, and a zero here
    // would tell a caller that re-reads the struct that it never passed one.
    put_u64(&mut out, BI_BTF, ubtf);
    put_u32(&mut out, BI_BTF_SIZE, raw.len() as u32);
    put_u32(&mut out, BI_ID, file.id());
    put_u64(&mut out, BI_NAME, u64_at(&uin, BI_NAME));
    // LINUX-GAP: `name` / `name_len`. Linux names the vmlinux and module BTFs;
    // a blob loaded through `BPF_BTF_LOAD` is anonymous there too, and NARF has
    // no kernel BTF to name. 0 is "no name", and the caller's buffer is left
    // untouched rather than filled with something invented.
    put_u32(&mut out, BI_NAME_LEN, 0);
    // Not kernel BTF: NARF has none. This one is load-bearing rather than a
    // gap — a loader uses it to decide whether the blob may be freed.
    put_u32(&mut out, BI_KERNEL_BTF, 0);
    write_info(attr_uptr, uinfo, user_len, &out, BTF_INFO_LEN)
}

// ── the id family ───────────────────────────────────────────────────

/// Shared body of `BPF_PROG_GET_NEXT_ID` / `BPF_MAP_GET_NEXT_ID`.
///
/// One function taking the resolved id, because the two commands differ in
/// exactly which table they walk and nothing else — and two copies of the
/// "write `next_id` back, `ENOENT` at the end" logic is how one of them ends up
/// reporting the wrong errno at the end of the table.
fn get_next_id(attr_uptr: u64, size: usize, next: impl FnOnce(u32) -> Option<u32>) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < GI_NEXT_ID_END {
        return -EINVAL;
    }
    if let Err(e) = check_attr_tail(&attr, GI_NEXT_ID_END, size) {
        return e;
    }
    let start = u32_at(&attr, GI_START_ID);
    // "The next id strictly greater than `start_id`" — so a walk is
    // `start_id = 0` then feeding each answer back in, and an id seen twice
    // means the table was mutated under the walk, never that the walk stalled.
    let Some(id) = next(start) else {
        // End of table. `ENOENT` and not an empty success, because a loader
        // enumerating has to be able to stop.
        return -ENOENT;
    };
    // SAFETY: range-validated inside `copy_to_user`, which brackets SMAP.
    match unsafe { copy_to_user(attr_uptr + GI_NEXT_ID as u64, &id.to_le_bytes()) } {
        Ok(()) => 0,
        Err(e) => -(e as i64),
    }
}

pub(crate) fn bpf_prog_get_next_id(attr_uptr: u64, size: usize) -> i64 {
    get_next_id(attr_uptr, size, |after| {
        narf_bpf::idreg::progs().next_id(after)
    })
}

pub(crate) fn bpf_map_get_next_id(attr_uptr: u64, size: usize) -> i64 {
    get_next_id(attr_uptr, size, |after| {
        narf_bpf::idreg::maps().next_id(after)
    })
}

pub(crate) fn bpf_link_get_next_id(attr_uptr: u64, size: usize) -> i64 {
    get_next_id(attr_uptr, size, |after| {
        narf_bpf::idreg::links().next_id(after)
    })
}

pub(crate) fn bpf_btf_get_next_id(attr_uptr: u64, size: usize) -> i64 {
    get_next_id(attr_uptr, size, |after| super::btf_ids().next_id(after))
}

/// Install a freshly built anon-fd file in the caller's table.
///
/// The `FileOps` handed in holds its **own** `Arc` to the object, cloned out of
/// the registry — that is what makes an fd obtained by id independent of the fd
/// that created the object. Closing the original leaves this one working, which
/// is the entire reason `GET_FD_BY_ID` exists.
fn install_fd(ops: alloc::sync::Arc<dyn narf_filesystem::FileOps>) -> i64 {
    match fd::with_table(current_task_id(), |t| {
        t.open(crate::fd::FdEntry {
            ops,
            offset: 0,
            // As `bpf_prog_new_fd` / `bpf_map_new_fd`: `O_CLOEXEC`, because a
            // leaked bpf fd is a leaked capability.
            flags: crate::fd::FD_CLOEXEC,
            status_flags: 0,
        })
    }) {
        Some(n) => n as i64,
        None => -EMFILE,
    }
}

/// The shared prologue of every `GET_FD_BY_ID` whose last field is the bare id:
/// `BPF_PROG_GET_FD_BY_ID`, `BPF_BTF_GET_FD_BY_ID`, `BPF_LINK_GET_FD_BY_ID`.
///
/// One function because the three differ only in which table they consult, and
/// three copies of "reject a short `bpf_attr`, then `CHECK_ATTR` the tail" is
/// how one of them ends up silently accepting an `open_flags` it does not
/// honour. `BPF_MAP_GET_FD_BY_ID` is not one of them — it *does* take
/// `open_flags` — and keeps its own body below.
fn id_arg(attr_uptr: u64, size: usize) -> Result<u32, i64> {
    let attr = read_attr(attr_uptr, size)?;
    if size < GI_PROG_FD_END {
        return Err(-EINVAL);
    }
    check_attr_tail(&attr, GI_PROG_FD_END, size)?;
    Ok(u32_at(&attr, GI_START_ID))
}

pub(crate) fn bpf_prog_get_fd_by_id(attr_uptr: u64, size: usize) -> i64 {
    let id = match id_arg(attr_uptr, size) {
        Ok(i) => i,
        Err(e) => return e,
    };
    // `ENOENT` covers both "never existed" and "existed and was freed", and
    // they are genuinely the same answer: the registry holds a `Weak`, so a
    // freed program's entry cannot upgrade. That is the property that makes a
    // stale id a failed lookup rather than a dangling handle.
    let Some(prog) = narf_bpf::idreg::progs().get(id) else {
        return -ENOENT;
    };
    install_fd(alloc::sync::Arc::new(ProgFile::new(prog)))
}

pub(crate) fn bpf_map_get_fd_by_id(attr_uptr: u64, size: usize) -> i64 {
    let attr = match read_attr(attr_uptr, size) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if size < GI_PROG_FD_END {
        return -EINVAL;
    }
    if let Err(e) = check_attr_tail(&attr, GI_MAP_FD_END, size) {
        return e;
    }
    let flags = u32_at(&attr, GI_OPEN_FLAGS);
    if flags & !(super::BPF_F_RDONLY | super::BPF_F_WRONLY) != 0 {
        return -EINVAL;
    }
    let access = match super::map_access_from_flags(flags) {
        Ok(a) => a,
        Err(e) => return e,
    };
    let id = u32_at(&attr, GI_START_ID);
    let Some(map) = narf_bpf::idreg::maps().get(id) else {
        return -ENOENT;
    };
    super::install_map_fd(map, access)
}

pub(crate) fn bpf_link_get_fd_by_id(attr_uptr: u64, size: usize) -> i64 {
    let id = match id_arg(attr_uptr, size) {
        Ok(i) => i,
        Err(e) => return e,
    };
    // As for programs: `ENOENT` for an id that never existed and for one whose
    // link is gone, because the registry's `Weak` cannot upgrade a dead link.
    // For links that matters more than for any other object here — a strong
    // entry would hold the *attach* open for the rest of the boot, since
    // `BpfLink::drop` is the only thing that undoes one.
    let Some(link) = narf_bpf::idreg::links().get(id) else {
        return -ENOENT;
    };
    // `LinkFile::new` takes the `Arc` we just cloned out of the registry, so
    // this fd is an owner in its own right: closing the fd the link was created
    // through leaves the attach in place, and closing *this* one — when it is
    // the last — detaches.
    install_fd(alloc::sync::Arc::new(LinkFile::new(link)))
}

pub(crate) fn bpf_btf_get_fd_by_id(attr_uptr: u64, size: usize) -> i64 {
    let id = match id_arg(attr_uptr, size) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let Some(blob) = super::btf_ids().get(id) else {
        return -ENOENT;
    };
    install_fd(alloc::sync::Arc::new(super::BtfFile::from_blob(blob)))
}
