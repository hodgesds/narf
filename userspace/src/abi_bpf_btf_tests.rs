//! Linux syscall ABI conformance — `bpf(2)`'s `BPF_BTF_LOAD`.
//!
//! The parser itself is tested to death on the host in `narf-bpf-btf`
//! (66 cases, most of them malformed input). What is left for here is the
//! *syscall glue*, which the host tests cannot reach: the `union bpf_attr`
//! field offsets, the errno each rejection class maps to, the `btf_log_buf`
//! contract, and the promise that closing the fd frees the blob.
//!
//! A separate file from `abi_bpf_tests.rs` on purpose — that file is being
//! edited by two other agents at the same time.

use crate::abi_test_support::*;

const BPF_BTF_LOAD: u64 = 18;

const EOPNOTSUPP: i64 = -95;
const E2BIG: i64 = -7;

/// A `union bpf_attr` big enough for the `btf` sub-struct.
const ATTR_LEN: usize = 64;

// `struct { … } btf` field offsets.
const BTF_DATA: usize = 0;
const BTF_LOG_BUF: usize = 8;
const BTF_SIZE: usize = 16;
const BTF_LOG_SIZE: usize = 20;
const BTF_LOG_LEVEL: usize = 24;
const BTF_LOG_TRUE_SIZE: usize = 28;
const BTF_FLAGS: usize = 32;

fn put_u32(buf: &mut [u8; ATTR_LEN], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(buf: &mut [u8; ATTR_LEN], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u32(buf: &[u8; ATTR_LEN], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

/// The smallest well-formed blob: a header, one `BTF_KIND_INT` named "int",
/// and a five-byte string section. Hand-encoded so this file tests the ABI and
/// not the builder in `narf-bpf-btf`'s own tests.
fn minimal_btf() -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(&0xeb9fu16.to_le_bytes()); // magic
    v.push(1); // version
    v.push(0); // flags
    v.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
    v.extend_from_slice(&0u32.to_le_bytes()); // type_off
    v.extend_from_slice(&16u32.to_le_bytes()); // type_len
    v.extend_from_slice(&16u32.to_le_bytes()); // str_off
    v.extend_from_slice(&5u32.to_le_bytes()); // str_len
                                              // struct btf_type { name_off = 1, info = KIND_INT << 24, size = 4 }
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&(1u32 << 24).to_le_bytes());
    v.extend_from_slice(&4u32.to_le_bytes());
    // The trailing int_data word: 32 bits, no offset, no encoding.
    v.extend_from_slice(&32u32.to_le_bytes());
    v.extend_from_slice(b"\0int\0");
    v
}

fn load(blob: &[u8]) -> Option<i64> {
    let mut attr = [0u8; ATTR_LEN];
    put_u64(&mut attr, BTF_DATA, blob.as_ptr() as u64);
    put_u32(&mut attr, BTF_SIZE, blob.len() as u32);
    call(
        Syscall::Bpf.raw(),
        a2(BPF_BTF_LOAD, attr.as_ptr() as u64, ATTR_LEN as u64),
    )
}

// ── positive ────────────────────────────────────────────────────────

fn smoke_abi_bpf_btf_load_pos() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let fd = load(&blob).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD rejected a well-formed blob");
        }
        // Linux sets close-on-exec on every bpf fd; a leaked one is a leaked
        // capability.
        let flags =
            call(Syscall::Fcntl.raw(), a2(fd as u64, 1 /* F_GETFD */, 0)).ok_or("fcntl not Ok")?;
        if flags & 1 == 0 {
            return Err("btf fd is not close-on-exec");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_load_pos);

/// Closing the fd must free the blob, not leak a 16 MiB-capable allocation per
/// call. A counter rather than a comment, because "the `Arc` drops" is exactly
/// the kind of claim that stays true-looking after someone stashes a clone.
fn smoke_abi_bpf_btf_close_frees() -> TestResult {
    with_setup(|| {
        let before = crate::handlers::live_btf_count();
        let blob = minimal_btf();

        let mut fds = alloc::vec::Vec::new();
        for _ in 0..4 {
            let fd = load(&blob).ok_or("bpf() not Ok")?;
            if fd < 0 {
                return Err("BPF_BTF_LOAD rejected a well-formed blob");
            }
            fds.push(fd);
        }
        if crate::handlers::live_btf_count() != before + 4 {
            return Err("loading four blobs did not raise the live count by four");
        }
        for fd in fds {
            let _ = call(Syscall::Close.raw(), a0(fd as u64));
        }
        if crate::handlers::live_btf_count() != before {
            return Err("closing every btf fd did not free every blob");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_close_frees);

// ── negative ────────────────────────────────────────────────────────

fn smoke_abi_bpf_btf_load_neg() -> TestResult {
    with_setup(|| {
        // Null attr, and a zero-length attr.
        if call(Syscall::Bpf.raw(), a2(BPF_BTF_LOAD, 0, ATTR_LEN as u64)) != Some(EINVAL) {
            return Err("BPF_BTF_LOAD with a null attr did not return EINVAL");
        }
        let attr = [0u8; ATTR_LEN];
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr.as_ptr() as u64, 0),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_LOAD with size 0 did not return EINVAL");
        }

        // An attr too short to contain `btf_size`.
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr.as_ptr() as u64, 8),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_LOAD with a truncated attr did not return EINVAL");
        }

        // btf_size == 0.
        let blob = minimal_btf();
        let mut a = [0u8; ATTR_LEN];
        put_u64(&mut a, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut a, BTF_SIZE, 0);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, a.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("BPF_BTF_LOAD with btf_size 0 did not return EINVAL");
        }

        // A null blob pointer with a nonzero size is a bad address, not bad
        // input — Linux distinguishes the two and so must we.
        let mut a = [0u8; ATTR_LEN];
        put_u64(&mut a, BTF_DATA, 0);
        put_u32(&mut a, BTF_SIZE, blob.len() as u32);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, a.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EFAULT)
        {
            return Err("BPF_BTF_LOAD with a null btf pointer did not return EFAULT");
        }

        // Larger than BTF_MAX_SIZE: E2BIG, and refused before the copy, so a
        // bogus size never reaches the allocator.
        let mut a = [0u8; ATTR_LEN];
        put_u64(&mut a, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut a, BTF_SIZE, 16 * 1024 * 1024 + 1);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, a.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(E2BIG)
        {
            return Err("an oversized btf_size did not return E2BIG");
        }

        // `btf_flags` is where BPF_F_TOKEN_FD lives; a flag we silently
        // ignored would be a permission check we silently skipped.
        let mut a = [0u8; ATTR_LEN];
        put_u64(&mut a, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut a, BTF_SIZE, blob.len() as u32);
        put_u32(&mut a, BTF_FLAGS, 1);
        if call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, a.as_ptr() as u64, ATTR_LEN as u64),
        ) != Some(EINVAL)
        {
            return Err("a nonzero btf_flags was not refused");
        }

        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_load_neg);

/// The three errno classes the parser distinguishes must survive the trip
/// through the syscall layer: malformed is `EINVAL`, over-limit is `E2BIG`,
/// and "a BTF feature this kernel does not do" is `EOPNOTSUPP` — which is what
/// lets a probing loader tell those apart.
fn smoke_abi_bpf_btf_errno_classes() -> TestResult {
    with_setup(|| {
        // Bad magic → EINVAL.
        let mut blob = minimal_btf();
        blob[0] = 0;
        if load(&blob) != Some(EINVAL) {
            return Err("a bad-magic blob did not return EINVAL");
        }

        // Unsupported version → EOPNOTSUPP.
        let mut blob = minimal_btf();
        blob[2] = 2;
        if load(&blob) != Some(EOPNOTSUPP) {
            return Err("an unsupported BTF version did not return EOPNOTSUPP");
        }

        // Split BTF (`flags != 0`) → EOPNOTSUPP.
        let mut blob = minimal_btf();
        blob[3] = 1;
        if load(&blob) != Some(EOPNOTSUPP) {
            return Err("a split-BTF blob did not return EOPNOTSUPP");
        }

        // A header longer than we know, with nonzero bytes in the tail →
        // E2BIG, matching Linux.
        let mut blob = minimal_btf();
        blob[4..8].copy_from_slice(&32u32.to_le_bytes()); // hdr_len = 32
        let mut extended = blob[..24].to_vec();
        extended.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]);
        extended.extend_from_slice(&blob[24..]);
        if load(&extended) != Some(E2BIG) {
            return Err("a header with a nonzero unknown tail did not return E2BIG");
        }

        // A truncated blob → EINVAL and, crucially, not a panic.
        let blob = minimal_btf();
        for n in 1..blob.len() {
            let r = load(&blob[..n]);
            match r {
                Some(v) if v < 0 => {}
                _ => return Err("a truncated blob was accepted"),
            }
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_errno_classes);

// ── the log buffer ──────────────────────────────────────────────────

fn smoke_abi_bpf_btf_log_attrs_validated() -> TestResult {
    with_setup(|| {
        let blob = minimal_btf();
        let mut log = [0u8; 128];

        let with = |log_buf: u64, log_size: u32, level: u32| -> Option<i64> {
            let mut a = [0u8; ATTR_LEN];
            put_u64(&mut a, BTF_DATA, blob.as_ptr() as u64);
            put_u32(&mut a, BTF_SIZE, blob.len() as u32);
            put_u64(&mut a, BTF_LOG_BUF, log_buf);
            put_u32(&mut a, BTF_LOG_SIZE, log_size);
            put_u32(&mut a, BTF_LOG_LEVEL, level);
            call(
                Syscall::Bpf.raw(),
                a2(BPF_BTF_LOAD, a.as_ptr() as u64, ATTR_LEN as u64),
            )
        };

        let buf = log.as_mut_ptr() as u64;
        // A buffer with no size, and a size with no buffer.
        if with(buf, 0, 1) != Some(EINVAL) {
            return Err("log_buf without log_size was not refused");
        }
        if with(0, 128, 1) != Some(EINVAL) {
            return Err("log_size without log_buf was not refused");
        }
        // A buffer nothing will ever be written to.
        if with(buf, 128, 0) != Some(EINVAL) {
            return Err("log_buf with log_level 0 was not refused");
        }
        // An undefined level bit.
        if with(buf, 128, 0x100) != Some(EINVAL) {
            return Err("an undefined log_level bit was not refused");
        }
        // A log_size beyond what the field can mean.
        if with(buf, 0xc000_0000, 1) != Some(EINVAL) {
            return Err("an absurd log_size was not refused");
        }
        // No log at all is the common case and must work.
        let fd = with(0, 0, 0).ok_or("bpf() not Ok")?;
        if fd < 0 {
            return Err("BPF_BTF_LOAD without a log buffer was refused");
        }
        let _ = call(Syscall::Close.raw(), a0(fd as u64));
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_log_attrs_validated);

/// A rejection must land in the caller's buffer, NUL-terminated, without
/// writing one byte past `btf_log_size`.
fn smoke_abi_bpf_btf_log_buf_written_and_bounded() -> TestResult {
    with_setup(|| {
        // A blob whose *type section* is malformed, so the message names a
        // type id and is longer than the tiny buffer below.
        let mut blob = minimal_btf();
        // Turn the INT's kind into BTF_KIND_UNKN.
        blob[24 + 4..24 + 8].copy_from_slice(&0u32.to_le_bytes());

        // 16 bytes of buffer inside a 64-byte array; everything past the
        // sixteenth byte is a canary.
        let mut log = [0xAAu8; 64];
        const LOG_SIZE: u32 = 16;

        let mut a = [0u8; ATTR_LEN];
        put_u64(&mut a, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut a, BTF_SIZE, blob.len() as u32);
        put_u64(&mut a, BTF_LOG_BUF, log.as_mut_ptr() as u64);
        put_u32(&mut a, BTF_LOG_SIZE, LOG_SIZE);
        put_u32(&mut a, BTF_LOG_LEVEL, 1);

        // `as_mut_ptr`, not `as_ptr`: the handler writes `btf_log_true_size`
        // back into this buffer, and the test reads it afterwards.
        let attr_ptr = a.as_mut_ptr() as u64;
        let r = call(
            Syscall::Bpf.raw(),
            a2(BPF_BTF_LOAD, attr_ptr, ATTR_LEN as u64),
        );
        if r != Some(EINVAL) {
            return Err("a malformed type section did not return EINVAL");
        }

        // Something was written…
        if log[0] == 0xAA {
            return Err("btf_log_buf was not written on rejection");
        }
        // …it is NUL-terminated within the buffer…
        if !log[..LOG_SIZE as usize].contains(&0) {
            return Err("btf_log_buf was not NUL-terminated");
        }
        // …and not one byte past it.
        if log[LOG_SIZE as usize..].iter().any(|b| *b != 0xAA) {
            return Err("btf_log_buf was written past btf_log_size");
        }

        // `btf_log_true_size` is an output field: the length the message
        // *would* have needed, so a caller can retry with a big enough buffer.
        let true_size = get_u32(&a, BTF_LOG_TRUE_SIZE);
        if true_size <= LOG_SIZE {
            return Err("btf_log_true_size did not report the untruncated length");
        }

        // Retrying with that much room must produce the whole message.
        let mut big = alloc::vec![0xAAu8; true_size as usize + 8];
        let mut a2buf = [0u8; ATTR_LEN];
        put_u64(&mut a2buf, BTF_DATA, blob.as_ptr() as u64);
        put_u32(&mut a2buf, BTF_SIZE, blob.len() as u32);
        put_u64(&mut a2buf, BTF_LOG_BUF, big.as_mut_ptr() as u64);
        put_u32(&mut a2buf, BTF_LOG_SIZE, true_size);
        put_u32(&mut a2buf, BTF_LOG_LEVEL, 1);
        let a2ptr = a2buf.as_mut_ptr() as u64;
        let _ = call(Syscall::Bpf.raw(), a2(BPF_BTF_LOAD, a2ptr, ATTR_LEN as u64));
        if big[true_size as usize - 1] != 0 {
            return Err("the untruncated message is not NUL-terminated at true_size-1");
        }
        if big[true_size as usize..].iter().any(|b| *b != 0xAA) {
            return Err("the untruncated message overran true_size");
        }
        Ok(())
    })
}
kernel_test_in!("syscall_abi", smoke_abi_bpf_btf_log_buf_written_and_bounded);
