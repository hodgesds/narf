#[allow(unused_imports)]
use super::*;

/// `drivers/char/random.c::SYSCALL_DEFINE3(getrandom, char __user *, ubuf,
/// size_t, len, unsigned int, flags)`.
///
/// ```text
/// if (flags & ~(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE))
///         return -EINVAL;
/// /* Requesting insecure and blocking randomness at the same time makes
///    no sense. */
/// if ((flags & (GRND_INSECURE | GRND_RANDOM)) == (GRND_INSECURE | GRND_RANDOM))
///         return -EINVAL;
/// ...
/// ret = import_ubuf(ITER_DEST, ubuf, len, &iter);   /* -EFAULT */
/// ```
///
/// `flags` was read into `_flags` and discarded. That is the silent half of
/// this bug class and it is worse than a wrong errno: a caller passing an
/// unsupported bit — or the contradictory GRND_INSECURE|GRND_RANDOM pair,
/// which Linux rejects precisely BECAUSE it is contradictory — was told the
/// request succeeded and handed bytes generated under semantics it did not
/// ask for. Nothing in the return value could reveal that.
///
/// Note the flags check comes FIRST, before the buffer is examined, so
/// `getrandom(NULL, 0, 0xdeadbeef)` is -EINVAL, not -EFAULT.
pub(crate) fn sys_getrandom(ctx: &mut dyn TrapContext) {
    /// `include/uapi/linux/random.h`.
    const GRND_NONBLOCK: u32 = 0x0001;
    const GRND_RANDOM: u32 = 0x0002;
    const GRND_INSECURE: u32 = 0x0004;
    let args = *ctx.args();
    let ptr = args.arg0;
    let len = args.arg1 as usize;
    // `unsigned int flags` — the argument is the low 32 bits.
    let flags = args.arg2 as u32;
    if flags & !(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE) != 0 {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    if flags & (GRND_INSECURE | GRND_RANDOM) == (GRND_INSECURE | GRND_RANDOM) {
        ctx.set_return(SyscallReturn::ok((-EINVAL) as u64));
        return;
    }
    // The `!crng_ready()` arm (#1026): while the csprng pool is
    // unseeded, try_fill refuses and the refusal maps to -EAGAIN for
    // every flags combination. Linux parks a blocking call until the
    // CRNG initialises and returns -EAGAIN only under GRND_NONBLOCK;
    // NARF's syscall handlers have no readiness source to park on, so
    // a blocking caller takes -EAGAIN too — the same failure mode the
    // compat read paths use when a blocking read has nothing to park
    // on. GRND_INSECURE waives blocking, not provenance: it is served
    // from the seeded pool like any other call and takes the same
    // -EAGAIN while unseeded — there is no partial-entropy pool state
    // to honour it with. On any machine with a hardware RNG the pool
    // seeds during Stage::Subsys init, before userspace runs, so the
    // refusal window is "hardware with no RNG source", not early boot.
    if ptr == 0 {
        // `import_ubuf`'s `access_ok` arm.
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if len > MAX_USER_COPY {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // Generate random bytes into a kernel buffer, then copy to user
    // space under the SMAP bracket.
    let mut kbuf = alloc::vec![0u8; len];
    // The same ChaCha20 pool `/dev/random` and `/dev/urandom` read from
    // (`drivers/char/random.c` backs `getrandom(2)` with the identical CRNG).
    //
    // This used to assemble the buffer from `next_random_u32()`, which tries
    // RDSEED, then RDRAND, then a Park-Miller LCG seeded from
    // `monotonic_ns ^ cycles`. `rdseed_u64` is a stub returning None, and on
    // aarch64 so is `rdrand_u64` — so on that arch every getrandom(2) byte
    // came from a clock-seeded LCG, which is trivially invertible from a few
    // outputs. That is the interface glibc/musl `arc4random`, TLS and SSH key
    // generation, and stack-canary/ASLR seeding all draw from. The CSPRNG
    // module exists precisely to replace that LCG (its header cites the
    // Wave-13/Wave-35 audits) and already prefers RNDRRS/RNDR on aarch64;
    // getrandom simply never used it.
    //
    // Since #1026 the fill is the fallible `try_fill`: the pool seeds
    // only from hardware entropy through narf-crypto's fail-closed
    // surface, and an unseeded pool refuses here (see the crng_ready
    // note above) rather than serving weaker bytes.
    if narf_filesystem::csprng::try_fill(&mut kbuf).is_err() {
        ctx.set_return(errno_ret(EAGAIN));
        return;
    }
    // SAFETY: `ptr` is the user buffer (non-zero, `len <= MAX_USER_COPY`, both
    // checked above); copy_to_user range-validates it and SMAP-brackets the write of `kbuf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(ptr, &kbuf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-EFAULT) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(len as u64));
}
