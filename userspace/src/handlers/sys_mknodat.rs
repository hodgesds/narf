#[allow(unused_imports)]
use super::*;

/// Linux `mknodat(dirfd, pathname, mode, dev)` (and `mknod`, which musl
/// routes through mknodat with AT_FDCWD). Creates a filesystem node.
///
/// NARF has no FIFO / socket / character / block node types, so every
/// non-directory node is created as a regular file. That's enough for the
/// callers that matter: elogind/systemd create a per-session `.ref` FIFO
/// (and `/run/systemd/inaccessible/{reg,fifo,sock,chr,blk}` sandbox nodes)
/// and only need the node to EXIST and be openable — without it, elogind's
/// `CreateSession` fails with EINVAL and no logind session is ever created
/// (which a Wayland compositor needs to TakeDevice the GPU). A `S_IFDIR`
/// request is routed to the directory-create path for correctness.
pub(crate) fn sys_mknodat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // mknodat(dirfd, path, mode, dev): path=arg1, mode=arg2, dev=arg3.
    let ret = mknod_common(args.arg1, args.arg2, args.arg3);
    ctx.set_return(ret);
}
