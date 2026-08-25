#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_finit_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    // arg1 = params_ptr, arg2 = flags — both ignored in Phase 1.
    // Read the file via the fd table.
    let task = current_task_id();
    let resolved = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        Some((entry.ops.clone(), t.offset(fd)?))
    })
    .flatten();
    let outcome = resolved.map(|(ops, mut offset)| {
        let mut accum = alloc::vec::Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let n = poll_blocking(ops.read(offset, &mut buf))
                .and_then(|r| r.ok())
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            accum.extend_from_slice(&buf[..n]);
            offset = offset.saturating_add(n as u64);
            if accum.len() > (1 << 28) {
                return Err(());
            }
        }
        let _ = fd::with_table(task, |t| t.set_offset(fd, offset));
        Ok(accum)
    });
    match outcome {
        Some(Ok(bytes)) => ctx.set_return(SyscallReturn::ok(init_module_result(
            narf_modules::syscalls::sys_finit_module(&bytes),
        ))),
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
