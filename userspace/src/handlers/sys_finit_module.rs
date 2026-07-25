#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_finit_module(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    // arg1 = params_ptr, arg2 = flags — both ignored in Phase 1.
    // Read the file via the fd table.
    let task = current_task_id();
    let outcome = fd::with_table(task, |t| {
        let entry = t.get_mut(fd).ok_or(())?;
        let mut accum = alloc::vec::Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let off = entry.offset;
            let n = poll_blocking(entry.ops.read(off, &mut buf))
                .and_then(|r| r.ok())
                .unwrap_or(0);
            if n == 0 {
                break;
            }
            accum.extend_from_slice(&buf[..n]);
            entry.offset = off + n as u64;
            if accum.len() > (1 << 28) {
                return Err(());
            }
        }
        Ok(accum)
    });
    match outcome {
        Some(Ok(bytes)) => ctx.set_return(SyscallReturn::ok(init_module_result(
            narf_modules::syscalls::sys_finit_module(&bytes),
        ))),
        _ => ctx.set_return(SyscallReturn::ok((-9i64) as u64)),
    }
}
