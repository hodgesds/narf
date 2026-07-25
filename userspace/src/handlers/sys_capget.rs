#[allow(unused_imports)]
use super::*;

/// `capget(hdrp, datap)` — read a task's capability sets.
pub(crate) fn sys_capget(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let hdrp = a.arg0;
    let datap = a.arg1;
    if hdrp == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let mut hdr = [0u8; 8];
    // SAFETY: hdrp checked non-zero; copy_from_user range-validates the read.
    if unsafe { copy_from_user(&mut hdr, hdrp) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let version = u32::from_le_bytes(hdr[..4].try_into().unwrap());
    let pid = i32::from_le_bytes(hdr[4..].try_into().unwrap());
    let ndata = match cap_ndata(version) {
        Some(n) => n,
        None => {
            // Linux rewrites the header to the preferred version and
            // returns EINVAL so the caller can retry.
            hdr[..4].copy_from_slice(&CAP_VERSION_3.to_le_bytes());
            // SAFETY: hdrp validated by the read above; same 8-byte range.
            let _ = unsafe { copy_to_user(hdrp, &hdr) };
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };
    // datap == NULL is a version probe — succeed without writing data.
    if datap == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let task = if pid == 0 {
        current_task_id()
    } else {
        pid as u64
    };
    let caps = {
        let g = CAP_TABLE.lock();
        g.as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or([0; 3])
    };
    let mut out = alloc::vec![0u8; ndata * 12];
    for (field, &val) in caps.iter().enumerate() {
        // data[0] carries the low 32 bits; data[1] (v2/v3) the high.
        out[field * 4..field * 4 + 4].copy_from_slice(&(val as u32).to_le_bytes());
        if ndata == 2 {
            let hi = (val >> 32) as u32;
            out[12 + field * 4..12 + field * 4 + 4].copy_from_slice(&hi.to_le_bytes());
        }
    }
    // SAFETY: datap checked non-zero; copy_to_user range-validates the write.
    if unsafe { copy_to_user(datap, &out) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}
