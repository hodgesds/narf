#[allow(unused_imports)]
use super::*;

/// `get_mempolicy(mode, nodemask, maxnode, addr, flags)` — report the
/// policy in force. Honors the query flags:
/// - `MPOL_F_ADDR`: report the policy covering `addr` (an mbind range,
///   else the task default).
/// - `MPOL_F_NODE` (with `MPOL_F_ADDR`): write the node the page at
///   `addr` would allocate from into `*mode`.
/// - `MPOL_F_MEMS_ALLOWED`: write the set of allowed nodes into the
///   nodemask (all online nodes here).
pub(crate) fn sys_get_mempolicy(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let mode_ptr = a.arg0;
    let nodemask_ptr = a.arg1;
    let addr = a.arg3;
    let flags = a.arg4 as u32;
    let task = current_task_id();

    if flags & MPOL_F_MEMS_ALLOWED != 0 {
        // Report the mask of nodes this task may use: every online node.
        let n = numa_node_count().min(64);
        let allowed: u64 = if n >= 64 { u64::MAX } else { (1u64 << n) - 1 };
        if nodemask_ptr != 0 {
            // SAFETY: copy_to_user validates the user pointer/length.
            let _ = unsafe { copy_to_user(nodemask_ptr, &allowed.to_le_bytes()) };
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    let (mode, nodemask) = if flags & MPOL_F_ADDR != 0 {
        resolve_policy(task, addr)
    } else {
        MEMPOLICY_TABLE
            .lock()
            .as_ref()
            .and_then(|m| m.get(&task).copied())
            .unwrap_or((0, 0)) // MPOL_DEFAULT
    };

    if mode_ptr != 0 {
        let out_word: i32 = if flags & MPOL_F_NODE != 0 && flags & MPOL_F_ADDR != 0 {
            // Report the node the page at `addr` would come from.
            let pol = narf_memory::Mempolicy {
                mode: mode & !MPOL_MODE_FLAGS,
                nodemask,
            };
            mempolicy_resolved_node(pol) as i32
        } else {
            mode as i32
        };
        // SAFETY: mode_ptr is the user int out-pointer; copy_to_user validates it.
        if unsafe { copy_to_user(mode_ptr, &out_word.to_le_bytes()) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    }
    if nodemask_ptr != 0 {
        // SAFETY: nodemask_ptr is the user unsigned-long array; copy_to_user validates it.
        let _ = unsafe { copy_to_user(nodemask_ptr, &nodemask.to_le_bytes()) };
    }
    ctx.set_return(SyscallReturn::ok(0));
}
