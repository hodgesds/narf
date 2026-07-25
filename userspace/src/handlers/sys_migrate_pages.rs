#[allow(unused_imports)]
use super::*;

/// `migrate_pages(pid, maxnode, old_nodes, new_nodes)` — migrate a
/// process's pages between node sets. NARF is effectively single-node for
/// placement, so this is a no-op: 0 pages could not be migrated.
pub(crate) fn sys_migrate_pages(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::ok(0));
}
