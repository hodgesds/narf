//! Container-personality feature marker.
//!
//! Gated on `#[cfg(feature = "container")]`. The implementations live in
//! their owning modules rather than this marker module:
//!
//! - PID namespace (clone CLONE_NEWPID, pid_ns_init)
//! - Mount namespace (CLONE_NEWNS, pivot_root, mount propagation)
//! - Network namespace (CLONE_NEWNET, veth pairs)
//! - UTS namespace (CLONE_NEWUTS, sethostname)
//! - IPC namespace (CLONE_NEWIPC)
//! - User namespace (CLONE_NEWUSER, uid/gid maps)
//!
//! Orthogonal to `linux-compat`: a native NARF container runtime can
//! use namespaces without the full Linux syscall surface.
//!
//! This module remains as a stable feature-presence import for downstream
//! crates; namespace types and operations are exported by `namespaces`,
//! `pid_ns`, the syscall handlers, and `narf_filesystem`.
