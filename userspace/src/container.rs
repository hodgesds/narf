//! Container-personality stub.
//!
//! Gated on `#[cfg(feature = "container")]`.  Waves 63-67 will land
//! the real implementations here:
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
//! Nothing is exported yet; the module exists so downstream crates can
//! write `#[cfg(feature = "container")] use narf_userspace::container;`
//! without a compile error.
