//! Hibernation (S4): the pieces of Linux's `kernel/power/hibernate.c` that
//! run in the hibernating kernel. The plan of work is in
//! `power/research/s4-hibernation-plan.md`. The key custody, the sealed
//! image format and the resume pipeline live in
//! [`crate::suspend_service`].

pub mod image_file;
pub mod payload;
pub mod snapshot;
