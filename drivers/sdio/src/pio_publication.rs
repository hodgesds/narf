// SPDX-License-Identifier: GPL-2.0-or-later
//! Only actual COMMAND publication runs under this kernel fixed scope.
//! Inhibit/response/FIFO waits and terminal failure handling stay outside.
use super::{Error, Registers};
use crate::sdhci::regs::COMMAND;

/// A kernel producer's fixed original authority scope, prepared before native
/// State. It must invoke the supplied actual action once inside that scope;
/// no provider/socket callbacks, hardware waits or fresh authority lookup.
/// This supplies no native host/Card permission; those remain independent.
pub trait Publication {
    fn publish(&mut self, command: &mut dyn FnMut()) -> Result<(), Error>;
}
#[derive(Debug)]
pub(super) struct Immediate;
impl Publication for Immediate {
    fn publish(&mut self, command: &mut dyn FnMut()) -> Result<(), Error> {
        command();
        Ok(())
    }
}
pub(super) fn issue(
    io: &mut impl Registers,
    word: u16,
    scope: &mut dyn Publication,
) -> Result<(), Error> {
    let mut attempts = 0u8;
    let result = scope.publish(&mut || {
        attempts = attempts.saturating_add(1);
        if attempts == 1 {
            io.write16(COMMAND, word);
        }
    });
    match (result, attempts) {
        (Ok(()), 1) => Ok(()),
        (_, 0) => Err(Error::Denied),
        // Action entry may have issued a native command. Never turn a late
        // denial/duplicate action into definitely-unissued retry credit.
        _ => Err(Error::Failed),
    }
}
