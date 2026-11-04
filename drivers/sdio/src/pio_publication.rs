// SPDX-License-Identifier: GPL-2.0-or-later
//! Only actual COMMAND publication runs under this kernel fixed scope.
//! Inhibit/response/FIFO waits and terminal failure handling stay outside.
use super::{Error, Registers};
use crate::sdhci::regs::{COMMAND, INT_CARD_INT, INT_ENABLE, INT_STATUS};

/// A kernel producer's fixed original authority scope, prepared before native
/// State. It must invoke the supplied actual action once inside that scope;
/// no provider/socket callbacks, hardware waits or fresh authority lookup.
/// This supplies no native host/Card permission; those remain independent.
pub trait Publication {
    fn publish(&mut self, command: &mut dyn FnMut()) -> Result<(), Error>;
}
#[derive(Debug)]
pub(super) struct Immediate;
pub(super) struct Mode<'a> {
    pub(super) scope: &'a mut dyn Publication,
    pub(super) observe_pending: bool,
}

impl Publication for Immediate {
    fn publish(&mut self, command: &mut dyn FnMut()) -> Result<(), Error> {
        command();
        Ok(())
    }
}
pub(super) fn issue(io: &mut impl Registers, word: u16, mode: Mode<'_>) -> Result<(), Error> {
    let mut attempts = 0u8;
    let mut issued = false;
    let mut pending = false;
    let mut gone = false;
    let result = mode.scope.publish(&mut || {
        attempts = attempts.saturating_add(1);
        if attempts != 1 {
            return;
        }
        if mode.observe_pending {
            let enabled = io.read32(INT_ENABLE);
            let status = io.read32(INT_STATUS);
            if status == u32::MAX || enabled == u32::MAX {
                gone = true;
                return;
            }
            if enabled & INT_CARD_INT == 0 {
                return;
            }
            if status & INT_CARD_INT != 0 {
                pending = true;
                return;
            }
        }
        issued = true;
        io.write16(COMMAND, word);
    });
    if gone {
        return Err(Error::Gone);
    }
    match (result, issued, attempts, pending) {
        (Ok(()), true, 1, _) => Ok(()),
        (Ok(()), false, 1, true) => Err(Error::Busy),
        (_, false, _, _) => Err(Error::Denied),
        // Action entry may have issued a native command. Never turn a late
        // denial/duplicate action into definitely-unissued retry credit.
        _ => Err(Error::Failed),
    }
}
