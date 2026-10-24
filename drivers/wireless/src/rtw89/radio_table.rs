// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
//! Checked Linux PHY pair-table/headline selection. No register publication.
use alloc::vec::Vec;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pair(pub u32, pub u32);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Empty,
    Profile,
    Grammar,
}
fn target(pair: Pair) -> u32 {
    pair.0 & 0x0fff_ffff
}
fn select(table: &[Pair], rfe: u8, cut: u8) -> Result<(usize, u32), Error> {
    if table.is_empty() {
        return Err(Error::Empty);
    }
    let headlines = table.iter().take_while(|p| p.0 >> 28 == 15).count();
    if headlines == 0 {
        return Ok((0, target(table[0])));
    }
    let header = &table[..headlines];
    let exact = (u32::from(rfe) << 16) | u32::from(cut);
    let wildcard = (u32::from(rfe) << 16) | 255;
    for wanted in [exact, wildcard] {
        if let Some(pair) = header.iter().find(|p| target(**p) == wanted) {
            return Ok((headlines, target(*pair)));
        }
    }
    for wanted in [rfe, 255] {
        // max_by_key chooses the last equal-cut headline, matching Linux's >=.
        if let Some(pair) = header
            .iter()
            .filter(|p| ((p.0 >> 16) & 255) == u32::from(wanted))
            .max_by_key(|p| p.0 & 255)
        {
            return Ok((headlines, target(*pair)));
        }
    }
    Err(Error::Profile)
}
/// Validate/select the complete immutable table before its first device write.
/// Malformed syntax never yields a successful partially selected program.
pub(super) fn program(table: &[Pair], rfe: u8, cut: u8) -> Result<Vec<Pair>, Error> {
    let (headlines, configured) = select(table, rfe, cut)?;
    let mut output = Vec::new();
    let mut branch = false;
    let mut check = false;
    let mut matched = true;
    let mut found = false;
    let mut chosen = 0;
    for &pair in &table[headlines..] {
        match pair.0 >> 28 {
            8 => {
                if branch {
                    return Err(Error::Grammar);
                }
                branch = true;
                check = true;
                chosen = target(pair);
            }
            9 => {
                if !branch || check {
                    return Err(Error::Grammar);
                }
                check = true;
                chosen = target(pair);
            }
            4 => {
                if !branch || !check {
                    return Err(Error::Grammar);
                }
                check = false;
                matched = !found && chosen == configured;
                found |= matched;
            }
            10 => {
                if !branch || check || !found {
                    return Err(Error::Grammar);
                }
                matched = false;
            }
            11 => {
                if !branch || check {
                    return Err(Error::Grammar);
                }
                branch = false;
                matched = true;
                found = false;
            }
            15 => return Err(Error::Grammar),
            _ => {
                if check {
                    return Err(Error::Grammar);
                }
                if matched {
                    output.push(pair);
                }
            }
        }
    }
    if branch {
        return Err(Error::Grammar);
    }
    Ok(output)
}
#[cfg(any(test, feature = "kernel-test"))]
#[path = "radio_table/tests.rs"]
mod tests;
