// SPDX-License-Identifier: GPL-2.0-or-later
//! Independent native WPA2 RSN snapshots; never cryptographic PMF evidence.
use alloc::{vec, vec::Vec};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Hold {
    None,
    Mode,
    Request,
    Response,
}
#[derive(Clone, Debug)]
pub(crate) struct Conversation {
    pub mode: u32,
    pub ap: Vec<u8>,
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
    pub hold: Hold,
    pub keys: bool,
}
impl Conversation {
    pub(crate) fn new(mode: u32, ap: u8) -> Self {
        Self {
            mode,
            ap: rsne(ap),
            request: None,
            response: None,
            hold: Hold::None,
            keys: true,
        }
    }
    pub(crate) fn response(&self) -> Vec<u8> {
        self.response.clone().unwrap_or_else(|| self.ap.clone())
    }
    pub(crate) fn expected_request(&self, secure: bool) -> Vec<u8> {
        if !secure {
            Vec::new()
        } else {
            rsne(match self.mode {
                0 => 0,
                1 => 128,
                2 => 192,
                _ => panic!("native fixture mode"),
            })
        }
    }
}
pub(crate) fn rsne(bits: u8) -> Vec<u8> {
    let mut ie = vec![
        48, 20, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2, bits, 0,
    ];
    if bits != 0 {
        ie[1] = 26;
        ie.extend_from_slice(&[0, 0, 0, 15, 172, 6]);
    }
    ie
}
