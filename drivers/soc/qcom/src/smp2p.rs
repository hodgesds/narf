//! Shared Memory Point-to-Point (SMP2P).
//!
//! Linux `drivers/soc/qcom/smp2p.c`. Each direction of an edge is one
//! SMEM item written by a single side:
//!
//! ```text
//! 0   u32 magic ("$SMP")      12  u16 total_entries, u16 valid_entries
//! 4   u8 version, u24 features 16 u32 flags (SSR restart done / ack)
//! 8   u16 local_pid, u16 remote_pid
//! 20  entries[16] { u8 name[16]; u32 value; }
//! ```
//!
//! Outbound entries are named 32-bit "states" the local side drives
//! (`qcom_smem_state_update_bits`); inbound entries are the remote's
//! values, each bit a virtual edge-triggered interrupt. The remoteproc
//! uses inbound `slave-kernel` bits 0..3 (+7 on WPSS) as its
//! fatal/ready/handover/stop-ack(/shutdown-ack) interrupts and outbound
//! `master-kernel` bit 0 as `stop`; ath11k on WCN6750 drives the `wlan`
//! outbound entry for WoW power-save messages.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hwlock::HwSpinlock;
use crate::io::RegIo;
use crate::ipc::Kick;
use crate::smem::{Smem, SmemError, SmemItem};

pub const SMP2P_MAGIC: u32 = 0x504d_5324;
pub const SMP2P_MAX_ENTRY: u32 = 16;
pub const SMP2P_MAX_ENTRY_NAME: usize = 16;
pub const SMP2P_FEATURE_SSR_ACK: u32 = 0x1;
pub const SMP2P_ALL_FEATURES: u32 = SMP2P_FEATURE_SSR_ACK;
pub const FLAGS_RESTART_DONE_BIT: u32 = 0;
pub const FLAGS_RESTART_ACK_BIT: u32 = 1;
/// `sizeof(struct smp2p_smem_item)`.
pub const ITEM_SIZE: u32 = 20 + SMP2P_MAX_ENTRY * 20;

const OFF_MAGIC: u32 = 0;
const OFF_VERSION: u32 = 4;
const OFF_PIDS: u32 = 8;
const OFF_ENTRIES_N: u32 = 12;
const OFF_FLAGS: u32 = 16;
const OFF_ENTRY: u32 = 20;

/// SMP2P failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Smp2pError {
    Smem(SmemError),
    /// All 16 outbound entries are in use.
    Full,
    /// Entry name longer than 15 bytes.
    BadName,
    /// Unknown handle.
    BadHandle,
    /// The outbound item is smaller than `struct smp2p_smem_item`.
    ItemTooSmall,
}

impl From<SmemError> for Smp2pError {
    fn from(e: SmemError) -> Self {
        Smp2pError::Smem(e)
    }
}

/// Static description of one edge (`qcom,smem`, `qcom,local-pid`,
/// `qcom,remote-pid`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Smp2pConfig {
    /// `qcom,smem = <inbound outbound>`.
    pub smem_in: u32,
    pub smem_out: u32,
    pub local_pid: u16,
    pub remote_pid: u16,
}

/// Outbound entry handle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OutHandle(usize);
/// Inbound entry handle.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct InHandle(usize);

#[derive(Clone, Debug)]
struct InEntry {
    name: String,
    /// Offset of `value` in the SMEM region once the remote created it.
    value: Option<u32>,
    last_value: u32,
    enabled: u32,
    rising: u32,
    falling: u32,
}

#[derive(Clone, Debug)]
struct OutEntry {
    value: u32,
}

/// An inbound virtual-interrupt edge delivered by
/// [`Smp2p::handle_interrupt`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Smp2pIrq {
    pub entry: InHandle,
    pub bit: u32,
    /// Level after the change (rising edge = true).
    pub high: bool,
}

/// One SMP2P edge (`struct qcom_smp2p`).
#[derive(Debug)]
pub struct Smp2p<K: Kick> {
    cfg: Smp2pConfig,
    kick: K,
    out: SmemItem,
    inb: Option<SmemItem>,
    valid_entries: u32,
    negotiation_done: bool,
    ssr_ack_enabled: bool,
    ssr_ack: bool,
    inbound: Vec<InEntry>,
    outbound: Vec<OutEntry>,
}

fn name_words(name: &str) -> Result<[u32; 4], Smp2pError> {
    let b = name.as_bytes();
    if b.len() >= SMP2P_MAX_ENTRY_NAME {
        return Err(Smp2pError::BadName);
    }
    let mut raw = [0u8; 16];
    raw[..b.len()].copy_from_slice(b);
    let mut w = [0u32; 4];
    for (i, c) in raw.chunks_exact(4).enumerate() {
        w[i] = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    Ok(w)
}

impl<K: Kick> Smp2p<K> {
    /// `qcom_smp2p_alloc_outbound_item`: allocate (or reuse) the outbound
    /// item, zero it, write the header, then publish `version = 1` last
    /// and kick.
    pub async fn new<R: RegIo, L: HwSpinlock>(
        smem: &Smem<R>,
        lock: &L,
        cfg: Smp2pConfig,
        kick: K,
    ) -> Result<Self, Smp2pError> {
        match smem
            .alloc(lock, cfg.remote_pid, cfg.smem_out, ITEM_SIZE)
            .await
        {
            Ok(()) | Err(SmemError::Exists) => {}
            Err(e) => return Err(e.into()),
        }
        let out = smem.get(cfg.remote_pid, cfg.smem_out)?;
        if out.len < ITEM_SIZE {
            return Err(Smp2pError::ItemTooSmall);
        }
        let m = smem.mem();
        for w in 0..ITEM_SIZE / 4 {
            m.write32(out.offset + w * 4, 0);
        }
        m.write32(out.offset + OFF_MAGIC, SMP2P_MAGIC);
        m.write32(
            out.offset + OFF_PIDS,
            cfg.local_pid as u32 | ((cfg.remote_pid as u32) << 16),
        );
        m.write32(out.offset + OFF_ENTRIES_N, SMP2P_MAX_ENTRY);
        // features in the upper 24 bits of the version word; version 0
        // until the rest is visible.
        m.write32(out.offset + OFF_VERSION, SMP2P_ALL_FEATURES << 8);
        m.write32(out.offset + OFF_VERSION, (SMP2P_ALL_FEATURES << 8) | 1);
        kick.kick();
        Ok(Self {
            cfg,
            kick,
            out,
            inb: None,
            valid_entries: 0,
            negotiation_done: false,
            ssr_ack_enabled: false,
            ssr_ack: false,
            inbound: Vec::new(),
            outbound: Vec::new(),
        })
    }

    pub fn config(&self) -> Smp2pConfig {
        self.cfg
    }
    pub fn negotiated(&self) -> bool {
        self.negotiation_done
    }
    pub fn ssr_ack_enabled(&self) -> bool {
        self.ssr_ack_enabled
    }
    /// The outbound item (tests and the remote-side fixture read it).
    pub fn outbound_item(&self) -> SmemItem {
        self.out
    }

    /// `qcom_smp2p_outbound_entry`: claim the next entry slot.
    pub fn add_outbound<R: RegIo>(
        &mut self,
        smem: &Smem<R>,
        name: &str,
    ) -> Result<OutHandle, Smp2pError> {
        let words = name_words(name)?;
        let m = smem.mem();
        let n = m.read32(self.out.offset + OFF_ENTRIES_N) >> 16;
        if n >= SMP2P_MAX_ENTRY {
            return Err(Smp2pError::Full);
        }
        let e = self.out.offset + OFF_ENTRY + n * 20;
        for (i, w) in words.iter().enumerate() {
            m.write32(e + i as u32 * 4, *w);
        }
        m.write32(e + 16, 0);
        m.write32(
            self.out.offset + OFF_ENTRIES_N,
            SMP2P_MAX_ENTRY | ((n + 1) << 16),
        );
        self.outbound.push(OutEntry { value: e + 16 });
        Ok(OutHandle(self.outbound.len() - 1))
    }

    /// `smp2p_update_bits` (`qcom_smem_state_update_bits`): kick only if
    /// the value changed.
    pub fn update_bits<R: RegIo>(
        &self,
        smem: &Smem<R>,
        h: OutHandle,
        mask: u32,
        value: u32,
    ) -> Result<(), Smp2pError> {
        let e = self.outbound.get(h.0).ok_or(Smp2pError::BadHandle)?;
        let m = smem.mem();
        let orig = m.read32(e.value);
        let v = (orig & !mask) | (value & mask);
        m.write32(e.value, v);
        if v != orig {
            self.kick.kick();
        }
        Ok(())
    }

    /// Current outbound value.
    pub fn outbound_value<R: RegIo>(&self, smem: &Smem<R>, h: OutHandle) -> Option<u32> {
        let e = self.outbound.get(h.0)?;
        Some(smem.mem().read32(e.value))
    }

    /// Register an inbound entry (`slave-kernel`, `wlan`, ...).
    pub fn add_inbound(&mut self, name: &str) -> Result<InHandle, Smp2pError> {
        name_words(name)?;
        self.inbound.push(InEntry {
            name: String::from(name),
            value: None,
            last_value: 0,
            enabled: 0,
            rising: 0,
            falling: 0,
        });
        Ok(InHandle(self.inbound.len() - 1))
    }

    /// `smp2p_set_irq_type` + `smp2p_unmask_irq` for one bit.
    pub fn enable_irq(
        &mut self,
        h: InHandle,
        bit: u32,
        rising: bool,
        falling: bool,
    ) -> Result<(), Smp2pError> {
        let e = self.inbound.get_mut(h.0).ok_or(Smp2pError::BadHandle)?;
        let b = 1u32 << (bit & 31);
        e.enabled |= b;
        if rising {
            e.rising |= b;
        } else {
            e.rising &= !b;
        }
        if falling {
            e.falling |= b;
        } else {
            e.falling &= !b;
        }
        Ok(())
    }

    /// `smp2p_mask_irq`.
    pub fn disable_irq(&mut self, h: InHandle, bit: u32) -> Result<(), Smp2pError> {
        let e = self.inbound.get_mut(h.0).ok_or(Smp2pError::BadHandle)?;
        e.enabled &= !(1 << (bit & 31));
        Ok(())
    }

    /// `qcom_smp2p_intr`: the edge's incoming IPC interrupt. Locates the
    /// remote item, negotiates features, matches newly-created remote
    /// entries by name, and returns every enabled bit whose edge matches
    /// its trigger type; then acknowledges an SSR restart if one is
    /// pending.
    pub fn handle_interrupt<R: RegIo>(&mut self, smem: &Smem<R>) -> Vec<Smp2pIrq> {
        let mut fired = Vec::new();
        if self.inb.is_none() {
            match smem.get(self.cfg.remote_pid, self.cfg.smem_in) {
                Ok(i) if i.len >= ITEM_SIZE => self.inb = Some(i),
                _ => return fired,
            }
        }
        let Some(inb) = self.inb else {
            return fired;
        };
        let m = smem.mem();
        if !self.negotiation_done {
            let in_ver = m.read32(inb.offset + OFF_VERSION);
            let out_ver = m.read32(self.out.offset + OFF_VERSION);
            if in_ver & 0xff == out_ver & 0xff {
                let features = (out_ver >> 8) & (in_ver >> 8);
                m.write32(
                    self.out.offset + OFF_VERSION,
                    (features << 8) | (out_ver & 0xff),
                );
                self.ssr_ack_enabled = features & SMP2P_FEATURE_SSR_ACK != 0;
                self.negotiation_done = true;
            }
        }
        if !self.negotiation_done {
            return fired;
        }
        // qcom_smp2p_check_ssr
        let ack_restart = self.ssr_ack_enabled
            && ((m.read32(inb.offset + OFF_FLAGS) >> FLAGS_RESTART_DONE_BIT) & 1 != 0)
                != self.ssr_ack;
        // qcom_smp2p_notify_in: match newly valid remote entries.
        let in_valid = (m.read32(inb.offset + OFF_ENTRIES_N) >> 16).min(SMP2P_MAX_ENTRY);
        for i in self.valid_entries..in_valid {
            let e = inb.offset + OFF_ENTRY + i * 20;
            let mut raw = [0u8; 16];
            for w in 0..4u32 {
                raw[w as usize * 4..w as usize * 4 + 4]
                    .copy_from_slice(&m.read32(e + w * 4).to_le_bytes());
            }
            let len = raw.iter().position(|&b| b == 0).unwrap_or(16);
            for ent in self.inbound.iter_mut() {
                if ent.value.is_none() && ent.name.as_bytes() == &raw[..len] {
                    ent.value = Some(e + 16);
                    break;
                }
            }
        }
        self.valid_entries = in_valid.max(self.valid_entries);
        for (idx, ent) in self.inbound.iter_mut().enumerate() {
            let Some(vo) = ent.value else { continue };
            let val = m.read32(vo);
            let status = val ^ ent.last_value;
            ent.last_value = val;
            if status == 0 {
                continue;
            }
            for bit in 0..32 {
                let b = 1u32 << bit;
                if ent.enabled & b == 0 || status & b == 0 {
                    continue;
                }
                let high = val & b != 0;
                if (high && ent.rising & b != 0) || (!high && ent.falling & b != 0) {
                    fired.push(Smp2pIrq {
                        entry: InHandle(idx),
                        bit,
                        high,
                    });
                }
            }
        }
        if ack_restart {
            // qcom_smp2p_do_ssr_ack
            self.ssr_ack = !self.ssr_ack;
            let f = m.read32(self.out.offset + OFF_FLAGS) & !(1 << FLAGS_RESTART_ACK_BIT);
            m.write32(
                self.out.offset + OFF_FLAGS,
                f | ((self.ssr_ack as u32) << FLAGS_RESTART_ACK_BIT),
            );
            self.kick.kick();
        }
        fired
    }
}
