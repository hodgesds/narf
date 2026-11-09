//! I225/I226 control protocol. Reference: ~/git/linux ecd997b0189a,
//! drivers/net/ethernet/intel/igc/{igc_base,igc_phy,igc_i225,igc_main}.c.
//! Register access and deadlines are injected so tests run the real protocol.

use super::protocol::IgcError;

#[cfg(feature = "builtin")]
pub(crate) fn wait_until(us: u64, ready: impl FnMut() -> bool) -> bool {
    // The predicate may acquire a read-to-set hardware semaphore. Preserve
    // the waiter's result; evaluating it again can lose or repeat ownership.
    narf_scheduler::responsive_spin_until(ready, narf_time::Deadline::after_us(us))
}

pub(crate) trait Registers {
    fn read(&self, reg: u64) -> u32;
    fn write(&self, reg: u64, value: u32);
    fn wait(&self, us: u64, ready: impl FnMut() -> bool) -> bool;
    fn delay(&self, us: u64);
    fn flush(&self) {
        let _ = self.read(8);
    }
}

// Keep the timeout construction at the caller: outlining its enum copy can
// introduce an unavailable memcpy relocation in the standalone ARM module.
#[inline(always)]
pub(crate) fn poll(r: &impl Registers, reg: u64, mask: u32, value: u32) -> Result<(), IgcError> {
    if r.wait(100_000, || {
        let observed = r.read(reg);
        observed != u32::MAX && observed & mask == value
    }) {
        Ok(())
    } else {
        Err(IgcError::RegisterTimeout {
            register: reg,
            mask,
            expected: value,
            observed: r.read(reg),
        })
    }
}

/// No buffer can be freed or reused until this returns successfully.
pub(crate) fn quiesce(r: &impl Registers, queues: usize) -> Result<(), IgcError> {
    r.write(0x150c, u32::MAX);
    r.write(0x1528, u32::MAX);
    r.write(0x100, 0);
    r.write(0x400, 8);
    for q in 0..queues {
        r.write(0xc028 + q as u64 * 0x40, 0);
        r.write(0xe028 + q as u64 * 0x40, 0);
    }
    r.flush();
    r.write(0, r.read(0) | 4); // GIO_MASTER_DISABLE
    r.flush();
    poll(r, 8, 0x80000, 0)
}

pub(crate) fn reset(r: &impl Registers, queues: usize) -> Result<(), IgcError> {
    quiesce(r, queues)?;
    r.delay(10_000);
    r.write(0, r.read(0) | (1 << 26));
    r.flush();
    poll(r, 0, 1 << 26, 0)?;
    poll(r, 0x10, 0x200, 0x200)?; // EECD.AUTO_RD_DONE
    r.write(0x150c, u32::MAX);
    r.write(0x1528, u32::MAX);
    let _ = r.read(0x1500);
    // Restore PCIe master requests and software ownership after auto-load.
    r.write(0, (r.read(0) & !4) | 0x40);
    r.write(0x18, r.read(0x18) | 0x10000000);
    Ok(())
}

#[cfg(feature = "builtin")]
pub(crate) fn reset_queues<Q: core::borrow::Borrow<super::queue::Queue>>(
    r: &impl Registers,
    queues: &[Q],
) -> Result<(), IgcError> {
    reset(r, queues.len())?;
    for queue in queues {
        // SAFETY: reset completed only after PCIe master drain was acknowledged.
        unsafe {
            queue.borrow().reset_after_quiesce();
        }
    }
    Ok(())
}

fn semaphore(r: &impl Registers) -> Result<(), IgcError> {
    if !r.wait(100_000, || {
        let s = r.read(0x5b50); // SMBI is acquired by the read.
        if s & 1 != 0 {
            return false;
        }
        r.write(0x5b50, r.read(0x5b50) | 2);
        if r.read(0x5b50) & 2 != 0 {
            return true;
        }
        r.write(0x5b50, r.read(0x5b50) & !3);
        false
    }) {
        return Err(IgcError::Other("hardware semaphore busy"));
    }
    Ok(())
}

fn unlock(r: &impl Registers) {
    r.write(0x5b50, r.read(0x5b50) & !3);
}

fn phy_transaction<T>(
    r: &impl Registers,
    f: impl FnOnce() -> Result<T, IgcError>,
) -> Result<T, IgcError> {
    swfw_transaction(r, 2, f)
}
fn swfw_transaction<T>(
    r: &impl Registers,
    mask: u32,
    f: impl FnOnce() -> Result<T, IgcError>,
) -> Result<T, IgcError> {
    let mut acquired = false;
    let mut hw_error = false;
    r.wait(1_000_000, || {
        if semaphore(r).is_err() {
            hw_error = true;
            return true;
        }
        let s = r.read(0x5b5c);
        if s & (mask | (mask << 16)) == 0 {
            r.write(0x5b5c, s | mask);
            acquired = true;
        }
        unlock(r);
        acquired
    });
    if hw_error || !acquired {
        return Err(IgcError::Other("PHY owned by firmware"));
    }
    let result = f();
    // A release failure is an error too; never steal firmware's semaphore.
    semaphore(r)?;
    r.write(0x5b5c, r.read(0x5b5c) & !mask);
    unlock(r);
    result
}

fn mdio(r: &impl Registers, reg: u8, value: Option<u16>) -> Result<u16, IgcError> {
    let command = (u32::from(reg) << 16)
        | (1 << 21)
        | value.map_or(0x08000000, |v| 0x04000000 | u32::from(v));
    r.write(0x20, command);
    if !r.wait(30_000, || r.read(0x20) & 0x10000000 != 0) {
        return Err(IgcError::Other("MDIC timeout"));
    }
    let result = r.read(0x20);
    if result & 0x40000000 != 0 || (result >> 16) & 31 != u32::from(reg) {
        return Err(IgcError::Other("MDIC completion error"));
    }
    Ok(result as u16)
}

fn mmd(r: &impl Registers, dev: u16, reg: u16, value: Option<u16>) -> Result<u16, IgcError> {
    mdio(r, 13, Some(dev))?;
    mdio(r, 14, Some(reg))?;
    mdio(r, 13, Some(dev | 0x4000))?;
    let result = mdio(r, 14, value);
    let cleanup = mdio(r, 13, Some(0));
    cleanup?;
    result
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LinkPolicy {
    pub advertised: u32,
    pub autoneg: bool,
    pub speed_mbps: u32,
    pub full_duplex: bool,
}
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PausePolicy {
    pub autoneg: bool,
    pub rx: bool,
    pub tx: bool,
}
pub(crate) fn setup_phy(r: &impl Registers, gigabit_only: bool) -> Result<(), IgcError> {
    setup_link(
        r,
        gigabit_only,
        &LinkPolicy {
            advertised: 0x3f,
            autoneg: true,
            speed_mbps: 0,
            full_duplex: true,
        },
        PausePolicy::default(),
        false,
    )
}
#[cfg(feature = "builtin")]
pub(crate) fn setup_phy_policy(
    r: &impl Registers,
    gigabit_only: bool,
    link: &narf_net::nic::LinkSettings,
    pause: narf_net::nic::Pause,
    eee: bool,
) -> Result<(), IgcError> {
    setup_link(
        r,
        gigabit_only,
        &LinkPolicy {
            advertised: link.advertised,
            autoneg: link.autoneg,
            speed_mbps: link.speed_mbps,
            full_duplex: link.full_duplex,
        },
        PausePolicy {
            autoneg: pause.autoneg,
            rx: pause.rx,
            tx: pause.tx,
        },
        eee,
    )
}
fn setup_link(
    r: &impl Registers,
    gigabit_only: bool,
    link: &LinkPolicy,
    pause: PausePolicy,
    eee: bool,
) -> Result<(), IgcError> {
    // igc_setup_link: with MANC.BLK_PHY_RST_ON_IDE set, firmware owns the
    // PHY and link is already configured; Linux leaves both alone.
    if phy_reset_blocked(r) {
        return Ok(());
    }
    phy_transaction(r, || {
        phy_hw_reset(r);
        let id_high = mdio(r, 2, None)?;
        r.delay(200); // igc_get_phy_id: settle between PHY ID words.
        let id = (u32::from(id_high) << 16) | u32::from(mdio(r, 3, None)?);
        if id == 0 || id == u32::MAX {
            return Err(IgcError::Other("missing copper PHY"));
        }
        let advertisement = link.advertised & if gigabit_only { 0x1f } else { 0x3f };
        let pause_bits = if pause.autoneg {
            match (pause.rx, pause.tx) {
                (true, true) => 0x400,
                (true, false) => 0xc00,
                (false, true) => 0x800,
                _ => 0,
            }
        } else {
            0
        };
        let adv = (mdio(r, 4, None)? & !0x0fe0) | ((advertisement as u16 & 15) << 5) | pause_bits;
        mdio(r, 4, Some(adv))?;
        let g = (mdio(r, 9, None)? & !0x300) | if advertisement & 0x10 != 0 { 0x200 } else { 0 };
        mdio(r, 9, Some(g))?;
        let mg = mmd(r, 7, 32, None)? & !0x80;
        mmd(
            r,
            7,
            32,
            Some(mg | if advertisement & 0x20 != 0 { 0x80 } else { 0 }),
        )?;
        let eee_adv = if eee {
            (if advertisement & 8 != 0 { 2 } else { 0 })
                | (if advertisement & 0x10 != 0 { 4 } else { 0 })
        } else {
            0
        };
        mmd(r, 7, 60, Some(eee_adv))?;
        mmd(r, 7, 62, Some(u16::from(eee && advertisement & 0x20 != 0)))?;
        let mut control = mdio(r, 0, None)? & !0x3f40;
        control |= if link.autoneg {
            0x1200
        } else {
            (if link.speed_mbps == 100 { 0x2000 } else { 0 })
                | if link.full_duplex { 0x100 } else { 0 }
        };
        mdio(r, 0, Some(control))?;
        Ok(())
    })?;
    let mut ctrl = (r.read(0) | 0x40) & !0x18001b01;
    if !link.autoneg {
        ctrl |= 0x1800
            | if link.speed_mbps == 100 { 0x100 } else { 0 }
            | if link.full_duplex { 1 } else { 0 };
    }
    r.write(0, ctrl);
    let mut eee_advertisement = 0;
    if eee {
        if link.advertised & 8 != 0 {
            eee_advertisement |= 4;
        }
        if link.advertised & 0x10 != 0 {
            eee_advertisement |= 8;
        }
        if link.advertised & 0x20 != 0 && !gigabit_only {
            eee_advertisement |= 16;
        }
    }
    r.write(0xe38, (r.read(0xe38) & !0x1c) | eee_advertisement);
    r.write(
        0xe30,
        (r.read(0xe30) & !0x70000) | if eee { 0x70000 } else { 0 },
    );
    Ok(())
}

/// igc_check_reset_block: MANC.BLK_PHY_RST_ON_IDE.
pub(crate) fn phy_reset_blocked(r: &impl Registers) -> bool {
    r.read(0x5820) & 0x40000 != 0
}

/// Check whether the copper PHY reports link up via MII BMSR (register 1).
///
/// Per IEEE 802.3 §22.2.4.2, the BMSR link status bit (bit 2, 0x0004) has
/// latch-low behavior: if link ever dropped, the bit remains 0 until read.
/// A second read returns the current live status.
pub(crate) fn phy_has_link(r: &impl Registers) -> bool {
    phy_transaction(r, || {
        let _ = mdio(r, 1, None)?;
        let status = mdio(r, 1, None)?;
        Ok(status & 0x0004 != 0)
    })
    .unwrap_or(false)
}

/// PHPM.PHY_RST_COMP polling budget: igc_phy_hw_reset spins
/// `timeout = 10000` iterations of `udelay(1)`.
pub(crate) const PHY_RESET_COMPLETE_US: u64 = 10_000;

/// igc_phy_hw_reset (igc_phy.c), called with the PHY semaphore held.
///
/// PHPM (0x0E14) bit 8 is IGC_PHY_RST_COMP. Linux bounds the wait at ~10 ms
/// and only logs on expiry: on I225-V silicon the bit need not latch after a
/// CTRL.PHY_RST pulse (observed PHPM 0x44080 on hardware), and the PHY ID
/// read that follows is what actually validates the PHY. Treating the
/// timeout as fatal rejected working NICs at probe.
fn phy_hw_reset(r: &impl Registers) -> bool {
    let ctrl = r.read(0);
    r.write(0, ctrl | (1 << 31)); // CTRL.PHY_RST
    r.flush();
    r.delay(100); // phy->reset_delay_us
    r.write(0, ctrl);
    r.flush();
    // SW should guarantee 100us for the completion of the PHY reset.
    r.delay(100);
    let completed = r.wait(PHY_RESET_COMPLETE_US, || {
        let phpm = r.read(0xe14);
        phpm != u32::MAX && phpm & 0x100 != 0
    });
    r.delay(100);
    completed
}

pub(crate) fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

pub(crate) fn power_down_phy(r: &impl Registers) -> Result<(), IgcError> {
    phy_transaction(r, || {
        let control = mdio(r, 0, None)?;
        mdio(r, 0, Some(control | 0x800))?;
        r.delay(1000);
        Ok(())
    })
}

pub(crate) fn read_mac(r: &impl Registers) -> Result<[u8; 6], IgcError> {
    let lo = r.read(0x5400).to_le_bytes();
    let hi = r.read(0x5404).to_le_bytes();
    let mac = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    if !valid_mac(mac) {
        return Err(IgcError::Other("NVM has no valid unicast MAC"));
    }
    Ok(mac)
}

pub(crate) fn write_mac(r: &impl Registers, mac: [u8; 6]) {
    r.write(0x5400, u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]));
    r.write(0x5404, u32::from_le_bytes([mac[4], mac[5], 0, 0x80]));
}

pub(crate) fn queue(
    r: &impl Registers,
    q: usize,
    tx: u64,
    rx: u64,
    count: usize,
) -> Result<(), IgcError> {
    queue_sized(r, q, tx, rx, count, count)
}

pub(crate) fn queue_sized(
    r: &impl Registers,
    q: usize,
    tx: u64,
    rx: u64,
    tx_count: usize,
    rx_count: usize,
) -> Result<(), IgcError> {
    if q >= 4
        || tx & 127 != 0
        || rx & 127 != 0
        || [tx_count, rx_count]
            .into_iter()
            .any(|count| !(64..=4096).contains(&count) || count % 8 != 0)
    {
        return Err(IgcError::Other("invalid DMA ring geometry"));
    }
    let offset = q as u64 * 0x40;
    for base in [0xc000, 0xe000] {
        r.write(base + offset + 0x28, 0);
        r.flush();
        poll(r, base + offset + 0x28, 1 << 25, 0)?;
        let addr = if base == 0xc000 { rx } else { tx };
        r.write(base + offset, addr as u32);
        r.write(base + offset + 4, (addr >> 32) as u32);
        let count = if base == 0xc000 { rx_count } else { tx_count };
        r.write(base + offset + 8, (count * 16) as u32);
        r.write(base + offset + 0x10, 0);
        r.write(base + offset + 0x18, 0);
        // A previous owner may have selected head writeback instead of DD.
        // Never publish an address for that mode or infer completion from TDH.
        if base == 0xe000 {
            r.write(base + offset + 0x38, 0);
            r.write(base + offset + 0x3c, 0);
        }
        r.flush();
        for (register, expected) in [
            (base + offset, addr as u32),
            (base + offset + 4, (addr >> 32) as u32),
            (base + offset + 8, (count * 16) as u32),
        ] {
            if r.read(register) != expected {
                return Err(IgcError::Other("DMA ring address/length readback failed"));
            }
        }
        if base == 0xe000
            && (r.read(base + offset + 0x38) != 0 || r.read(base + offset + 0x3c) != 0)
        {
            return Err(IgcError::Other("descriptor writeback mode rejected"));
        }
    }
    // Advanced one-buffer RX, 2048 bytes, drop on exhausted queue so a
    // congested RSS queue cannot stall every other queue (no flow control).
    // igc_base.h: BSIZEHDR is in 64-byte units; Linux uses 256 bytes even
    // in advanced one-buffer mode. I225 SRRCTL.Drop_En is bit 31, not the
    // reserved bit 28 (Intel SUM §8.9.6).
    r.write(
        0xc00c + q as u64 * 0x40,
        2 | (4 << 8) | (1 << 25) | (1 << 31),
    );
    r.flush();
    if r.read(0xc00c + offset) != 0x82000402 {
        return Err(IgcError::Other("RX descriptor format readback failed"));
    }
    r.write(0xe028 + offset, 8 | (1 << 8) | (16 << 16) | (1 << 25));
    poll(r, 0xe028 + offset, 1 << 25, 1 << 25)?;
    r.write(0xc028 + offset, 8 | (8 << 8) | (4 << 16) | (1 << 25));
    poll(r, 0xc028 + offset, 1 << 25, 1 << 25)?;
    r.write(0xc018 + offset, rx_count as u32 - 1);
    Ok(())
}

#[cfg(feature = "builtin")]
pub(crate) fn configure(
    r: &impl Registers,
    mac: [u8; 6],
    mtu: u32,
    rss: &narf_net::rss::RssConfig,
) {
    configure_tables(r, mac, mtu, &rss.key, &rss.indirection)
}
pub(crate) fn configure_tables(
    r: &impl Registers,
    mac: [u8; 6],
    mtu: u32,
    key: &[u8],
    indirection: &[u8],
) {
    write_mac(r, mac);
    for slot in 1..16 {
        r.write(0x5404 + slot * 8, 0);
    }
    for slot in 0..128 {
        r.write(0x5200 + slot * 4, 0);
        r.write(0xa000 + slot * 4, 0);
    }
    r.write(0x2404, 34 | (2 << 6));
    r.write(0x3404, 20 | (4 << 24));
    r.write(0x38, 0x8100);
    r.write(0x28, 0x00c28001);
    r.write(0x2c, 0x100);
    r.write(0x30, 0x8808);
    r.write(0x170, 0xffff);
    r.write(0x2160, 0);
    r.write(0x2168, 0); // pause disabled
    r.write(0x5004, mtu + 14 + 4 + 4); // include one VLAN header and FCS
                                       // Enable VME for TX VLAN insertion; RX reconstructs stripped VLANs.
    r.write(0, r.read(0) | (1 << 30));
    for (i, word) in key.chunks_exact(4).enumerate() {
        r.write(
            0x5c80 + i as u64 * 4,
            u32::from_le_bytes(word.try_into().unwrap()),
        );
    }
    for (i, word) in indirection.chunks_exact(4).enumerate() {
        r.write(
            0x5c00 + i as u64 * 4,
            u32::from_le_bytes(word.try_into().unwrap()),
        );
    }
    r.write(0x5000, (1 << 13) | (1 << 11) | (1 << 9) | (1 << 8)); // PCSD + TUOFL

    // IPv4/v6 TCP RSS; UDP L4 hashing off by default (Linux igc_setup_mrqc).
    r.write(0x5818, 2 | 0x00370000);
    r.write(0x410, 8 | (8 << 10) | (6 << 20));
    // Multicast accept supports IPv6 and joined groups. Unicast promiscuity
    // is enabled only through the explicit receive-mode control.
    r.write(0x100, (1 << 4) | (1 << 5) | (1 << 15) | (1 << 26));
    r.write(0x400, 8 | (15 << 4) | (63 << 12) | (1 << 24));
    r.flush();
}

pub(crate) fn enable_data(r: &impl Registers) -> Result<(), IgcError> {
    r.write(0x100, r.read(0x100) | 2);
    r.write(0x400, r.read(0x400) | 2);
    r.flush();
    poll(r, 0x100, 2, 2)?;
    poll(r, 0x400, 2, 2)
}

/// Resolve IEEE 802.3 Annex 28B pause advertisement after autoneg completes.
#[cfg(feature = "builtin")]
pub(crate) fn resolve_pause(
    local: u16,
    partner: u16,
    desired: narf_net::nic::Pause,
) -> (bool, bool) {
    if !desired.autoneg {
        return (desired.rx, desired.tx);
    }
    if local & partner & 0x400 != 0 {
        return (desired.rx, desired.tx);
    }
    if local & partner & 0x800 != 0 {
        if local & 0x400 != 0 {
            return (desired.rx, false);
        }
        if partner & 0x400 != 0 {
            return (false, desired.tx);
        }
    }
    (false, false)
}

#[cfg(feature = "builtin")]
pub(crate) fn update_pause(
    r: &impl Registers,
    pause: narf_net::nic::Pause,
    mtu: u32,
) -> Result<(), IgcError> {
    let (rx, tx) = if r.read(8) & 3 != 3 {
        (false, false)
    } else {
        phy_transaction(r, || {
            let _ = mdio(r, 1, None)?;
            let status = mdio(r, 1, None)?;
            if pause.autoneg && status & 0x20 == 0 {
                return Ok((false, false));
            }
            Ok(resolve_pause(mdio(r, 4, None)?, mdio(r, 5, None)?, pause))
        })?
    };
    r.write(
        0,
        (r.read(0) & !0x18000000)
            | if rx { 0x08000000 } else { 0 }
            | if tx { 0x10000000 } else { 0 },
    );
    let high = ((r.read(0x2404) & 63) * 1024u32).saturating_sub(mtu + 22 + 9728) & !15;
    r.write(
        0x2160,
        if tx {
            high.saturating_sub(16) | 0x80000000
        } else {
            0
        },
    );
    r.write(0x2168, if tx { high | 0x80000000 } else { 0 });
    r.write(0x2460, 0x8000);
    Ok(())
}

#[cfg(feature = "builtin")]
pub(crate) fn read_nvm(
    r: &impl Registers,
    offset: u32,
    length: u32,
) -> Result<alloc::vec::Vec<u8>, IgcError> {
    // I225 shadow RAM is read through EERD at 0x12014, never legacy 0x14.
    let size = nvm_size(r);
    if offset.checked_add(length).is_none_or(|end| end > size) {
        return Err(IgcError::Other("NVM range"));
    }
    swfw_transaction(r, 1, || {
        let mut bytes = alloc::vec::Vec::with_capacity(length as usize);
        let mut word_offset = offset / 2;
        while bytes.len() < length as usize {
            r.write(0x12014, (word_offset << 2) | 1);
            poll(r, 0x12014, 2, 2)?;
            let value = (r.read(0x12014) >> 16) as u16;
            for (side, b) in value.to_le_bytes().into_iter().enumerate() {
                if word_offset * 2 + side as u32 >= offset && bytes.len() < length as usize {
                    bytes.push(b);
                }
            }
            word_offset += 1;
        }
        Ok(bytes)
    })
}

/// NVM size in bytes from EECD SIZE_EX (igc_regs.h:10, igc_defines.h:196-197).
#[cfg(feature = "builtin")]
fn nvm_size(r: &impl Registers) -> u32 {
    2u32 << (((r.read(0x10) & 0x7800) >> 11) + 6).min(15)
}

/// Flash presence on i225-class silicon: EECD FLASH_DETECTED bit
/// (IGC_EECD_FLASH_DETECTED_I225 0x00080000, igc_defines.h:200). Linux
/// refuses the ethtool EEPROM write when no flash is detected on i225
/// (igc_ethtool.c:520-523); without flash there is no write op at all
/// (igc_init_nvm_params_i225 leaves ops.write NULL, igc_i225.c:483-491).
#[cfg(feature = "builtin")]
pub(crate) fn flash_present(r: &impl Registers) -> bool {
    r.read(0x10) & 0x00080000 != 0
}

/// Write words to shadow RAM through SRWR at 0x12018 (igc_regs.h:312).
/// Linux igc_write_nvm_srwr / igc_write_nvm_srwr_i225 (igc_i225.c:226-309):
/// per word `(offset << 2) | (data << 16) | START`, polled for the DONE bit
/// (IGC_NVM_RW_REG_DONE 2, igc_defines.h:206; ADDR shift 2, DATA shift 16,
/// START 1, igc_defines.h:205-208), in bursts of at most 512 words under
/// one SW/FW semaphore hold (IGC_EERD_EEWR_MAX_COUNT, igc_defines.h:202).
/// The checksum is not updated here; Linux warns the shadow RAM most
/// likely holds an invalid checksum until igc_update_nvm_checksum runs.
#[cfg(feature = "builtin")]
pub(crate) fn write_nvm_words(
    r: &impl Registers,
    offset: u32,
    words: &[u16],
) -> Result<(), IgcError> {
    let word_size = nvm_size(r) / 2;
    if words.is_empty() || offset >= word_size || words.len() > (word_size - offset) as usize {
        return Err(IgcError::Other("NVM range"));
    }
    let mut written = 0usize;
    while written < words.len() {
        let count = (words.len() - written).min(512);
        let chunk = &words[written..written + count];
        let base = offset + written as u32;
        swfw_transaction(r, 1, || {
            for (i, word) in chunk.iter().enumerate() {
                r.write(
                    0x12018,
                    ((base + i as u32) << 2) | (u32::from(*word) << 16) | 1,
                );
                poll(r, 0x12018, 2, 2)?;
            }
            Ok(())
        })?;
        written += count;
    }
    Ok(())
}

/// Byte-level NVM write with Linux's ethtool edge-word read-modify-write
/// (igc_ethtool.c:507-575): an odd start offset preserves the first word's
/// low byte, an odd end offset preserves the last word's high byte; the
/// checksum update is a separate step, as in Linux.
#[cfg(feature = "builtin")]
pub(crate) fn write_nvm(r: &impl Registers, offset: u32, data: &[u8]) -> Result<(), IgcError> {
    let size = nvm_size(r);
    if data.is_empty()
        || offset
            .checked_add(data.len() as u32)
            .is_none_or(|end| end > size)
    {
        return Err(IgcError::Other("NVM range"));
    }
    let first_word = offset / 2;
    let last_word = (offset + data.len() as u32 - 1) / 2;
    let count = (last_word - first_word + 1) as usize;
    // Linux builds the word buffer by pre-reading the edge words and then
    // memcpy'ing the payload over them at byte offset (offset & 1): a
    // payload byte *replaces* the pre-read byte, it is never OR'd into it.
    let mut bytes = alloc::vec![0u8; count * 2];
    if offset & 1 != 0 {
        bytes[..2].copy_from_slice(&read_nvm(r, first_word * 2, 2)?);
    }
    if (offset + data.len() as u32) & 1 != 0 {
        bytes[count * 2 - 2..].copy_from_slice(&read_nvm(r, last_word * 2, 2)?);
    }
    bytes[(offset & 1) as usize..(offset & 1) as usize + data.len()].copy_from_slice(data);
    let words: alloc::vec::Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    write_nvm_words(r, first_word, &words)
}

/// Recompute the NVM checksum and commit shadow RAM to flash.
/// Linux igc_update_nvm_checksum_i225 + igc_update_flash_i225
/// (igc_i225.c:369-455): sum words 0..NVM_CHECKSUM_REG (0x3F, igc_defines.h:213),
/// store NVM_SUM (0xBABA, igc_defines.h:216) minus the sum at word 0x3F, then
/// set EECD FLUPD (0x00800000) once FLUDONE (0x04000000) is observed and poll
/// FLUDONE again (igc_defines.h:198-201, IGC_FLUDONE_ATTEMPTS 20000).
/// The stored word makes the 64-word sum equal 0xBABA, the invariant
/// igc_validate_nvm_checksum checks (igc_nvm.c:111-135).
#[cfg(feature = "builtin")]
pub(crate) fn update_nvm_checksum(r: &impl Registers) -> Result<(), IgcError> {
    // Fail fast on an unreadable word 0, as Linux does before acquiring.
    let _probe = read_nvm(r, 0, 2)?;
    let bytes = read_nvm(r, 0, 128)?;
    let mut checksum = 0u16;
    for i in 0..0x3f {
        checksum = checksum.wrapping_add(u16::from_le_bytes([bytes[2 * i], bytes[2 * i + 1]]));
    }
    let checksum = 0xbaba_u16.wrapping_sub(checksum);
    write_nvm_words(r, 0x3f, &[checksum])?;
    update_flash(r)
}

/// Commit shadow RAM to flash (igc_update_flash_i225, igc_i225.c:372-396).
#[cfg(feature = "builtin")]
fn update_flash(r: &impl Registers) -> Result<(), IgcError> {
    poll(r, 0x10, 0x04000000, 0x04000000)?;
    r.write(0x10, r.read(0x10) | 0x00800000);
    poll(r, 0x10, 0x04000000, 0x04000000)
}

/// Linux igc_ethtool_set_eeprom (igc_ethtool.c:507-575): len == 0 and a
/// flash-absent i225 both refuse with -EOPNOTSUPP; a magic other than
/// vendor | (device << 16) fails with -EFAULT; a successful write is
/// followed by the checksum update. Distinct `Other` strings let the
/// control plane map each refusal to its Linux errno.
#[cfg(feature = "builtin")]
pub(crate) fn write_eeprom(
    r: &impl Registers,
    magic: u32,
    device_id: u16,
    offset: u32,
    data: &[u8],
) -> Result<(), IgcError> {
    if data.is_empty() {
        return Err(IgcError::Other("EEPROM empty"));
    }
    if !flash_present(r) {
        return Err(IgcError::Other("no flash"));
    }
    if magic != 0x8086 | (u32::from(device_id) << 16) {
        return Err(IgcError::Other("bad EEPROM magic"));
    }
    write_nvm(r, offset, data)?;
    update_nvm_checksum(r)
}

/// Firmware version in Linux `igc_ethtool_get_drvinfo` shape: `"%x:%x"` of
/// the NVM image version (word 5, IGC_NVM_DEV_STARTER) and the gPHY firmware
/// version (PHY register 0x1E, IGC_GPHY_VERSION, read through plain MDIC:
/// `igc_read_phy_reg_gpy` takes the MDIC path when no MMD device is encoded).
/// Best-effort: `None` when the NVM read fails; a failed PHY read reports 0,
/// as Linux's `igc_read_phy_fw_version` does. Never fails probe.
#[cfg(feature = "builtin")]
pub(crate) fn fw_version(r: &impl Registers) -> Option<alloc::string::String> {
    let nvm = read_nvm(r, 10, 2).ok()?;
    let nvm_version = u16::from_le_bytes([nvm[0], nvm[1]]);
    let gphy = mdio(r, 0x1e, None).unwrap_or(0);
    Some(alloc::format!("{nvm_version:x}:{gphy:x}"))
}

/// Update the MRQC UDP RSS field bits (Linux `igc_ethtool_set_rxfh_fields`):
/// the IPv4/IPv6/TCP base bits are always set and the UDP bits follow the
/// ethtool RXFH field flags. Live read-modify-write, no restart.
#[cfg(feature = "builtin")]
pub(crate) fn set_rss_fields(r: &impl Registers, udp4: bool, udp6: bool) {
    let mut mrqc = r.read(0x5818);
    mrqc |= 0x10000 | 0x20000 | 0x100000 | 0x200000;
    mrqc &= !(0x400000 | 0x800000);
    if udp4 {
        mrqc |= 0x400000;
    }
    if udp6 {
        mrqc |= 0x800000;
    }
    r.write(0x5818, mrqc);
}

/// Linux wake flags differ from WUFC. Engines remain DMA-disabled while
/// the always-on wake comparator and PHY stay powered in D3.
#[cfg(feature = "builtin")]
pub(crate) fn wake(r: &impl Registers, flags: u32) -> Result<bool, IgcError> {
    if flags & !0x2f != 0 {
        return Err(IgcError::Other("unsupported wake flags"));
    }
    let mut filter = (flags & 1) | ((flags & 0x20) >> 4) | ((flags & 0x0e) << 1);
    if r.read(8) & 2 != 0 {
        filter &= !1;
    }
    if filter != 0 {
        r.write(0, r.read(0) | 0x00100000);
        if flags & 4 != 0 {
            r.write(0x100, r.read(0x100) | 0x10);
        }
        phy_transaction(r, || {
            let v = mdio(r, 0, None)?;
            mdio(r, 0, Some(v & !0x800))?;
            Ok(())
        })?;
        r.write(0x5800, 2);
        r.write(0x5808, filter);
    } else {
        r.write(0x5800, 0);
        r.write(0x5808, 0);
        power_down_phy(r)?;
    }
    r.flush();
    Ok(filter != 0)
}

#[cfg(feature = "builtin")]
pub(crate) fn eee_status(r: &impl Registers) -> Result<narf_net::nic::EeeStatus, IgcError> {
    phy_transaction(r, || {
        let local = mmd(r, 7, 60, None)?;
        let local2 = mmd(r, 7, 62, None)?;
        let partner = mmd(r, 7, 61, None)?;
        let partner2 = mmd(r, 7, 63, None)?;
        let modes = |v: u16, v2: u16| {
            (u32::from(v & 2 != 0) * 8)
                | (u32::from(v & 4 != 0) * 16)
                | (u32::from(v2 & 1 != 0) * 32)
        };
        Ok(narf_net::nic::EeeStatus {
            advertised: modes(local, local2),
            partner: modes(partner, partner2),
            active: r.read(8) & 2 != 0 && r.read(0xe30) & 0x20000000 != 0,
            tx_lpi: r.read(0xe30) & 0x10000 != 0,
        })
    })
}
