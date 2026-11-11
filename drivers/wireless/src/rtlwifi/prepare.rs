// SPDX-License-Identifier: GPL-2.0-or-later
//! Exact linked PCI descriptor/FIFO prerequisite for the retained rtlwifi
//! profiles (RTL8188EE, RTL8821AE, RTL8192CE, RTL8723BE, RTL8192DE). Linux
//! rtl8188ee/, rtl8821ae/, rtl8192ce/, rtl8723be/ and rtl8192de/ hw.c/trx.h.
//! Ordinary DMA/MAC remain closed; this is below RF and station admission.
use super::firmware_transport::{Error as AccessError, Io};
use alloc::vec::Vec;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Geometry,
    Address,
    Memory,
    Access(AccessError),
    State,
    LltTimeout,
    Readback,
    Radio(super::radio::Error),
    Power(super::channel_power::Error),
    Packet,
    Descriptor,
    PacketTimeout,
    CommandTimeout,
    RadioOff,
}
impl From<AccessError> for Error {
    fn from(error: AccessError) -> Self {
        Self::Access(error)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Allocated,
    Prepared,
    RadioConfigured,
    ChannelConfigured,
    MacConfigured,
    Running,
    Stopping,
    Stopped,
    Failed,
}
/// # Safety
/// The reported DMA extent is exclusively backed by this allocation, valid
/// for the retained device, and sync publishes all prior stores with device
/// ordering. Drop releases it only when the outer owner permits reclamation.
pub unsafe trait Memory: Send {
    fn address(&self) -> u64;
    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    fn write32(&mut self, offset: usize, value: u32) -> Result<(), Error>;
    fn read32(&self, _offset: usize) -> Result<u32, Error> {
        Err(Error::Memory)
    }
    fn write_bytes(&mut self, _offset: usize, _bytes: &[u8]) -> Result<(), Error> {
        Err(Error::Memory)
    }
    fn read_bytes(&self, _offset: usize, _bytes: &mut [u8]) -> Result<(), Error> {
        Err(Error::Memory)
    }
    fn sync(&self);
}
const TX_BYTES: usize = 64;
const RX_BYTES: usize = 32;
// Linux rtlwifi/pci.c uses 9100-byte slots for the 7935-byte HT A-MSDU
// body plus raw QoS/CCMP/FCS and native driver-info/shift prefixes.
pub(super) const RX_BUFFER: usize = 9100;
// Exact RTL8188EE linked-ring map. The unused generic mac.rs/dma.rs
// scaffolds carry the different RTL8192EE TXBD map and cannot authorize
// this retained EE transport. Every queue has a distinct linked ring.
const TX_BASES: [u16; 7] = [
    super::rtl8188ee::REG_BCNQ_DESA,
    super::rtl8188ee::REG_MGQ_DESA,
    super::rtl8188ee::REG_VOQ_DESA,
    super::rtl8188ee::REG_VIQ_DESA,
    super::rtl8188ee::REG_BEQ_DESA,
    super::rtl8188ee::REG_BKQ_DESA,
    super::rtl8188ee::REG_HQ_DESA,
];
const RX_BASE: u16 = super::rtl8188ee::REG_RX_DESA;
/// Linked-ring/LLT profile of the retained owner. Both chips use the same
/// `REG_*_DESA` map (`rtl8188ee/reg.h`, `rtl8821ae/reg.h` 0x308..0x340),
/// 64-byte `rtl_tx_desc` slots and 32-byte RX descriptors with the buffer at
/// dword 6; they differ in the next-descriptor dword and the LLT layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chip {
    Rtl8188ee,
    Rtl8821ae,
    /// New-TRX-flow buffer-descriptor profile (`rtl8192ee/packet_owner.rs`):
    /// no linked next pointer; built only by `Prepared::allocate_rtl8192ee`.
    Rtl8192ee,
    /// RTL8192CE / RTL8188CE linked rings (`rtl8192ce/trx.h`): 88EE ring
    /// geometry, `_rtl92ce_llt_table_init` and the 92C IMR map.
    Rtl8192ce,
    /// RTL8723BE linked rings (`rtl8723be/trx.h`): 88EE ring geometry with
    /// the next link at dword 12 (byte 48), `_rtl8723be_llt_table_init`,
    /// the 88EE IMR map (`REG_HIMR` 0xb0 / `REG_HIMRE` 0xb8) and the
    /// `REG_PCIE_CTRL_REG + 1` (0x301) DMA stop.
    Rtl8723be,
    /// RTL8192DE linked rings (`rtl8192de/trx.h`): 88EE ring geometry
    /// with the next link at dword 10 (byte 40),
    /// `_rtl92de_llt_table_init` (mode-dependent boundary/RQPN) and the
    /// DE IMR map (`REG_HIMR` 0x120 / `REG_HIMRE` 0x128).
    Rtl8192de,
}
impl Chip {
    pub const fn from_device(did: u16) -> Option<Self> {
        match did {
            super::regs::RTL_DEV_8188EE => Some(Self::Rtl8188ee),
            super::regs::RTL_DEV_8821AE => Some(Self::Rtl8821ae),
            super::regs::RTL_DEV_8192EE => Some(Self::Rtl8192ee),
            did if super::rtl8192ce::is_8192ce(did) => Some(Self::Rtl8192ce),
            super::regs::RTL_DEV_8723BE => Some(Self::Rtl8723be),
            super::regs::RTL_DEV_8192DE => Some(Self::Rtl8192de),
            _ => None,
        }
    }
    /// Byte offset of `set_tx_desc_next_desc_address`: 88EE dword 10,
    /// 8821AE dword 12 (`rtl8821ae/trx.h`; its dword 10 is the buffer).
    /// `None` for the RTL8192EE buffer-descriptor rings, which have none.
    pub const fn next_desc_offset(self) -> Option<usize> {
        match self {
            Self::Rtl8188ee => Some(40),
            Self::Rtl8821ae => Some(48),
            // TX_DESC_NEXT_DESC_OFFSET.
            Self::Rtl8192ce => Some(super::rtl8192ce::trx::TX_DESC_NEXT_DESC_OFFSET),
            Self::Rtl8723be => Some(super::rtl8723be::trx::NEXT_DESC_BYTE),
            Self::Rtl8192de => Some(super::rtl8192de::trx::NEXT_DESC_BYTE),
            Self::Rtl8192ee => None,
        }
    }
}
/// Exact-width adapter for the 8821AE LLT sequence over the retained Io.
struct LltRegs<'a, I: Io>(&'a I);
impl<I: Io> super::rtl8821ae::llt::Regs for LltRegs<'_, I> {
    fn read32(&self, reg: u16) -> Result<u32, AccessError> {
        self.0.read32(reg)
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), AccessError> {
        self.0.write8(reg, value)
    }
    fn write16(&self, reg: u16, value: u16) -> Result<(), AccessError> {
        self.0.write16(reg, value)
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), AccessError> {
        self.0.write32(reg, value)
    }
}
fn extent(memory: &impl Memory, needed: usize, alignment: u64) -> Result<u32, Error> {
    let base = memory.address();
    if needed == 0
        || memory.len() < needed
        || base & (alignment - 1) != 0
        || base
            .checked_add(needed as u64 - 1)
            .is_none_or(|end| end > u64::from(u32::MAX))
    {
        return Err(Error::Address);
    }
    Ok(base as u32)
}
/// `REG_MULTI_FUNC_CTRL` BIT(18): the combo board's Bluetooth function.
pub const RTL8821AE_BT_FUNCTION: u32 = 1 << 18;
pub struct Prepared<I: Io, M: Memory> {
    io: I,
    chip: Chip,
    tx: Vec<M>,
    receive: Option<M>,
    buffers: Vec<M>,
    depth: usize,
    phase: Phase,
    published: bool,
    radio: Option<super::radio::Report>,
    rtl8821ae: Option<super::rtl8821ae::phy::Report>,
    rtl8821ae_identity: Option<[u8; 32]>,
    rtl8821ae_power: Option<super::rtl8821ae::envelope::Permission>,
    /// RTL8821AE coexistence owner (`rtl8821ae/coex.rs`), bound when a
    /// BT-strapped board is admitted in [`Self::configure_rtl8821ae_mac`].
    rtl8821ae_coex: Option<alloc::boxed::Box<super::rtl8821ae::coex::Owner>>,
    /// RTL8192EE factory identity and configured radio (`rtl8192ee/init.rs`).
    rtl8192ee: Option<alloc::boxed::Box<([u8; 32], super::rtl8192ee::init::Radio)>>,
    /// Admitted `N92E` operating point (`rtl8192ee/envelope.rs`).
    rtl8192ee_power: Option<super::rtl8192ee::envelope::Permission>,
    /// RTL8192CE / RTL8188CE factory identity and configured radio
    /// (`rtl8192ce/init.rs`).
    rtl8192ce: Option<alloc::boxed::Box<([u8; 32], super::rtl8192ce::init::Radio)>>,
    /// Admitted `N92C` operating point (`rtl8192ce/envelope.rs`).
    rtl8192ce_power: Option<super::rtl8192ce::envelope::Permission>,
    /// RTL8723BE factory identity and configured radio (`rtl8723be/init.rs`).
    rtl8723be: Option<alloc::boxed::Box<([u8; 32], super::rtl8723be::init::Radio)>>,
    /// RTL8723BE coexistence owner (`rtl8723be/coex.rs`), bound before
    /// [`Self::prepare`] (`rtl_pci_start` → `btc_init_variables`).
    rtl8723be_coex: Option<alloc::boxed::Box<super::rtl8723be::coex::Owner>>,
    /// Admitted `NAPC` operating point (`rtl8723be/envelope.rs`) whose
    /// [`super::rtl8723be::channel::Grant`] programmed the channel.
    rtl8723be_power: Option<super::rtl8723be::envelope::Permission>,
    /// RTL8192DE factory identity, configured radio, factory TX-power
    /// data and channel bandset (`rtl8192de/radio_owner.rs`).
    rtl8192de: Option<alloc::boxed::Box<de92_radio::De92Radio>>,
    /// Admitted `N92D` operating point (`rtl8192de/envelope.rs`).
    rtl8192de_power: Option<super::rtl8192de::envelope::Permission>,
    /// RTL8192DE MAC/PHY mode bound before [`Self::prepare`] (the LLT
    /// is mode-dependent); [`Self::configure_rtl8192de`] re-derives it
    /// from the PROM and refuses a mismatch.
    rtl8192de_mode: Option<super::rtl8192de::MacPhyMode>,
    permission: Option<super::channel_power::Permission>,
    packet: packet::State<M>,
    station: station::State,
}
impl<I: Io, M: Memory> core::fmt::Debug for Prepared<I, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Rtl8188eePrepared")
            .field("phase", &self.phase)
            .field("depth", &self.depth)
            .finish_non_exhaustive()
    }
}
impl<I: Io, M: Memory> Prepared<I, M> {
    /// Allocation/validation and descriptor construction precede every BAR
    /// side effect. The caller retains exclusive PCI authority with BME off.
    pub fn allocate(
        io: I,
        depth: usize,
        allocate: impl FnMut(usize) -> Result<M, Error>,
    ) -> Result<Self, Error> {
        Self::allocate_for(Chip::Rtl8188ee, io, depth, allocate)
    }
    /// As [`Self::allocate`] for an explicit linked-ring profile.
    pub fn allocate_for(
        chip: Chip,
        io: I,
        depth: usize,
        mut allocate: impl FnMut(usize) -> Result<M, Error>,
    ) -> Result<Self, Error> {
        let Some(next_offset) = chip.next_desc_offset() else {
            return Err(Error::Geometry);
        };
        if !(4..=256).contains(&depth) || !depth.is_power_of_two() {
            return Err(Error::Geometry);
        }
        let mut tx = Vec::new();
        tx.try_reserve_exact(7).map_err(|_| Error::Memory)?;
        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(depth + 8)
            .map_err(|_| Error::Memory)?;
        let mut reserve = |needed, alignment| -> Result<M, Error> {
            let block = allocate(needed)?;
            let address = extent(&block, needed, alignment)?;
            let end = u64::from(address) + needed as u64;
            if ranges
                .iter()
                .any(|&(a, b)| u64::from(address) < b && a < end)
            {
                return Err(Error::Address);
            }
            ranges.push((u64::from(address), end));
            Ok(block)
        };
        for _ in TX_BASES {
            let mut ring = reserve(depth * TX_BYTES, 256)?;
            let base = extent(&ring, depth * TX_BYTES, 256)?;
            for slot in 0..depth {
                for word in 0..TX_BYTES / 4 {
                    ring.write32(slot * TX_BYTES + word * 4, 0)?;
                }
                // Linux txdesc.next_desc_address (88EE DW10, 8821AE DW12);
                // never alias queues or use another family's TXBD convention.
                let next = base + (((slot + 1) % depth) * TX_BYTES) as u32;
                ring.write32(slot * TX_BYTES + next_offset, next)?;
            }
            ring.sync();
            tx.push(ring);
        }
        let mut receive = reserve(depth * RX_BYTES, 256)?;
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(depth)
            .map_err(|_| Error::Memory)?;
        for slot in 0..depth {
            let buffer = reserve(RX_BUFFER, 4)?;
            for word in 0..RX_BYTES / 4 {
                receive.write32(slot * RX_BYTES + word * 4, 0)?;
            }
            receive.write32(slot * RX_BYTES + 24, extent(&buffer, RX_BUFFER, 4)?)?;
            buffer.sync();
            let end = if slot == depth - 1 { 1 << 30 } else { 0 };
            receive.write32(slot * RX_BYTES, RX_BUFFER as u32 | end | (1 << 31))?;
            buffers.push(buffer);
        }
        receive.sync();
        Ok(Self::assemble(chip, io, tx, receive, buffers, depth))
    }
    /// The unpublished owner over already built and validated rings.
    fn assemble(chip: Chip, io: I, tx: Vec<M>, receive: M, buffers: Vec<M>, depth: usize) -> Self {
        Self {
            io,
            chip,
            tx,
            receive: Some(receive),
            buffers,
            depth,
            phase: Phase::Allocated,
            published: false,
            radio: None,
            rtl8821ae: None,
            rtl8821ae_identity: None,
            rtl8821ae_power: None,
            rtl8821ae_coex: None,
            rtl8192ee: None,
            rtl8192ee_power: None,
            rtl8192ce: None,
            rtl8192ce_power: None,
            rtl8723be: None,
            rtl8723be_coex: None,
            rtl8723be_power: None,
            rtl8192de: None,
            rtl8192de_power: None,
            rtl8192de_mode: None,
            permission: None,
            packet: packet::State::new(),
            station: station::State::new(),
        }
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn chip(&self) -> Chip {
        self.chip
    }
    pub fn radio_report(&self) -> Option<&super::radio::Report> {
        self.radio.as_ref()
    }
    pub fn channel_permission(&self) -> Option<super::channel_power::Permission> {
        self.permission
    }
    /// The same factory identity qualifies radio, gain and the operational
    /// MAC. MAC readiness leaves BME, CR packet gates and IRQs closed.
    pub fn configure_mac(&mut self, factory: &super::efuse::Factory) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured {
            return Err(Error::State);
        }
        self.permission
            .ok_or(Error::State)?
            .check(super::radio::factory_identity(factory))
            .map_err(Error::Power)?;
        self.phase = Phase::Failed;
        super::packet_mac::configure(&self.io, factory)?;
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
        Ok(())
    }
    pub async fn configure_channel(
        &mut self,
        permission: super::channel_power::Permission,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) {
            return Err(Error::State);
        }
        let report = self.radio.as_ref().ok_or(Error::State)?;
        permission.check(report.identity).map_err(Error::Power)?;
        self.phase = Phase::Failed;
        self.permission = None;
        let rf = super::radio::channel(&self.io, report, permission)
            .await
            .map_err(Error::Radio)?;
        self.radio.as_mut().ok_or(Error::State)?.channel_rf = rf;
        self.permission = Some(permission);
        self.phase = Phase::ChannelConfigured;
        Ok(())
    }

    /// Continue the same retained PacketIo/ring owner through exact EE radio
    /// tables and calibration. Cancellation is terminal before the first wait;
    /// published DMA remains owned even when no report can be committed.
    pub async fn configure_radio(&mut self, profile: super::radio::Profile) -> Result<(), Error> {
        // The EE radio tables/calibration cannot qualify another profile.
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8188ee {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let report = super::radio::configure(&self.io, profile)
            .await
            .map_err(Error::Radio)?;
        self.radio = Some(report);
        self.phase = Phase::RadioConfigured;
        Ok(())
    }
    /// RTL8821AE BB/RF/MAC facts committed by [`Self::configure_rtl8821ae`].
    pub fn rtl8821ae_report(&self) -> Option<super::rtl8821ae::phy::Report> {
        self.rtl8821ae
    }
    /// Continue the same retained 8821AE owner through the parked
    /// `rtl8821ae_hw_init` hardware steps. The table selector is qualified
    /// from live `REG_SYS_CFG`/`REG_MULTI_FUNC_CTRL` and the retained factory
    /// map; an unprovisioned or test-chip board selects nothing and fails.
    /// Packet DMA, CR gates and IRQs stay closed; the channel is not set.
    pub async fn configure_rtl8821ae(
        &mut self,
        factory: &super::efuse::Factory,
    ) -> Result<super::rtl8821ae::phy::Report, Error> {
        use super::rtl8821ae::headerfile;
        if self.phase != Phase::Prepared || self.chip != Chip::Rtl8821ae {
            return Err(Error::State);
        }
        self.phase = Phase::Failed;
        let condition = headerfile::Condition::from_hardware(
            self.io.read32(headerfile::REG_SYS_CFG)?,
            self.io.read32(headerfile::REG_MULTI_FUNC_CTRL)?,
            &factory.logical,
        )
        .map_err(|_| Error::State)?;
        let report =
            super::rtl8821ae::mac::configure(&self.io, &condition, &factory.logical, &factory.mac)
                .await?;
        self.rtl8821ae = Some(report);
        self.rtl8821ae_identity = Some(super::radio::factory_identity(factory));
        self.phase = Phase::RadioConfigured;
        Ok(report)
    }
    /// Admitted 8821AE 2.4 GHz operating point committed by
    /// [`Self::configure_rtl8821ae_channel`].
    pub fn rtl8821ae_permission(&self) -> Option<super::rtl8821ae::envelope::Permission> {
        self.rtl8821ae_power
    }
    /// Continue the same retained 8821AE owner through the 2.4 GHz band
    /// select, channel switch (at the 40 MHz wide channel when the
    /// permission is 40 MHz) with the admitted per-board TXAGC indices, and
    /// 20/40 MHz bandwidth (`rtl8821ae/channel.rs`, `reg_837` from the
    /// committed BB report). The permission must have been minted from this
    /// owner's factory identity; 5 GHz and 80 MHz permissions are refused.
    pub async fn configure_rtl8821ae_channel(
        &mut self,
        permission: super::rtl8821ae::envelope::Permission,
    ) -> Result<(), Error> {
        if !matches!(
            self.phase,
            Phase::RadioConfigured | Phase::ChannelConfigured
        ) || self.chip != Chip::Rtl8821ae
        {
            return Err(Error::State);
        }
        if self.rtl8821ae_identity != Some(permission.identity()) {
            return Err(Error::Power(super::channel_power::Error::Identity));
        }
        let reg_837 = self.rtl8821ae.ok_or(Error::State)?.reg_837;
        self.phase = Phase::Failed;
        self.rtl8821ae_power = None;
        super::rtl8821ae::channel::configure(&self.io, &permission, reg_837).await?;
        self.rtl8821ae_power = Some(permission);
        self.phase = Phase::ChannelConfigured;
        Ok(())
    }
    /// The admitted 8821AE board's coexistence owner, if it is BT-strapped.
    pub fn rtl8821ae_coex(&self) -> Option<&super::rtl8821ae::coex::Owner> {
        self.rtl8821ae_coex.as_deref()
    }
    /// Continue the retained 8821AE owner from the admitted channel to the
    /// operational MAC (ChannelConfigured → MacConfigured). `configure_rtl8821ae`
    /// already wrote the station address (`HW_VAR_ETHER_ADDR`); the factory
    /// identity must be the one the channel permission was minted for.
    /// Boards with the Bluetooth function strapped on (`REG_MULTI_FUNC_CTRL`
    /// BIT(18), Linux `_rtl8821ae_read_bt_coexist_info_from_hwpg`) are
    /// admitted with a coexistence owner (`rtl8821ae/coex.rs`): coex takes
    /// LPS/antenna control from here on. Packet DMA, CR gates and IRQs
    /// stay closed until the packet owner starts.
    pub fn configure_rtl8821ae_mac(
        &mut self,
        factory: &super::efuse::Factory,
    ) -> Result<(), Error> {
        if self.phase != Phase::ChannelConfigured || self.chip != Chip::Rtl8821ae {
            return Err(Error::State);
        }
        let identity = super::radio::factory_identity(factory);
        if self.rtl8821ae_identity != Some(identity)
            || self.rtl8821ae_power.map(|p| p.identity()) != Some(identity)
        {
            return Err(Error::Power(super::channel_power::Error::Identity));
        }
        let strap = self
            .io
            .read32(super::rtl8821ae::headerfile::REG_MULTI_FUNC_CTRL)?;
        if strap == u32::MAX {
            return Err(Error::Access(AccessError::Gone));
        }
        // The owner reflects the current strap: BT-strapped boards get a
        // coexistence owner, WLAN-only boards get none.
        self.rtl8821ae_coex = if strap & RTL8821AE_BT_FUNCTION != 0 {
            Some(alloc::boxed::Box::new(super::rtl8821ae::coex::Owner::bind()))
        } else {
            None
        };
        self.packet.local = Some(factory.mac);
        self.phase = Phase::MacConfigured;
        Ok(())
    }
    /// `rtl8821ae_phy_iq_calibrate` at the admitted band and 20/40/80 MHz width of this
    /// retained 8821AE owner (`rtl8821ae/iqk.rs`). The station owner calls it
    /// when [`super::rtl8821ae::iqk::LinkedInterval::tick`] fires, as Linux DM
    /// does. All backed-up MAC/BB/AFE/RF state is restored before return; an
    /// I/O failure fails the owner.
    pub async fn calibrate_rtl8821ae_iqk(
        &mut self,
    ) -> Result<super::rtl8821ae::iqk::Report, Error> {
        if self.chip != Chip::Rtl8821ae
            || self.rtl8821ae_power.is_none()
            || !matches!(
                self.phase,
                Phase::ChannelConfigured | Phase::MacConfigured | Phase::Running
            )
        {
            return Err(Error::State);
        }
        use super::rtl8821ae::envelope::Band;
        let op = self.rtl8821ae_power.ok_or(Error::State)?.operating();
        // 80 MHz runs `_rtl8821ae_iqk_tx`'s VDF branch.
        let report =
            super::rtl8821ae::iqk::calibrate_at(&self.io, op.band == Band::B5g, op.width).await;
        if report.is_err() {
            self.phase = Phase::Failed;
        }
        report
    }
    /// Prepare internal SRAM and masked, inactive native rings. The native
    /// Io validates current PCI authority/BME at each actual access. No helper
    /// here can enable PCI bus mastering or release host/MAC packet gates.
    pub async fn prepare(&mut self) -> Result<(), Error> {
        if self.phase != Phase::Allocated {
            return Err(Error::State);
        }
        // Install terminal state before the first await. A cancelled LLT
        // command cannot later resume/retry against its uncertain SRAM state.
        self.phase = Phase::Failed;
        let result = self.prepare_inner().await;
        match result {
            Ok(()) => self.phase = Phase::Prepared,
            Err(_) => self.phase = Phase::Failed,
        }
        result
    }
    async fn prepare_inner(&mut self) -> Result<(), Error> {
        if self.chip == Chip::Rtl8192ee {
            return self.ee92_prepare().await;
        }
        // Linux poweroff stops PCIe DMA through this byte. Preparing never
        // reopens it; BME remains off independently in the native adapter.
        // The 92C has no such HCI DMA-stop byte in Linux (`REG_PCIE_CTRL_REG`
        // is only its TX polling doorbell), so CR gates and parked BME alone
        // hold its DMA closed.
        let ce = self.chip == Chip::Rtl8192ce;
        if !ce {
            self.io.write8(0x301, 0xff)?;
            if self.io.read8(0x301)? != 0xff {
                return Err(Error::Readback);
            }
        }
        if self.chip == Chip::Rtl8723be {
            // `_rtl8723be_init_mac` between the enable flow and the LLT
            // (`btc_power_on_setting` belongs to the coexistence owner):
            // `REG_CR = 0xff` with its `mdelay(2)`, then the clock segment
            // (`HWSEQ_CTRL |= 0x7f` and its own 2 ms). The 0x301 stop above
            // and parked BME hold host DMA closed while CR is fully open;
            // the deferred `REG_CR = 0x2ff` belongs to packet start, so the
            // DMA/MAC gates are closed again below before the LLT.
            // `hw.c:827` `btc_power_on_setting` after the enable flow; every
            // 8723BE runs it (`get_btc_status()` is always true), so an
            // unbound coexistence owner refuses.
            let coex = self.rtl8723be_coex.as_deref_mut().ok_or(Error::State)?;
            coex.power_on_setting(&self.io).await?;
            super::rtl8723be::mac::init_mac_pre_cr(&self.io)?;
            self.io.write8(0x100, 0xff)?;
            self.io.delay_us(2000).await;
            super::rtl8723be::mac::init_mac_clocks(&self.io).await?;
        }
        let cr = self.io.read8(0x100)?;
        self.io.write8(0x100, cr & !0xcf)?;
        if self.io.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        let imr = if self.chip == Chip::Rtl8192de {
            [
                super::rtl8192de::mac::REG_HIMR,
                super::rtl8192de::mac::REG_HIMRE,
            ]
        } else if ce {
            [
                super::rtl8192ce::mac::REG_HIMR,
                super::rtl8192ce::mac::REG_HIMRE,
            ]
        } else {
            [0xb0, 0xb8]
        };
        for address in imr {
            self.io.write32(address, 0)?;
            if self.io.read32(address)? != 0 {
                return Err(Error::Readback);
            }
        }
        self.llt().await?;
        // The owner marks all resources retained before the first potentially
        // visible BAR base write. Even ambiguous publication pins every page.
        self.published = true;
        for (address, ring) in TX_BASES.iter().zip(&self.tx) {
            let base = extent(ring, self.depth * TX_BYTES, 256)?;
            self.io.write32(*address, base)?;
            if self.io.read32(*address)? != base {
                return Err(Error::Readback);
            }
        }
        let base = extent(
            self.receive.as_ref().ok_or(Error::State)?,
            self.depth * RX_BYTES,
            256,
        )?;
        self.io.write32(RX_BASE, base)?;
        if self.io.read32(RX_BASE)? != base {
            return Err(Error::Readback);
        }
        // Ordinary DMA, IRQ and MAC gates remain independently closed.
        if (!ce && self.io.read8(0x301)? != 0xff) || self.io.read8(0x100)? & 0xcf != 0 {
            return Err(Error::Readback);
        }
        Ok(())
    }
    async fn llt(&self) -> Result<(), Error> {
        if self.chip == Chip::Rtl8821ae {
            // Exact rtl8821ae/hw.c::_rtl8821ae_llt_table_init.
            return super::rtl8821ae::llt::init(&LltRegs(&self.io)).map_err(|e| match e {
                AccessError::Deadline => Error::LltTimeout,
                e => Error::Access(e),
            });
        }
        if self.chip == Chip::Rtl8723be {
            // Exact rtl8723be/hw.c::_rtl8723be_llt_table_init (boundary 245).
            return super::rtl8723be::llt::init(&LltRegs(&self.io)).map_err(|e| match e {
                AccessError::Deadline => Error::LltTimeout,
                e => Error::Access(e),
            });
        }
        if self.chip == Chip::Rtl8192ce {
            // Exact rtl8192ce/hw.c::_rtl92ce_llt_table_init (LLT_CONFIG 5).
            return super::rtl8192ce::llt::init(&LltRegs(&self.io)).map_err(|e| match e {
                AccessError::Deadline => Error::LltTimeout,
                e => Error::Access(e),
            });
        }
        if self.chip == Chip::Rtl8192de {
            // Exact rtl8192de/hw.c::_rtl92de_llt_table_init, over the
            // retained Io (the DE LLT needs no register adapter): the
            // mode was bound before `prepare` and is refused when absent.
            let mode = self.rtl8192de_mode.ok_or(Error::State)?;
            return super::rtl8192de::llt::init(&self.io, mode).map_err(|e| match e {
                AccessError::Deadline => Error::LltTimeout,
                e => Error::Access(e),
            });
        }
        // Exact _rtl88ee_llt_table_init: TX0..170 ends atff; 171..175
        // forms the reserved ring. This is 0xab/0xaf, not 0xe0/0xff.
        self.io.write8(0x214, 1)?;
        self.io.write32(0x200, 0x80730d29)?;
        self.io.write32(0x114, 0x25ff00ab)?;
        for address in [0x209, 0x424, 0x425, 0x45d] {
            self.io.write8(address, 0xab)?;
        }
        self.io.write8(0x104, 0x11)?;
        self.io.write8(0x60f, 4)?;
        for address in 0u8..176 {
            let next = match address {
                170 => 255,
                175 => 171,
                _ => address + 1,
            };
            self.io.write32(
                0x1e0,
                (1 << 30) | (u32::from(address) << 8) | u32::from(next),
            )?;
            let mut complete = false;
            for _ in 0..24 {
                let value = self.io.read32(0x1e0)?;
                if value == u32::MAX {
                    return Err(Error::Access(AccessError::Gone));
                }
                if value >> 30 == 0 {
                    complete = true;
                    break;
                }
                self.io.delay_us(5).await;
            }
            if !complete {
                return Err(Error::LltTimeout);
            }
        }
        Ok(())
    }
}
impl<I: Io, M: Memory> Drop for Prepared<I, M> {
    fn drop(&mut self) {
        if self.published {
            // Clearing BME/revoking authority alone is not a prefetch fence.
            // A future reset/quiescence owner must prove reclamation first.
            core::mem::forget(core::mem::take(&mut self.tx));
            core::mem::forget(self.receive.take());
            core::mem::forget(core::mem::take(&mut self.buffers));
            self.packet.retain();
        }
    }
}

#[path = "rtl8723be/radio_owner.rs"]
mod be8723_radio;
#[path = "rtl8192ce/radio_owner.rs"]
mod ce92_radio;
#[path = "rtl8192de/radio_owner.rs"]
mod de92_radio;
#[path = "packet.rs"]
pub mod packet;
#[path = "station.rs"]
pub(crate) mod station;
/// Retain the complete owner before the first device-visible base write.
/// This is the actual native worker's shared storage/await boundary. An async
/// mutex, unlike an IRQ-disabling guard, may span the self-driven LLT wait.
pub(super) async fn retain_and_prepare<I: Io, M: Memory>(
    retained: &narf_lib::mutex::Mutex<Option<Prepared<I, M>>>,
    prepared: Prepared<I, M>,
) -> Result<(), Error> {
    let mut storage = retained.lock().await;
    if storage.is_some() {
        return Err(Error::State);
    }
    *storage = Some(prepared);
    storage.as_mut().ok_or(Error::State)?.prepare().await
}

#[cfg(any(test, feature = "kernel-test"))]
#[path = "prepare_tests.rs"]
pub(crate) mod tests;
