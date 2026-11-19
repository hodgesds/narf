use super::*;
use crate::rtw89::{dma::addr_set_for_chip, mac::ChipId};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

const AWAKE_STOP1: u32 = TX_STOP1_MASK_V1 & !(1 << 8 | 1 << 16 | STOP_CH12);
const AWAKE_PPDU: u32 = 0x2b;
const AWAKE_RPT: u32 = 0x1;
const AWAKE_FLTR_OPT: u32 = 0x0031_0001;

struct Model {
    words: Vec<u32>,
    halves: Vec<(u32, u16)>,
    writes: usize,
    now: u64,
    queue_busy: bool,
    stuck_bdram: bool,
}
impl Model {
    fn awake() -> Self {
        let mut words = vec![0; 0x10000 / 4];
        let mut set = |address: u32, value: u32| words[address as usize / 4] = value;
        set(STOP1, AWAKE_STOP1);
        set(INIT_CFG1, HCI_EN | 1 << 5);
        set(PLE_QTA6, QTA6_SCC);
        set(MGNT_FLTR, FLTR_TO_HOST);
        set(CTRL_FLTR, FLTR_TO_HOST);
        set(DATA_FLTR, 0x5555_1555);
        set(RX_FLTR_OPT, AWAKE_FLTR_OPT);
        set(PPDU_STAT, AWAKE_PPDU);
        set(HW_RPT_FWD, AWAKE_RPT);
        set(ACTION_FWD0, 0x02a9_5a95);
        set(TF_FWD, 0x0000_aa55);
        // Every `mac_is_txq_empty_ax` quota bit set. Not all-ones: an
        // all-ones read is a removed device, which `Access::read` refuses.
        set(DLE_EMPTY0, DLE_EMPTY_MASK);
        Self {
            words,
            halves: Vec::new(),
            writes: 0,
            now: 0,
            queue_busy: false,
            stuck_bdram: false,
        }
    }
    fn get(&self, address: u32) -> u32 {
        self.words[address as usize / 4]
    }
    fn set(&mut self, address: u32, value: u32) {
        self.words[address as usize / 4] = value;
    }
    fn half(&self, address: u32) -> u16 {
        self.halves
            .iter()
            .find(|(a, _)| *a == address)
            .map_or(0, |(_, value)| *value)
    }
}
impl Io for Model {
    fn read8(&mut self, _: u32) -> Result<u8, power::Error> {
        Err(power::Error::Unsupported)
    }
    fn read16(&mut self, address: u32) -> Result<u16, power::Error> {
        Ok(self.half(address))
    }
    fn read32(&mut self, address: u32) -> Result<u32, power::Error> {
        match address {
            INIT_CFG1 if !self.stuck_bdram => {
                let value = self.get(address) & !RST_BDRAM;
                self.set(address, value);
            }
            WDE_DFI_CTL => {
                let value = self.get(address);
                self.set(address, value & !DFI_ACTIVE);
            }
            _ => {}
        }
        Ok(self.get(address))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write16(&mut self, address: u32, value: u16) -> Result<(), power::Error> {
        self.writes += 1;
        self.halves.retain(|(a, _)| *a != address);
        self.halves.push((address, value));
        Ok(())
    }
    fn write32(&mut self, address: u32, value: u32) -> Result<(), power::Error> {
        self.writes += 1;
        self.set(address, value);
        let regs = addr_set_for_chip(ChipId::Rtl8852B);
        match address {
            WDE_DFI_CTL => {
                let group = value & 0xffff;
                let data = if self.queue_busy && group == 0 {
                    0xffff_fff1
                } else if group == MGQ_GROUP {
                    MGQ_EMPTY
                } else {
                    u32::MAX
                };
                self.set(WDE_DFI_DATA, data);
            }
            TXBD_RWPTR_CLR1 => {
                for (bit, channel) in [(0, 0), (1, 1), (2, 2), (3, 3), (8, 8), (9, 9), (10, 12)] {
                    if value & 1 << bit != 0 {
                        self.set(regs.tx[channel].idx as u32, 0);
                    }
                }
            }
            RXBD_RWPTR_CLR => {
                for ring in 0..2 {
                    if value & 1 << ring != 0 {
                        self.set(regs.rx[ring].idx as u32, 0);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
fn once<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}
fn rings() -> Vec<Ring> {
    let regs = addr_set_for_chip(ChipId::Rtl8852B);
    vec![
        Ring::Tx {
            channel: 0,
            regs: regs.tx[0],
            address: 0x1_2340_0000,
            depth: 512,
        },
        Ring::Tx {
            channel: 8,
            regs: regs.tx[8],
            address: 0x1_2341_0000,
            depth: 512,
        },
        Ring::Tx {
            channel: 12,
            regs: regs.tx[12],
            address: 0x1_2342_0000,
            depth: 256,
        },
        Ring::Rx {
            regs: regs.rx[0],
            address: 0x1_2343_0000,
            depth: 512,
        },
        Ring::Rx {
            regs: regs.rx[1],
            address: 0x1_2344_0000,
            depth: 512,
        },
    ]
}

fn smoke_rtw89_wow_trx_halt_restart_reversible() -> TestResult {
    let awake = Model::awake();
    let mut io = Model::awake();
    let Some(Ok(snapshot)) = once(enter_pre(&mut io)) else {
        return TestResult::Fail("enable_trx_pre on an awake quiet station");
    };
    if io.get(STOP1) != AWAKE_STOP1 | (TX_STOP1_MASK_V1 & !STOP_CH12)
        || io.get(MGNT_FLTR) != FLTR_DROP
        || io.get(CTRL_FLTR) != FLTR_DROP
        || io.get(DATA_FLTR) != FLTR_DROP
        || io.get(PPDU_STAT) & PPDU_STAT_RPT_EN != 0
        || io.get(INIT_CFG1) & HCI_EN != HCI_EN
        || snapshot.open_channels() != 1 << 8 | 1 << 16 | STOP_CH12
    {
        return TestResult::Fail("ctrl_txdma_ch(false)+fw_ch(true), drop filters, PPDU off");
    }
    let rings = rings();
    let regs = addr_set_for_chip(ChipId::Rtl8852B);
    if once(enter_post(&mut io, CpuIoRx::Absent, &rings)) != Some(Ok(())) {
        return TestResult::Fail("enable_trx_post");
    }
    if io.get(INIT_CFG1) & HCI_EN != 0
        || io.get(PLE_QTA6) != QTA6_WOW
        || io.get(PLE_QTA7) != 0
        || io.get(RX_FUNCTION_STOP) & HDR_RX_STOP == 0
        || io.get(RX_FLTR_OPT) & SNIFFER_MODE != 0
        || [ACTION_FWD0, ACTION_FWD1, TF_FWD, HW_RPT_FWD]
            .iter()
            .any(|address| io.get(*address) != 0)
        || io.get(MGNT_FLTR) != FLTR_TO_HOST
        || io.get(DATA_FLTR) != FLTR_TO_HOST
    {
        return TestResult::Fail("wow_config_mac_ax(true) with NO_WOW_CPU_IO_RX");
    }
    for (channel, partition) in BDRAM {
        if io.get(regs.tx[channel].bdram as u32) != partition {
            return TestResult::Fail("rtw89_bd_ram_table_single partitions");
        }
    }
    for ring in &rings {
        let (num, desa_l, desa_h, address, depth) = match *ring {
            Ring::Tx {
                regs,
                address,
                depth,
                ..
            } => (regs.num, regs.desa_l, regs.desa_h, address, depth),
            Ring::Rx {
                regs,
                address,
                depth,
            } => (regs.num, regs.desa_l, regs.desa_h, address, depth),
        };
        if io.half(num as u32) != depth
            || io.get(desa_l as u32) != address as u32
            || io.get(desa_h as u32) != (address >> 32) as u32
        {
            return TestResult::Fail("reset_trx_rings re-publishes the same bases");
        }
    }
    // Unpublished channels keep their bases (only partitions are written).
    if io.get(regs.tx[1].desa_l as u32) != 0 {
        return TestResult::Fail("unpublished ring base written");
    }
    // The WoW firmware moves every index while the host is parked.
    for ring in &rings {
        io.set(ring.index(), 0x0042_0017);
    }
    if once(leave_pre(&mut io, &snapshot, &rings, Rewind::B)) != Some(Ok(())) {
        return TestResult::Fail("disable_trx_pre");
    }
    if rings.iter().any(|ring| io.get(ring.index()) != 0)
        || io.get(INIT_CFG1) & (HCI_EN | RST_BDRAM) != HCI_EN
        || io.get(STOP1) != AWAKE_STOP1
        || io.get(PLE_QTA6) != QTA6_SCC
        || io.get(RX_FUNCTION_STOP) & HDR_RX_STOP != 0
    {
        return TestResult::Fail("clr_idx_all, rst_bdram, trxhci(true), awake channels, SCC");
    }
    if leave_post(&mut io, snapshot) != Ok(()) {
        return TestResult::Fail("disable_trx_post");
    }
    for address in [
        STOP1,
        MGNT_FLTR,
        CTRL_FLTR,
        DATA_FLTR,
        RX_FLTR_OPT,
        PPDU_STAT,
        HW_RPT_FWD,
        ACTION_FWD0,
        ACTION_FWD1,
        TF_FWD,
        PLE_QTA6,
        PLE_QTA7,
        RX_FUNCTION_STOP,
    ] {
        if io.get(address) != awake.get(address) {
            return TestResult::Fail("awake register not restored");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wow_trx_halt_restart_reversible
);

fn smoke_rtw89_wow_trx_refusals_fail_closed() -> TestResult {
    // A busy WDE queue is never dropped by firmware here: 50 ms, then Queue.
    let mut io = Model::awake();
    io.queue_busy = true;
    if once(enter_pre(&mut io)) != Some(Err(Error::Queue)) || io.now < 50_000 {
        return TestResult::Fail("busy TX queue must fail after the Linux window");
    }
    // Not an awake HCI station: nothing is written.
    let mut io = Model::awake();
    io.set(INIT_CFG1, 0);
    if once(enter_pre(&mut io)) != Some(Err(Error::State)) || io.writes != 0 {
        return TestResult::Fail("HCI-off precondition");
    }
    let mut io = Model::awake();
    io.set(PLE_QTA6, QTA6_WOW);
    if once(enter_pre(&mut io)) != Some(Err(Error::State)) || io.writes != 0 {
        return TestResult::Fail("non-SCC quota precondition");
    }
    // CPU IO RX firmware is refused before any write.
    let mut io = Model::awake();
    if once(enter_post(&mut io, CpuIoRx::Required, &rings())) != Some(Err(Error::Unsupported))
        || io.writes != 0
    {
        return TestResult::Fail("WOW_CPUIO_RX_CTRL firmware");
    }
    if CpuIoRx::for_8852b([0, 29, 29, 15]) != CpuIoRx::Absent
        || CpuIoRx::for_8852b([0, 27, 32, 1]) != CpuIoRx::Absent
        || CpuIoRx::for_8852b([0, 29, 30, 0]) != CpuIoRx::Required
    {
        return TestResult::Fail("NO_WOW_CPU_IO_RX version boundary");
    }
    // Stuck BD-RAM reset on resume.
    let mut io = Model::awake();
    let Some(Ok(snapshot)) = once(enter_pre(&mut io)) else {
        return TestResult::Fail("enter_pre");
    };
    io.stuck_bdram = true;
    if once(leave_pre(&mut io, &snapshot, &rings(), Rewind::B)) != Some(Err(Error::Timeout)) {
        return TestResult::Fail("reset bdram busy");
    }
    // An index the clear did not reach is not a restarted ring.
    let mut io = Model::awake();
    let Some(Ok(snapshot)) = once(enter_pre(&mut io)) else {
        return TestResult::Fail("enter_pre");
    };
    let regs = addr_set_for_chip(ChipId::Rtl8852B);
    let mut stale = rings();
    stale.push(Ring::Tx {
        channel: 9,
        regs: regs.tx[9],
        address: 0,
        depth: 0,
    });
    io.set(regs.tx[9].idx as u32, 5);
    // Channel 9 is cleared by CLR1 bit 9 in the model; a ring outside the
    // RTL8852B clear mask (ACH4) must be reported.
    stale.push(Ring::Tx {
        channel: 4,
        regs: regs.tx[4],
        address: 0,
        depth: 0,
    });
    io.set(regs.tx[4].idx as u32, 5);
    if once(leave_pre(&mut io, &snapshot, &stale, Rewind::B)) != Some(Err(Error::Index)) {
        return TestResult::Fail("uncleared index");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wow_trx_refusals_fail_closed
);

fn smoke_rtw8852c_wow_rewind_uses_v1_rwptr_clear_registers() -> TestResult {
    let mut io = Model::awake();
    let mut a = Access(&mut io);
    if Rewind::C.clear(&mut a).is_err() {
        return TestResult::Fail("C clr_idx_all failed");
    }
    // rtw89_pci_clr_idx_all_ax for RTL8852C: CLR1 incl. ACH4..7, CLR2_V1
    // CH10/CH11, RXBD_RWPTR_CLR_V1; the B RX clear register is untouched.
    if io.get(TXBD_RWPTR_CLR1) != C_CLR_TX_IDX
        || io.get(C_TXBD_RWPTR_CLR2) != 3
        || io.get(C_RXBD_RWPTR_CLR) != CLR_RX_IDX
        || io.get(RXBD_RWPTR_CLR) != 0
        || Rewind::for_chip(ChipId::Rtl8852C) != Some(Rewind::C)
        || Rewind::for_chip(ChipId::Rtl8852B) != Some(Rewind::B)
        || Rewind::for_chip(ChipId::Rtl8852A).is_some()
    {
        return TestResult::Fail("C rewind registers differ from rtw8852c_pci_info");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw8852c_wow_rewind_uses_v1_rwptr_clear_registers
);
