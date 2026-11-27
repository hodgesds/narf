//! Couple the shared sink-training algorithm to an Intel source PHY.
//! This observes typed native DPCD writes, with no second AUX codec or
//! training/fallback implementation. Source changes precede the matching
//! sink write, so CR/EQ never measures a different pattern or drive level.
use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse};
use crate::intel_gpu_pll::LinkRate;

#[derive(Copy, Clone, Debug)]
pub(crate) struct State {
    pub rate: LinkRate,
    pub lanes: u8,
    pub levels: [(u8, u8); 4],
    pub pattern: u8,
    pub dirty: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Configure,
    Levels,
    Pattern,
}

impl State {
    pub fn new(rate: LinkRate, lanes: u8) -> Self {
        Self {
            rate,
            lanes,
            levels: [(0, 0); 4],
            pattern: 1,
            dirty: false,
        }
    }
    pub fn pattern_bits(self) -> Result<u32, AuxError> {
        let pattern = match self.pattern {
            0 => 3,
            1 => 0,
            2 => 1,
            3 => 4,
            7 => 5,
            _ => return Err(AuxError::Nacked),
        };
        Ok(pattern << 8
            | if matches!(self.pattern, 1..=3) {
                1 << 7
            } else {
                0
            })
    }
}

pub(crate) struct TrainingAux<A, F> {
    aux: A,
    state: State,
    source: F,
    /// LTTPRs in non-transparent mode the training runs through hop by hop
    /// (`intel_dp_link_train_all_phys`), 0 for none.
    lttprs: u8,
}
impl<A, F> TrainingAux<A, F> {
    pub fn new(aux: A, state: State, source: F) -> Self {
        Self {
            aux,
            state,
            source,
            lttprs: 0,
        }
    }

    /// Train through `lttprs` repeaters in non-transparent mode: every
    /// PHY's `DP_TRAINING_PATTERN_SET` (or the PHY repeater's) programs the
    /// source pattern (`intel_dp_program_link_training_pattern`), but only
    /// the lane settings of the hop the source feeds (`DP_PHY_LTTPR(n - 1)`,
    /// `intel_dp_phy_is_downstream_of_source`) its levels; a repeater's
    /// pattern disable is DPCD only (`intel_dp_disable_dpcd_training_pattern`).
    pub fn with_lttprs(mut self, lttprs: u8) -> Self {
        self.lttprs = lttprs.min(8);
        self
    }

    /// What a native write to `address` means for the source: the
    /// repeater whose pattern or lane-set register it is, if any.
    fn lttpr_reg(&self, address: u32) -> Option<(u8, u32)> {
        let rel = address.checked_sub(LTTPR1_PATTERN_SET)?;
        let (hop, reg) = (rel / LTTPR_STRIDE, rel % LTTPR_STRIDE);
        (hop < u32::from(self.lttprs) && reg <= 4).then_some((hop as u8, reg))
    }
}

/// `DP_TRAINING_PATTERN_SET_PHY_REPEATER1` and the LTTPR register stride.
const LTTPR1_PATTERN_SET: u32 = 0xf_0010;
const LTTPR_STRIDE: u32 = 0x50;
impl<A: AuxChannel, F: FnMut(&State, Change) -> Result<(), AuxError>> AuxChannel
    for TrainingAux<A, F>
{
    fn transact<'a>(
        &mut self,
        request: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        if request.cmd == AuxCommand::NativeWrite && self.lttprs != 0 {
            return self.transact_hops(request, reply);
        }
        if request.cmd == AuxCommand::NativeWrite {
            let mut change = None;
            for (index, byte) in request.data.iter().copied().enumerate() {
                match request.address + index as u32 {
                    0x100 => {
                        let rate = match byte {
                            0x06 => LinkRate::DpRbr,
                            0x0A => LinkRate::DpHbr,
                            0x14 => LinkRate::DpHbr2,
                            0x1E => LinkRate::DpHbr3,
                            _ => return Err(AuxError::Nacked),
                        };
                        self.state.dirty |= rate != self.state.rate;
                        self.state.rate = rate;
                        change = Some(Change::Configure);
                    }
                    0x101 => {
                        let lanes = byte & 0x1F;
                        if !matches!(lanes, 1 | 2 | 4) {
                            return Err(AuxError::Nacked);
                        }
                        self.state.dirty |= lanes != self.state.lanes;
                        self.state.lanes = lanes;
                        change = Some(Change::Configure);
                    }
                    0x102 => {
                        self.state.pattern = byte & 7;
                        change = Some(Change::Pattern);
                    }
                    address @ 0x103..=0x106 => {
                        self.state.levels[(address - 0x103) as usize] = (byte & 3, (byte >> 3) & 3);
                        change = Some(Change::Levels);
                    }
                    _ => {}
                }
            }
            if let Some(change) = change {
                (self.source)(&self.state, change)?;
                if change == Change::Pattern && self.state.pattern == 1 {
                    self.state.dirty = false;
                }
            }
        }
        self.aux.transact(request, reply)
    }
}

impl<A: AuxChannel, F: FnMut(&State, Change) -> Result<(), AuxError>> TrainingAux<A, F> {
    /// A native write while training hop by hop: the rate and lane count
    /// configure the source; each written PHY's pattern (a repeater's
    /// disable excepted) and the source-fed hop's lane settings follow in
    /// Linux's order (`intel_dp_reset_link_train`: levels, then
    /// `intel_dp_set_link_train`: pattern), before the write goes out.
    fn transact_hops<'a>(
        &mut self,
        request: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        let (mut configure, mut levels, mut pattern) = (false, false, false);
        let source_hop = self.lttprs - 1;
        for (index, byte) in request.data.iter().copied().enumerate() {
            let address = request.address + index as u32;
            match (address, self.lttpr_reg(address)) {
                (0x100, _) => {
                    let rate = match byte {
                        0x06 => LinkRate::DpRbr,
                        0x0A => LinkRate::DpHbr,
                        0x14 => LinkRate::DpHbr2,
                        0x1E => LinkRate::DpHbr3,
                        _ => return Err(AuxError::Nacked),
                    };
                    self.state.dirty |= rate != self.state.rate;
                    self.state.rate = rate;
                    configure = true;
                }
                (0x101, _) => {
                    let lanes = byte & 0x1F;
                    if !matches!(lanes, 1 | 2 | 4) {
                        return Err(AuxError::Nacked);
                    }
                    self.state.dirty |= lanes != self.state.lanes;
                    self.state.lanes = lanes;
                    configure = true;
                }
                // The DPRX behind repeaters: its pattern reaches the
                // source, its lane settings do not.
                (0x102, _) => {
                    self.state.pattern = byte & 7;
                    pattern = true;
                }
                (_, Some((_, 0))) if byte & 7 != 0 => {
                    self.state.pattern = byte & 7;
                    pattern = true;
                }
                (_, Some((hop, reg))) if hop == source_hop && reg != 0 => {
                    self.state.levels[(reg - 1) as usize] = (byte & 3, (byte >> 3) & 3);
                    levels = true;
                }
                _ => {}
            }
        }
        if configure {
            (self.source)(&self.state, Change::Configure)?;
        }
        if levels {
            (self.source)(&self.state, Change::Levels)?;
        }
        if pattern {
            (self.source)(&self.state, Change::Pattern)?;
            if self.state.pattern == 1 {
                self.state.dirty = false;
            }
        }
        self.aux.transact(request, reply)
    }
}
