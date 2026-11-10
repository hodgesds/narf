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
}
impl<A, F> TrainingAux<A, F> {
    pub fn new(aux: A, state: State, source: F) -> Self {
        Self { aux, state, source }
    }
}
impl<A: AuxChannel, F: FnMut(&State, Change) -> Result<(), AuxError>> AuxChannel
    for TrainingAux<A, F>
{
    fn transact<'a>(
        &mut self,
        request: &AuxRequest<'_>,
        reply: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
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
