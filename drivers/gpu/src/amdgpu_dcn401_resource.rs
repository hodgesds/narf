//! DCN401's pipe acquisition as Linux DC runs it (dc_resource.c,
//! dcn32_resource.c, dcn20_resource.c, dc_state.c and DML2's
//! map_dc_pipes_with_callbacks), over a resource context of pool pipe
//! indices: which pipe a new stream's OTG master takes, which free pipe a
//! plane's secondary DPP, an MPC slice or an ODM slice's OPP head takes,
//! and how they are released. Every search prefers the pipes the current
//! state used the same way, to avoid pipe swaps across a commit.
//!
//! A [`DcState`] is a `dc_state` reduced to what acquisition reads: each
//! pool pipe's `pipe_ctx` (its stream, plane and top/bottom/ODM links, by
//! pipe index) and the streams with their planes in `stream_status` order.
//! Streams and planes are ids (Linux's object pointers). DCN401's pool has
//! as many DSCs as OPPs, so dcn20_acquire_dsc always gives a pipe index its
//! own DSC and DSC needs no state here. Every function is the Linux one of
//! the same name with `self` the new state and `cur` the current
//! (`dc->current_state`); `tests/dcn401_pipes` holds Linux's own code to
//! vectors this module replays.
//!
//! The state also holds the stream encoders, as resource_map_pool_resources
//! acquires them for a stream after its OTG master: a DIO stream encoder
//! for every stream (dcn10_find_first_free_match_stream_enc_for_link), and
//! for a 128b/132b DP stream an HPO DP stream encoder
//! (find_first_free_match_hpo_dp_stream_enc_for_link) and its link's HPO DP
//! link encoder, one per link shared by every stream on it and taken from
//! the free pool (add_hpo_dp_link_enc_to_ctx). A stream with audio then
//! takes an Azalia audio endpoint keyed by its DIO stream encoder's engine,
//! whatever its signal (find_first_free_audio: the endpoint of that
//! engine's index when free, else the first free one, else none).

/// Pipe contexts per state (DCN401's pipes; Linux sizes them MAX_PIPES,
/// the pipes past the pool staying clear).
pub const MAX_PIPES: usize = 4;
/// MAX_SURFACES: planes per stream.
pub const MAX_SURFACES: usize = 4;
/// Streams per state: one per timing generator.
pub const MAX_STREAMS: usize = MAX_PIPES;
/// DIO stream encoders, DIGA-DIGD (res_cap_dcn4_01 num_stream_encoder).
pub const STREAM_ENCODERS: usize = 4;
/// HPO DP stream encoders (num_hpo_dp_stream_encoder).
pub const HPO_DP_STREAM_ENCODERS: usize = 4;
/// HPO DP link encoders (num_hpo_dp_link_encoder, MAX_HPO_DP2_LINK_ENCODERS).
pub const HPO_DP_LINK_ENCODERS: usize = 4;
/// Azalia audio endpoints (res_cap_dcn4_01 num_audio).
pub const AUDIOS: usize = 4;

/// What encoder acquisition reads of a stream's output.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamOutput {
    /// Its dc_link's link_index (the board connector).
    pub link: u8,
    /// Its PHY link encoder's preferred_engine: the DIG of its transmitter
    /// (dcn401_link_encoder_construct maps UNIPHY A-E to DIGA-DIGE).
    pub preferred_engine: u8,
    /// A 128b/132b DP stream (dp_get_encoding_format of its link settings).
    pub hpo_dp: bool,
    /// The stream carries audio: an audio-capable signal whose sink
    /// declared audio modes (resource_map_pool_resources' audio check).
    pub audio: bool,
}

/// The encoders a stream's OTG master holds: stream_res.stream_enc,
/// stream_res.hpo_dp_stream_enc and link_res.hpo_dp_link_enc, by instance,
/// and its stream_res.audio endpoint (none when the stream has no audio or
/// every endpoint is taken: the stream then lights without audio).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamEncoders {
    pub stream_enc: u8,
    pub hpo_dp_stream_enc: Option<u8>,
    pub hpo_dp_link_enc: Option<u8>,
    pub audio: Option<u8>,
}

/// One pipe's `pipe_ctx` as acquisition sees it. All `None` is a cleared
/// (memset) pipe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipeCtx {
    pub stream: Option<u8>,
    pub plane: Option<u8>,
    pub top: Option<u8>,
    pub bottom: Option<u8>,
    pub prev_odm: Option<u8>,
    pub next_odm: Option<u8>,
}

/// One stream of a state and its planes (`dc_stream_status`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamStatus {
    pub stream: u8,
    pub planes: [u8; MAX_SURFACES],
    pub plane_count: u8,
    /// The stream's output and the encoders it acquired on it.
    pub output: StreamOutput,
    pub encoders: Option<StreamEncoders>,
}
impl StreamStatus {
    pub fn planes(&self) -> &[u8] {
        &self.planes[..usize::from(self.plane_count)]
    }
}

/// DML's pipe counts for one stream (map_dc_pipes_with_callbacks's target
/// factors): its ODM slices and each plane's MPC slices, in
/// `stream_status` order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Target {
    pub odm: u8,
    pub mpc: [u8; MAX_SURFACES],
}

/// A `dc_state`'s streams and pipe contexts on a pool of `pipe_count`
/// pipes (the pool's `pipe_count` and `timing_generator_count`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DcState {
    pub pipe_count: u8,
    pub pipes: [PipeCtx; MAX_PIPES],
    pub streams: [StreamStatus; MAX_STREAMS],
    pub stream_count: u8,
    /// res_ctx.is_stream_enc_acquired.
    pub stream_enc_acquired: [bool; STREAM_ENCODERS],
    /// res_ctx.is_hpo_dp_stream_enc_acquired.
    pub hpo_dp_stream_enc_acquired: [bool; HPO_DP_STREAM_ENCODERS],
    /// res_ctx.hpo_dp_link_enc_to_link_idx and hpo_dp_link_enc_ref_cnts.
    pub hpo_dp_link_enc_link: [u8; HPO_DP_LINK_ENCODERS],
    pub hpo_dp_link_enc_refs: [u8; HPO_DP_LINK_ENCODERS],
    /// res_ctx.is_audio_acquired.
    pub audio_acquired: [bool; AUDIOS],
}

/// resource_build_scaling_params for `pipe` of `state`: whether SPL can
/// scale the pipe's plane on the pipe's ODM and MPC slice. DC runs it on
/// every pipe of a plane whose MPC slices or stream's ODM slices change
/// (update_pipe_params_after_{mpc,odm}_slice_count_change) and rolls the
/// change back, or fails it, when one cannot scale.
pub trait Scaling {
    fn build(&self, state: &DcState, pipe: u8) -> bool;
}
impl<F: Fn(&DcState, u8) -> bool> Scaling for F {
    fn build(&self, state: &DcState, pipe: u8) -> bool {
        self(state, pipe)
    }
}
/// Every plane scales on any slice: for planes no SPL input describes
/// (stand-in planes of admission checks).
#[derive(Clone, Copy, Debug)]
pub struct ScalesAnywhere;
impl Scaling for ScalesAnywhere {
    fn build(&self, _: &DcState, _: u8) -> bool {
        true
    }
}

/// resource_is_pipe_type's types.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PipeType {
    OtgMaster,
    OppHead,
    DppPipe,
    FreePipe,
}

impl DcState {
    /// An empty state on a pool of `pipe_count` pipes.
    pub const fn new(pipe_count: u8) -> Self {
        let pipe_count = if pipe_count as usize > MAX_PIPES {
            MAX_PIPES as u8
        } else {
            pipe_count
        };
        Self {
            pipe_count,
            pipes: [PipeCtx {
                stream: None,
                plane: None,
                top: None,
                bottom: None,
                prev_odm: None,
                next_odm: None,
            }; MAX_PIPES],
            streams: [StreamStatus {
                stream: 0,
                planes: [0; MAX_SURFACES],
                plane_count: 0,
                output: StreamOutput {
                    link: 0,
                    preferred_engine: 0,
                    hpo_dp: false,
                    audio: false,
                },
                encoders: None,
            }; MAX_STREAMS],
            stream_count: 0,
            stream_enc_acquired: [false; STREAM_ENCODERS],
            hpo_dp_stream_enc_acquired: [false; HPO_DP_STREAM_ENCODERS],
            hpo_dp_link_enc_link: [0; HPO_DP_LINK_ENCODERS],
            hpo_dp_link_enc_refs: [0; HPO_DP_LINK_ENCODERS],
            audio_acquired: [false; AUDIOS],
        }
    }
    pub fn streams(&self) -> &[StreamStatus] {
        &self.streams[..usize::from(self.stream_count)]
    }
    fn pool(&self) -> core::ops::Range<u8> {
        0..self.pipe_count
    }
    fn p(&self, i: u8) -> &PipeCtx {
        &self.pipes[usize::from(i)]
    }
    fn pm(&mut self, i: u8) -> &mut PipeCtx {
        &mut self.pipes[usize::from(i)]
    }

    fn is(&self, i: u8, t: PipeType) -> bool {
        let p = self.p(i);
        match t {
            PipeType::OtgMaster => p.prev_odm.is_none() && p.top.is_none() && p.stream.is_some(),
            PipeType::OppHead => p.top.is_none() && p.stream.is_some(),
            PipeType::DppPipe => p.plane.is_some() && p.stream.is_some(),
            PipeType::FreePipe => p.plane.is_none() && p.stream.is_none(),
        }
    }

    /// resource_get_otg_master_for_stream.
    pub fn otg_master_for_stream(&self, stream: u8) -> Option<u8> {
        (0..MAX_PIPES as u8)
            .find(|&i| self.p(i).stream == Some(stream) && self.is(i, PipeType::OtgMaster))
    }
    /// resource_get_opp_heads_for_otg_master: the OTG master and its
    /// further OPP heads, left to right.
    pub fn opp_heads(&self, otg_master: u8) -> ([u8; MAX_PIPES], usize) {
        let mut heads = [0; MAX_PIPES];
        let mut n = 0;
        if !self.is(otg_master, PipeType::OtgMaster) {
            return (heads, 0);
        }
        let mut at = Some(otg_master);
        while let Some(h) = at {
            if n == MAX_PIPES {
                break;
            }
            heads[n] = h;
            n += 1;
            at = self.p(h).next_odm;
        }
        (heads, n)
    }
    /// resource_get_dpp_pipes_for_plane: the plane's first-slice pipe, then
    /// its ODM pipes, or (without ODM) its MPC slices.
    pub fn dpp_pipes_for_plane(&self, plane: u8) -> ([u8; MAX_PIPES], usize) {
        let mut out = [0; MAX_PIPES];
        let mut n = 0;
        let found = (0..MAX_PIPES as u8).find(|&j| {
            let p = self.p(j);
            p.plane == Some(plane)
                && p.prev_odm.is_none()
                && (self.is(j, PipeType::OppHead)
                    || p.top.is_none_or(|t| self.p(t).plane != Some(plane)))
        });
        if let Some(j) = found {
            let mut at = Some(j);
            if self.p(j).next_odm.is_some() {
                while let Some(q) = at.filter(|_| n < MAX_PIPES) {
                    out[n] = q;
                    n += 1;
                    at = self.p(q).next_odm;
                }
            } else {
                while let Some(q) = at.filter(|&q| n < MAX_PIPES && self.p(q).plane == Some(plane))
                {
                    out[n] = q;
                    n += 1;
                    at = self.p(q).bottom;
                }
            }
        }
        (out, n)
    }
    /// resource_get_odm_slice_index: the pipe's OPP head's position among
    /// its stream's ODM slices.
    pub fn odm_slice_index(&self, pipe: u8) -> usize {
        let mut head = self.opp_head(pipe);
        let mut index = 0;
        while let Some(prev) = self.p(head).prev_odm {
            index += 1;
            head = prev;
        }
        index
    }
    /// resource_get_otg_master.
    pub fn otg_master(&self, pipe: u8) -> u8 {
        let mut m = self.opp_head(pipe);
        while let Some(prev) = self.p(m).prev_odm {
            m = prev;
        }
        m
    }
    /// resource_get_opp_head.
    pub fn opp_head(&self, pipe: u8) -> u8 {
        let mut h = pipe;
        while let Some(top) = self.p(h).top {
            h = top;
        }
        h
    }
    /// resource_get_mpc_slice_index.
    pub fn mpc_slice_index(&self, pipe: u8) -> usize {
        let plane = self.p(pipe).plane;
        let mut index = 0;
        let mut at = self.p(pipe).top;
        while let Some(t) = at.filter(|&t| self.p(t).plane == plane) {
            index += 1;
            at = self.p(t).top;
        }
        index
    }
    /// resource_get_mpc_slice_count.
    pub fn mpc_slice_count(&self, pipe: u8) -> usize {
        let plane = self.p(pipe).plane;
        let mut count = 1;
        let mut at = self.p(pipe).bottom;
        while let Some(b) = at.filter(|&b| self.p(b).plane == plane) {
            count += 1;
            at = self.p(b).bottom;
        }
        at = self.p(pipe).top;
        while let Some(t) = at.filter(|&t| self.p(t).plane == plane) {
            count += 1;
            at = self.p(t).top;
        }
        count
    }
    /// resource_get_odm_slice_count.
    pub fn odm_slice_count(&self, pipe: u8) -> usize {
        let mut count = 1;
        let mut at = self.otg_master(pipe);
        while let Some(next) = self.p(at).next_odm {
            count += 1;
            at = next;
        }
        count
    }

    // The free-pipe searches. Each returns the pipe or None
    // (FREE_PIPE_INDEX_NOT_FOUND).

    /// resource_find_free_pipe_used_as_sec_opp_head_by_cur_otg_master.
    fn free_used_as_sec_opp_head_by_cur_otg_master(&self, cur: &Self, cur_otg: u8) -> Option<u8> {
        let mut at = cur.p(cur_otg).next_odm;
        while let Some(h) = at {
            if self.is(h, PipeType::FreePipe) {
                return Some(h);
            }
            at = cur.p(h).next_odm;
        }
        None
    }
    /// resource_find_free_pipe_used_in_cur_mpc_blending_tree.
    fn free_used_in_cur_mpc_blending_tree(&self, cur: &Self, cur_opp_head: u8) -> Option<u8> {
        let mut at = cur.p(cur_opp_head).bottom;
        while let Some(d) = at {
            if self.is(d, PipeType::FreePipe) {
                return Some(d);
            }
            at = cur.p(d).bottom;
        }
        None
    }
    /// recource_find_free_pipe_not_used_in_cur_res_ctx.
    fn free_not_used_in_cur(&self, cur: &Self) -> Option<u8> {
        self.pool()
            .find(|&i| cur.is(i, PipeType::FreePipe) && self.is(i, PipeType::FreePipe))
    }
    /// recource_find_free_pipe_used_as_otg_master_in_cur_res_ctx.
    fn free_used_as_otg_master_in_cur(&self, cur: &Self) -> Option<u8> {
        self.pool()
            .find(|&i| cur.is(i, PipeType::OtgMaster) && self.is(i, PipeType::FreePipe))
    }
    /// resource_find_free_pipe_used_as_cur_sec_dpp.
    fn free_used_as_cur_sec_dpp(&self, cur: &Self) -> Option<u8> {
        self.pool().find(|&i| {
            cur.is(i, PipeType::DppPipe)
                && !cur.is(i, PipeType::OppHead)
                && self.is(i, PipeType::FreePipe)
        })
    }
    /// resource_find_free_pipe_used_as_cur_sec_dpp_in_mpcc_combine.
    fn free_used_as_cur_sec_dpp_in_mpcc_combine(&self, cur: &Self) -> Option<u8> {
        self.pool().find(|&i| {
            cur.is(i, PipeType::DppPipe)
                && !cur.is(i, PipeType::OppHead)
                && cur.mpc_slice_index(i) > 0
                && self.is(i, PipeType::FreePipe)
        })
    }
    /// resource_find_any_free_pipe.
    fn any_free(&self) -> Option<u8> {
        self.pool().find(|&i| self.is(i, PipeType::FreePipe))
    }

    /// get_tail_pipe.
    fn tail_pipe(&self, head: u8) -> u8 {
        let mut h = head;
        while let Some(b) = self.p(h).bottom {
            h = b;
        }
        h
    }
    /// get_last_opp_head.
    fn last_opp_head(&self, opp_head: u8) -> u8 {
        let mut h = opp_head;
        while let Some(n) = self.p(h).next_odm {
            h = n;
        }
        h
    }
    /// get_last_dpp_pipe_in_mpcc_combine.
    fn last_dpp_in_mpcc_combine(&self, dpp: u8) -> u8 {
        let mut d = dpp;
        while let Some(b) = self
            .p(d)
            .bottom
            .filter(|&b| self.p(b).plane == self.p(d).plane)
        {
            d = b;
        }
        d
    }
    /// get_num_of_free_pipes.
    fn free_pipe_count(&self) -> usize {
        self.pool()
            .filter(|&i| self.is(i, PipeType::FreePipe))
            .count()
    }

    /// acquire_otg_master_pipe_for_stream: the pipe the current state used
    /// as an OTG master (Linux keeps this for test automation and eDP),
    /// else one the current state does not use (no pipe swap), else one it
    /// used as a secondary DPP (more streams before MPO planes), else any
    /// free pipe, else an MPC split (acquire_first_split_pipe).
    fn acquire_otg_master(&mut self, cur: &Self, stream: u8, sc: &dyn Scaling) -> Option<u8> {
        let found = self
            .free_used_as_otg_master_in_cur(cur)
            .or_else(|| self.free_not_used_in_cur(cur))
            .or_else(|| self.free_used_as_cur_sec_dpp(cur))
            .or_else(|| self.any_free());
        match found {
            Some(i) => {
                *self.pm(i) = PipeCtx {
                    stream: Some(stream),
                    ..PipeCtx::default()
                };
                Some(i)
            }
            None => self.acquire_first_split_pipe(stream, sc),
        }
    }
    /// acquire_first_split_pipe: the first pipe MPC-combined with the one
    /// above it leaves that tree for the stream; the pipe above scales its
    /// plane again (its result unchecked, as in Linux).
    fn acquire_first_split_pipe(&mut self, stream: u8, sc: &dyn Scaling) -> Option<u8> {
        for i in self.pool() {
            let p = *self.p(i);
            let Some(top) = p.top else { continue };
            if self.p(top).plane != p.plane {
                continue;
            }
            self.pm(top).bottom = p.bottom;
            if let Some(b) = p.bottom {
                self.pm(b).top = p.top;
            }
            if self.p(top).plane.is_some() {
                sc.build(self, top);
            }
            *self.pm(i) = PipeCtx {
                stream: Some(stream),
                ..PipeCtx::default()
            };
            return Some(i);
        }
        None
    }

    /// dcn32_find_optimal_free_pipe_as_secondary_dpp_pipe: a free pipe of
    /// the current blending tree of the OPP head at this index (no MPO
    /// pipe moves to another tree), else one the current state does not
    /// use, else a current MPC slice's (beyond its first), else any.
    fn optimal_free_as_secondary_dpp(&self, cur: &Self, new_opp_head: u8) -> Option<u8> {
        self.free_used_in_cur_mpc_blending_tree(cur, new_opp_head)
            .or_else(|| self.free_not_used_in_cur(cur))
            .or_else(|| self.free_used_as_cur_sec_dpp_in_mpcc_combine(cur))
            .or_else(|| self.any_free())
    }
    /// dcn32_acquire_free_pipe_as_secondary_dpp_pipe (DCN401 sets
    /// enable_windowed_mpo_odm, so the optimal search).
    fn acquire_secondary_dpp(&mut self, cur: &Self, opp_head: u8) -> Option<u8> {
        let i = self.optimal_free_as_secondary_dpp(cur, opp_head)?;
        self.pm(i).stream = self.p(opp_head).stream;
        Some(i)
    }
    /// find_optimal_free_pipe_as_secondary_opp_head: a free pipe the
    /// current OTG master at this index had as a further OPP head, else
    /// one the current state does not use, else any.
    fn optimal_free_as_secondary_opp_head(&self, cur: &Self, new_otg_master: u8) -> Option<u8> {
        self.free_used_as_sec_opp_head_by_cur_otg_master(cur, new_otg_master)
            .or_else(|| self.free_not_used_in_cur(cur))
            .or_else(|| self.any_free())
    }
    /// dcn32_acquire_free_pipe_as_secondary_opp_head.
    fn acquire_secondary_opp_head(&mut self, cur: &Self, otg_master: u8) -> Option<u8> {
        let i = self.optimal_free_as_secondary_opp_head(cur, otg_master)?;
        self.pm(i).stream = self.p(otg_master).stream;
        Some(i)
    }
    /// dcn20_release_pipe.
    fn release_pipe(&mut self, pipe: u8) {
        *self.pm(pipe) = PipeCtx::default();
    }

    /// add_plane_to_opp_head_pipes.
    fn add_plane_to_opp_heads(&mut self, otg_master: u8, plane: u8) -> bool {
        let mut at = Some(otg_master);
        while let Some(h) = at {
            if self.p(h).plane.is_some() {
                return false;
            }
            self.pm(h).plane = Some(plane);
            at = self.p(h).next_odm;
        }
        true
    }
    /// acquire_secondary_dpp_pipes_and_add_plane: one free pipe per OPP
    /// head at the bottom of its tree, linked across the ODM slices.
    fn acquire_secondary_dpps_and_add_plane(
        &mut self,
        cur: &Self,
        otg_master: u8,
        plane: u8,
    ) -> bool {
        let (heads, n) = self.opp_heads(otg_master);
        if self.free_pipe_count() < n {
            return false;
        }
        for &head in &heads[..n] {
            let Some(sec) = self.acquire_secondary_dpp(cur, head) else {
                return false;
            };
            self.pm(sec).plane = Some(plane);
            let tail = self.tail_pipe(head);
            self.pm(tail).bottom = Some(sec);
            self.pm(sec).top = Some(tail);
            self.pm(sec).bottom = None;
            match self.p(tail).prev_odm {
                Some(prev) => {
                    let left = self.p(prev).bottom;
                    self.pm(sec).prev_odm = left;
                    if let Some(left) = left {
                        self.pm(left).next_odm = Some(sec);
                    }
                }
                None => self.pm(sec).prev_odm = None,
            }
        }
        true
    }
    /// resource_append_dpp_pipes_for_plane_composition: the plane on the
    /// OPP heads or a secondary DPP per head, then its scaling on each of
    /// its pipes (its MPC slice count went from 0 to 1); a plane that
    /// cannot scale is removed again.
    fn append_dpp_pipes_for_plane(
        &mut self,
        cur: &Self,
        otg_master: u8,
        plane: u8,
        sc: &dyn Scaling,
    ) -> bool {
        let mut success = if self.p(otg_master).plane.is_none() {
            self.add_plane_to_opp_heads(otg_master, plane)
        } else {
            self.acquire_secondary_dpps_and_add_plane(cur, otg_master, plane)
        };
        if success {
            success = self.update_pipe_params_after_mpc_slice_count_change(plane, sc);
            if !success {
                self.remove_dpp_pipes_for_plane(plane);
            }
        }
        success
    }
    /// update_pipe_params_after_odm_slice_count_change: every planed pipe
    /// of the OTG master's stream scales on its slice, in pipe order until
    /// one cannot.
    fn update_pipe_params_after_odm_slice_count_change(
        &self,
        otg_master: u8,
        sc: &dyn Scaling,
    ) -> bool {
        let stream = self.p(otg_master).stream;
        self.pool().all(|i| {
            let p = self.p(i);
            p.stream != stream || p.plane.is_none() || sc.build(self, i)
        })
    }
    /// update_pipe_params_after_mpc_slice_count_change: every pipe of the
    /// plane scales on its slice, in pipe order until one cannot.
    fn update_pipe_params_after_mpc_slice_count_change(&self, plane: u8, sc: &dyn Scaling) -> bool {
        self.pool()
            .all(|i| self.p(i).plane != Some(plane) || sc.build(self, i))
    }
    /// resource_remove_dpp_pipes_for_plane_composition: from the last pool
    /// pipe down, each of the plane's pipes leaves its tree; an OPP head
    /// keeps its pipe without the plane, any other is cleared.
    fn remove_dpp_pipes_for_plane(&mut self, plane: u8) {
        for i in self.pool().rev() {
            let p = *self.p(i);
            if p.plane != Some(plane) {
                continue;
            }
            if let Some(top) = p.top {
                self.pm(top).bottom = p.bottom;
            }
            if let (Some(b), Some(_)) = (p.bottom, p.top) {
                self.pm(b).top = p.top;
            }
            if p.top.is_none() {
                self.pm(i).plane = None;
            } else {
                *self.pm(i) = PipeCtx::default();
            }
        }
    }

    /// acquire_pipes_and_add_odm_slice: a further OPP head after the last,
    /// and a secondary DPP under it for each plane below the last slice's
    /// top, duplicating its blending tree.
    fn acquire_pipes_and_add_odm_slice(&mut self, cur: &Self, otg_master: u8) -> bool {
        let last_head = self.last_opp_head(otg_master);
        let Some(new_head) = self.acquire_secondary_opp_head(cur, otg_master) else {
            return false;
        };
        self.pm(last_head).next_odm = Some(new_head);
        self.pm(new_head).prev_odm = Some(last_head);
        self.pm(new_head).next_odm = None;
        self.pm(new_head).plane = self.p(last_head).plane;
        // Linux never moves new_top_dpp_pipe off the new OPP head: each
        // further plane links under it (on DCN401's four pipes a second
        // slice holds at most one plane below the top).
        let new_top = new_head;
        let mut last_top = last_head;
        while let Some(last_bottom) = self.p(last_top).bottom {
            let Some(new_bottom) = self.acquire_secondary_dpp(cur, new_head) else {
                return false;
            };
            self.pm(new_bottom).plane = self.p(last_bottom).plane;
            self.pm(new_top).bottom = Some(new_bottom);
            self.pm(new_bottom).top = Some(new_top);
            self.pm(last_bottom).next_odm = Some(new_bottom);
            self.pm(new_bottom).prev_odm = Some(last_bottom);
            self.pm(new_bottom).next_odm = None;
            last_top = last_bottom;
        }
        true
    }
    /// release_pipes_and_remove_odm_slice: the last slice's pipes, its tree
    /// from the bottom, then its OPP head.
    fn release_pipes_and_remove_odm_slice(&mut self, otg_master: u8) -> bool {
        let last_head = self.last_opp_head(otg_master);
        let mut tail = self.tail_pipe(last_head);
        if self.is(last_head, PipeType::OtgMaster) {
            return false;
        }
        while let Some(top) = self.p(tail).top {
            if let Some(prev) = self.p(tail).prev_odm {
                self.pm(prev).next_odm = None;
            }
            tail = top;
            if let Some(b) = self.p(tail).bottom {
                self.release_pipe(b);
            }
            self.pm(tail).bottom = None;
        }
        if let Some(prev) = self.p(last_head).prev_odm {
            self.pm(prev).next_odm = None;
        }
        self.release_pipe(last_head);
        true
    }
    /// acquire_dpp_pipe_and_add_mpc_slice: a secondary DPP right after the
    /// plane's last MPC slice in its tree.
    fn acquire_dpp_pipe_and_add_mpc_slice(&mut self, cur: &Self, dpp: u8) -> bool {
        let last = self.last_dpp_in_mpcc_combine(dpp);
        let opp_head = self.opp_head(dpp);
        let Some(new) = self.acquire_secondary_dpp(cur, opp_head) else {
            return false;
        };
        if self.odm_slice_count(dpp) > 1 {
            return false;
        }
        let below = self.p(last).bottom;
        self.pm(new).bottom = below;
        if let Some(b) = below {
            self.pm(b).top = Some(new);
        }
        self.pm(new).top = Some(last);
        self.pm(last).bottom = Some(new);
        self.pm(new).plane = self.p(last).plane;
        true
    }
    /// release_dpp_pipe_and_remove_mpc_slice: the plane's last MPC slice.
    fn release_dpp_pipe_and_remove_mpc_slice(&mut self, dpp: u8) -> bool {
        let last = self.last_dpp_in_mpcc_combine(dpp);
        if self.is(last, PipeType::OppHead) || self.odm_slice_count(dpp) > 1 {
            return false;
        }
        let (top, bottom) = (self.p(last).top, self.p(last).bottom);
        if let Some(t) = top {
            self.pm(t).bottom = bottom;
        }
        if let Some(b) = bottom {
            self.pm(b).top = top;
        }
        self.release_pipe(last);
        true
    }

    /// resource_update_pipes_for_stream_with_slice_count.
    pub fn update_pipes_for_stream_with_slice_count(
        &mut self,
        cur: &Self,
        stream: u8,
        slices: usize,
        sc: &dyn Scaling,
    ) -> bool {
        let Some(otg) = self.otg_master_for_stream(stream) else {
            return false;
        };
        let have = self.odm_slice_count(otg);
        if slices == have {
            return true;
        }
        let mut result = true;
        if slices > have {
            for _ in 0..slices - have {
                if !result {
                    break;
                }
                result = self.acquire_pipes_and_add_odm_slice(cur, otg);
            }
        } else {
            for _ in 0..have - slices {
                if !result {
                    break;
                }
                result = self.release_pipes_and_remove_odm_slice(otg);
            }
        }
        if result {
            result = self.update_pipe_params_after_odm_slice_count_change(otg, sc);
        }
        result
    }
    /// resource_update_pipes_for_plane_with_slice_count.
    pub fn update_pipes_for_plane_with_slice_count(
        &mut self,
        cur: &Self,
        plane: u8,
        slices: usize,
        sc: &dyn Scaling,
    ) -> bool {
        let (dpp, n) = self.dpp_pipes_for_plane(plane);
        if n == 0 {
            return false;
        }
        let have = self.mpc_slice_count(dpp[0]);
        if slices == have {
            return true;
        }
        let mut result = true;
        if slices > have {
            for _ in 0..slices - have {
                if !result {
                    break;
                }
                result = self.acquire_dpp_pipe_and_add_mpc_slice(cur, dpp[0]);
            }
        } else {
            for _ in 0..have - slices {
                if !result {
                    break;
                }
                result = self.release_dpp_pipe_and_remove_mpc_slice(dpp[0]);
            }
        }
        if result {
            // dpp_pipes[0]->plane_state: the plane.
            result = self.update_pipe_params_after_mpc_slice_count_change(plane, sc);
        }
        result
    }

    fn status_index(&self, stream: u8) -> Option<usize> {
        self.streams().iter().position(|s| s.stream == stream)
    }

    /// dc_state_add_stream: one stream per timing generator; its OTG master
    /// (resource_map_pool_resources's acquisition). A stream without one is
    /// still in the state (DC_NO_CONTROLLER_RESOURCE fails the commit).
    pub fn add_stream(&mut self, cur: &Self, stream: u8, sc: &dyn Scaling) -> bool {
        if self.stream_count >= self.pipe_count {
            return false;
        }
        self.streams[usize::from(self.stream_count)] = StreamStatus {
            stream,
            ..StreamStatus::default()
        };
        self.stream_count += 1;
        self.acquire_otg_master(cur, stream, sc);
        self.otg_master_for_stream(stream).is_some()
    }
    /// dc_state_remove_stream: its ODM slices released, its encoders
    /// released (resource_remove_otg_master_for_stream_output), its OTG
    /// master cleared, its status dropped.
    pub fn remove_stream(&mut self, cur: &Self, stream: u8, sc: &dyn Scaling) -> bool {
        if self.otg_master_for_stream(stream).is_none() {
            return false;
        }
        self.update_pipes_for_stream_with_slice_count(cur, stream, 1, sc);
        if let Some(i) = self.status_index(stream) {
            if let Some(e) = self.streams[i].encoders.take() {
                let link = self.streams[i].output.link;
                self.release_stream_encoders(link, e);
            }
        }
        if let Some(otg) = self.otg_master_for_stream(stream) {
            *self.pm(otg) = PipeCtx::default();
        }
        let Some(i) = self.status_index(stream) else {
            return false;
        };
        let n = usize::from(self.stream_count);
        self.streams.copy_within(i + 1..n, i);
        self.stream_count -= 1;
        self.streams[usize::from(self.stream_count)] = StreamStatus::default();
        true
    }
    /// dcn10_find_first_free_match_stream_enc_for_link: the free DIO stream
    /// encoder of the link encoder's preferred engine, else the last free
    /// one ("for CZ and later, we can allow DIG FE and BE to differ").
    pub fn find_first_free_match_stream_enc_for_link(&self, output: StreamOutput) -> Option<u8> {
        let mut j = None;
        for i in 0..STREAM_ENCODERS as u8 {
            if !self.stream_enc_acquired[usize::from(i)] {
                j = Some(i);
                if i == output.preferred_engine {
                    return Some(i);
                }
            }
        }
        j
    }
    /// find_first_free_match_hpo_dp_stream_enc_for_link.
    pub fn find_first_free_match_hpo_dp_stream_enc_for_link(&self) -> Option<u8> {
        (0..HPO_DP_STREAM_ENCODERS as u8)
            .find(|&i| !self.hpo_dp_stream_enc_acquired[usize::from(i)])
    }
    /// find_acquired_hpo_dp_link_enc_for_link.
    pub fn find_acquired_hpo_dp_link_enc_for_link(&self, link: u8) -> Option<u8> {
        (0..HPO_DP_LINK_ENCODERS as u8).find(|&i| {
            self.hpo_dp_link_enc_refs[usize::from(i)] > 0
                && self.hpo_dp_link_enc_link[usize::from(i)] == link
        })
    }
    /// find_free_hpo_dp_link_enc.
    fn find_free_hpo_dp_link_enc(&self) -> Option<u8> {
        (0..HPO_DP_LINK_ENCODERS as u8).find(|&i| self.hpo_dp_link_enc_refs[usize::from(i)] == 0)
    }
    /// add_hpo_dp_link_enc_to_ctx: the link's acquired HPO DP link encoder
    /// retained, else a free one acquired for it.
    fn add_hpo_dp_link_enc_to_ctx(&mut self, link: u8) -> Option<u8> {
        if let Some(i) = self.find_acquired_hpo_dp_link_enc_for_link(link) {
            self.hpo_dp_link_enc_refs[usize::from(i)] += 1;
            return Some(i);
        }
        let i = self.find_free_hpo_dp_link_enc()?;
        self.hpo_dp_link_enc_link[usize::from(i)] = link;
        self.hpo_dp_link_enc_refs[usize::from(i)] = 1;
        Some(i)
    }
    /// find_first_free_audio for the stream encoder of engine `id`: the
    /// free endpoint of that index whose stream encoder is acquired, else
    /// the free endpoint of that index, else the first free one.
    pub fn find_first_free_audio(&self, id: u8) -> Option<u8> {
        let id = usize::from(id);
        for i in 0..AUDIOS {
            if !self.audio_acquired[i] && self.stream_enc_acquired.get(i) == Some(&true) {
                // We have enough audio endpoints: find the matching inst.
                if id != i {
                    continue;
                }
                return Some(i as u8);
            }
        }
        if id < AUDIOS && !self.audio_acquired[id] {
            return Some(id as u8);
        }
        // Not found the matching one: first come, first served.
        (0..AUDIOS)
            .find(|&i| !self.audio_acquired[i])
            .map(|i| i as u8)
    }
    /// The encoders `encoders` of a stream on `link` held in this state
    /// (update_stream_engine_usage, update_hpo_dp_stream_engine_usage and
    /// update_audio_usage with acquired set, add_hpo_dp_link_enc_to_ctx).
    fn hold_stream_encoders(&mut self, link: u8, e: StreamEncoders) {
        self.stream_enc_acquired[usize::from(e.stream_enc)] = true;
        if let Some(a) = e.audio {
            self.audio_acquired[usize::from(a)] = true;
        }
        if let Some(h) = e.hpo_dp_stream_enc {
            self.hpo_dp_stream_enc_acquired[usize::from(h)] = true;
        }
        if let Some(l) = e.hpo_dp_link_enc {
            let refs = &mut self.hpo_dp_link_enc_refs[usize::from(l)];
            if *refs == 0 {
                self.hpo_dp_link_enc_link[usize::from(l)] = link;
            }
            *refs += 1;
        }
    }
    /// resource_remove_otg_master_for_stream_output's encoder releases.
    fn release_stream_encoders(&mut self, link: u8, e: StreamEncoders) {
        self.stream_enc_acquired[usize::from(e.stream_enc)] = false;
        if let Some(h) = e.hpo_dp_stream_enc {
            self.hpo_dp_stream_enc_acquired[usize::from(h)] = false;
        }
        // remove_hpo_dp_link_enc_from_ctx: the link's encoder, by link.
        if e.hpo_dp_link_enc.is_some() {
            if let Some(i) = self.find_acquired_hpo_dp_link_enc_for_link(link) {
                self.hpo_dp_link_enc_refs[usize::from(i)] -= 1;
            }
        }
        if let Some(a) = e.audio {
            self.audio_acquired[usize::from(a)] = false;
        }
    }
    /// resource_map_pool_resources' encoders for `stream`, which holds its
    /// OTG master: the DIO stream encoder (DC_NO_STREAM_ENC_RESOURCE
    /// without one), then on a 128b/132b DP output the first free HPO DP
    /// stream encoder and the link's HPO DP link encoder
    /// (DC_NO_LINK_ENC_RESOURCE without one), then for a stream with audio
    /// the endpoint find_first_free_audio gives its DIO stream encoder's
    /// engine (none leaves the stream without audio, as Linux does). None
    /// refuses the state, as Linux fails the commit.
    pub fn map_stream_encoders(
        &mut self,
        stream: u8,
        output: StreamOutput,
    ) -> Option<StreamEncoders> {
        let i = self.status_index(stream)?;
        self.otg_master_for_stream(stream)?;
        if self.streams[i].encoders.is_some() {
            return None;
        }
        let stream_enc = self.find_first_free_match_stream_enc_for_link(output)?;
        self.stream_enc_acquired[usize::from(stream_enc)] = true;
        let mut e = StreamEncoders {
            stream_enc,
            hpo_dp_stream_enc: None,
            hpo_dp_link_enc: None,
            audio: None,
        };
        self.streams[i].output = output;
        self.streams[i].encoders = Some(e);
        if output.hpo_dp {
            let h = self.find_first_free_match_hpo_dp_stream_enc_for_link()?;
            self.hpo_dp_stream_enc_acquired[usize::from(h)] = true;
            e.hpo_dp_stream_enc = Some(h);
            self.streams[i].encoders = Some(e);
            e.hpo_dp_link_enc = Some(self.add_hpo_dp_link_enc_to_ctx(output.link)?);
            self.streams[i].encoders = Some(e);
        }
        if output.audio {
            // stream_enc->id: DIGA-DIGD are engines 0-3.
            e.audio = self.find_first_free_audio(stream_enc);
            if let Some(a) = e.audio {
                self.audio_acquired[usize::from(a)] = true;
            }
            self.streams[i].encoders = Some(e);
        }
        Some(e)
    }
    /// A running stream's encoders, as the state it runs in records them.
    pub fn adopt_stream_encoders(&mut self, stream: u8, output: StreamOutput, e: StreamEncoders) {
        let Some(i) = self.status_index(stream) else {
            return;
        };
        self.streams[i].output = output;
        self.streams[i].encoders = Some(e);
        self.hold_stream_encoders(output.link, e);
    }

    /// dc_state_add_plane: the plane on the stream's OPP heads (its first)
    /// or on a secondary DPP per OPP head; short of pipes, every stream's
    /// MPC combine is dropped and it tries again, then the stream's ODM
    /// slices one by one.
    pub fn add_plane(&mut self, cur: &Self, stream: u8, plane: u8, sc: &dyn Scaling) -> bool {
        let Some(si) = self.status_index(stream) else {
            return false;
        };
        if usize::from(self.streams[si].plane_count) == MAX_SURFACES {
            return false;
        }
        let Some(otg) = self.otg_master_for_stream(stream) else {
            return false;
        };
        let mut added = self.append_dpp_pipes_for_plane(cur, otg, plane, sc);
        if !added {
            // remove_mpc_combine_for_stream on every stream.
            for i in 0..usize::from(self.stream_count) {
                let s = self.streams[i];
                for &p in s.planes() {
                    self.update_pipes_for_plane_with_slice_count(cur, p, 1, sc);
                }
            }
            added = self.append_dpp_pipes_for_plane(cur, otg, plane, sc);
        }
        if !added {
            let slices = self.odm_slice_count(otg);
            for i in (1..slices).rev() {
                self.update_pipes_for_stream_with_slice_count(cur, stream, i, sc);
                added = self.append_dpp_pipes_for_plane(cur, otg, plane, sc);
                if added {
                    break;
                }
            }
        }
        if added {
            let s = &mut self.streams[si];
            s.planes[usize::from(s.plane_count)] = plane;
            s.plane_count += 1;
        }
        added
    }
    /// dc_state_remove_plane.
    pub fn remove_plane(&mut self, stream: u8, plane: u8) -> bool {
        let Some(si) = self.status_index(stream) else {
            return false;
        };
        self.remove_dpp_pipes_for_plane(plane);
        let s = &mut self.streams[si];
        let n = usize::from(s.plane_count);
        let Some(k) = s.planes[..n].iter().position(|&p| p == plane) else {
            return false;
        };
        s.planes.copy_within(k + 1..n, k);
        s.plane_count -= 1;
        s.planes[usize::from(s.plane_count)] = 0;
        true
    }

    /// map_dc_pipes_with_callbacks: each stream's ODM and each plane's MPC
    /// source counts from this state and `target(stream)`'s (an MPC target
    /// of 1 on an ODM stream); every reduction first (a stream's planes,
    /// then its ODM), then every increase, stream by stream.
    pub fn map_pipes(
        &mut self,
        cur: &Self,
        target: impl Fn(u8) -> Target,
        sc: &dyn Scaling,
    ) -> bool {
        #[derive(Clone, Copy, Default)]
        struct Factor {
            source: usize,
            target: usize,
        }
        let n = usize::from(self.stream_count);
        let mut odm = [Factor::default(); MAX_STREAMS];
        let mut mpc = [[Factor::default(); MAX_SURFACES]; MAX_STREAMS];
        for (i, f) in odm.iter_mut().enumerate().take(n) {
            let s = self.streams[i];
            let t = target(s.stream);
            *f = Factor {
                source: self
                    .otg_master_for_stream(s.stream)
                    .map_or(0, |m| self.odm_slice_count(m)),
                target: usize::from(t.odm),
            };
        }
        for i in 0..n {
            let s = self.streams[i];
            let t = target(s.stream);
            for (k, &p) in s.planes().iter().enumerate() {
                let (dpp, count) = self.dpp_pipes_for_plane(p);
                mpc[i][k] = Factor {
                    source: if count > 0 {
                        self.mpc_slice_count(dpp[0])
                    } else {
                        0
                    },
                    target: if odm[i].target == 1 {
                        usize::from(t.mpc[k])
                    } else {
                        1
                    },
                };
            }
        }
        let mut result = true;
        for i in 0..n {
            let s = self.streams[i];
            for (k, &p) in s.planes().iter().enumerate() {
                if mpc[i][k].target < mpc[i][k].source {
                    result &=
                        self.update_pipes_for_plane_with_slice_count(cur, p, mpc[i][k].target, sc);
                }
            }
            if odm[i].target < odm[i].source {
                result &=
                    self.update_pipes_for_stream_with_slice_count(cur, s.stream, odm[i].target, sc);
            }
        }
        for i in 0..n {
            let s = self.streams[i];
            for (k, &p) in s.planes().iter().enumerate() {
                if mpc[i][k].target > mpc[i][k].source {
                    result &=
                        self.update_pipes_for_plane_with_slice_count(cur, p, mpc[i][k].target, sc);
                }
            }
            if odm[i].target > odm[i].source {
                result &=
                    self.update_pipes_for_stream_with_slice_count(cur, s.stream, odm[i].target, sc);
            }
        }
        result
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn401_resource_tests.rs"]
mod tests;
