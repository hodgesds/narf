//! DCN 3.x/4 CRTC color math, ported bit-exactly from Linux's integer code:
//! dc/basics/fixpt31_32.c (`Fixed31_32`), modules/color/color_gamma.c (the
//! distributed transfer-function points), dc/dcn30/dcn30_cm_common.c (their
//! translation into MPC OGAM PWL registers), dc/basics/custom_float.c,
//! dc/basics/conversion.c and mpc401_set_gamut_remap (CTM coefficients),
//! with the DRM-facing helpers of amdgpu_dm_color.c.
//!
//! Only what amdgpu_dm's CRTC properties reach on DCN 4.0.1 is here: the
//! post-blend GAMMA_LUT (a 4096-entry atomic LUT on a linear base, or a
//! 256-entry legacy ramp on an sRGB base), the CTM, and legacy gamma's
//! implicit BT.709 degamma of an NV12 plane (mod_color_calculate_degamma_params
//! and cm3_helper_translate_curve_to_degamma_hw_format: the DPP GAMCOR
//! curve). DCN 4.0.1 exposes no CRTC DEGAMMA_LUT (amdgpu_dm_crtc.c), so no
//! other GAMCOR curve is built.
//! Everything is pure integer arithmetic on the heap; nothing touches
//! hardware. `drivers/gpu/tests/dcn401_color/check.sh` checks the outputs
//! against Linux compiled on the host.
//!
//! C's signed overflow (undefined, two's-complement on every Linux target)
//! is reproduced with wrapping arithmetic. Where Linux would divide by zero
//! or loop forever (inputs these entry points never produce), the port
//! returns zero or stops after a bound instead of trapping.
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

/// DRM's `struct drm_color_lut`: one 16-bit entry per channel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrmColorLut {
    pub red: u16,
    pub green: u16,
    pub blue: u16,
    pub reserved: u16,
}

impl DrmColorLut {
    /// Decode a GAMMA_LUT/DEGAMMA_LUT blob (8-byte little-endian entries);
    /// `None` when its length is not a whole number of entries, as
    /// drm_atomic_replace_property_blob_from_id's element size check.
    pub fn from_bytes(blob: &[u8]) -> Option<Vec<Self>> {
        if blob.len() % 8 != 0 {
            return None;
        }
        Some(
            blob.chunks_exact(8)
                .map(|e| Self {
                    red: u16::from_le_bytes([e[0], e[1]]),
                    green: u16::from_le_bytes([e[2], e[3]]),
                    blue: u16::from_le_bytes([e[4], e[5]]),
                    reserved: u16::from_le_bytes([e[6], e[7]]),
                })
                .collect(),
        )
    }
}

/// amdgpu_dm's LUT sizes and DRM's maximum entry value.
pub const MAX_COLOR_LUT_ENTRIES: usize = 4096;
pub const MAX_COLOR_LEGACY_LUT_ENTRIES: usize = 256;
pub const MAX_DRM_LUT_VALUE: u32 = 0xFFFF;

/// Linux `struct fixed31_32`: signed 31.32 fixed point, two's complement.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Fixed31_32(pub i64);

const FRACTIONAL_MASK: u64 = (1 << 32) - 1;

// Named after Linux's dc_fixpt_* helpers rather than core::ops, so every
// operation keeps C's wrapping and rounding visibly.
#[allow(clippy::should_implement_trait)]
impl Fixed31_32 {
    pub const ZERO: Self = Self(0);
    pub const EPSILON: Self = Self(1);
    pub const HALF: Self = Self(0x8000_0000);
    pub const ONE: Self = Self(0x1_0000_0000);
    const LN2: Self = Self(2_977_044_471);
    const LN2_DIV_2: Self = Self(1_488_522_236);

    /// The magnitude as C's `arg < 0 ? -arg : arg` cast to unsigned.
    fn magnitude(self) -> u64 {
        if self.0 < 0 {
            self.0.wrapping_neg() as u64
        } else {
            self.0 as u64
        }
    }
    /// dc_fixpt_from_int.
    pub fn from_int(arg: i32) -> Self {
        Self(i64::from(arg) << 32)
    }
    /// dc_fixpt_from_fraction: long division with the LSB rounded half up.
    /// A zero denominator (a division trap in C) gives zero.
    pub fn from_fraction(numerator: i64, denominator: i64) -> Self {
        let negative = (numerator < 0) ^ (denominator < 0);
        let a1 = Self(numerator).magnitude();
        let a2 = Self(denominator).magnitude();
        if a2 == 0 {
            return Self::ZERO;
        }
        let mut res = a1 / a2;
        let mut remainder = a1 % a2;
        for _ in 0..32 {
            remainder <<= 1;
            res <<= 1;
            if remainder >= a2 {
                res |= 1;
                remainder -= a2;
            }
        }
        res = res.wrapping_add(u64::from((remainder << 1) >= a2));
        let value = res as i64;
        Self(if negative {
            value.wrapping_neg()
        } else {
            value
        })
    }
    pub fn neg(self) -> Self {
        Self(self.0.wrapping_neg())
    }
    pub fn abs(self) -> Self {
        if self.0 < 0 {
            self.neg()
        } else {
            self
        }
    }
    pub fn lt(self, other: Self) -> bool {
        self.0 < other.0
    }
    pub fn le(self, other: Self) -> bool {
        self.0 <= other.0
    }
    /// dc_fixpt_clamp.
    pub fn clamp_to(self, min: Self, max: Self) -> Self {
        if self.le(min) {
            min
        } else if max.le(self) {
            max
        } else {
            self
        }
    }
    pub fn add(self, other: Self) -> Self {
        Self(self.0.wrapping_add(other.0))
    }
    pub fn sub(self, other: Self) -> Self {
        Self(self.0.wrapping_sub(other.0))
    }
    /// dc_fixpt_shl (shift counts wrap modulo 64, as x86 shifts do).
    pub fn shl(self, shift: u8) -> Self {
        Self(self.0.wrapping_shl(u32::from(shift)))
    }
    /// dc_fixpt_shr: the magnitude shifted, the sign kept.
    pub fn shr(self, shift: u8) -> Self {
        let negative = self.0 < 0;
        let mut v = if negative {
            self.0.wrapping_neg()
        } else {
            self.0
        };
        v = v.wrapping_shr(u32::from(shift));
        Self(if negative { v.wrapping_neg() } else { v })
    }
    /// dc_fixpt_mul: integer and fractional cross products, the
    /// fraction-by-fraction term rounded half up.
    pub fn mul(self, other: Self) -> Self {
        let negative = (self.0 < 0) ^ (other.0 < 0);
        let (a1, a2) = (self.magnitude(), other.magnitude());
        let (i1, i2) = (a1 >> 32, a2 >> 32);
        let (f1, f2) = (a1 & FRACTIONAL_MASK, a2 & FRACTIONAL_MASK);
        let mut res = i1.wrapping_mul(i2) << 32;
        res = res.wrapping_add(i1.wrapping_mul(f2));
        res = res.wrapping_add(i2.wrapping_mul(f1));
        let tmp = f1 * f2;
        res = res.wrapping_add((tmp >> 32) + u64::from(tmp >= Self::HALF.0 as u64));
        let value = res as i64;
        Self(if negative {
            value.wrapping_neg()
        } else {
            value
        })
    }
    pub fn mul_int(self, arg: i32) -> Self {
        self.mul(Self::from_int(arg))
    }
    pub fn div(self, other: Self) -> Self {
        Self::from_fraction(self.0, other.0)
    }
    /// dc_fixpt_div_int (the divisor goes through `int`, as in C).
    pub fn div_int(self, arg: i64) -> Self {
        Self::from_fraction(self.0, Self::from_int(arg as i32).0)
    }
    pub fn recip(self) -> Self {
        Self::from_fraction(Self::ONE.0, self.0)
    }
    /// fixed31_32_exp_from_taylor_series (|arg| < 1).
    fn exp_taylor(self) -> Self {
        let mut n: i64 = 9;
        let mut res = Self::from_fraction(n + 2, n + 1);
        loop {
            res = Self::ONE.add(self.mul(res).div_int(n));
            n -= 1;
            if n == 1 {
                break;
            }
        }
        Self::ONE.add(self.mul(res))
    }
    /// dc_fixpt_exp: exp(r + m ln 2) = 2^m exp(r).
    pub fn exp(self) -> Self {
        if Self::LN2_DIV_2.le(self.abs()) {
            let m = self.div(Self::LN2).round();
            let r = self.sub(Self::LN2.mul_int(m));
            if m > 0 {
                r.exp_taylor().shl(m as u8)
            } else {
                r.exp_taylor()
                    .div_int(1i64.wrapping_shl(m.wrapping_neg() as u32))
            }
        } else if self.0 != 0 {
            self.exp_taylor()
        } else {
            Self::ONE
        }
    }
    /// dc_fixpt_log: Newton iteration from -1 until the step is at most 100
    /// ULP. Linux iterates without bound; this stops after 1000 steps, far
    /// beyond what any positive argument needs.
    pub fn log(self) -> Self {
        let mut res = Self::ONE.neg();
        for _ in 0..1000 {
            let res1 = res.sub(Self::ONE).add(self.div(res.exp()));
            let error = res.sub(res1);
            res = res1;
            if error.magnitude() <= 100 {
                break;
            }
        }
        res
    }
    /// dc_fixpt_pow: exp(log(a) * b); 0^0 = 1, 0^b = 0.
    pub fn pow(self, power: Self) -> Self {
        if self.0 == 0 {
            return if power.0 == 0 { Self::ONE } else { Self::ZERO };
        }
        self.log().mul(power).exp()
    }
    /// C's `(int)` of the shifted magnitude, then the sign.
    fn signed_int(self, magnitude: u64) -> i32 {
        let v = (magnitude >> 32) as u32 as i32;
        if self.0 >= 0 {
            v
        } else {
            v.wrapping_neg()
        }
    }
    /// dc_fixpt_floor (truncation toward zero, as Linux does it).
    pub fn floor(self) -> i32 {
        self.signed_int(self.magnitude())
    }
    /// dc_fixpt_round (half away from zero).
    pub fn round(self) -> i32 {
        self.signed_int(self.magnitude().wrapping_add(Self::HALF.0 as u64))
    }
    /// dc_fixpt_ceil (away from zero).
    pub fn ceil(self) -> i32 {
        self.signed_int(
            self.magnitude()
                .wrapping_add((Self::ONE.0 - Self::EPSILON.0) as u64),
        )
    }
    /// dc_fixpt_clamp_u0d14: clamp_ux_dy(value, 0, 14, 1).
    pub fn clamp_u0d14(self) -> u32 {
        let value = self.0;
        // ux_dy: no integer bits, the top 14 fraction bits.
        let truncated = ((value as u64 & FRACTIONAL_MASK) as u32) >> (32 - 14);
        if value >= 1 << 32 {
            (1 << 14) - 1
        } else if truncated > 1 {
            truncated
        } else {
            1
        }
    }
}

type Fx = Fixed31_32;

/// Linux `struct custom_float_format`.
#[derive(Clone, Copy)]
struct CustomFloatFormat {
    mantissa_bits: u32,
    exponenta_bits: u32,
    sign: bool,
}

/// convert_to_custom_float_format (build_custom_float then
/// setup_custom_float). Never fails for the formats used here.
fn custom_float(mut value: Fx, format: CustomFloatFormat) -> u32 {
    let exp_offset: u32 = (1 << (format.exponenta_bits - 1)) - 1;
    let max_fraction = Fx::from_fraction(
        (1i64 << (format.mantissa_bits + 1)) - 1,
        1i64 << format.mantissa_bits,
    );
    let (negative, mantissa, exponenta) = 'build: {
        if value == Fx::ZERO {
            break 'build (false, 0u32, 0u32);
        }
        let negative = if value.lt(Fx::ZERO) {
            value = value.neg();
            format.sign
        } else {
            false
        };
        let exponenta;
        if value.lt(Fx::ONE) {
            let mut i: u32 = 1;
            // Linux loops until the value reaches one; a value that the
            // shifts lose entirely (none here) would never get there.
            loop {
                value = value.shl(1);
                i += 1;
                if !value.lt(Fx::ONE) || i > 66 {
                    break;
                }
            }
            i -= 1;
            if exp_offset <= i {
                break 'build (negative, 0, 0);
            }
            exponenta = exp_offset - i;
        } else if max_fraction.le(value) {
            let mut i: u32 = 1;
            loop {
                value = value.shr(1);
                i += 1;
                if !max_fraction.lt(value) {
                    break;
                }
            }
            exponenta = exp_offset + i - 1;
        } else {
            exponenta = exp_offset;
        }
        let mut mantiss = value.sub(Fx::ONE);
        if mantiss.lt(Fx::ZERO) || Fx::ONE.lt(mantiss) {
            mantiss = Fx::ZERO;
        } else {
            mantiss = mantiss.shl(format.mantissa_bits as u8);
        }
        (negative, mantiss.floor() as u32, exponenta)
    };
    // setup_custom_float, its verification masks included.
    let mantissa_mask = (1u32 << (format.mantissa_bits + 1)) - 1;
    let exponenta_mask = (1u32 << (format.exponenta_bits + 1)) - 1;
    let mantissa = if mantissa & !mantissa_mask != 0 {
        mantissa_mask
    } else {
        mantissa
    };
    let exponenta = if exponenta & !exponenta_mask != 0 {
        exponenta_mask
    } else {
        exponenta
    };
    let m = format.mantissa_bits;
    let e = format.exponenta_bits;
    let mut out = mantissa & ((1u32 << m) - 1);
    out |= (exponenta & ((1u32 << e) - 1)) << m;
    if negative && format.sign {
        out |= 1 << (m + e);
    }
    out
}

/// __is_lut_linear: equal channels within +-1 of i * 0xFFFF / (size - 1).
/// Fewer than two entries are never linear.
pub fn is_lut_linear(lut: &[DrmColorLut]) -> bool {
    let size = lut.len() as u32;
    if size < 2 {
        return false;
    }
    lut.iter().enumerate().all(|(i, e)| {
        let expected = (i as u32).wrapping_mul(MAX_DRM_LUT_VALUE) / (size - 1);
        let delta = u32::from(e.red).wrapping_sub(expected) as i32;
        e.red == e.green && e.green == e.blue && (-1..=1).contains(&delta)
    })
}

/// amdgpu_dm_fixpt_from_s3132: DRM's sign-magnitude S31.32 to two's
/// complement.
pub fn fixpt_from_s3132(x: u64) -> Fx {
    let x = if x & 1 << 63 != 0 {
        (x & !(1 << 63)).wrapping_neg()
    } else {
        x
    };
    Fixed31_32(x as i64)
}

/// A DRM CTM blob (`struct drm_color_ctm`, nine u64), or `None` for any
/// other length.
pub fn ctm_from_bytes(blob: &[u8]) -> Option<[u64; 9]> {
    if blob.len() != 72 {
        return None;
    }
    let mut m = [0u64; 9];
    for (v, b) in m.iter_mut().zip(blob.chunks_exact(8)) {
        *v = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    }
    Some(m)
}

/// __drm_ctm_to_dc_matrix: the 3x3 CTM as DC's 3x4 matrix, every fourth
/// (offset) entry zero.
pub fn ctm_matrix(ctm: &[u64; 9]) -> [Fx; 12] {
    let mut m = [Fx::ZERO; 12];
    for (i, v) in m.iter_mut().enumerate() {
        if i % 4 != 3 {
            *v = fixpt_from_s3132(ctm[i - i / 4]);
        }
    }
    m
}

/// The MPCC OGAM gamut remap coefficients mpc401_set_gamut_remap programs
/// for a software matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GamutRemap {
    /// convert_float_matrix's register values, C11..C14, C21..C24, C31..C34.
    pub coef: [u16; 12],
    /// MPCC_GAMUT_REMAP_COEF_FORMAT: S3.12 (1) when some coefficient's
    /// magnitude exceeds S2.13's 3.9999, else S2.13 (0).
    pub s3_12: bool,
}

impl GamutRemap {
    /// MPC_GAMUT_REMAP_C11_C12 .. C33_C34 as cm_helper_program_color_matrices
    /// writes them: the even coefficient low, the odd one high.
    pub fn words(&self) -> [u32; 6] {
        core::array::from_fn(|i| {
            u32::from(self.coef[2 * i]) | u32::from(self.coef[2 * i + 1]) << 16
        })
    }
}

const DIVIDER: i64 = 10000;
const S2D13_MIN: i64 = -4 * DIVIDER;
const S2D13_MAX: i64 = 39999;
const S3D12_MIN: i64 = -8 * DIVIDER;
const S3D12_MAX: i64 = 79998;

/// conversion.c's fixed_point_to_int_frac.
fn fixed_point_to_int_frac(arg: Fx, integer_bits: u32, fractional_bits: u32) -> u16 {
    let divisor: i32 = 1 << fractional_bits;
    let d = arg.abs().floor() as u16;
    // (uint16_t)(1 << integer_bits) - 1 / (uint16_t)divisor; the quotient is 0.
    let numerator: i32 = if i32::from(d) <= (1i32 << integer_bits) - 1 / divisor {
        i32::from(arg.mul_int(divisor).round() as u16)
    } else {
        Fx::from_int(1 << integer_bits)
            .sub(Fx::from_int(divisor).recip())
            .floor()
    };
    let mut result = if numerator >= 0 {
        numerator as u16
    } else {
        ((1i32 << (integer_bits + fractional_bits + 1)) + numerator) as u16
    };
    if result != 0 && arg.lt(Fx::ZERO) {
        result |= 1 << (integer_bits + fractional_bits);
    }
    result
}

/// mpc401_set_gamut_remap's software path: the format from the largest
/// coefficient magnitude, then convert_float_matrix (each coefficient
/// clamped to the format's range).
pub fn gamut_remap(matrix: &[Fx; 12]) -> GamutRemap {
    let mut abs_max = Fx::ZERO;
    for m in matrix {
        if abs_max.le(m.abs()) {
            abs_max = m.abs();
        }
    }
    let s3_12 = !abs_max.le(Fx::from_fraction(S2D13_MAX, DIVIDER));
    let (min, max, int_bits, frac_bits) = if s3_12 {
        (S3D12_MIN, S3D12_MAX, 3, 12)
    } else {
        (S2D13_MIN, S2D13_MAX, 2, 13)
    };
    let (min, max) = (
        Fx::from_fraction(min, DIVIDER),
        Fx::from_fraction(max, DIVIDER),
    );
    GamutRemap {
        coef: core::array::from_fn(|i| {
            fixed_point_to_int_frac(matrix[i].clamp_to(min, max), int_bits, frac_bits)
        }),
        s3_12,
    }
}

const NUM_PTS_IN_REGION: usize = 16;
const NUM_REGIONS: i32 = 32;
const MAX_HW_POINTS: usize = NUM_PTS_IN_REGION * NUM_REGIONS as usize;
/// Linux's TRANSFER_FUNC_POINTS.
pub const TRANSFER_FUNC_POINTS: usize = 1025;
const EXTRA_POINTS: usize = 3;

/// setup_x_points_distribution's coordinates_x: 32 regions of 16 points
/// from 2^-25 to 2^7, then two copies of 128.
fn coordinates_x() -> Vec<Fx> {
    let mut x = vec![Fx::ZERO; MAX_HW_POINTS + 2];
    let mut region_size = Fx::from_int(128);
    x[MAX_HW_POINTS] = region_size;
    x[MAX_HW_POINTS + 1] = region_size;
    let mut segment: i32 = 6;
    while segment > 6 - NUM_REGIONS {
        region_size = region_size.div_int(2);
        let increment = region_size.div_int(NUM_PTS_IN_REGION as i64);
        let seg_offset = (segment + (NUM_REGIONS - 7)) as usize * NUM_PTS_IN_REGION;
        x[seg_offset] = region_size;
        for index in seg_offset + 1..seg_offset + NUM_PTS_IN_REGION {
            x[index] = x[index - 1].add(increment);
        }
        segment -= 1;
    }
    x
}

/// `struct dc_transfer_func_distributed_points`'s curves (1025 points per
/// channel).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TfPoints {
    pub red: Vec<Fx>,
    pub green: Vec<Fx>,
    pub blue: Vec<Fx>,
}

impl TfPoints {
    fn new() -> Self {
        Self {
            red: vec![Fx::ZERO; TRANSFER_FUNC_POINTS],
            green: vec![Fx::ZERO; TRANSFER_FUNC_POINTS],
            blue: vec![Fx::ZERO; TRANSFER_FUNC_POINTS],
        }
    }
    fn channel(&mut self, c: usize) -> &mut Vec<Fx> {
        match c {
            0 => &mut self.red,
            1 => &mut self.green,
            _ => &mut self.blue,
        }
    }
}

/// `struct dc_gamma`'s entries, per channel.
struct Gamma {
    channels: [Vec<Fx>; 3],
}

/// __drm_lut_to_dc_gamma: legacy entries as integers, atomic ones as
/// fractions of 0xFFFF (drm_color_lut_extract at 16 bits is the identity).
fn dc_gamma(lut: &[DrmColorLut], legacy: bool) -> Gamma {
    let conv = |v: u16| {
        if legacy {
            Fx::from_int(i32::from(v))
        } else {
            Fx::from_fraction(i64::from(v), i64::from(MAX_DRM_LUT_VALUE))
        }
    };
    Gamma {
        channels: [
            lut.iter().map(|e| conv(e.red)).collect(),
            lut.iter().map(|e| conv(e.green)).collect(),
            lut.iter().map(|e| conv(e.blue)).collect(),
        ],
    }
}

/// build_new_custom_resulted_curve: clamp points 0..=hw_points to [0, 1].
fn clamp_curve(tf: &mut TfPoints, hw_points: usize) {
    for c in 0..3 {
        for v in &mut tf.channel(c)[..=hw_points] {
            *v = v.clamp_to(Fx::ZERO, Fx::ONE);
        }
    }
}

/// apply_lut_1d for a 4096-entry GAMMA_CUSTOM/GAMMA_CS_TFM_1D ramp: each
/// curve point indexes the ramp and interpolates between neighbours.
fn apply_lut_1d(ramp: &Gamma, num_hw_points: usize, tf: &mut TfPoints) {
    const MAX_LUT_INDEX: i32 = 4095;
    let penult = Fx::from_int(MAX_LUT_INDEX - 1);
    let max = Fx::from_int(MAX_LUT_INDEX);
    for i in 0..num_hw_points {
        for c in 0..3 {
            let lut = &ramp.channels[c];
            let y = &mut tf.channel(c)[i];
            let norm_y = max.mul(*y);
            let mut index = norm_y.floor();
            let mut index_f = Fx::from_int(index);
            if index < 0 {
                continue;
            }
            let index_next;
            if index <= MAX_LUT_INDEX {
                index_next = if index == MAX_LUT_INDEX {
                    index
                } else {
                    index + 1
                };
            } else {
                index = MAX_LUT_INDEX - 1;
                index_next = MAX_LUT_INDEX;
                index_f = penult;
            }
            let (Some(&lut1), Some(&lut2)) =
                (lut.get(index as usize), lut.get(index_next as usize))
            else {
                continue;
            };
            *y = lut1.add(norm_y.sub(index_f).mul(lut2.sub(lut1)));
        }
    }
}

/// mod_color_calculate_degamma_params for a DISTRIBUTED_POINTS transfer
/// function with tf LINEAR and a GAMMA_CUSTOM ramp, as __set_output_tf
/// calls it for the atomic GAMMA_LUT: the linear curve, clamped, through
/// the ramp.
fn linear_custom(ramp: &Gamma) -> TfPoints {
    let x = coordinates_x();
    let mut tf = TfPoints::new();
    for c in 0..3 {
        tf.channel(c)[..=MAX_HW_POINTS].copy_from_slice(&x[..=MAX_HW_POINTS]);
    }
    clamp_curve(&mut tf, MAX_HW_POINTS);
    apply_lut_1d(ramp, MAX_HW_POINTS, &mut tf);
    tf
}

/// color_gamma.c's calculate_buffer: the pow results of the last region,
/// reused (times 2^(1/gamma)) for the next one.
struct CalBuffer {
    buffer: [Fx; NUM_PTS_IN_REGION],
    index: i32,
    gamma_of_2: Fx,
}

/// Regamma coefficients (build_coefficients, sRGB column).
struct Coefficients {
    a0: Fx,
    a1: Fx,
    a2: Fx,
    a3: Fx,
    gamma: Fx,
}

fn srgb_coefficients() -> Coefficients {
    Coefficients {
        a0: Fx::from_fraction(31308, 10_000_000),
        a1: Fx::from_fraction(12920, 1000),
        a2: Fx::from_fraction(55, 1000),
        a3: Fx::from_fraction(55, 1000),
        gamma: Fx::from_fraction(2400, 1000),
    }
}

/// translate_from_linear_space with the calculate_buffer optimisation.
fn translate_from_linear_space(arg: Fx, k: &Coefficients, cal: &mut CalBuffer) -> Fx {
    let one = Fx::ONE;
    if one.le(arg) {
        return one;
    }
    if arg.le(k.a0.neg()) {
        let s1 = one.add(k.a3);
        let s2 = arg.neg().pow(k.gamma.recip());
        k.a2.sub(s1.mul(s2))
    } else if k.a0.le(arg) {
        if cal.index == 0 {
            cal.gamma_of_2 = Fx::from_int(2).pow(k.gamma.recip());
        }
        let s1 = one.add(k.a3);
        let slot = cal.index.rem_euclid(NUM_PTS_IN_REGION as i32) as usize;
        let s2 = if (224..=239).contains(&cal.index) || cal.index < 16 {
            arg.pow(k.gamma.recip())
        } else {
            cal.gamma_of_2.mul(cal.buffer[slot])
        };
        if cal.index != -1 {
            cal.buffer[slot] = s2;
            cal.index += 1;
        }
        s1.mul(s2).sub(k.a2)
    } else {
        arg.mul(k.a1)
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum HwPos {
    #[default]
    Middle,
    Left,
    Right,
}

/// Linux `struct gamma_point`.
#[derive(Clone, Copy, Default)]
struct GammaPoint {
    left: i32,
    right: i32,
    pos: HwPos,
    coeff: Fx,
}

/// find_software_points on an axis whose channels are equal (the evenly
/// distributed one); `None` where Linux returns false.
fn find_software_points(axis: &[Fx], hw_point: Fx) -> Option<(usize, usize, HwPos)> {
    let max_number = axis.len();
    for i in 0..max_number {
        let left = axis[i];
        let right = if i < max_number - 1 {
            axis[i + 1]
        } else {
            axis[max_number - 1]
        };
        if left.le(hw_point) && hw_point.le(right) {
            let r = if i < max_number - 1 {
                i + 1
            } else {
                max_number - 1
            };
            return Some((i, r, HwPos::Middle));
        } else if i == 0 && hw_point.le(left) {
            return Some((i, i, HwPos::Left));
        } else if i == max_number - 1 && right.le(hw_point) {
            return Some((i, i, HwPos::Right));
        }
    }
    None
}

/// calculate_mapped_value.
fn mapped_value(rgb: &[Fx], p: &GammaPoint, max_index: i32) -> Fx {
    if p.left < 0 || p.left > max_index || p.right < 0 || p.right > max_index {
        return Fx::ZERO;
    }
    match p.pos {
        HwPos::Middle => {
            let (l, r) = (rgb[p.left as usize], rgb[p.right as usize]);
            p.coeff.mul(r.sub(l)).add(l)
        }
        HwPos::Left => Fx::ZERO,
        HwPos::Right => Fx::ONE,
    }
}

/// mod_color_calculate_regamma_params for a DISTRIBUTED_POINTS sRGB
/// transfer function and a 256-entry GAMMA_RGB_256 ramp mapped as the user
/// ramp (map_user_ramp, no ROM, no FreeSync tone mapping), as
/// __set_legacy_tf calls it: the sRGB regamma curve, each point looked up
/// through the user's ramp, clamped.
// Channel-major like Linux (a failing channel stops the rest), so the
// channel indexes the inner point arrays.
#[allow(clippy::needless_range_loop)]
fn legacy_srgb(ramp: &Gamma) -> TfPoints {
    let n = ramp.channels[0].len();
    let dividers = [
        Fx::from_fraction(3, 2),
        Fx::from_int(2),
        Fx::from_fraction(5, 2),
    ];
    // build_evenly_distributed_points (channels are equal).
    let mut axis: Vec<Fx> = (0..n)
        .map(|i| Fx::from_fraction(i as i64, n as i64 - 1))
        .collect();
    let last = axis[n - 1];
    axis.extend(dividers.iter().map(|&d| last.div(d)));
    // scale_gamma: 0xFF00 full scale unless an entry exceeds it.
    let max_os = Fx::from_int(0xFF00);
    let scaler = if (0..n).any(|i| ramp.channels.iter().any(|ch| max_os.lt(ch[i]))) {
        Fx::from_int(0xFFFF)
    } else {
        max_os
    };
    let rgb_user: [Vec<Fx>; 3] = core::array::from_fn(|c| {
        let mut v: Vec<Fx> = ramp.channels[c].iter().map(|&e| e.div(scaler)).collect();
        let last = v[n - 1];
        v.extend(dividers.iter().map(|&d| last.mul(d)));
        v
    });
    // calculate_curve -> build_regamma over points 0..=MAX_HW_POINTS.
    let x = coordinates_x();
    let k = srgb_coefficients();
    let mut cal = CalBuffer {
        buffer: [Fx::ZERO; NUM_PTS_IN_REGION],
        index: 0,
        gamma_of_2: Fx::ZERO,
    };
    let mut regamma = vec![Fx::ZERO; MAX_HW_POINTS + EXTRA_POINTS];
    for (r, &xi) in regamma.iter_mut().zip(&x[..=MAX_HW_POINTS]) {
        *r = translate_from_linear_space(xi, &k, &mut cal);
    }
    // map_regamma_hw_to_x_user: copy_rgb_regamma_to_coordinates_x, then
    // calculate_interpolated_hardware_curve.
    let regamma_y = &regamma[..MAX_HW_POINTS + 2];
    let mut tf = TfPoints::new();
    let mut coeff = vec![[GammaPoint::default(); 3]; MAX_HW_POINTS + EXTRA_POINTS];
    let mut found = true;
    'channels: for c in 0..3 {
        for (i, &coord) in regamma_y[..=MAX_HW_POINTS].iter().enumerate() {
            let Some((left, right, pos)) = find_software_points(&axis, coord) else {
                found = false;
                break 'channels;
            };
            let (lp, rp) = (axis[left], axis[right]);
            coeff[i][c] = GammaPoint {
                left: left as i32,
                right: right as i32,
                pos,
                coeff: match pos {
                    HwPos::Middle => coord.sub(lp).div(rp.sub(lp)),
                    HwPos::Left => Fx::ZERO,
                    HwPos::Right => Fx::from_int(2),
                },
            };
        }
    }
    if found {
        let max_entries = 2 + n as i32;
        for (i, p) in coeff.iter().enumerate().take(MAX_HW_POINTS + 1) {
            for c in 0..3 {
                tf.channel(c)[i] = mapped_value(&rgb_user[c], &p[c], max_entries);
            }
        }
    }
    clamp_curve(&mut tf, MAX_HW_POINTS);
    tf
}

/// The out transfer function amdgpu_dm_check_crtc_color_mgmt builds for a
/// GAMMA_LUT: 256 entries through __set_legacy_tf (sRGB base), 4096
/// through amdgpu_dm_set_atomic_regamma's __set_output_tf on a linear base.
/// `None` for any other size (amdgpu_dm_verify_lut_sizes rejects them).
/// The caller bypasses OGAM for a linear 4096-entry LUT, as amdgpu_dm does.
pub fn regamma_tf(lut: &[DrmColorLut]) -> Option<TfPoints> {
    match lut.len() {
        MAX_COLOR_LEGACY_LUT_ENTRIES => Some(legacy_srgb(&dc_gamma(lut, true))),
        MAX_COLOR_LUT_ENTRIES => Some(linear_custom(&dc_gamma(lut, false))),
        _ => None,
    }
}

/// Linux `struct gamma_curve`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GammaCurve {
    pub offset: u32,
    pub segments_num: u32,
}

/// One channel's corner points as custom floats (`struct curve_points`'s
/// register fields).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Corner {
    pub custom_float_x: u32,
    pub custom_float_y: u32,
    pub custom_float_offset: u32,
    pub custom_float_slope: u32,
}

/// `struct pwl_params` as cm3_helper_translate_curve_to_hw_format fills it
/// (fixpoint = false), reduced to what the hardware gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pwl {
    /// corner_points[0] (start) and [1] (end), each [red, green, blue].
    pub corners: [[Corner; 3]; 2],
    pub arr_curve_points: [GammaCurve; 34],
    /// The LUT entries written per channel (257 - 62 = 195 for the 13-region
    /// SDR layout).
    pub hw_points_num: u32,
    /// rgb_resulted[..hw_points_num]'s red_reg, green_reg, blue_reg.
    pub red_reg: Vec<u32>,
    pub green_reg: Vec<u32>,
    pub blue_reg: Vec<u32>,
}

/// What cm_helper_program_gamcor_xfer_func writes for a `Pwl`, with the
/// MPCC_OGAM_RAMA/RAMB field layout (CM_GAMCOR's is identical). Each
/// three-element array is in Linux's write order: blue, green, red.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XferRegs {
    /// START_CNTL: EXP_REGION_START (18 bits), START_SEGMENT 0 (bits 20..27).
    pub start_cntl: [u32; 3],
    /// START_SLOPE_CNTL: EXP_REGION_START_SLOPE (18 bits).
    pub start_slope_cntl: [u32; 3],
    /// END_CNTL1: EXP_REGION_END_BASE (18 bits).
    pub end_cntl1: [u32; 3],
    /// END_CNTL2: EXP_REGION_END (bits 0..16), END_SLOPE (bits 16..32).
    pub end_cntl2: [u32; 3],
    /// REGION_0_1 .. REGION_32_33: REGION0_LUT_OFFSET (9 bits),
    /// REGION0_NUM_SEGMENTS (bits 12..15), REGION1_LUT_OFFSET (bits 16..25),
    /// REGION1_NUM_SEGMENTS (bits 28..31).
    pub region: [u32; 17],
}

impl Pwl {
    /// The register image, as cm_helper_program_gamcor_xfer_func's REG_SETs
    /// compose each register from zero.
    pub fn registers(&self) -> XferRegs {
        let [start, end] = self.corners;
        // [red, green, blue] -> B, G, R.
        let bgr = |f: &dyn Fn(&Corner, &Corner) -> u32| {
            [
                f(&start[2], &end[2]),
                f(&start[1], &end[1]),
                f(&start[0], &end[0]),
            ]
        };
        let curve = &self.arr_curve_points;
        XferRegs {
            start_cntl: bgr(&|s, _| s.custom_float_x & 0x3ffff),
            start_slope_cntl: bgr(&|s, _| s.custom_float_slope & 0x3ffff),
            end_cntl1: bgr(&|_, e| e.custom_float_y & 0x3ffff),
            end_cntl2: bgr(&|_, e| {
                (e.custom_float_x & 0xffff) | (e.custom_float_slope << 16 & 0xffff_0000)
            }),
            region: core::array::from_fn(|i| {
                let (c0, c1) = (curve[2 * i], curve[2 * i + 1]);
                (c0.offset & 0x1ff)
                    | (c0.segments_num << 12 & 0x7000)
                    | (c1.offset << 16 & 0x1ff_0000)
                    | (c1.segments_num << 28 & 0x7000_0000)
            }),
        }
    }
    /// is_rgb_equal over the written points: mpc3_program_ogam_pwl then
    /// writes the red words once with all three channels enabled.
    pub fn rgb_equal(&self) -> bool {
        self.red_reg == self.green_reg && self.green_reg == self.blue_reg
    }
    /// mpc3_program_ogam_pwl's MPCC_OGAM_LUT_DATA passes: (LUT write color
    /// mask, words). With equal channels one pass under the configured mask
    /// 7; otherwise red (4), green (2) then blue (1), with LUT_INDEX reset
    /// to 0 before green and blue. Each word is masked to LUT_DATA's 18 bits.
    pub fn ogam_lut_passes(&self) -> Vec<(u32, Vec<u32>)> {
        let words = |v: &[u32]| v.iter().map(|w| w & 0x3ffff).collect::<Vec<u32>>();
        if self.rgb_equal() {
            vec![(7, words(&self.red_reg))]
        } else {
            vec![
                (4, words(&self.red_reg)),
                (2, words(&self.green_reg)),
                (1, words(&self.blue_reg)),
            ]
        }
    }
}

const MAX_REGIONS_NUMBER: usize = 34;
const MAX_LOW_POINT: i32 = 25;
const NUMBER_SW_SEGMENTS: i32 = 16;
const UNUSED: u32 = u32::MAX;

/// cm3_helper_translate_curve_to_hw_format(fixpoint = false) for an SDR
/// transfer function (anything but PQ, GAMMA22 and HLG, which take the
/// 32-region layout amdgpu_dm's CRTC properties never produce): 12 regions
/// of 16 points from 2^-12, one of 2 points to 2^1, then
/// cm3_helper_convert_to_custom_float.
pub fn translate_curve_to_hw_format(tf: &TfPoints) -> Option<Box<Pwl>> {
    const SEG_COUNT: usize = 12;
    let mut seg_distr = [0u32; MAX_REGIONS_NUMBER];
    seg_distr[..SEG_COUNT].fill(4);
    seg_distr[SEG_COUNT] = 1;
    let region_start: i32 = -(SEG_COUNT as i32);
    let region_end: i32 = 1;
    for s in &mut seg_distr[(region_end - region_start) as usize..] {
        *s = UNUSED;
    }
    let hw_points: usize = seg_distr
        .iter()
        .filter(|&&s| s != UNUSED)
        .map(|&s| 1usize << s)
        .sum();
    // rgb_resulted[256 + 3], zeroed by the memset of lut_params.
    let mut rgb = vec![[Fx::ZERO; 3]; 256 + 3];
    let channels = [&tf.red, &tf.green, &tf.blue];
    let mut j = 0;
    let span = (region_end - region_start) as usize;
    'regions: for (k, &seg) in seg_distr[..span].iter().enumerate() {
        let increment = NUMBER_SW_SEGMENTS as usize / (1usize << seg);
        let start = ((region_start + k as i32 + MAX_LOW_POINT) * NUMBER_SW_SEGMENTS) as usize;
        for i in (start..start + NUMBER_SW_SEGMENTS as usize).step_by(increment) {
            if j == hw_points {
                break 'regions;
            }
            if i >= TRANSFER_FUNC_POINTS {
                return None;
            }
            rgb[j] = core::array::from_fn(|c| channels[c][i]);
            j += 1;
        }
    }
    let last = ((region_end + MAX_LOW_POINT) * NUMBER_SW_SEGMENTS) as usize;
    rgb[hw_points] = core::array::from_fn(|c| channels[c][last]);
    rgb[hw_points + 1] = rgb[hw_points];
    let x0 = Fx::from_int(2).pow(Fx::from_int(region_start));
    let x1 = Fx::from_int(2).pow(Fx::from_int(region_end));
    let mut arr_curve_points = [GammaCurve::default(); MAX_REGIONS_NUMBER];
    let mut k = 0;
    for i in 1..MAX_REGIONS_NUMBER {
        if seg_distr[k] != UNUSED {
            arr_curve_points[k].segments_num = seg_distr[k];
            arr_curve_points[i].offset = arr_curve_points[k].offset + (1 << seg_distr[k]);
        }
        k += 1;
    }
    if seg_distr[k] != UNUSED {
        arr_curve_points[k].segments_num = seg_distr[k];
    }
    // cm3_helper_convert_to_custom_float(rgb_resulted, corners,
    // hw_points + 1, false).
    let num = hw_points + 1;
    let m12 = CustomFloatFormat {
        mantissa_bits: 12,
        exponenta_bits: 6,
        sign: false,
    };
    let m10 = CustomFloatFormat {
        mantissa_bits: 10,
        ..m12
    };
    let corners = [
        core::array::from_fn(|c| Corner {
            custom_float_x: custom_float(x0, m12),
            custom_float_y: 0,
            custom_float_offset: custom_float(Fx::ZERO, m12),
            custom_float_slope: custom_float(rgb[0][c].div(x0), m12),
        }),
        core::array::from_fn(|c| Corner {
            custom_float_x: custom_float(x1, m10),
            custom_float_y: custom_float(rgb[hw_points][c], m12),
            custom_float_offset: 0,
            custom_float_slope: custom_float(Fx::ZERO, m10),
        }),
    ];
    let regs = |c: usize| rgb[..num].iter().map(|p| custom_float(p[c], m12)).collect();
    Some(Box::new(Pwl {
        corners,
        arr_curve_points,
        hw_points_num: num as u32,
        red_reg: regs(0),
        green_reg: regs(1),
        blue_reg: regs(2),
    }))
}

/// build_coefficients' BT.709 column (numerator01..05[1]) and
/// translate_to_linear_space: the BT.709 OETF inverted.
fn bt709_to_linear(arg: Fx) -> Fx {
    let a0 = Fx::from_fraction(180_000, 10_000_000);
    let a1 = Fx::from_fraction(4500, 1000);
    let a2 = Fx::from_fraction(99, 1000);
    let a3 = Fx::from_fraction(99, 1000);
    let gamma = Fx::from_fraction(2222, 1000);
    let a0 = a0.mul(a1);
    if arg.le(a0.neg()) {
        a2.sub(arg).div(Fx::ONE.add(a3)).pow(gamma).neg()
    } else if a0.neg().le(arg) && arg.le(a0) {
        arg.div(a1)
    } else {
        a2.add(arg).div(Fx::ONE.add(a3)).pow(gamma)
    }
}

/// mod_color_calculate_degamma_params(caps, input_tf, NULL, false) for
/// map_crtc_degamma_to_dc_plane's TF_TYPE_PREDEFINED BT.709 input (an NV12
/// plane under legacy gamma), which DCN 4.0.1's DGAM ROM caps do not
/// short-circuit: it becomes TF_TYPE_DISTRIBUTED_POINTS from build_degamma
/// (zero below 2^-12, BT.709's inverse OETF to 2^0, one above) copied and
/// clamped by map_regamma_hw_to_x_user (no user ramp).
#[allow(
    clippy::needless_range_loop,
    reason = "indexes the coordinates and the curve together, as build_degamma"
)]
pub fn bt709_degamma_tf() -> TfPoints {
    let x = coordinates_x();
    let begin = 13 * NUM_PTS_IN_REGION;
    let end = begin + 12 * NUM_PTS_IN_REGION;
    let mut tf = TfPoints::new();
    for i in 0..=MAX_HW_POINTS {
        let y = if i < begin {
            Fx::ZERO
        } else if i < end {
            bt709_to_linear(x[i])
        } else {
            Fx::ONE
        };
        tf.red[i] = y;
        tf.green[i] = y;
        tf.blue[i] = y;
    }
    clamp_curve(&mut tf, MAX_HW_POINTS);
    tf
}

/// interp_tf_pts: point `i >> 4` of `channel` plus (i & 0xf)/16 of the step
/// to the next.
fn interp_tf_pts(channel: &[Fx], i: usize) -> Fx {
    let t = (i & 0xf) as i32;
    let (at, next) = (channel[i >> 4], channel[(i >> 4) + 1]);
    at.add(next.sub(at).mul_int(t).shr(4))
}

/// cm3_helper_translate_curve_to_degamma_hw_format: NUM_DEGAMMA_REGIONS (9)
/// regions from 2^-9 to 2^0 of 1, 1, 2, 4 .. 128 points (256 in all), the
/// last the curve at 2^0; flat corner slopes; then made monotonic and
/// cm3_helper_convert_to_custom_float(fixpoint = false). The PWL
/// dpp3_program_gamcor_lut loads into the DPP's GAMCOR.
#[allow(
    clippy::needless_range_loop,
    reason = "the monotonic clamp reads point i and writes point i + 1, as cm3_helper does"
)]
pub fn translate_curve_to_degamma_hw_format(tf: &TfPoints) -> Option<Box<Pwl>> {
    const NUM_DEGAMMA_REGIONS: usize = 9;
    let mut seg_distr = [UNUSED; MAX_REGIONS_NUMBER];
    seg_distr[0] = 0;
    for (k, s) in seg_distr
        .iter_mut()
        .enumerate()
        .take(NUM_DEGAMMA_REGIONS)
        .skip(1)
    {
        *s = k as u32 - 1;
    }
    let region_start: i32 = -(NUM_DEGAMMA_REGIONS as i32);
    let region_end: i32 = 0;
    let hw_points: usize = seg_distr
        .iter()
        .filter(|&&s| s != UNUSED)
        .map(|&s| 1usize << s)
        .sum();
    // rgb_resulted[256 + 3], zeroed by the memset of lut_params.
    let mut rgb = vec![[Fx::ZERO; 3]; 256 + 3];
    let channels = [&tf.red, &tf.green, &tf.blue];
    let mut j = 0;
    for (k, &seg) in seg_distr[..(region_end - region_start) as usize]
        .iter()
        .enumerate()
    {
        let increment = (NUMBER_SW_SEGMENTS as usize) << 4 >> seg;
        let start = ((region_start + k as i32 + MAX_LOW_POINT) * NUMBER_SW_SEGMENTS) as usize;
        for i in ((start << 4)..((start + NUMBER_SW_SEGMENTS as usize) << 4)).step_by(increment) {
            if j == hw_points - 1 {
                break;
            }
            if (i >> 4) + 1 >= TRANSFER_FUNC_POINTS {
                return None;
            }
            rgb[j] = core::array::from_fn(|c| interp_tf_pts(channels[c], i));
            j += 1;
        }
    }
    let last = ((region_end + MAX_LOW_POINT) * NUMBER_SW_SEGMENTS) as usize;
    rgb[hw_points - 1] = core::array::from_fn(|c| channels[c][last]);
    let x0 = Fx::from_int(2).pow(Fx::from_int(region_start));
    let x1 = Fx::from_int(2).pow(Fx::from_int(region_end));
    // The corners' y before the curve is made monotonic.
    let y1 = rgb[hw_points - 1];
    let mut arr_curve_points = [GammaCurve::default(); MAX_REGIONS_NUMBER];
    let mut k = 0;
    for i in 1..MAX_REGIONS_NUMBER {
        if seg_distr[k] != UNUSED {
            arr_curve_points[k].segments_num = seg_distr[k];
            arr_curve_points[i].offset = arr_curve_points[k].offset + (1 << seg_distr[k]);
        }
        k += 1;
    }
    if seg_distr[k] != UNUSED {
        arr_curve_points[k].segments_num = seg_distr[k];
    }
    for i in 0..hw_points {
        for c in 0..3 {
            if rgb[i + 1][c].lt(rgb[i][c]) {
                rgb[i + 1][c] = rgb[i][c];
            }
        }
    }
    let m12 = CustomFloatFormat {
        mantissa_bits: 12,
        exponenta_bits: 6,
        sign: false,
    };
    let m10 = CustomFloatFormat {
        mantissa_bits: 10,
        ..m12
    };
    // corner_points[0]'s slope and offset and [1]'s slope stay as the
    // memset left them (zero); [0]'s y and [1]'s offset are never converted.
    let corners = [
        core::array::from_fn(|_| Corner {
            custom_float_x: custom_float(x0, m12),
            custom_float_y: 0,
            custom_float_offset: custom_float(Fx::ZERO, m12),
            custom_float_slope: custom_float(Fx::ZERO, m12),
        }),
        core::array::from_fn(|c| Corner {
            custom_float_x: custom_float(x1, m10),
            custom_float_y: custom_float(y1[c], m12),
            custom_float_offset: 0,
            custom_float_slope: custom_float(Fx::ZERO, m10),
        }),
    ];
    let regs = |c: usize| {
        rgb[..hw_points]
            .iter()
            .map(|p| custom_float(p[c], m12))
            .collect()
    };
    Some(Box::new(Pwl {
        corners,
        arr_curve_points,
        hw_points_num: hw_points as u32,
        red_reg: regs(0),
        green_reg: regs(1),
        blue_reg: regs(2),
    }))
}

/// The GAMCOR PWL dcn32_set_input_transfer_func programs for an NV12 plane
/// under legacy gamma: bt709_degamma_tf, then
/// translate_curve_to_degamma_hw_format.
pub fn bt709_degamma_pwl() -> Option<Box<Pwl>> {
    translate_curve_to_degamma_hw_format(&bt709_degamma_tf())
}

/// A GAMMA_LUT's MPC OGAM curve, as amdgpu_dm and dcn401_set_output_transfer_func
/// compute it: regamma_tf, then translate_curve_to_hw_format.
pub fn regamma_pwl(lut: &[DrmColorLut]) -> Option<Box<Pwl>> {
    translate_curve_to_hw_format(&regamma_tf(lut)?)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_color_tests.rs"]
mod tests;
