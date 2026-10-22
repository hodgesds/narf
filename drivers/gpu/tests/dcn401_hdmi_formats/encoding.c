/* Primary Linux functions, compiled verbatim by check.sh. The recording
 * register macros and minimal context types replace only OS/MMIO plumbing. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "asic_reg/dcn/dcn_4_1_0_sh_mask.h"
#define BIT(n) (1u << (n))
#define drm_dbg_kms(dev, ...) ((void)(dev))
#define drm_warn(dev, ...) ((void)(dev))
#define DC_LOG_DEBUG(...) ((void)0)
#define VBI_LINE_0 0
#define DRM_EDID_HDMI_DC_30 0x10
#define DRM_EDID_HDMI_DC_36 0x20
#define DRM_EDID_YCBCR420_DC_30 1
#define DRM_EDID_YCBCR420_DC_36 2
#define DRM_EDID_YCBCR420_DC_48 4
typedef uint8_t u8;
enum drm_output_color_format { DRM_OUTPUT_COLOR_FORMAT_RGB444, DRM_OUTPUT_COLOR_FORMAT_YCBCR444,
    DRM_OUTPUT_COLOR_FORMAT_YCBCR422, DRM_OUTPUT_COLOR_FORMAT_YCBCR420 };
struct drm_device { int unused; };
struct drm_display_mode { unsigned vic; };
struct drm_display_info { bool is_hdmi, only420, also420; unsigned color_formats;
    unsigned edid_hdmi_rgb444_dc_modes, edid_hdmi_ycbcr444_dc_modes;
    struct { unsigned y420_dc_modes; } hdmi; };
struct drm_connector { struct drm_device *dev; struct { unsigned supported_formats; } hdmi; };
static unsigned drm_match_cea_mode(const struct drm_display_mode *m) { return m->vic; }
static bool drm_mode_is_420_only(const struct drm_display_info *i, const struct drm_display_mode *m)
{ (void)m; return i->only420; }
static bool drm_mode_is_420(const struct drm_display_info *i, const struct drm_display_mode *m)
{ (void)m; return i->only420 || i->also420; }
/* LINUX_SINK */

enum dc_pixel_encoding { PIXEL_ENCODING_RGB = 1, PIXEL_ENCODING_YCBCR422,
    PIXEL_ENCODING_YCBCR444, PIXEL_ENCODING_YCBCR420 };
enum dc_color_depth { COLOR_DEPTH_888, COLOR_DEPTH_101010, COLOR_DEPTH_121212, COLOR_DEPTH_161616 };
struct dc { struct { bool force_chroma_subsampling_1tap; } debug; };
struct dc_context { struct dc *dc; };
struct dcn10_opp { struct { struct dc_context *ctx; } base; };
struct clamping_and_pixel_encoding_params { enum dc_pixel_encoding pixel_encoding; };
struct dcn10_stream_encoder { int unused; };
struct dc_crtc_timing { enum dc_pixel_encoding pixel_encoding; enum dc_color_depth display_color_depth;
    struct { bool DSC; } flags; unsigned h_addressable, h_border_left, h_border_right, h_total; };
struct frl_borrow_params { unsigned borrow_mode, audio_packets_line, hc_active_target, hc_blank_target; };
struct afmt { struct { void (*audio_info_immediate_update)(struct afmt *); } *funcs; };
struct hpo_frl_stream_encoder { struct afmt *afmt; };
struct dcn401_hpo_frl_stream_encoder { int unused; };
#define DCN401_HPO_FRL_STRENC_FROM_HPO_FRL_STRENC(enc) ((struct dcn401_hpo_frl_stream_encoder *)(enc))
/* FIELD_ENUM */
static unsigned observed[FIELD_COUNT];
#define REG_UPDATE(r, f, v) (observed[FIELD_##f] = (v))
#define REG_UPDATE_2(r, f, v, g, w) do { REG_UPDATE(r, f, v); REG_UPDATE(r, g, w); } while (0)
#define REG_UPDATE_3(r, f, v, g, w, h, z) do { REG_UPDATE_2(r, f, v, g, w); REG_UPDATE(r, h, z); } while (0)
#define REG_SET_2(r, init, f, v, g, w) REG_UPDATE_2(r, f, v, g, w)
/* LINUX_OPP */
/* LINUX_TMDS */
/* LINUX_FRL */

_Static_assert(FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING_MASK == 0x30000, "FMT encoding bits");
_Static_assert(FMT0_FMT_CONTROL__FMT_SUBSAMPLING_MODE_MASK == 0xc0000, "FMT subsampling bits");
_Static_assert(DIG0_HDMI_CONTROL__TMDS_PIXEL_ENCODING_MASK == 0x1000, "TMDS422 bits");
_Static_assert(HDMI_TB_ENC_PIXEL_FORMAT__HDMI_PIXEL_ENCODING_MASK == 0x30000, "FRL encoding bits");
_Static_assert(HDMI_TB_ENC_PIXEL_FORMAT__HDMI_DEEP_COLOR_DEPTH_MASK == 0x300, "FRL depth bits");

int main(void)
{
    struct drm_device dev = {0};
    struct drm_connector connector = { .dev = &dev, .hdmi.supported_formats = 15 };
    struct drm_display_mode mode = { .vic = 97 };
    unsigned count = 0;
    for (unsigned dc = 0; dc < 4; ++dc) {
        struct drm_display_info info = { .is_hdmi = true, .color_formats = 15,
            .edid_hdmi_rgb444_dc_modes = (dc & 1) ? 0x30 : 0,
            .edid_hdmi_ycbcr444_dc_modes = (dc & 2) ? 0x30 : 0, .hdmi.y420_dc_modes = 3, .also420 = true };
        for (unsigned bpc = 8; bpc <= 12; bpc += 2) {
            assert(sink_supports_format_bpc(&connector, &info, &mode, DRM_OUTPUT_COLOR_FORMAT_YCBCR422, bpc));
            ++count;
            assert(sink_supports_format_bpc(&connector, &info, &mode, DRM_OUTPUT_COLOR_FORMAT_YCBCR444, bpc) == (bpc == 8 || (dc & 2)));
            ++count;
        }
    }
    struct drm_display_info info = { .is_hdmi = true, .color_formats = 15 };
    assert(!sink_supports_format_bpc(&connector, &info, &mode, DRM_OUTPUT_COLOR_FORMAT_YCBCR422, 16)); ++count;
    info.color_formats &= ~BIT(DRM_OUTPUT_COLOR_FORMAT_YCBCR422);
    assert(!sink_supports_format_bpc(&connector, &info, &mode, DRM_OUTPUT_COLOR_FORMAT_YCBCR422, 8)); ++count;
    info.color_formats = 15; info.only420 = true;
    assert(!sink_supports_format_bpc(&connector, &info, &mode, DRM_OUTPUT_COLOR_FORMAT_YCBCR422, 8)); ++count;
    struct dc dc = {0}; struct dc_context ctx = { &dc }; struct dcn10_opp opp = { .base.ctx = &ctx };
    struct hpo_frl_stream_encoder enc = {0}; struct frl_borrow_params borrow = {0};
    for (unsigned e = PIXEL_ENCODING_RGB; e <= PIXEL_ENCODING_YCBCR420; ++e) {
        unsigned format = e == PIXEL_ENCODING_YCBCR422 ? 1 : e == PIXEL_ENCODING_YCBCR420 ? 2 : 0;
        struct clamping_and_pixel_encoding_params params = { e };
        memset(observed, 0xff, sizeof(observed)); opp1_set_pixel_encoding(&opp, &params);
        assert(observed[FIELD_FMT_PIXEL_ENCODING] == format);
        assert(observed[FIELD_FMT_SUBSAMPLING_MODE] == (format ? 2 : 0));
        assert(observed[FIELD_FMT_CBCR_BIT_REDUCTION_BYPASS] == (e == PIXEL_ENCODING_YCBCR420)); ++count;
        for (unsigned depth = COLOR_DEPTH_888; depth <= COLOR_DEPTH_121212; ++depth) {
            struct dc_crtc_timing t = { .pixel_encoding = e, .display_color_depth = depth,
                .h_addressable = 1920, .h_total = 2200 };
            enc1_stream_encoder_set_stream_attribute_helper(NULL, &t);
            assert(observed[FIELD_TMDS_PIXEL_ENCODING] == (e == PIXEL_ENCODING_YCBCR422)); ++count;
            for (unsigned compressed = 0; compressed < 2; ++compressed) {
                t.flags.DSC = compressed;
                hpo_enc401_set_hdmi_stream_attribute(&enc, &t, &borrow, 1);
                assert(observed[FIELD_HDMI_PIXEL_ENCODING] == format);
                assert(observed[FIELD_FIFO_UNCOMPRESSED_PIXEL_FORMAT] == (e == PIXEL_ENCODING_YCBCR420));
                assert(observed[FIELD_HDMI_DEEP_COLOR_DEPTH] == (compressed ? 0 : depth));
                assert(observed[FIELD_HDMI_DEEP_COLOR_ENABLE] == (!compressed && depth && e != PIXEL_ENCODING_YCBCR422));
                assert(observed[FIELD_HDMI_H_ACTIVE] == (format ? 960 : 1920));
                assert(observed[FIELD_HDMI_H_BLANK] == (format ? 140 : 280)); ++count;
            }
        }
    }
    printf("Linux HDMI encoding: %u sink/FMT/TMDS/FRL comparisons passed\n", count);
    return 0;
}
