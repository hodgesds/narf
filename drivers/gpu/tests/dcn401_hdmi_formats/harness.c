/* Compile the real Linux function verbatim. drm_match_cea_mode is a fixture
 * input here; these native tests select VIC97 after the existing EDID matcher. */
#include <assert.h>
#include <stdio.h>

#define DRM_MODE_FLAG_DBLCLK (1u << 12)
#define DIV_ROUND_CLOSEST_ULL(n, d) (((n) + (d) / 2) / (d))
enum drm_output_color_format {
    DRM_OUTPUT_COLOR_FORMAT_RGB,
    DRM_OUTPUT_COLOR_FORMAT_YCBCR444,
    DRM_OUTPUT_COLOR_FORMAT_YCBCR422,
    DRM_OUTPUT_COLOR_FORMAT_YCBCR420,
};
struct drm_display_mode { unsigned clock, flags, vic; };
static unsigned drm_match_cea_mode(const struct drm_display_mode *mode)
{
    return mode->vic;
}
/* LINUX_FUNCTION */

int main(void)
{
    struct drm_display_mode mode = { 594000, 0, 97 };
    const unsigned bpc[] = { 8, 10, 12 };
    const unsigned long long want[] = { 297000000, 371250000, 445500000 };
    unsigned count = 0;
    for (unsigned i = 0; i < 3; ++i) {
        assert(drm_hdmi_compute_mode_clock(&mode, bpc[i],
               DRM_OUTPUT_COLOR_FORMAT_YCBCR420) == want[i]);
        ++count;
        assert(drm_hdmi_compute_mode_clock(&mode, bpc[i],
               DRM_OUTPUT_COLOR_FORMAT_RGB) == 2 * want[i]);
        ++count;
        assert(drm_hdmi_compute_mode_clock(&mode, bpc[i],
               DRM_OUTPUT_COLOR_FORMAT_YCBCR444) == 2 * want[i]);
        ++count;
        assert(drm_hdmi_compute_mode_clock(&mode, bpc[i],
               DRM_OUTPUT_COLOR_FORMAT_YCBCR422) == 594000000);
        ++count;
    }
    puts("Linux HDMI clock: 12 RGB/444/422/420 comparisons passed");
    return count != 12;
}
