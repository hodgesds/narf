/* Check the RLC image against Linux's source table (no Rust constants).
 * cc -Wall -Wextra -I/usr/src/linux/drivers/gpu/drm/amd/amdgpu \
 *    drivers/gpu/tests/gfx12_clearstate.c -o /tmp/narf-gfx12-clearstate
 * /tmp/narf-gfx12-clearstate
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include "clearstate_defs.h"
#include "clearstate_gfx12.h"
int main(void)
{
    uint32_t image[75] = {0};
    size_t count = 1;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (const struct cs_section_def *s = gfx12_cs_data; s->section; ++s) {
        assert(s->id == SECT_CONTEXT);
        for (const struct cs_extent_def *e = s->section; e->extent; ++e) {
            assert(count + 2 + e->reg_count <= 75);
            ++image[0];
            image[count++] = e->reg_count;
            image[count++] = e->reg_index;
            for (uint32_t i = 0; i < e->reg_count; ++i)
                image[count++] = e->extent[i];
        }
    }
    assert(count == 75 && image[0] == 6);
    for (size_t i = 0; i < count; ++i)
        for (unsigned shift = 0; shift < 32; shift += 8) {
            hash ^= (image[i] >> shift) & 255;
            hash *= UINT64_C(1099511628211);
        }
    printf("%016llx\n", (unsigned long long)hash);
    return 0;
}
