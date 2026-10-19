// SPDX-License-Identifier: GPL-2.0-or-later
// Capture-only host stubs for unchanged IGT encode builders; no GPU is opened.
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void *amdgpu_device_handle;
#define ALIGN(n, a) (((n) + (a) - 1) & ~((a) - 1))
#define AMDGPU_GEM_DOMAIN_GTT 2
#define AMDGPU_HW_IP_VCN_ENC 4
#define upper_32_bits(n) ((uint32_t)((uint64_t)(n) >> 32))
#define lower_32_bits(n) ((uint32_t)(n))
#define igt_assert_eq(a, b) assert((a) == (b))
struct amdgpu_mmd_bo { int handle; uint64_t addr; uint8_t *ptr; };
struct mmd_shared_context { int vcn_ip_version_major; bool vcn_unified_ring; };
struct mmd_context { int num_resources, resources[8], ib_handle; uint32_t *ib_cpu; };
struct vcn_context {
    struct amdgpu_mmd_bo enc_buf, cpb_buf;
    uint32_t *ib_checksum, *ib_size_in_dw, enc_task_id;
    unsigned gWidth, gHeight, gSliceType;
};
static uint64_t addresses[6];
static void *memory[6];
static unsigned allocations, submissions;
static void alloc_resource(amdgpu_device_handle device, struct amdgpu_mmd_bo *bo,
        unsigned bytes, unsigned domain)
{
    assert(allocations < 6);
    unsigned n = allocations++;
    memory[n] = calloc(1, bytes);
    assert(memory[n]);
    *bo = (struct amdgpu_mmd_bo){.handle=n, .addr=addresses[n], .ptr=memory[n]};
}
static void free_resource(struct amdgpu_mmd_bo *bo) { free(memory[bo->handle]); }
static int amdgpu_bo_cpu_map(int handle, void **out) { *out = memory[handle]; return 0; }
static int amdgpu_bo_cpu_unmap(int handle) { return 0; }
static int submit(amdgpu_device_handle device, struct mmd_context *context,
        int length, unsigned ip)
{
    printf("%u", submissions++);
    for (int i=0; i<length; i++) printf(" %08x", context->ib_cpu[i]);
    puts("");
    return 0;
}
// Pixel and returned-bitstream validation belong to the native proof; this
// harness captures constructors and must not simulate a successful encode.
static void check_result(struct vcn_context *vcn, struct amdgpu_mmd_bo feedback,
        struct amdgpu_mmd_bo bitstream, int frame_type) {}
#include "amd_mmd_frame.h"
#include "native_encode_funcs.h"
int main(int argc, char **argv)
{
    if (argc != 7) return 1;
    for (int i=0; i<6; i++) addresses[i] = strtoull(argv[i+1], NULL, 0);
    uint32_t words[2048] = {0};
    struct mmd_shared_context shared = {.vcn_ip_version_major=5, .vcn_unified_ring=true};
    struct mmd_context context = {.ib_cpu=words};
    struct vcn_context vcn = {0};
    amdgpu_cs_vcn_enc_create(NULL, &shared, &context, &vcn);
    amdgpu_cs_vcn_enc_encode_frame(NULL, &shared, &context, &vcn, 2);
    amdgpu_cs_vcn_enc_destroy(NULL, &shared, &context, &vcn);
    assert(allocations == 6 && submissions == 3);
    return 0;
}
