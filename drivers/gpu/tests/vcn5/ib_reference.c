// SPDX-License-Identifier: GPL-2.0-or-later
// Compile unchanged Linux VCN session constructors against capture-only stubs.
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint64_t u64;
#define cpu_to_le32(x) (x)
#define upper_32_bits(x) ((uint32_t)((x) >> 32))
#define AMDGPU_GPU_PAGE_SIZE 4096
#define AMDGPU_GPU_PAGE_ALIGN(x) (((x) + 4095) & ~(uint64_t)4095)
#define AMDGPU_IB_POOL_DIRECT 0
#define AMDGPU_KERNEL_JOB_ID_VCN_RING_TEST 0
struct dma_fence { int dummy; };
struct amdgpu_ib { uint32_t *ptr; uint32_t length_dw; uint64_t gpu_addr; };
struct amdgpu_job { struct amdgpu_ib ibs[1]; };
struct amdgpu_device { struct { struct { bool using_unified_queue; } inst[1]; } vcn; };
struct amdgpu_ring { struct amdgpu_device *adev; unsigned me; };
static uint32_t job_words[128];
static alignas(4096) uint32_t message[2048];
static struct amdgpu_job captured;
static struct dma_fence done;
static uint64_t message_address;
static int amdgpu_job_alloc_with_ib(struct amdgpu_device *adev, void *vm,
        void *entity, unsigned bytes, unsigned pool, unsigned id,
        struct amdgpu_job **out)
{
    if (bytes > sizeof(job_words)) return -1;
    memset(job_words, 0, sizeof(job_words));
    captured.ibs[0] = (struct amdgpu_ib){.ptr=job_words};
    *out = &captured;
    return 0;
}
static int amdgpu_job_submit_direct(struct amdgpu_job *job,
        struct amdgpu_ring *ring, struct dma_fence **fence)
{
    *fence = &done;
    return 0;
}
static struct dma_fence *dma_fence_get(struct dma_fence *f) { return f; }
static void dma_fence_put(struct dma_fence *f) {}
static void amdgpu_job_free(struct amdgpu_job *job) {}
static void amdgpu_ib_free(struct amdgpu_ib *ib, struct dma_fence *f) {}
static int amdgpu_ib_get(struct amdgpu_device *adev, void *vm, unsigned bytes,
        unsigned pool, struct amdgpu_ib *ib)
{
    if (bytes > sizeof(message)) return -1;
    memset(message, 0, sizeof(message));
    *ib = (struct amdgpu_ib){.ptr=message, .gpu_addr=message_address};
    return 0;
}
#include "native_vcn_test_funcs.h"
static void dump(const char *name, const uint32_t *words, unsigned count)
{
    printf("%s", name);
    for (unsigned i=0; i<count; i++) printf(" %08x", words[i]);
    puts("");
}
int main(void)
{
    struct amdgpu_device adev = {.vcn.inst[0].using_unified_queue=true};
    struct amdgpu_ring ring = {.adev=&adev};
    struct amdgpu_ib ib = {.gpu_addr=0x810000000ull};
    if (amdgpu_vcn_enc_get_create_msg(&ring, 1, &ib, NULL)) return 1;
    dump("encode_create", captured.ibs[0].ptr, captured.ibs[0].length_dw);
    if (amdgpu_vcn_enc_get_destroy_msg(&ring, 1, &ib, NULL)) return 1;
    dump("encode_destroy", captured.ibs[0].ptr, captured.ibs[0].length_dw);
    message_address = 0x810022000ull;
    if (amdgpu_vcn_dec_get_create_msg(&ring, 1, &ib)) return 1;
    dump("decode_create_message", message, 14);
    if (amdgpu_vcn_dec_sw_send_msg(&ring, &ib, NULL)) return 1;
    dump("decode_create", captured.ibs[0].ptr, captured.ibs[0].length_dw);
    message_address = 0x810023000ull;
    if (amdgpu_vcn_dec_get_destroy_msg(&ring, 1, &ib)) return 1;
    dump("decode_destroy_message", message, 14);
    if (amdgpu_vcn_dec_sw_send_msg(&ring, &ib, NULL)) return 1;
    dump("decode_destroy", captured.ibs[0].ptr, captured.ibs[0].length_dw);
    return 0;
}
