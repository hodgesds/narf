// SPDX-License-Identifier: MIT
// Capture unchanged IGT decode-buffer builders; never opens a GPU device.
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define igt_info(...) ((void)0)
struct mmd_shared_context { bool vcn_dec_sw_ring, vcn_unified_ring; int vcn_reg_index; };
struct mmd_context { uint32_t *ib_cpu; };
struct vcn_context {
    uint32_t *ib_checksum, *ib_size_in_dw;
    struct rvcn_decode_buffer *decode_buffer;
};
static struct { uint32_t data0, data1, cmd; } reg[1];
#include "native_decode_funcs.h"
int main(int argc, char **argv)
{
    if (argc != 11) return 1;
    uint64_t at[10];
    for (int i=0; i<10; i++) at[i] = strtoull(argv[i+1], NULL, 0);
    struct mmd_shared_context shared = {.vcn_dec_sw_ring=true, .vcn_unified_ring=true};
    for (int phase=0; phase<3; phase++) {
        uint32_t words[43] = {0};
        struct mmd_context context = {.ib_cpu=words};
        struct vcn_context vcn = {0};
        int length = 0;
        vcn_dec_cmd(&shared,&context,&vcn,at[0],DECODE_CMD_SESSION_CONTEXT_BUFFER,&length,INVALID_DECODER_NONE);
        vcn_dec_cmd(&shared,&context,&vcn,at[phase+1],DECODE_CMD_MSG_BUFFER,&length,INVALID_DECODER_NONE);
        if (phase == 1) {
            const uint32_t commands[] = {DECODE_CMD_DPB_BUFFER,DECODE_CMD_DECODING_TARGET_BUFFER,
                DECODE_CMD_FEEDBACK_BUFFER,DECODE_CMD_BITSTREAM_BUFFER,
                DECODE_CMD_IT_SCALING_TABLE_BUFFER,DECODE_CMD_CONTEXT_BUFFER};
            for (int i=0; i<6; i++)
                vcn_dec_cmd(&shared,&context,&vcn,at[i+4],commands[i],&length,INVALID_DECODER_NONE);
        }
        amdgpu_cs_sq_ib_tail(&vcn,words+length);
        printf("%d",phase);
        for (int i=0; i<length; i++) printf(" %08x",words[i]);
        puts("");
    }
    return 0;
}
