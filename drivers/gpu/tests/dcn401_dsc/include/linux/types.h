/* Host stand-in for <linux/types.h>: the kernel integer names. */
#ifndef NARF_DSC_LINUX_TYPES_H
#define NARF_DSC_LINUX_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint16_t __be16;
typedef uint32_t __be32;
#define __packed __attribute__((packed))
#endif
