/* Host stand-in for the kernel's linux/types.h (harness only). */
#ifndef NARF_HDR_LINUX_TYPES_H
#define NARF_HDR_LINUX_TYPES_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;
typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#define BIT(n) (1UL << (n))
#define __packed __attribute__((packed))
#define DIV_ROUND_CLOSEST(x, d) (((x) + ((d) / 2)) / (d))
#endif
