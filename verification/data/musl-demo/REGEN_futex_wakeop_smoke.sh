#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large futex_wakeop_smoke_x86_64.c -o futex_wakeop_smoke_x86_64
