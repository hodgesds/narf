#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fpu_preempt_smoke_x86_64.c -o fpu_preempt_smoke_x86_64
