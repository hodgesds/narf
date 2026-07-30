#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sched_affinity_smp_smoke_x86_64.c -o sched_affinity_smp_smoke_x86_64
