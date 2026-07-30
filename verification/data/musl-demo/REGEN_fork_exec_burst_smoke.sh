#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fork_exec_burst_smoke_x86_64.c -o fork_exec_burst_smoke_x86_64
