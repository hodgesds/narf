#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fork_pipe_smoke_x86_64.c -o fork_pipe_smoke_x86_64
