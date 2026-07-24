#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pipeblk_smoke_x86_64.c -o pipeblk_smoke_x86_64
