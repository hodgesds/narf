#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large sockpair_smoke_x86_64.c -o sockpair_smoke_x86_64
