#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large wlserve_smoke_x86_64.c -o wlserve_smoke_x86_64
