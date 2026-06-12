#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large itimer_smoke_x86_64.c -o itimer_smoke_x86_64
