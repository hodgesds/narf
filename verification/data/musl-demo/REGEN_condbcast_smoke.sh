#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large condbcast_smoke_x86_64.c -o condbcast_smoke_x86_64
