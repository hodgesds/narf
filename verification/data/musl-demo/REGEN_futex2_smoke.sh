#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large futex2_smoke_x86_64.c -o futex2_smoke_x86_64
