#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mempolicy_smoke_x86_64.c -o mempolicy_smoke_x86_64
