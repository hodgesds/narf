#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large psched_smoke_x86_64.c -o psched_smoke_x86_64
