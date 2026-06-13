#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large jobctl2_smoke_x86_64.c -o jobctl2_smoke_x86_64
