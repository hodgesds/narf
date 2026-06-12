#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large getrandom_smoke_x86_64.c -o getrandom_smoke_x86_64
