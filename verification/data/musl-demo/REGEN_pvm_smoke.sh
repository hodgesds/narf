#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pvm_smoke_x86_64.c -o pvm_smoke_x86_64
