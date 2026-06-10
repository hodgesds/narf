#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large signal_smoke_x86_64.c -o signal_smoke_x86_64
