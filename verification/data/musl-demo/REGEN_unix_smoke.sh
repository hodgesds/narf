#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large unix_smoke_x86_64.c -o unix_smoke_x86_64
