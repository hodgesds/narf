#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large pipehup_smoke_x86_64.c -o pipehup_smoke_x86_64
