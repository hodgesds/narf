#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large ppoll_smoke_x86_64.c -o ppoll_smoke_x86_64
