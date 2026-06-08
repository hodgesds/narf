#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large net6_smoke_x86_64.c -o net6_smoke_x86_64
