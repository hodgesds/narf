#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fhint_smoke_x86_64.c -o fhint_smoke_x86_64
