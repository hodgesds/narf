#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large preemptsched_smoke_x86_64.c -o preemptsched_smoke_x86_64
