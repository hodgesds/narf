#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large landlock_smoke_x86_64.c -o landlock_smoke_x86_64
