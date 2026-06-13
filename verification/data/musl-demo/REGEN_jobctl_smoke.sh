#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large jobctl_smoke_x86_64.c -o jobctl_smoke_x86_64
