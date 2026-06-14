#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large alarmloop_smoke_x86_64.c -o alarmloop_smoke_x86_64
