#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large mq_smoke_x86_64.c -o mq_smoke_x86_64
