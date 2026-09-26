#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large fifoeintr_smoke_x86_64.c -o fifoeintr_smoke_x86_64
