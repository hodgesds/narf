#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large distro_kde.c -o distro_kde_x86_64
