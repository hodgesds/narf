#!/bin/sh
musl-gcc -O2 -Wall -fPIE -pie -mcmodel=large distro_fedora.c -o distro_fedora_x86_64
