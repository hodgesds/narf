#!/bin/sh
musl-gcc -shared -fPIC -O2 -Wl,-soname,liba.so liba.c -o liba.so
musl-gcc -shared -fPIC -O2 -Wl,-soname,libb.so libb.c -L. -la -Wl,-rpath,/lib -o libb.so
musl-gcc -O2 -fPIE -pie -mcmodel=large dso_smoke.c -L. -lb -la -Wl,-rpath,/lib -o dso_smoke_x86_64
