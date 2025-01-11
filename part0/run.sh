#!/usr/bin/env bash
mkdir -p obj-intel64
make -e obj-intel64/inscount0.so
pin -t obj-intel64/inscount0.so -- /bin/ls
cat inscount.out
