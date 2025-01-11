#!/usr/bin/env bash
mkdir -p obj-intel64
make -e obj-intel64/script.so
pin -t obj-intel64/script.so -- /bin/ls
cat script.out
