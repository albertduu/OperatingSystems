#!/bin/bash
make SCHED=$([ "$1" = "p" ] && echo "PSJF" || echo "MLFQ")
cd ./benchmarks
make
./genRecord.sh
# make test
# ./test
cd ..