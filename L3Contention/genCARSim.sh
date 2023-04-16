#!/bin/bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 CAR output"
    exit 1
fi

CAR=$1
OUT=$2

CAR=$((CAR-6))

if ((CAR < 0)); then
    echo "the CAR is too small to simulate, force it to 7."
fi

if ((CAR <= 0)); then
    NOPSTR=
else
    NOPSTR=$(printf "nop;%.0s" $(seq 1 $CAR))
fi


gcc -DNOPSTR=\"${NOPSTR}\" /home/pzy/project/PTATM/L3Contention/CARSimulator.c -O1 -o $OUT
