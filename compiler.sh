#!/bin/bash

# Script to compile process_monitor

echo "Compiling process_monitor..."

gcc -Iheaders -Iexternals main.c utils.c track.c finder.c process.c decompile.c proxy.c -o process_monitor -lssl -lcrypto

if [ $? -eq 0 ]; then
    echo "Compilation successful! Executable created: ./process_monitor"
else
    echo "Compilation failed."
fi
