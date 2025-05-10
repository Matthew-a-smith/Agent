# C Client Agent

This is the lightweight C-based client component of the remote process monitoring and control tool. It connects back to a listener server, handles command execution, file retrieval, and reports process activity.

---

## Features

- Persistent socket connection to a remote listener
- Remote file reception and disk write
- Remote command execution via system shell
- Process monitoring and optional logging
- Daemon mode for stealth operation

---

## Build Instructions

You need `gcc` to compile the program, I also included a compiler.sh it does not include any functions for the flags however so you will have to compile it manually to set up a listener or use any flags. make sure that you use single quotes around the macro value in the ip address

gcc -Iheaders -Iexternals main.c utils.c track.c finder.c process.c decompile.c proxy.c -o process_monitor -lssl -lcrypto -DPROXY_IP='"ip"' -DPROXY_PORT=port
other flags
-DDAEMON_ENABLED
-DSAVE_ENABLED
-DLOG_ENABLED

please refer to for full doc
https://github.com/Matthew-a-smith/Agent-P

