#ifndef PROCESS_FINAL_TRACKER_H
#define PROCESS_FINAL_TRACKER_H

#include "utils.h"  // Include the shared utilities

#define LOG_FILE "new_process_log1.txt"
#define SUSPICIOUS_LOG_FILE "suspicious_processes.log"

typedef struct Process {
    char pid[16];
    char cmd[2048];
    char user[64];
    char exe[512];
} Process;

void trim_whitespace(char *str);
Process* get_process_from_log();
void track_process(Process *proc);
void continuously_monitor_process();

#endif

