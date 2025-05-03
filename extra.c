#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <time.h>
#include <pwd.h>
#include <uthash.h>
#include <sys/stat.h>
#include <sys/types.h>   // <-- for ino_t
#include <limits.h> // for PATH_MAX
#include <unistd.h> // for access()

#include "headers/utils.h"
#include "headers/finder.h"
#include "headers/utils.h"
#include "headers/process_info.h"
#include "headers/binarys.h"

#define LOG_FILE "logs/new_process_log11.txt"
#define CHECK_SUM_CHANGE "logs/changes.txt"

#define COMMON_PROCESSES "logs/unique_checksums.txt"
#define ADDITIONAL_TRUSTED_PROCESSES "logs/extra_verified_checksums.txt"
#define CONNECTION_LOG_FILE "logs/suspicious_connections.log"

// Place this inside track.c anywere after getting the process info to save logs, make sure to add extra.c when compileing.
// You will also get a error due to the globals being used in the utils file so you might have to remove them here or copy the function 
// over to utils.c
// log_unknown_process(pid, proc_name, cmd, user, user, ppid, mem, exe, checksum, start_time, src_path, src_sum);

//GLOBALS
KnownProcess *known_processes = NULL;
size_t known_count = 0;
LoggedPID *logged_pids = NULL;
KnownProcess *extra_known_processes = NULL;
size_t extra_known_count = 0;

void log_unknown_process(const char *pid, const char *proc_name, const char *cmd, const char *user, 
    const char *uid, const char *ppid, const char *mem, const char *exe, 
    const char *exe_checksum, const char *start_time, const char *src_path, const char *src_sum) {

    if (!log_enabled) return;
    
    if (is_from_blocked_directory(exe)) {
        return;  // Don't log if the executable is from a blocked directory
    }

    struct stat st;
    if (stat(exe, &st) != 0) {
        perror("stat failed on exe path");
        return;
    }

    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("Error opening log file");
        return;
    }

    time_t t = time(NULL);
    struct tm tm = *localtime(&t);

    fprintf(log, "%d-%02d-%02d %02d:%02d:%02d - New Uncommon Process Detected:\n", 
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    fprintf(log, "  PID: %s\n", pid);
    fprintf(log, "  Process Name: %s\n", proc_name);
    fprintf(log, "  CMD: %s\n", cmd);
    fprintf(log, "  User: %s (UID: %s)\n", user, uid);
    fprintf(log, "  Parent PID: %s\n", ppid);
    fprintf(log, "  Memory Usage: %s\n", mem);
    fprintf(log, "  Executable Path: %s\n", exe);
    fprintf(log, "  Executable Checksum: %s\n", exe_checksum);
    fprintf(log, "  src path: %s\n", src_path);
    fprintf(log, "  src sum: %s\n", src_sum);
    fprintf(log, "  Start Time (ticks): %s\n", start_time);

    fprintf(log, "-------------------------------------\n");
    fclose(log);
}

void ensure_log_file_exists() {
    FILE *log = fopen(LOG_FILE, "a");
    if (!log) {
        perror("Error creating log file");
    } else {
        fclose(log);
    }
}

void ensure_file_exists()
{
    FILE *log_file = fopen(CONNECTION_LOG_FILE, "a");
    if (!log_file)
    {
        perror("Error creating log file");
    }
    else
    {
        fclose(log_file);
    }
}

void ensure_add_file_exists() {
    FILE *log = fopen(ADDITIONAL_TRUSTED_PROCESSES, "a");
    if (!log) {
        perror("Error creating log file");
    } else {
        fclose(log);
    }
}

void load_additional_trusted_processes() {
    FILE *file = fopen(ADDITIONAL_TRUSTED_PROCESSES, "r");
    if (!file) {
        perror("Failed to open additional trusted process file");
        return;
    }

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || strlen(line) < 10) continue;

        char *checksum = strtok(line, " ");
        char *path = strtok(NULL, " #\n");

        if (checksum && path) {
            KnownProcess *temp = realloc(extra_known_processes, (extra_known_count + 1) * sizeof(KnownProcess));
            if (!temp) {
                perror("Memory allocation error (extra)");
                fclose(file);
                return;
            }
            extra_known_processes = temp;

            strncpy(extra_known_processes[extra_known_count].checksum, checksum, sizeof(extra_known_processes[extra_known_count].checksum) - 1);
            strncpy(extra_known_processes[extra_known_count].path, path, sizeof(extra_known_processes[extra_known_count].path) - 1);

            struct stat st;
            if (stat(path, &st) == 0) {
                extra_known_processes[extra_known_count].inode = st.st_ino;
            } else {
                extra_known_processes[extra_known_count].inode = 0;
            }

            extra_known_count++;
        }
    }

    fclose(file);
}

void print_outgoing_connections_for_pid(int target_pid, const char *start_time)
{
    FILE *cmd = popen("netstat -antp 2>/dev/null", "r");
    if (!cmd)
    {
        perror("Failed to execute netstat");
        return;
    }

    char line[512];
    fgets(line, sizeof(line), cmd); // Skip header line

    while (fgets(line, sizeof(line), cmd))
    {
        char proto[10], local_addr[50], remote_addr[50], state[20], pid_info[50];
        int local_port, remote_port;
        int pid = -1;

        if (sscanf(line, "%s %*d %*d %[^:]:%d %[^:]:%d %s %s",
                   proto, local_addr, &local_port, remote_addr, &remote_port, state, pid_info) < 6)
        {
            continue;
        }

        sscanf(pid_info, "%d/", &pid);

        if (pid == target_pid && !is_connection_seen(local_port, remote_addr, remote_port))
        {
            ConnectionInfo cinfo;
            strncpy(cinfo.proto, proto, sizeof(cinfo.proto));
            strncpy(cinfo.local_addr, local_addr, sizeof(cinfo.local_addr));
            strncpy(cinfo.remote_addr, remote_addr, sizeof(cinfo.remote_addr));
            strncpy(cinfo.state, state, sizeof(cinfo.state));
            strncpy(cinfo.start_time, start_time, sizeof(cinfo.start_time));
            cinfo.local_port = local_port;
            cinfo.remote_port = remote_port;
            cinfo.pid = pid;
            handle_suspicious_connection(&cinfo);
            add_connection_to_seen(local_port, remote_addr, remote_port);

        }
    }

    pclose(cmd);
}

// Extract network connections using `netstat -antp` and log them
void log_outgoing_connections_for_pid(int target_pid, const char *start_time)
{

    if (!log_enabled)
    {
        return;
    }

    FILE *cmd = popen("netstat -antp 2>/dev/null", "r");
    if (!cmd)
    {
        perror("Failed to execute netstat");
        return;
    }

    FILE *log_file = fopen(CONNECTION_LOG_FILE, "a");
    if (!log_file)
    {
        perror("Failed to open connection log file");
        pclose(cmd);
        return;
    }

    char line[512];
    fgets(line, sizeof(line), cmd); // Skip header line

    while (fgets(line, sizeof(line), cmd))
    {
        char proto[10], local_addr[50], remote_addr[50], state[20], pid_info[50];
        int local_port, remote_port, pid = -1;

        if (sscanf(line, "%s %*d %*d %[^:]:%d %[^:]:%d %s %s",
                   proto, local_addr, &local_port, remote_addr, &remote_port, state, pid_info) < 6)
        {
            continue;
        }

        sscanf(pid_info, "%d/", &pid);

        time_t t = time(NULL);
        struct tm tm = *localtime(&t);

        if (pid == target_pid && !is_logged_connection_seen(local_port, remote_port))
        {
            fprintf(log_file, "Suspicious Connection logged at - %d-%02d-%02d %02d:%02d:%02d\n",
                    tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
            fprintf(log_file, "  Protocol: %d\n", pid);
            fprintf(log_file, "  Protocol: %s\n", proto);
            fprintf(log_file, "  Local Address: %s:%d\n", local_addr, local_port);
            fprintf(log_file, "  Remote Address: %s:%d\n", remote_addr, remote_port);
            fprintf(log_file, "  Process Start Time (ticks): %s\n", start_time);
            fprintf(log_file, "  State: %s\n\n", state);
            fflush(log_file);
            add_logged_connection(local_port, remote_port);
        }
    }

    fclose(log_file); // ✅ Correctly placed outside the loop
    pclose(cmd);
}
