#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <time.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>   // <-- for ino_t
#include <limits.h> // for PATH_MAX
#include <unistd.h> // for access()

#include "uthash.h"
#include "headers/utils.h"

// Global variables
KnownProcess *known_processes = NULL;
size_t known_count = 0;
LoggedPID *logged_pids = NULL;
KnownProcess *extra_known_processes = NULL;
size_t extra_known_count = 0;

#define PATH_MAX 4096
// Function Definitions
typedef struct LoggedChecksum {
    char checksum[SHA256_DIGEST_LENGTH * 2 + 1];
    UT_hash_handle hh;
} LoggedChecksum;

LoggedChecksum *logged_checksums = NULL;

void compute_sha256(const char *path, char *output) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        strncpy(output, "UNKNOWN", 64);
        return;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        strncpy(output, "ERROR", 64);
        fclose(file);
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        strncpy(output, "ERROR", 64);
        goto cleanup;
    }

    unsigned char buffer[4096];
    size_t bytesRead;
    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytesRead) != 1) {
            strncpy(output, "ERROR", 64);
            goto cleanup;
        }
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    unsigned int length = 0;

    if (EVP_DigestFinal_ex(mdctx, hash, &length) != 1) {
        strncpy(output, "ERROR", 64);
    } else {
        for (unsigned int i = 0; i < length; i++) {
            snprintf(output + (i * 2), 3, "%02x", hash[i]);
        }
    }

cleanup:
    EVP_MD_CTX_free(mdctx);
    fclose(file);
}

void trim_newline(char *str) {
    char *p = str;
    while (*p) {
        if (*p == '\n' || *p == '\r') {
            *p = '\0'; // Null-terminate the string at the newline
            break;
        }
        p++;
    }
}


int is_known_src_path_and_sum(const char *src_path, const char *src_sum) {
    for (size_t i = 0; i < extra_known_count; i++) {
        if (strcmp(extra_known_processes[i].path, src_path) == 0 &&
            strncmp(extra_known_processes[i].checksum, src_sum, SHA256_DIGEST_LENGTH * 2) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_from_blocked_directory(const char *exe_path) {
    // Exact paths to block (e.g., specific binaries)
    const char *blocked_binaries[] = {
        "/usr/bin/VBoxClient",
        "/usr/bin/dbus-daemon",
        "/usr/bin/pipewire",
        "/usr/bin/sleep",
        "/usr/bin/fusermount3"
        
    };

    // Directories to block, including all subdirectories
    const char *blocked_dirs[] = {
        "/snap/code",
        "/usr/bin/apt-get"
    };

    // Block specific binaries
    for (int i = 0; i < sizeof(blocked_binaries) / sizeof(blocked_binaries[0]); i++) {
        if (strcmp(exe_path, blocked_binaries[i]) == 0) {
            return 1; // Exact binary match
        }
    }

    // Block entire directory trees
    for (int i = 0; i < sizeof(blocked_dirs) / sizeof(blocked_dirs[0]); i++) {
        if (strncmp(exe_path, blocked_dirs[i], strlen(blocked_dirs[i])) == 0) {
            // Make sure it’s a full path match (like /usr/lib or /usr/lib/foo)
            if (exe_path[strlen(blocked_dirs[i])] == '/' || exe_path[strlen(blocked_dirs[i])] == '\0') {
                return 1; // It's inside a blocked directory
            }
        }
    }

    return 0; // Allowed
}


int print_unknown_process(const char *pid, const char *proc_name, const char *cmd, const char *user, 
    const char *uid, const char *ppid, const char *mem, const char *exe, 
    const char *exe_checksum, const char *start_time, const char *src_path, const char *src_sum) {
    if (!log_enabled) return 0;

    if (is_from_blocked_directory(exe)) {
        return 0;  // Return 0 if we don't want to log this process
    }

    struct stat st;
    if (stat(exe, &st) != 0) {
        perror("stat failed on exe path");
        return 0;  // Return 0 if there was an error
    }

    return 1;  // Return 1 to indicate successful logging
}


int is_checksum_logged(const char *checksum) {
    LoggedChecksum *s;
    HASH_FIND_STR(logged_checksums, checksum, s);
    return s != NULL;
}

void add_logged_checksum(const char *checksum) {
    LoggedChecksum *s = malloc(sizeof(LoggedChecksum));
    if (!s) return;
    strncpy(s->checksum, checksum, sizeof(s->checksum));
    HASH_ADD_STR(logged_checksums, checksum, s);
}

int is_pid_logged(const char *pid) {
    LoggedPID *s;
    HASH_FIND_STR(logged_pids, pid, s); // Find PID in hash table
    return s != NULL;
}

void add_logged_pid(const char *pid) {
    LoggedPID *s = (LoggedPID *)malloc(sizeof(LoggedPID));
    strncpy(s->pid, pid, sizeof(s->pid) - 1);
    HASH_ADD_STR(logged_pids, pid, s); // Add PID to hash table
}







