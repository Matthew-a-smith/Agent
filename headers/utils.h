#ifndef UTILS_H
#define UTILS_H

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <uthash.h>

// Structure definitions
typedef struct {
    char pid[16];
    UT_hash_handle hh;
} LoggedPID;

typedef struct {
    char checksum[SHA256_DIGEST_LENGTH * 2 + 1];
    char path[512];
    ino_t inode;  // Add inode tracking
} KnownProcess;


// Global variable declarations
extern KnownProcess *known_processes;
extern size_t known_count;
extern LoggedPID *logged_pids;
extern int connection_count;       // Declare without defining
extern int log_enabled;  // Declare as an external variable
extern int save_enabled;  
extern int daemon_enabled;  
extern int strict_mode;
// Function declarations
void ensure_log_file_exists();
void ensure_add_file_exists();

//void check_and_log_checksum_changes(const char *exe_path);
void compute_sha256(const char *path, char *output);
//void load_common_processes();
void load_additional_trusted_processes();

//int is_known_process_name(const char *exe, const char *checksum, ino_t inode);
int is_known_src_path_and_sum(const char *src_path, const char *src_sum);
int is_from_blocked_directory(const char *exe_path);
void log_unknown_process(const char *pid, const char *proc_name, const char *cmd, 
                         const char *user, const char *uid, const char *ppid, 
                         const char *mem, const char *exe, const char *exe_checksum, 
                         const char *start_time, const char *src_path, const char *src_sum);

int print_unknown_process(const char *pid, const char *proc_name, const char *cmd, 
                           const char *user, const char *uid, const char *ppid, 
                           const char *mem, const char *exe, const char *exe_checksum, 
                           const char *start_time, const char *src_path, const char *src_sum);
int is_pid_logged(const char *pid);
void add_logged_pid(const char *pid);

int is_checksum_logged(const char *checksum);
void add_logged_checksum(const char *checksum);
void trim_newline(char *str);


#endif // UTILS_H





