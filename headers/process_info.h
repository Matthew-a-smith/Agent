// process_info.h
#ifndef PROCESS_INFO_H
#define PROCESS_INFO_H

extern int bash_header; // Declare it here
typedef struct {
    char pid[16];
    char proc_name[256];
    char cmd[2048];
    char user[64];
    char ppid[16];
    char mem[32];
    char exe[512];
    char checksum[65];
    char saved_file[2048];
    char src_path[512];
    char src_sum[65];
    char start_time[64];
} ProcessInfo;

typedef struct {
    char saved_file[2048];
} File;

typedef struct {
    char pid[16];
    char proc_name[256];
    char cmd[2048];
    char user[64];
    char ppid[16];
    char mem[32];
    char exe[512];
    char checksum[65];
    char src_path[512];
    char src_sum[65];
    char start_time[64];
} NormalInfo;

typedef struct {
    char proto[10]; 
    char local_addr[50]; 
    int local_port;
    char remote_addr[50]; 
    int remote_port; 
    char state[20];
    int pid;
    char start_time[64];
    char filepath[512];
    char e_entry[64];
    char e_phoff[64];
    char e_shoff[64];
} ConnectionInfo;

typedef struct {
    char filepath[512];
    char e_entry[64];
    char e_phoff[64];
    char e_shoff[64];
} Elf32;

typedef struct {
    char suspicious_extensions[16];
    char filepath[512];
} Extension;

typedef struct {
    char suspicious_patterns[512];
    char buffer[256];
    int i;
} BashPattern;

typedef struct {
    char filepath[512];
    char e_entry[64];
    char e_phoff[64];
    char e_shoff[64];
} python;

typedef struct {
    char filepath[512];
    char e_entry[64];
    char e_phoff[64];
    char e_shoff[64];
} bin;
#endif