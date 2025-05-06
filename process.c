#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>  // for dirname()
#include <sys/stat.h>

#include "headers/process_info.h"
#include "headers/proxy.h"

void handle_suspicious_process(const ProcessInfo *p) {
    // Calculate the required size for the message
    size_t needed_size = 1024 +
        strlen(p->start_time) +
        strlen(p->pid) +
        strlen(p->proc_name) +
        strlen(p->cmd) +
        strlen(p->user) +
        strlen(p->ppid) +
        strlen(p->mem) +
        strlen(p->exe) +
        strlen(p->checksum) +
        strlen(p->saved_file) +
        strlen(p->src_path) +
        strlen(p->src_sum);

    // Allocate memory for the message
    char *msg = malloc(needed_size);
    if (!msg) {
        perror("malloc failed");
        return;
    }

    // Build the message
    snprintf(msg, needed_size,
        "[Suspicious Process]\n"
        "Start Time: %s\n"
        "PID: %s\n"
        "Process Name: %s\n"
        "CMD: %s\n"
        "User: %s\n"
        "Parent PID: %s\n"
        "Memory: %s\n"
        "Executable Path: %s\n"
        "Checksum: %s\n"
        "Source Path: %s\n"
        "Source Checksum: %s\n"
        "Saved File: %s\n",
        p->start_time,
        p->pid,
        p->proc_name,
        p->cmd,
        p->user,
        p->ppid,
        p->mem,
        p->exe,
        p->checksum,
        p->src_path,
        p->src_sum,
        p->saved_file // From saved full command
    );

    // Send message to the Python socket or handle as necessary
    send_request_to_proxy(msg);
}

void handle_file(const File *f) {
    size_t needed_size = 1024 + strlen(f->saved_file);
    char *msg = malloc(needed_size);
    if (!msg) {
        perror("malloc failed");
        return;
    }

    snprintf(msg, needed_size,
        "[File Found]\n"
        "Saved File: %s\n",
        f->saved_file
    );
    printf("FILE SENT: %s\n", msg);

    // Actually send the file using the correct file path
    send_file_to_proxy(f->saved_file);    

    free(msg);
}



void handle_normal_process(const NormalInfo *n) {
    char msg[4096];
    snprintf(msg, sizeof(msg),
        "[Normal Process]\n"
        "Start Time: %s\n"
        "PID: %s\n"
        "Process Name: %s\n"
        "CMD: %s\n"
        "User: %s\n"
        "Parent PID: %s\n"
        "Memory: %s\n"
        "Executable Path: %s\n"
        "Checksum: %s\n"
        "Source Path: %s\n"
        "Source Checksum: %s\n",
        n->start_time,
        n->pid,
        n->proc_name,
        n->cmd,
        n->user,
        n->ppid,
        n->mem,
        n->exe,
        n->checksum,
        n->src_path,
        n->src_sum
    );
    send_request_to_proxy(msg);
}

void handle_suspicious_connection(const ConnectionInfo *c) {
    char msg[2048];
    snprintf(msg, sizeof(msg),
        "[Suspicious Connection]\n"
        "PID: %d\n"
        "Protocol: %s\n"
        "Local Address: %s:%d\n"
        "Remote Address: %s:%d\n"
        "State: %s\n"
        "Start Time: %s\n",
        c->pid,
        c->proto,
        c->local_addr, c->local_port,
        c->remote_addr, c->remote_port,
        c->state,
        c->start_time
    );
    send_request_to_proxy(msg);
}

void decompile(const Elf32 *h) {
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "[Decompilation]\n"
        "FilePath: %s\n"
        "Entry Point: %s\n"
        "Program Header Offset: %s\n"
        "Section Header Offset: %s\n",
        h->filepath,
        h->e_entry,
        h->e_phoff,
        h->e_shoff
    );
    send_request_to_proxy(msg);
}

void bash_script(const BashPattern *b) {
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "[Suspicious Bash Pattern]\n"
        "Pattern: (%s) → %s",
        b->suspicious_patterns,
        b->buffer
    );
    send_request_to_proxy(msg);
}

void extensions_suspicous(const Extension *e) {
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "[Suspicious Extension Detected]\n"
        "Extension: %s\n"
        "Filepath: %s",
        e->suspicious_extensions,
        e->filepath
    );
    send_request_to_proxy(msg);
}




