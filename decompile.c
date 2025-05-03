#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>  // <-- Add this to the top
#include <libgen.h> // for basename()
#include <ctype.h>  // for isspace()

#include "headers/decompile.h"
#include "headers/process_info.h"
#include "headers/binarys.h"
#include "headers/utils.h"


void bash_script(const BashPattern *bp);
void extensions_suspicous(const Extension *e);

int suspend_suspicious_processes = 0;
// List of suspicious commands to track
const char *suspicious_commands[] = {
    "bash -i",   // Interactive bash shell
    "sh -i",     // Interactive shell
    "sh -i wn",  // Specific interactive shell
    "import",
    "os",
    "pty",
    NULL         // End of list marker
};

// List of suspicious file extensions
const char *suspicious_extensions[] = {
    ".elf",
    ".sh",
    ".py",
    ".pl",     // Perl script
    ".bin",    // Binary file
    ".out",    // Generic output binary
    ".exe",    // Windows-style executable
    NULL       // End of list marker
};

const char *suspicious_patterns[] = {
    "expect",
    "nc ", "ncat", "curl", "wget", "ftp", "scp", "rsync", "telnet", "socat", "openssl s_client", "whois",
    "/dev/tcp/", "0<&196", "exec 5<>/dev/tcp", "bash -i", "| bash",
    "chmod 777", "chown root", "setuid", "sudo", "pkexec", "su root", "mount", "umount", "kill", "systemctl", "crontab", "at ", "nohup",
    "base64", "eval", "exec", "LD_PRELOAD", "ptrace", "strace", "gdb",
    "> /dev/null", "2>/dev/null", "history -c", "unset HISTFILE", "rm -rf /var/log", "auditctl"
};

// Only Python-related suspicious patterns
const char *suspicious_python_patterns[] = {
    "import os",
    "import subprocess",
    "import socket",
    "import sys",
    "import shutil",
    "os.system",
    "subprocess.call",
    "subprocess.Popen",
    "eval(",
    "exec(",
    "open('/dev/tcp",
    "base64.b64decode",
    "__import__",
    "pickle.load",
    "marshal.loads"
};

int has_suspicious_extension(const char *cmd) {
    char temp[2048];
    strncpy(temp, cmd, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';

    // Tokenize the command and check each token
    char *token = strtok(temp, " \t");
    while (token != NULL) {
        for (int i = 0; suspicious_extensions[i] != NULL; i++) {
            size_t len_token = strlen(token);
            size_t len_ext = strlen(suspicious_extensions[i]);

            if (len_token >= len_ext &&
                strcmp(token + len_token - len_ext, suspicious_extensions[i]) == 0) {
                return 1;  // Suspicious extension found
            }
        }
        token = strtok(NULL, " \t");
    }

    return 0;
}

void log_all_extensions(const char *filepath) {
    for (int i = 0; suspicious_extensions[i] != NULL; i++) {
        size_t len_filepath = strlen(filepath);
        size_t len_ext = strlen(suspicious_extensions[i]);

        if (len_filepath >= len_ext &&
            strcmp(filepath + len_filepath - len_ext, suspicious_extensions[i]) == 0) {

            Extension ep;
            strncpy(ep.suspicious_extensions, suspicious_extensions[i], sizeof(ep.suspicious_extensions));
            strncpy(ep.filepath, filepath, sizeof(ep.filepath));
            printf("Detected file with suspicious extension (%s): %s\n", ep.suspicious_extensions, ep.filepath);
            extensions_suspicous(&ep);
            return;
        }
    }
}

int is_suspicious_command(const char *cmd) {
    char cleaned_cmd[2048];
    strncpy(cleaned_cmd, cmd, sizeof(cleaned_cmd));
    cleaned_cmd[sizeof(cleaned_cmd)-1] = '\0';

    // Trim trailing space
    size_t len = strlen(cleaned_cmd);
    while (len > 0 && cleaned_cmd[len - 1] == ' ') {
        cleaned_cmd[len - 1] = '\0';
        len--;
    }

    for (int i = 0; suspicious_commands[i] != NULL; i++) {
        if (strstr(cleaned_cmd, suspicious_commands[i])) {
            return 1;  // Suspicious command found
        }
    }
    return 0;
}


// Function to handle Shell scripts (.sh)
void analyze_shell_script(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("Unable to open Shell script");
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file)) {
        // Skip commented lines
        if (buffer[0] == '#') {
            continue;
        }

        for (int i = 0; i < sizeof(suspicious_patterns)/sizeof(suspicious_patterns[0]); i++) {
            if (strstr(buffer, suspicious_patterns[i])) {
                BashPattern bp;
                strncpy(bp.suspicious_patterns, suspicious_patterns[i], sizeof(bp.suspicious_patterns));
                strncpy(bp.buffer, buffer, sizeof(bp.buffer));
                bp.i = i;
                bash_script(&bp);
            }
        }
    }

    fclose(file);
}

// Function to handle Python script files
void analyze_python_script(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("Unable to open Python script");
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file)) {
        // Skip commented lines
        if (buffer[0] == '#') {
            continue;
        }

        for (int i = 0; i < sizeof(suspicious_python_patterns)/sizeof(suspicious_python_patterns[0]); i++) {
            if (strstr(buffer, suspicious_python_patterns[i])) {
                BashPattern bp;
                strncpy(bp.suspicious_patterns, suspicious_python_patterns[i], sizeof(bp.suspicious_patterns));
                strncpy(bp.buffer, buffer, sizeof(bp.buffer));
                bp.i = i;
                bash_script(&bp);
            }
        }
    }

    fclose(file);
}

// Function to check for ".bin" files (Generic Binary)
int is_bin_file(const char *filename) {
    size_t len_filename = strlen(filename);
    size_t len_ext = strlen(".bin");
    if (len_filename >= len_ext && strcmp(filename + len_filename - len_ext, ".bin") == 0) {
        return 1;  // .bin file detected
    }
    return 0;
}

// Function to check for ".out" files (Generic output binary)
int is_out_file(const char *filename) {
    size_t len_filename = strlen(filename);
    size_t len_ext = strlen(".out");
    if (len_filename >= len_ext && strcmp(filename + len_filename - len_ext, ".out") == 0) {
        return 1;  // .out file detected
    }
    return 0;
}

void decompile(const Elf32 *h);

// New function: accepts file path and prints ELF info if valid
void analyze_elf_header(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Unable to open file");
        return;
    }

    Elf32_Ehdr header;
    if (fread(&header, sizeof(header), 1, file) != 1) {
        perror("Failed to read ELF header");
        fclose(file);
        return;
    }

    fclose(file);

    Elf32 hinfo;

    // Check the ELF magic number
    if (header.e_ident[0] == 0x7f && header.e_ident[1] == 'E' &&
        header.e_ident[2] == 'L' && header.e_ident[3] == 'F') {
        strncpy(hinfo.filepath, filepath, sizeof(hinfo.filepath));
        snprintf(hinfo.e_entry, sizeof(hinfo.e_entry), "0x%x", header.e_entry);
        snprintf(hinfo.e_phoff, sizeof(hinfo.e_phoff), "0x%x", header.e_phoff);
        snprintf(hinfo.e_shoff, sizeof(hinfo.e_shoff), "0x%x", header.e_shoff);
    } else {
        printf("❌ Not a valid ELF file: %s\n", filepath);
    }
    decompile(&hinfo);

}


// Function to handle Perl scripts (.pl)
void analyze_perl_script(const char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("Unable to open Perl script");
        return;
    }

    char buffer[256];
    while (fgets(buffer, sizeof(buffer), file)) {
        // Look for suspicious Perl patterns
        if (strstr(buffer, "system") || strstr(buffer, "exec")) {
            printf(" Suspicious Perl command detected: %s\n", buffer);
        }
    }
    fclose(file);
}



// Main function for analyzing files
void analyze_file(const char *filepath) {

    if (strstr(filepath, ".elf")) {
        analyze_elf_header(filepath);
        return;
    }

    if (strstr(filepath, ".bin")) {
        if (is_bin_file(filepath)) {
            printf("Binary file (.bin): %s — No specific signature check.\n", filepath);
            // You can optionally add heuristics here
        }
        return;
    }

    if (strstr(filepath, ".out")) {
        if (is_out_file(filepath)) {
            printf("Output binary file (.out): %s — Treated as raw binary.\n", filepath);
            // Optional: binary structure analysis
        }
        return;
    }

    if (strstr(filepath, ".py")) {
        analyze_python_script(filepath);
        return;
    }

    if (strstr(filepath, ".sh")) {
        analyze_shell_script(filepath);
        return;
    }

    if (strstr(filepath, ".pl")) {
        analyze_perl_script(filepath);
        return;
    }

    printf("Unrecognized or unsupported file type: %s\n", filepath);
}
