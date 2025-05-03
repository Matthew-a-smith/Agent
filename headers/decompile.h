// decompile.h
#ifndef DECOMPILE_H
#define DECOMPILE_H

extern int suspend_suspicious_processes;
extern const char *suspicious_extensions[];

// Declaration of the analyze_elf_header function
void analyze_elf_header(const char *filepath);

void analyze_file(const char *filepath);

int is_suspicious_command(const char *cmd);

int has_suspicious_extension(const char *cmd);
#endif // DECOMPILE_H
