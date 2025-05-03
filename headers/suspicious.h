#ifndef SUSPICIOUS_H
#define SUSPICIOUS_H

extern int suspend_suspicious_processes;
extern const char *suspicious_extensions[];

int is_suspicious_command(const char *cmd);

int has_suspicious_extension(const char *cmd);
#endif // SUSPICIOUS_H

