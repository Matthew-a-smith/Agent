#ifndef FINDER_H
#define FINDER_H

// Declaration of the function to monitor and log suspicious processes
void log_outgoing_connections_for_pid(int target_pid, const char *start_time);
void print_outgoing_connections_for_pid(int target_pid, const char *start_time);
int check_connections_for_pid(int pid, const char *start_time);
void ensure_file_exists(void); 

#endif // SUSPICIOUS_H