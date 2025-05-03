#ifndef PROXY_H
#define PROXY_H

void send_request_to_proxy(const char *request_message);
void run_command_if_requested(const char *command);
void create_directory_if_needed(const char *filepath);
#endif // SUSPICIOUS_H