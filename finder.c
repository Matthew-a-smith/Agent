#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#include "headers/finder.h"
#include "headers/utils.h"
#include "headers/process_info.h"
#include "headers/binarys.h"

#define MAX_PIDS 100        // Max suspicious PIDs to track
#define MAX_CONNECTIONS 100 // Max connections to track

int suspicious_pids[MAX_PIDS];
int pid_count = 0;

int seen_connections[MAX_CONNECTIONS]; // Track which connections have been listed
int connection_count = 0;

void handle_suspicious_connection(const ConnectionInfo *c);

// Check if a PID is in the suspicious list
int is_suspicious_pid(int pid)
{
    for (int i = 0; i < pid_count; i++)
    {
        if (suspicious_pids[i] == pid)
        {
            return 1;
        }
    }
    return 0;
}

// Check if the connection is already seen
int is_connection_seen(int local_port, const char *remote_addr, int remote_port)
{
    for (int i = 0; i < connection_count; i++)
    {
        if (seen_connections[i] == (local_port << 16 | remote_port))
        {
            return 1; // Already seen
        }
    }
    return 0; // Not seen
}

// Add a connection to the seen list
void add_connection_to_seen(int local_port, const char *remote_addr, int remote_port)
{
    if (connection_count < MAX_CONNECTIONS)
    {
        seen_connections[connection_count++] = (local_port << 16 | remote_port);
    }
}


// #define INTERCEPT_MESSAGE "echo '[!] Connection intercepted by security monitor.'\n"
// void send_message(const char *remote_addr, int remote_port)
// {
//     int sock;
//     struct sockaddr_in attacker_addr;
// 
//     // Create a TCP socket
//     if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
//     {
//         perror("Socket creation failed");
//         return;
//     }
// 
//     // Configure attacker's address
//     attacker_addr.sin_family = AF_INET;
//     attacker_addr.sin_port = htons(remote_port);
//     if (inet_pton(AF_INET, remote_addr, &attacker_addr.sin_addr) <= 0)
//     {
//         perror("Invalid attacker address");
//         close(sock);
//         return;
//     }
// 
//     // Connect to the attacker's session
//     if (connect(sock, (struct sockaddr *)&attacker_addr, sizeof(attacker_addr)) < 0)
//     {
//         perror("Connection to attacker failed (they may have closed the shell)");
//         close(sock);
//         return;
//     }
// 
//     // Send the message without terminating their session
//     send(sock, INTERCEPT_MESSAGE, strlen(INTERCEPT_MESSAGE), 0);
//     printf("🔴 Sent interception message to attacker at %s:%d\n", remote_addr, remote_port);
// 
//     sleep(2); // Ensure message is delivered before closing
//     close(sock);
// }

int check_connections_for_pid(int pid, const char *start_time) {
    FILE *cmd = popen("netstat -antp 2>/dev/null", "r");
    if (!cmd) {
        perror("Failed to execute netstat");
        return 0; // Return 0 to indicate failure
    }

    char line[512];
    fgets(line, sizeof(line), cmd); // Skip the header line

    while (fgets(line, sizeof(line), cmd)) {
        char proto[10], local_addr[50], remote_addr[50], state[20], pid_info[50];
        int local_port, remote_port;
        int current_pid = -1;

        // Parse the connection details from the line
        if (sscanf(line, "%s %*d %*d %[^:]:%d %[^:]:%d %s %s", 
                   proto, local_addr, &local_port, remote_addr, &remote_port, state, pid_info) < 6) {
            continue;
        }

        // Extract the PID
        sscanf(pid_info, "%d/", &current_pid);

        // If this connection belongs to the specified PID, log it
        if (current_pid == pid) {
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
            pclose(cmd);
            return 1;
        }
    }

    pclose(cmd);
    return 0; // No connections found for this PID, return 0
}




