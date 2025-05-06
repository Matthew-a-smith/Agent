#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "headers/track.h"
#include "headers/utils.h"
#include "headers/decompile.h"
#include "headers/finder.h"
#include "headers/suspicious.h"
#include "headers/process_info.h"

#define MAX_PATH_LEN 500

extern const char *suspicious_extensions[];
void handle_suspicious_process(const ProcessInfo *p);
void handle_file(const File *f);
void handle_normal_process(const NormalInfo *n);

ino_t inode = 0;

int get_process_cwd(const char *pid, char *cwd_path, size_t max_len) {
    char link_path[256];
    snprintf(link_path, sizeof(link_path), "/proc/%s/cwd", pid);
    ssize_t len = readlink(link_path, cwd_path, max_len - 1);
    if (len == -1) {
        perror("Failed to get cwd");
        return -1;
    }
    cwd_path[len] = '\0';
    return 0;
}


const char* get_filename_from_path(const char *src_path) {
    const char *filename = strrchr(src_path, '/');
    return filename ? filename + 1 : src_path;  // If '/' is found, return the part after it; else return the original path
}

void delete_file_if_exists(const char *filepath) {
    if (filepath && access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            perror("Failed to delete file");
        } else {
            printf("Deleted file: %s\n", filepath);
        }
    }
}

void copy_file_to_tmp_location(const char *src_path, char *saved_file, size_t saved_file_len) {
    if (!save_enabled) return;

    const char *filename = get_filename_from_path(src_path);

    char copy_path[MAX_PATH_LEN];
    snprintf(copy_path, sizeof(copy_path), "/tmp/%s", filename);

    FILE *src_file = fopen(src_path, "rb");
    if (src_file == NULL) {
        perror("Failed to open source file");
        return;
    }

    FILE *copy_file = fopen(copy_path, "wb");
    if (copy_file == NULL) {
        perror("Failed to create copy file");
        fclose(src_file);
        return;
    }

    char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes_read, copy_file);
    }

    fclose(copy_file);
    fclose(src_file);

    // Compress using gzip
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), "gzip -f '%s'", copy_path);  // quotes handle spaces
    int ret = system(cmd);
    if (ret != 0) {
        fprintf(stderr, "Failed to compress file\n");
        return;
    }

    // Generate gz_path safely
    char gz_path[MAX_PATH_LEN + 4];  // Enough for ".gz"
    snprintf(gz_path, sizeof(gz_path), "%s.gz", copy_path);

    printf("Compressed file saved to %s\n", gz_path);

    strncpy(saved_file, gz_path, saved_file_len);
    saved_file[saved_file_len - 1] = '\0';
}

void extract_source_path_from_cmd(
    const char *cmd,
    const char *cwd_path,
    char *out_path,
    size_t max_len,
    char *out_cmd,
    size_t cmd_max_len
) {
    char temp[2048];
    strncpy(temp, cmd, sizeof(temp));
    temp[sizeof(temp) - 1] = '\0';

    if (out_cmd != NULL) {
        strncpy(out_cmd, cmd, cmd_max_len);
        out_cmd[cmd_max_len - 1] = '\0';
    }

    char *token = strtok(temp, " \t");
    while (token != NULL) {
        if (token[0] == '"' || token[0] == '\'') {
            size_t len = strlen(token);
            if (token[len - 1] == token[0]) {
                token[len - 1] = '\0';
                token++;
            }
        }

        for (int i = 0; suspicious_extensions[i] != NULL; i++) {
            size_t len_token = strlen(token);
            size_t len_ext = strlen(suspicious_extensions[i]);

            if (len_token >= len_ext &&
                strcmp(token + len_token - len_ext, suspicious_extensions[i]) == 0) {

                // Resolve full path
                if (token[0] == '/') {
                    // Already absolute
                    strncpy(out_path, token, max_len);
                } else {
                    // Relative, prepend cwd
                    snprintf(out_path, max_len, "%s/%s", cwd_path, token);
                }

                out_path[max_len - 1] = '\0';
                return;
            }
        }

        token = strtok(NULL, " \t");
    }

    strncpy(out_path, "[NoneFound]", max_len);
    out_path[max_len - 1] = '\0';

    if (out_cmd != NULL) {
        strncpy(out_cmd, "[NoneFound]", cmd_max_len);
        out_cmd[cmd_max_len - 1] = '\0';
    }
}



void process_new_process(const char *pid) {
    char path[512], exe[512] = "[Unknown]", cmd[2048] = "[Unknown]";
    char proc_name[256] = "[Unknown]", checksum[65] = "UNKNOWN";
    char user[64] = "[Unknown]", mem[32] = "[Unknown]", ppid[16] = "[Unknown]";
    char start_time[64] = "UNKNOWN", src_path[512] = "[Unknown]";
    char src_sum[65] = "UNKNOWN", saved_file[2048] = "[Unknown]";
    char cwd_path[512] = "[Unknown]";
    struct passwd *pw;
    FILE *fp;
    int uid = -1, pid_sum = atoi(pid);

    if (is_pid_logged(pid)) return;

    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    fp = fopen(path, "r");
    if (fp) {
        fscanf(fp, "%255s", proc_name);
        fclose(fp);
    }

    if (strstr(proc_name, "kworker") || strstr(proc_name, "sed") || strstr(proc_name, "tr"))
        return;

    snprintf(path, sizeof(path), "/proc/%s/exe", pid);
    ssize_t len = readlink(path, exe, sizeof(exe) - 1);
    if (len != -1) {
        exe[len] = '\0';
        compute_sha256(exe, checksum);

        struct stat st;
        if (stat(exe, &st) == 0) {
            inode = st.st_ino;
        }
    }

    if (strcmp(exe, "[Unknown]") == 0) {
        snprintf(path, sizeof(path), "/proc/%s/maps", pid);
        fp = fopen(path, "r");
        if (fp) {
            char line[1024];
            if (fgets(line, sizeof(line), fp)) {
                char *first_path = strchr(line, '/');
                if (first_path) {
                    strncpy(exe, first_path, sizeof(exe) - 1);
                    trim_newline(exe);
                }
            }
            fclose(fp);
        }
    }

    if (strcmp(exe, "[Unknown]") == 0) {
        snprintf(exe, sizeof(exe), "[ExeNotFound]");
    }

    snprintf(path, sizeof(path), "/proc/%s/cmdline", pid);
    fp = fopen(path, "r");
    if (fp) {
        size_t read_len = fread(cmd, 1, sizeof(cmd) - 1, fp);
        fclose(fp);
        for (size_t i = 0; i < read_len; i++) {
            if (cmd[i] == '\0') cmd[i] = ' ';
        }
        cmd[read_len] = '\0';
    }

    snprintf(path, sizeof(path), "/proc/%s/status", pid);
    fp = fopen(path, "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "Uid:", 4) == 0) {
                sscanf(line, "Uid: %d", &uid);
                pw = getpwuid(uid);
                if (pw) strcpy(user, pw->pw_name);
            }
            if (strncmp(line, "VmRSS:", 6) == 0) {
                char *value = strchr(line, ':');
                if (value) {
                    value++;
                    while (*value == ' ' || *value == '\t') value++;
                    strncpy(mem, value, sizeof(mem) - 1);
                    trim_newline(mem);
                }
            }
        }
        fclose(fp);
    }

    snprintf(path, sizeof(path), "/proc/%s/stat", pid);
    fp = fopen(path, "r");
    if (fp) {
        long long start_ticks;
        int dummy;
        char comm[256], state;

        fscanf(fp, "%d %s %c %s", &dummy, comm, &state, ppid);
        for (int i = 5; i < 22; i++) fscanf(fp, "%*s");
        fscanf(fp, "%lld", &start_ticks);
        snprintf(start_time, sizeof(start_time), "%lld", start_ticks);
        fclose(fp);
    }

    if (is_from_blocked_directory(exe)) return;

    int connected = check_connections_for_pid(pid_sum, start_time);

    get_process_cwd(pid, cwd_path, sizeof(cwd_path));

    extract_source_path_from_cmd(cmd, cwd_path, src_path, sizeof(src_path), saved_file, sizeof(saved_file));
    compute_sha256(src_path, src_sum);

    if (is_known_src_path_and_sum(src_path, src_sum)) return;

    if (connected || is_suspicious_command(cmd) || has_suspicious_extension(cmd)) {
        ProcessInfo pinfo = {0};
        strncpy(pinfo.pid, pid, sizeof(pinfo.pid));
        strncpy(pinfo.proc_name, proc_name, sizeof(pinfo.proc_name));
        strncpy(pinfo.cmd, cmd, sizeof(pinfo.cmd));
        strncpy(pinfo.user, user, sizeof(pinfo.user));
        strncpy(pinfo.ppid, ppid, sizeof(pinfo.ppid));
        strncpy(pinfo.mem, mem, sizeof(pinfo.mem));
        strncpy(pinfo.src_path, src_path, sizeof(pinfo.src_path));
        strncpy(pinfo.src_sum, src_sum, sizeof(pinfo.src_sum));
        strncpy(pinfo.exe, exe, sizeof(pinfo.exe));
        strncpy(pinfo.checksum, checksum, sizeof(pinfo.checksum));
        strncpy(pinfo.start_time, start_time, sizeof(pinfo.start_time));

        handle_suspicious_process(&pinfo);

        if (suspend_suspicious_processes) {
            pid_t suspicious_pid = (pid_t)atoi(pid);
            if (kill(suspicious_pid, SIGKILL) != 0) {
                perror("Failed to suspend process");
            }
        }

        if (has_suspicious_extension(cmd)) {
            analyze_file(src_path);
        }

        if (strcmp(src_path, "[NoneFound]") != 0) {
            copy_file_to_tmp_location(src_path, saved_file, sizeof(saved_file));
            File finfo = {0};
            strncpy(finfo.saved_file, saved_file, sizeof(finfo.saved_file));
            handle_file(&finfo);
        }
        //delete_file_if_exists(src_path);
        return;
    }

    if (print_unknown_process(pid, proc_name, cmd, user, user, ppid, mem, exe, checksum, start_time, src_path, src_sum)) {
        NormalInfo ninfo = {0};
        strncpy(ninfo.pid, pid, sizeof(ninfo.pid));
        strncpy(ninfo.proc_name, proc_name, sizeof(ninfo.proc_name));
        strncpy(ninfo.cmd, cmd, sizeof(ninfo.cmd));
        strncpy(ninfo.user, user, sizeof(ninfo.user));
        strncpy(ninfo.ppid, ppid, sizeof(ninfo.ppid));
        strncpy(ninfo.mem, mem, sizeof(ninfo.mem));
        strncpy(ninfo.exe, exe, sizeof(ninfo.exe));
        strncpy(ninfo.checksum, checksum, sizeof(ninfo.checksum));
        strncpy(ninfo.start_time, start_time, sizeof(ninfo.start_time));
        handle_normal_process(&ninfo);
    }

    add_logged_pid(pid);
    add_logged_checksum(checksum);
}



