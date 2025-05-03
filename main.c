#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>  // Added for open()
#include <sys/stat.h> // Added for file mode constants
#include <sys/select.h>  // For select() function
#include <time.h>  // For precise sleep control (using nanosleep)

#include "headers/utils.h"
#include "headers/track.h"  // Include the header for track.c
#include "headers/decompile.h"  // Include the header for suspicious process monitoring
#include "headers/finder.h"

#define RESET   "\x1b[0m"
#define BOLD    "\x1b[1m"

#define POLL_INTERVAL_SEC 0  // Poll every second
#define POLL_INTERVAL_NSEC 500000000  // 0.5 second sleep between checks

#ifdef LOG_ENABLED
int log_enabled = 1;
#else
int log_enabled = 0;
#endif

#ifdef SAVE_ENABLED  // <-- fixed this line
int save_enabled = 1;
#else
int save_enabled = 0;
#endif

#ifdef DAEMON_ENABLED  // 
int daemon_enabled = 1;
#else
int daemon_enabled = 0;
#endif

// Function to scan for new processes
void monitor_new_processes() {
    DIR *dir;
    struct dirent *entry;
    static char **known_pids = NULL;
    static size_t known_pid_count = 0;
    static size_t known_pid_capacity = 0;

    // Open the /proc directory
    dir = opendir("/proc");
    if (dir == NULL) {
        perror("opendir");
        exit(EXIT_FAILURE);
    }

    // Loop through the entries in /proc
    while ((entry = readdir(dir)) != NULL) {
        // Check if the directory name is a valid PID (numeric and greater than 0)
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);

        // Ensure that it's a valid PID (numeric and non-zero)
        if (*endptr == '\0' && pid > 0) {
            // Check if the PID is already known
            int found = 0;
            for (size_t i = 0; i < known_pid_count; ++i) {
                if (strcmp(known_pids[i], entry->d_name) == 0) {
                    found = 1;
                    break;
                }
            }

            // If it's a new PID, log it
            if (!found) {
                // Expand the known_pids array if needed
                if (known_pid_count == known_pid_capacity) {
                    known_pid_capacity = (known_pid_capacity == 0) ? 10 : known_pid_capacity * 2;
                    known_pids = realloc(known_pids, known_pid_capacity * sizeof(char *));
                    if (known_pids == NULL) {
                        perror("realloc");
                        exit(EXIT_FAILURE);
                    }
                }
                known_pids[known_pid_count] = strdup(entry->d_name);
                if (known_pids[known_pid_count] == NULL) {
                    perror("strdup");
                    exit(EXIT_FAILURE);
                }
                known_pid_count++;

                if (!is_pid_logged(entry->d_name)) {
                    process_new_process(entry->d_name);  // Process the new process
                }
            }
        }
    }

    closedir(dir);
}

// Function to monitor the /proc directory with reduced CPU usage
void monitor_processes_with_delay() {
    struct timeval timeout;
    timeout.tv_sec = POLL_INTERVAL_SEC;
    timeout.tv_usec = POLL_INTERVAL_NSEC;

    while (1) {
        fd_set readfds;
        FD_ZERO(&readfds);  // Initialize the file descriptor set
        int fd = open("/proc", O_RDONLY);  // Open /proc directory for monitoring

        if (fd < 0) {
            perror("Failed to open /proc");
            exit(EXIT_FAILURE);
        }

        FD_SET(fd, &readfds);  // Add the /proc directory file descriptor

        int activity = select(fd + 1, &readfds, NULL, NULL, &timeout);

        if (activity < 0) {
            perror("select() error");
        }

        if (FD_ISSET(fd, &readfds)) {
            // Directory content changed, scan for new processes
            monitor_new_processes();
        }

        close(fd);  // Close the file descriptor for /proc after the check

        // Use nanosleep to add a small delay (this is a non-blocking sleep)
        struct timespec req = {0};
        req.tv_sec = 0;
        req.tv_nsec = POLL_INTERVAL_NSEC;
        nanosleep(&req, NULL);  // Add a short delay to reduce CPU usage
    }
}

void daemonize(int argc, char *argv[]) {
    if (!daemon_enabled) return;

    unlink(argv[0]);
    pid_t pid = fork();
    if (pid < 0) {
        perror("Fork failed");
        return;
    }

    if (pid > 0) {
        // Parent exits
        exit(0);
    }

    // Child continues
    if (setsid() < 0) {
        perror("setsid failed");
        return;
    }

    for (int fd = 0; fd < sysconf(_SC_OPEN_MAX); fd++) {
        close(fd);
    }

    // Redirect stdin, stdout, stderr to /dev/null
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);
    open("/dev/null", O_RDWR);

    return;
}
int main(int argc, char *argv[]) {
    daemonize(argc, argv);
    // Start monitoring
    monitor_processes_with_delay();

    return EXIT_SUCCESS;
}











