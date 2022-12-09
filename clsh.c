#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>

#define RD 0
#define WR 1

#define MAX_HOST 256
#define PIPE_BUFSIZ 4096

extern int optind;

char *host[MAX_HOST];
pid_t hostpid[MAX_HOST];

int host_count;

pid_t ssh_proc_open(char *hostname, char *command, int *to, int *from, int *err) {
    int to_pipe[2], from_pipe[2], err_pipe[2];
    pid_t pid;

    if (pipe(to_pipe) < 0)
        return -1;

    if (pipe(from_pipe) < 0) {
        close(to_pipe[RD]);
        close(to_pipe[WR]);
        return -1;
    }

    if (pipe(err_pipe) < 0) {
        close(to_pipe[RD]);
        close(to_pipe[WR]);
        close(from_pipe[RD]);
        close(from_pipe[WR]);
        return -1;
    }

    if ((pid = fork()) < 0) {
        perror("pid");
        return -1;
    } else if (pid == 0) {
        close(to_pipe[WR]);
        close(from_pipe[RD]);
        close(err_pipe[RD]);

        dup2(to_pipe[RD], STDIN_FILENO);
        dup2(from_pipe[WR], STDOUT_FILENO);
        dup2(err_pipe[WR], STDERR_FILENO);

        execlp("ssh", "ssh", hostname, command, (char *) 0);

        // Shouldn't be reached
        exit(EXIT_FAILURE);
    }

    close(to_pipe[RD]);
    close(from_pipe[WR]);
    close(err_pipe[WR]);

    *to = to_pipe[WR];
    *from = from_pipe[RD];
    *err = err_pipe[RD];

    return pid;
}

void get_host_from_file(char *path, const char *sep) {
    char *ptr;
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("open hostfile");
        exit(EXIT_FAILURE);
    }

    char buf[BUFSIZ];
    ssize_t n;
    while ((n = read(fd, buf, BUFSIZ)) > 0) {
        buf[n] = '\0';
        ptr = strtok(buf, sep);
        while (ptr != NULL) {
            if (host_count > MAX_HOST) {
                fprintf(stderr, "Too many hosts");
                exit(EXIT_FAILURE);
            }
            host[host_count++] = ptr;
            ptr = strtok(NULL, sep);
        }
    }
    close(fd);
}

void get_host_from_string(char *s, const char *sep) {
    char *ptr = strtok(s, sep);
    while (ptr) {
        if (host_count > MAX_HOST) {
            fprintf(stderr, "Too many hosts");
            exit(EXIT_FAILURE);
        }
        host[host_count++] = ptr;
        ptr = strtok(NULL, sep);
    }
}

void open_output_redirection(const int STD_FD, int out_redirection_fd[][MAX_HOST], char *out_redirection_path[],
                             const char *ext) {
    char buf[PATH_MAX];
    snprintf(buf, PATH_MAX, "mkdir -p %s", out_redirection_path[STD_FD]);
    if (system(buf) != 0) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < host_count; i++) {
        snprintf(buf, PATH_MAX, "%s/%s.%s", out_redirection_path[STD_FD], host[i], ext);
        if ((out_redirection_fd[STD_FD][i] = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
            perror("open output redirections");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char *argv[]) {
    char command[PIPE_BUFSIZ];
    char *opt_redirection_path[3] = {};
    int out_redirection_fd[3][MAX_HOST] = {};
    char *env;
    int c;

    // get hostname from args
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
                {"hostfile", required_argument, NULL, 'f'},
                {"out",      required_argument, NULL, 'o'},
                {"err",      required_argument, NULL, 'e'},
        };

        c = getopt_long(argc, argv, "h:f:o:e:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'f':
                get_host_from_file(optarg, "\n");
                break;
            case 'h':
                get_host_from_string(optarg, " ,");
                break;
            case 'o':
                opt_redirection_path[STDOUT_FILENO] = optarg;
                break;
            case 'e':
                opt_redirection_path[STDERR_FILENO] = optarg;
                break;
            default:    // '?' invalid option
                exit(EXIT_FAILURE);
        }
    }


    // try CLSH_HOSTS
    if (host_count < 1) {
        if ((env = getenv("CLSH_HOSTS")) != NULL) {
            printf("Note: use CLSH_HOSTS environment\n");
            get_host_from_string(env, ":");
        }
    }

    // try CLSH_HOSTFILE
    if (host_count < 1) {
        if ((env = getenv("CLSH_HOSTFILE")) != NULL) {
            printf("Note: use `%s` from CLSH_FILEHOST environment", env);
            get_host_from_file(env, "\n");
        }
    }

    // try .hostfile
    if (host_count < 1) {
        printf("Note: use .hostfile");
        get_host_from_file(".hostfile", "\n");
    }

    if (host_count < 1) {
        printf("usage: ./clsh --hostfile <path> <command>\n");
        exit(EXIT_FAILURE);
    }

    // make command (shell redirection)
    if (isatty(STDIN_FILENO)) {
        strncpy(command, argv[optind], PIPE_BUFSIZ);
    } else {
        char buf[PIPE_BUFSIZ];
        ssize_t n;
        if ((n = read(STDIN_FILENO, buf, PIPE_BUFSIZ - 1)) < 0) {
            perror("read stdin");
            exit(EXIT_FAILURE);
        }
        buf[n - 1] = '\0';    // remove last newline
        snprintf(command, PIPE_BUFSIZ, "echo \"%s\" | %s", buf, argv[optind]);
    }

    // assertion
    assert(host_count > 0);
    assert(host[0] != NULL);
    assert(command != NULL);

    // open output file
    if (opt_redirection_path[STDOUT_FILENO] != NULL) {
        open_output_redirection(STDOUT_FILENO, out_redirection_fd, opt_redirection_path, "out");
    }

    // open error file
    if (opt_redirection_path[STDERR_FILENO] != NULL) {
        open_output_redirection(STDERR_FILENO, out_redirection_fd, opt_redirection_path, "err");
    }

    // handling child termination with sigaction
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // remote exec with ssh
    struct pollfd hostpfds[3][MAX_HOST];
    for (int i = 0; i < host_count; i++) {
        hostpid[i] = ssh_proc_open(
                host[i],
                command,
                &hostpfds[STDIN_FILENO][i].fd,
                &hostpfds[STDOUT_FILENO][i].fd,
                &hostpfds[STDERR_FILENO][i].fd
        );
    }

    // set event flags
    for (int i = 0; i < host_count; i++) {
        hostpfds[STDOUT_FILENO][i].events = POLLIN;
        hostpfds[STDERR_FILENO][i].events = POLLIN;
    }

    // master stdin (option 4)
    struct pollfd command_fd;
    command_fd.fd = STDIN_FILENO;
    command_fd.events = POLLIN;

    int alive = host_count;
    while (alive > 0) {

        // poll stdout and stderr
        for (int fd_no = 1; fd_no < 3; fd_no++) {
            if (poll(hostpfds[fd_no], (nfds_t) host_count, -1) < 0) {
                fprintf(stderr, "Couldn't poll host stdout or stderr.\n");
                exit(EXIT_FAILURE);
            }

            for (int i = 0; i < host_count; i++) {
                if (hostpfds[fd_no][i].revents & POLLIN) {
                    int flag = 0;
                    char buf[PIPE_BUFSIZ];
                    ssize_t n;
                    while ((n = read(hostpfds[fd_no][i].fd, buf, PIPE_BUFSIZ)) > 0) {
                        if (!flag) {
                            if (opt_redirection_path[fd_no] == NULL) {
                                printf("[%s]: ", host[i]);
                            }
                            flag = 1;
                        }
                        buf[n] = '\0';
                        write((opt_redirection_path[fd_no] == NULL ? fd_no : out_redirection_fd[fd_no][i]), buf, n);
                    }
                    if (opt_redirection_path[fd_no] == NULL) printf("\n");

                    // poll 진입 후 한 번도 읽지 못 한 경우, 자식 프로세스 상태 확인
                    if (!flag) {
                        if (n < 0) {
                            strerror(errno);
                            exit(EXIT_FAILURE);
                        } else if (n == 0) {
                            // 프로세스 생존 체크: kill signo 0
                            if (kill(hostpid[i], 0) < 0) {
//                          fprintf(stderr, "pid %d doesn't exists anymore.\n", hostpid[i]);
                                close(hostpfds[STDOUT_FILENO][i].fd);
                                close(hostpfds[STDERR_FILENO][i].fd);
                                close(out_redirection_fd[STDOUT_FILENO][i]);
                                close(out_redirection_fd[STDERR_FILENO][i]);
                                alive--;
                            }
//                        else {
//                            fprintf(stderr, "%s's stdout return EOF. (running)\n", host[i]);
//                        }
                        }
                    }
                }
            }
        }
    }

    exit(EXIT_SUCCESS);
}