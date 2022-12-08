#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <poll.h>
#include <signal.h>

#define RD 0
#define WR 1

#define MAX_HOST 256
#define PIPE_BUFSIZ 4096

extern int optind;

char *host[MAX_HOST], *hostfile, *ptr;
pid_t hostpid[MAX_HOST];

int host_count;

pid_t ssh_proc_open(char *host, char *command, int *to, int *from, int *err) {
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

        execlp("ssh", "ssh", host, command, (char *) 0);

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

int main(int argc, char *argv[]) {
    char *command;
    int c;

    // get hostname from args
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
                {"hostfile", required_argument, NULL, 'f'}
        };

        c = getopt_long(argc, argv, "h:f:", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
            case 'f':
                hostfile = optarg;
                int fd = open(hostfile, O_RDONLY);
                if (fd == -1) {
                    perror("open hostfile");
                    exit(EXIT_FAILURE);
                }

                char buf[BUFSIZ];
                ssize_t n;
                while ((n = read(fd, buf, BUFSIZ)) > 0) {
                    buf[n] = '\0';
                    ptr = strtok(buf, "\n");
                    while (ptr != NULL) {
                        if (host_count > MAX_HOST) {
                            fprintf(stderr, "Too many hosts");
                            exit(EXIT_FAILURE);
                        }
                        host[host_count++] = ptr;
                        ptr = strtok(NULL, "\n");
                    }
                }
                break;
            case 'h':
                ptr = strtok(optarg, " ,");
                while (ptr) {
                    if (host_count > MAX_HOST) {
                        fprintf(stderr, "Too many hosts");
                        exit(EXIT_FAILURE);
                    }
                    host[host_count++] = ptr;
                    ptr = strtok(NULL, " ,");
                }
                break;
            default:    // '?' invalid option
                exit(EXIT_FAILURE);
        }
    }

    char *env;

    // try CLSH_HOSTS
    if (host_count < 1) {
        if ((env = getenv("CLSH_HOSTS")) != NULL) {
            ptr = strtok(env, ":");
            while (ptr != NULL) {
                if (host_count > MAX_HOST) {
                    fprintf(stderr, "Too many hosts");
                    exit(EXIT_FAILURE);
                }
                host[host_count++] = ptr;
                ptr = strtok(NULL, "\n");
            }
        }
    }

    // try CLSH_HOSTFILE
    if (host_count < 1) {
        if ((env = getenv("CLSH_HOSTFILE")) != NULL) {
            int fd = open(env, O_RDONLY);
            if (fd == -1) {
                perror("open hostfile");
                exit(EXIT_FAILURE);
            }

            char buf[BUFSIZ];
            ssize_t n;
            while ((n = read(fd, buf, BUFSIZ)) > 0) {
                buf[n] = '\0';
                ptr = strtok(buf, "\n");
                while (ptr != NULL) {
                    if (host_count > MAX_HOST) {
                        fprintf(stderr, "Too many hosts");
                        exit(EXIT_FAILURE);
                    }
                    host[host_count++] = ptr;
                    ptr = strtok(NULL, "\n");
                }
            }
        }
    }

    // try .hostfile
    if (host_count < 1) {
        int fd = open("./.hostfile", O_RDONLY);
        if (fd == -1) {
            perror("open .hostfile");
            exit(EXIT_FAILURE);
        }

        char buf[BUFSIZ];
        ssize_t n;
        while ((n = read(fd, buf, BUFSIZ)) > 0) {
            buf[n] = '\0';
            ptr = strtok(buf, "\n");
            while (ptr != NULL) {
                if (host_count > MAX_HOST) {
                    fprintf(stderr, "Too many hosts");
                    exit(EXIT_FAILURE);
                }
                host[host_count++] = ptr;
                ptr = strtok(NULL, "\n");
            }
        }
    }


    assert(host_count > 0);
    assert(host[0] != NULL);

    // handling child termination with sigaction
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_NOCLDWAIT;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    // get remote command
    command = argv[optind];
    printf("CLSH: {%s}\n", command);

    // make many ssh child
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

    // enroll poll
    for (int i = 0; i < host_count; i++) {
        hostpfds[STDOUT_FILENO][i].events = POLLIN;
        hostpfds[STDERR_FILENO][i].events = POLLIN;
    }

    // master stdin
    struct pollfd command_fd;
    command_fd.fd = STDIN_FILENO;
    command_fd.events = POLLIN;

    int alive = host_count;
    while (alive > 0) {
        // get only stdout and stderr
        for (int std_fd_no = 1; std_fd_no < 3; std_fd_no++) {
            if (poll(hostpfds[std_fd_no], (nfds_t) host_count, -1) < 0) {
                fprintf(stderr, "Couldn't poll host stdout\n");
                exit(EXIT_FAILURE);
            }

            for (int i = 0; i < host_count; i++) {
                if (hostpfds[std_fd_no][i].revents & POLLIN) {
                    char buf[PIPE_BUFSIZ];
                    ssize_t n;
                    while ((n = read(hostpfds[std_fd_no][i].fd, buf, PIPE_BUFSIZ)) > 0) {
                        buf[n] = '\0';
                        printf("%s: %s", host[i], buf);
                    }
                    if (n < 0) {
                        strerror(errno);
                        exit(EXIT_FAILURE);
                    } else if (n == 0) {
                        // 읽힌게 없으면 출력 없이 프로그램 실행 중이거나 pid가 죽거나 둘 중 하나
                        // pid 생존 체크: kill signo 0
                        if (kill(hostpid[i], 0) < 0) {
//                            fprintf(stderr, "pid %d doesn't exists anymore.\n", hostpid[i]);
                            close(hostpfds[STDOUT_FILENO][i].fd);
                            close(hostpfds[STDERR_FILENO][i].fd);
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

    exit(EXIT_SUCCESS);
}