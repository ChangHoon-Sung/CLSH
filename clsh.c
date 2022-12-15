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
#include <regex.h>

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...) fprintf(stderr, "<DEBUG>: %s:%d:%s(): " fmt, \
    __FILE__, __LINE__, __func__, ##args)
#else
#define DEBUG_PRINT(fmt, args...)
#endif

#define RD 0
#define WR 1

#define MAX_HOST 256
#define PIPE_BUFSIZ 4096

extern int optind;

char host[MAX_HOST][FILENAME_MAX];
struct pollfd hostpfds[3][MAX_HOST];
pid_t hostpid[MAX_HOST];
int host_count;

int out_redirected = 0, err_redirected = 0;

volatile sig_atomic_t alive;    // signal 내부에서 쓰기 수행

regex_t input_req_re;
static const char *Q_PATTERN = "[:?][ \n\t\r\f]*$";

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

        execlp("ssh", "ssh", "-tt", hostname, command, (char *) 0);

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
    while ((n = read(fd, buf, BUFSIZ - 1)) > 0) {
        buf[n] = '\0';
        ptr = strtok(buf, sep);
        while (ptr != NULL) {
            if (host_count > MAX_HOST) {
                fprintf(stderr, "Too many hosts");
                exit(EXIT_FAILURE);
            }
            strncpy(host[host_count++], ptr, strlen(ptr));
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
        strncpy(host[host_count++], ptr, strlen(ptr));
        ptr = strtok(NULL, sep);
    }
}

void open_redirection(const int STD_FD, char redirection_path[][PATH_MAX], int redirection_fd[][MAX_HOST],
                      const char *ext) {
    char buf[PATH_MAX];
    snprintf(buf, PATH_MAX, "mkdir -p %s", redirection_path[STD_FD]);
    if (system(buf) != 0) {
        perror("mkdir");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < host_count; i++) {
        snprintf(buf, PATH_MAX, "%s/%s.%s", redirection_path[STD_FD], host[i], ext);
        if ((redirection_fd[STD_FD][i] = open(buf, O_WRONLY | O_CREAT | O_TRUNC, 0644)) == -1) {
            perror("open output redirections");
            exit(EXIT_FAILURE);
        }
    }
}

void sa_sigchld_handler(int sig) {
    DEBUG_PRINT("SIGCHLD HANDLER\n");
    int status;
    pid_t pid;

    // 중첩된 시그널 처리를 위해 loop 적용
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        DEBUG_PRINT("WAITPID SUCCESS\n");
        if (pid <= 0) break; // 0: 자식이 있지만 아직 종료되지 않음, -1: 종료시킬 자식이 없음
        DEBUG_PRINT("PID TP REAP: %d\n", pid);
        for (int i = 0; i < host_count; i++) {
            DEBUG_PRINT("SIGCHLD ALIVE LOOP i:%d, hostpid[i]: %d, pid: %d\n", i, hostpid[i], pid);
            if (hostpid[i] == pid) {
                DEBUG_PRINT("[%s] pid %d exited with status %d\n", host[i], pid, status);
                --alive;
                DEBUG_PRINT("alive: %d\n", alive);
                break;
            }
        }
    }
}

void sa_sigquit_handler(int sig) {
    DEBUG_PRINT("SIGQUIT HANDLER\n");

//    // 원격지 프로세스 종료를 위한 pty 시그널 키 전송
//    char sq = 0x1c;     // ctrl + \ (SIGQUIT)
//    for (int i = 0; i < host_count; i++) {
//        if (hostpfds[STDIN_FILENO][i].fd != -1) {
//            if (write(hostpfds[STDIN_FILENO][i].fd, &sq, sizeof(char)) < 0) {
//                DEBUG_PRINT("write : %s\n", strerror(errno));
//            }
//        }
//    }

    // 아직 종료되지 않은 자식 프로세스 시그널 전파 시도
    for (int i = 0; i < host_count; i++) {
        if (hostpid[i] != -1) {
            if (kill(hostpid[i], SIGQUIT) == -1) {
                DEBUG_PRINT("kill : %s\n", strerror(errno));
            }
        }
    }
}

ssize_t consume_pipe(int fd, int redirection_fd, FILE *master_fp, int host_no, int redirected) {
    int flag = 0;
    char buf[PIPE_BUFSIZ];
    ssize_t n = 0, total = 0;
    while ((n = read(fd, buf, PIPE_BUFSIZ - 1)) > 0) {
        total += n;
        if (!flag) {
            if (!redirected) {
                fprintf(master_fp, "[%s]\n", host[host_no]);
            }
            flag = 1;
        }
        buf[n] = '\0';

        // naive connection error 처리
        if (strstr(buf, "Timeout") != NULL ||
            strstr(buf, "timed out") != NULL ||
            strstr(buf, "closed by remote host") != NULL ||
            strstr(buf, "refused") != NULL) {
            fprintf(stderr, "[%s]: Connection Error Detected!\n", host[host_no]);
            hostpfds[STDIN_FILENO][host_no].fd = -1;
            raise(SIGQUIT);
            return total;
        }

        if (!redirected) {
            fprintf(master_fp, "%s", buf);
        } else {
            write(redirection_fd, buf, n);
        }

        // naive input pattern matching
        if ((strstr(buf, "Current password:") != NULL ||
             strstr(buf, "[Y/n]") != NULL ||
             strstr(buf, "[y/N]") != NULL ||
             strstr(buf, "y/n") != NULL ||
             strstr(buf, "yes/no") != NULL ||
             strstr(buf, "ENTER") != NULL ||
             strstr(buf, "Geographic area: ") != NULL ||
             strstr(buf, "Time zone: ") != NULL ||
             (regexec(&input_req_re, buf, 0, NULL, 0) == 0))) {

            fprintf(master_fp, "[%s] > ", host[host_no]);
            fflush(master_fp);

            // ssh open 성공 시 stdin은 항상 사용 가능하다고 가정함
            // ssh pseudo-terminal에 key stroke 직접 전송
            // 시그널 등으로 인해 alive 자식 프로세스가 없으면 탈출
            char input;
            while (alive > 0) {
                if (read(STDIN_FILENO, &input, sizeof(char)) < 0) {
                    DEBUG_PRINT("read: %s\n", strerror(errno));
                    if (alive && errno == EINTR)
                        continue;    // read 대기 중 interrupt 발생 시 재시도
                }
                if (alive && write(hostpfds[STDIN_FILENO][host_no].fd, &input, sizeof(char)) < 0) {
                    DEBUG_PRINT("write : %s\n", strerror(errno));
                }
                if (input == '\n') {
                    DEBUG_PRINT("break input loop (newline found)");
                    break;
                }
            }
        }
    }
    if (!redirected && flag) fprintf(master_fp, "\n");

    return total;
}

int main(int argc, char *argv[]) {
    // unbuffered stdin
    setvbuf(stdin, NULL, _IONBF, 0);

    char command[PIPE_BUFSIZ];
    char redirection_path[3][PATH_MAX] = {};
    int redirection_fd[3][MAX_HOST] = {};
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
                out_redirected = 1;
                strncpy(redirection_path[STDOUT_FILENO], optarg, strlen(optarg));
                break;
            case 'e':
                err_redirected = 1;
                strncpy(redirection_path[STDERR_FILENO], optarg, strlen(optarg));
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
            printf("Note: use `%s` from CLSH_FILEHOST environment\n", env);
            get_host_from_file(env, "\n");
        }
    }

    // try .hostfile
    if (host_count < 1) {
        printf("Note: use .hostfile\n");
        get_host_from_file(".hostfile", "\n");
    }

    if (host_count < 1) {
        printf("usage: ./clsh --hostfile <path> <command>\n");
        exit(EXIT_FAILURE);
    }

    // debconf frontend configuration
    DEBUG_PRINT("Origin CMD (argv[optind]) : %s\n", argv[optind]);
    if (strncmp(argv[optind], "sudo", 4) == 0 && strstr(argv[optind], "apt") != NULL) {
        DEBUG_PRINT("sudo detected\n");
        snprintf(command, PIPE_BUFSIZ, "sudo DEBIAN_FRONTEND=readline %s", argv[optind] + 5);
    } else {
        DEBUG_PRINT("sudo not detected\n");
        snprintf(command, PIPE_BUFSIZ, "%s", argv[optind]);
    }
    DEBUG_PRINT("CMD: %s\n", command);

    // shell redirection
    if (!isatty(STDIN_FILENO)) {
        char buf[PIPE_BUFSIZ], temp[PIPE_BUFSIZ];
        ssize_t n;
        if ((n = read(STDIN_FILENO, buf, PIPE_BUFSIZ - 1)) < 0) {
            perror("read stdin");
            exit(EXIT_FAILURE);
        }
        buf[n - 1] = '\0';    // remove last newline
        snprintf(temp, PIPE_BUFSIZ, "echo \"%s\" | %s", buf, command);
        strncpy(command, temp, strlen(temp));
    }

    // assertion
    assert(host_count > 0);
    assert(host[0] != NULL);
    assert(command != NULL);

    // open output file
    if (out_redirected) {
        open_redirection(STDOUT_FILENO, redirection_path, redirection_fd, "out");
    }

    // open error file
    if (err_redirected) {
        open_redirection(STDERR_FILENO, redirection_path, redirection_fd, "err");
    }

    // remote exec with ssh
    for (int i = 0; i < host_count; i++) {
        hostpid[i] = ssh_proc_open(
                host[i],
                command,
                &hostpfds[STDIN_FILENO][i].fd,
                &hostpfds[STDOUT_FILENO][i].fd,
                &hostpfds[STDERR_FILENO][i].fd
        );
    }

    // signal handler
    struct sigaction sa_sigchld, sa_sigterm, sa_sigquit, sa_sigpipe;

    sa_sigchld.sa_handler = sa_sigchld_handler;
    sa_sigchld.sa_flags = SA_NOCLDSTOP;     // 자식의 STOP/CONT가 아닌, 종료에만 관심이 있음
    sigfillset(&sa_sigchld.sa_mask);
    if (sigaction(SIGCHLD, &sa_sigchld, NULL) == -1) {
        perror("sigaction(sigchld)");
        exit(EXIT_FAILURE);
    }

    sa_sigterm.sa_handler = SIG_IGN;    // 자식이 하던 일을 마칠 수 있도록 시그널 무시
    sa_sigterm.sa_flags = 0;
    sigemptyset(&sa_sigterm.sa_mask);
    if (sigaction(SIGTERM, &sa_sigterm, NULL) == -1) {
        perror("sigaction(sigterm)");
        exit(EXIT_FAILURE);
    }

    sa_sigquit.sa_handler = sa_sigquit_handler;
    sa_sigquit.sa_flags = 0;
    sigfillset(&sa_sigquit.sa_mask);    // 모든 시그널 블럭
    if (sigaction(SIGQUIT, &sa_sigquit, NULL) == -1) {
        perror("sigaction(sigquit)");
        exit(EXIT_FAILURE);
    }

    sa_sigpipe.sa_handler = SIG_IGN;
    sa_sigpipe.sa_flags = 0;
    sigemptyset(&sa_sigpipe.sa_mask);
    if (sigaction(SIGPIPE, &sa_sigpipe, NULL) == -1) {
        perror("sigaction(sigpipe)");
        exit(EXIT_FAILURE);
    }

    // set event flags for poll
    for (int i = 0; i < host_count; i++) {
        hostpfds[STDOUT_FILENO][i].events = (POLLIN | POLLHUP);
        hostpfds[STDERR_FILENO][i].events = (POLLIN | POLLHUP);
    }

    // set nonblock flags
    for (int i = 0; i < host_count; i++) {
        if (fcntl(hostpfds[STDOUT_FILENO][i].fd, F_SETFL, O_NONBLOCK) == -1) {
            perror("fcntl");
            raise(SIGQUIT);
        }
        if (fcntl(hostpfds[STDERR_FILENO][i].fd, F_SETFL, O_NONBLOCK) == -1) {
            perror("fcntl");
            raise(SIGQUIT);
        }
    }

    // compile regex (option 4)
    if (regcomp(&input_req_re, Q_PATTERN, REG_EXTENDED) != 0) {
        perror("regcomp");
        exit(EXIT_FAILURE);
    }

    alive = host_count;
    FILE *master_fps[3] = {stdin, stdout, stderr};
    ssize_t n;
    while (alive > 0) {
//        DEBUG_PRINT("alive(%d) loop\n", alive);
        for (int fd_no = 1; fd_no < 3; fd_no++) {
            if (poll(hostpfds[fd_no], (nfds_t) host_count, 100) < 0) {
                // SIGCHLD handler의 SA_RESTART에도 불구하고 poll과 같이 timeout 기능이 있는 syscall은 EINTR을 반환하는 경우가 있음
                if (errno == EINTR) {
                    // perror가 interrupted인 경우 SIGCHLD에 의해 poll이 중단됨
                    // perror가 no child process인 경우 sigchld_handler의 waitpid에서 errno가 넘어온 것.
                    // 두 경우 모두 무시 가능
                    DEBUG_PRINT("poll or waitpid: %s\n", strerror(errno));
                    continue;
                }
            }

            for (int i = 0; i < host_count; i++) {
                if (hostpfds[fd_no][i].revents & POLLHUP) {
                    switch (fd_no) {
                        case STDERR_FILENO:
                            consume_pipe(
                                    hostpfds[STDERR_FILENO][i].fd,
                                    redirection_fd[STDERR_FILENO][i],
                                    master_fps[STDERR_FILENO],
                                    i,
                                    err_redirected
                            );
                            close(hostpfds[STDERR_FILENO][i].fd);
                            hostpfds[STDERR_FILENO][i].fd = -1;
                            if (err_redirected) {
                                close(redirection_fd[STDERR_FILENO][i]);
                            }
                            DEBUG_PRINT("[%s] stderr closed\n", host[i]);
                            break;
                        case STDOUT_FILENO:
                            // print all stdout first
                            consume_pipe(
                                    hostpfds[STDOUT_FILENO][i].fd,
                                    redirection_fd[STDOUT_FILENO][i],
                                    master_fps[STDOUT_FILENO],
                                    i,
                                    out_redirected
                            );
                            fflush(stdout);
                            close(hostpfds[STDOUT_FILENO][i].fd);
                            hostpfds[STDOUT_FILENO][i].fd = -1;
                            if (out_redirected) {
                                close(redirection_fd[STDOUT_FILENO][i]);
                            }
                            DEBUG_PRINT("[%s] stdout closed\n", host[i]);
                            break;
                        default:
                            break;
                    }
                } else if (hostpfds[fd_no][i].revents & POLLIN) {
                    n = consume_pipe(
                            hostpfds[fd_no][i].fd,
                            redirection_fd[fd_no][i],
                            master_fps[fd_no],
                            i,
                            (fd_no == STDOUT_FILENO) ? out_redirected : err_redirected
                    );
                    if (n < 0 && errno != EAGAIN) {
                        perror("read");
                        exit(EXIT_FAILURE);
                    } else if (n == 0) {
                        DEBUG_PRINT(
                                "Note: caught [%s] POLLIN without POLLHUP but returned EOF. (maybe still in running)\n",
                                host[i]);
                    }
                }
            }
        }
    }

    regfree(&input_req_re);
    exit(EXIT_SUCCESS);
}