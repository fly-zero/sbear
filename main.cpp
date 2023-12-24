#include <bits/types/sigset_t.h>
#include <cerrno>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <cassert>
#include <cstddef>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <fstream>
#include <string>
#include <string_view>
#include <tuple>

static std::string_view s_output_file;
static char s_buffer[PATH_MAX];
static bool s_running = true;
static bool s_first_message = true;
static std::ofstream s_ofs;

static void * varint_encode(void * dst, uint64_t value) {
    auto p = static_cast<uint8_t *>(dst);
    while (value >= 0x80) {
        *p++ = static_cast<uint8_t>(value) | 0x80;
        value >>= 7;
    }

    *p++ = static_cast<uint8_t>(value);
    return p;
}

static void * varint_decode(void * src, uint64_t & value) {
    auto p = static_cast<uint8_t *>(src);
    value = 0;
    for (int shift = 0; shift < 64; shift += 7) {
        uint64_t const byte = *p++;
        value |= (byte & 0x7f) << shift;
        if ((byte & 0x80) == 0) {
            break;
        }
    }

    return p;
}

inline void print_usage(const char * arg0) {
    std::cerr << "Usage: " << arg0 << " [-o <output-file>] -- <command> [<args>...]\n";
}

inline int parse_args(int argc, char * argv[]) {
    // 如果 argv[0] 是以 "-gcc" 或 "-g++" 结尾的，那么就认为是 gcc 或 g++ 的别名
    auto const arg0 = std::string_view{argv[0]};
    if (arg0.ends_with("-gcc")) {
        argv[0] += arg0.size() - 3;
        return 0;
    } else if (arg0.ends_with("-g++")) {
        argv[0] += arg0.size() - 3;
        return 0;
    } else {
        int i = 1;
        while (true) {
            if (argv[i] == std::string_view{"-o"} && i + 1 < argc) {
                s_output_file = argv[i + 1];
                i += 2;
            } else if (argv[i] == std::string_view{"--"}) {
                ++i;
                break;
            } else {
                std::cerr << "Unknown argument: " << argv[i] << std::endl;
                goto error;
            }
        }

        if (i >= argc) {
            std::cerr << "No command given" << std::endl;
            goto error;
        }

        return i;
    }

error:
    print_usage(argv[0]);
    exit(EXIT_FAILURE);
}

inline bool is_compile_tool(std::string_view command) {
    std::string_view available_commands[]{
        "gcc", "g++", "clang", "clang++", "cc", "c++"};

    auto const pred = [command](std::string_view available_command) {
        return command == available_command;
    };

    auto const first = std::begin(available_commands);
    auto const last = std::end(available_commands);
    return std::any_of(first, last, pred);
}

inline char * get_cmdline(int argc, char * argv[], int i, const char * extra_args = nullptr) {
    auto p = s_buffer;
    for (; i < argc; ++i) {
        auto const arg = argv[i];
        auto const len = strlen(arg);
        memcpy(p, arg, len);
        p += len;
        *p++ = ' ';
    }

    if (extra_args) {
        auto const len = strlen(extra_args);
        memcpy(p, extra_args, len);
        p += len;
    }

    *p = '\0';
    return s_buffer;
}

inline const char * get_abs_path(const char * filename) {
    realpath(filename, s_buffer);
    return s_buffer;
}

inline const char * get_make_compiler_env_str(const char * name, const char * prefix, const char * exe) {
    auto const err = snprintf(s_buffer, sizeof s_buffer, "%s=%s-%s", name, prefix, exe);
    assert(0 < err && static_cast<size_t>(err) < sizeof s_buffer);
    return s_buffer;
}

inline int listen_unix_socket(const char * path) {
    // 创建 unix domain socket
    auto const fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);

    // 绑定 unix domain socket
    if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) != 0) {
        perror("bind");
        goto cleanup;
    }

    // 设置 unix domain socket 的权限
    if (chmod(path, 0600) != 0) {
        perror("chmod");
        goto cleanup;
    }

    // 设置非阻塞模式
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) != 0) {
        perror("fcntl");
        goto cleanup;
    }

    // 设置 CLOSE_ON_EXEC
    if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) != 0) {
        perror("fcntl");
        goto cleanup;
    }

    return fd;

cleanup:
    if (fd >= 0) {
        close(fd);
    }

    return -1;
}

inline int create_signalfd(int signo) {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, signo);
    int const sigfd = signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sigfd < 0) {
        perror("signalfd");
        return -1;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, signo);
    if (sigprocmask(SIG_BLOCK, &mask, nullptr) != 0) {
        perror("sigprocmask");
        close(sigfd);
        return -1;
    }

    return sigfd;
}

inline void read_unix_socket(int sock) {
    while (true) {
        char buff[8192];
        auto const n = recvfrom(sock, buff, sizeof buff, 0, nullptr, nullptr);
        if (n > 0) {
            auto p = buff;
            uint64_t len;
            p = static_cast<char *>(varint_decode(p, len));
            auto const pwd = std::string_view{p, len};
            p += len;

            p = static_cast<char *>(varint_decode(p, len));
            auto const cmdline = std::string_view{p, len};
            p += len;

            p = static_cast<char *>(varint_decode(p, len));
            auto const input = std::string_view{p, len};
            p += len;

            if (p > buff + n) {
                std::cerr << "Invalid message" << std::endl;
                break;
            }

            if (s_first_message) {
                s_first_message = false;
            } else {
                s_ofs << "," << std::endl;
            }

            s_ofs << "{" << std::endl;
            s_ofs << R"(  "directory": ")" << pwd << R"(",)" << std::endl;
            s_ofs << R"(  "command": ")" << cmdline << R"(",)" << std::endl;
            s_ofs << R"(  "file": ")" << input << R"(")" << std::endl;
            s_ofs << "}";
        } else if (n == 0) {
            break;
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
            break;
        } else {
            perror("recvfrom");
            break;
        }
    }
}

inline void read_signal_fd(int sigfd) {
    struct signalfd_siginfo siginfo;
    auto const n = read(sigfd, &siginfo, sizeof siginfo);
    if (n == sizeof siginfo) {
        s_running = false;
    } else if (n == 0) {
        std::cerr << "signalfd read EOF" << std::endl;
        abort();
    } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
    } else {
        perror("read");
    }
}

inline void do_make(const char * prog, int argc, char * argv[]) {
    auto const cmdline = static_cast<char **>(alloca((argc + 2) * sizeof(char *)));
    for (int j = 0; j < argc; ++j) {
        cmdline[j] = argv[j];
    }

    auto const abs_prog_path = strdupa(get_abs_path(prog));
    cmdline[argc + 0] = strdupa(get_make_compiler_env_str("CC", abs_prog_path, "gcc"));
    cmdline[argc + 1] = strdupa(get_make_compiler_env_str("CXX", abs_prog_path, "g++"));
    cmdline[argc + 2] = nullptr;

    // 构造 unix domain socket 路径
    char socket_path[PATH_MAX];
    auto const err = snprintf(socket_path, sizeof socket_path, "/tmp/sbeare-%u.sock", getpid());
    assert(0 < err && static_cast<size_t>(sizeof socket_path));

    // 将 unix domain socket 的路径保存到环境变量中
    if (setenv("SBEARE_SOCKET_PATH", socket_path, 1) != 0) {
        perror("setenv");
        exit(EXIT_FAILURE);
    }

    // 监听 unix domain socket
    int const sock = listen_unix_socket(socket_path);
    if (sock < 0) {
        return;
    }

    // 为 SIGCHLD 创建描述符
    int const sigfd = create_signalfd(SIGCHLD);
    if (sigfd < 0) {
        return;
    }

    // 打开输出文件
    s_ofs.open(s_output_file.data());
    if (!s_ofs) {
        perror("open");
        return;
    }

    auto const pid = fork();
    if (pid == 0) {
        execvp("make", cmdline);
    } else {
        // 初始化监听集合
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);
        FD_SET(sigfd, &readfds);
        auto const maxfdp1 = std::max(sock, sigfd) + 1;

        s_ofs << "[" << std::endl;

        while (s_running) {
            fd_set tmp = readfds;
            auto const n = select(maxfdp1, &tmp, nullptr, nullptr, nullptr);
            if (n > 0) {
                if (FD_ISSET(sock, &tmp)) {
                    read_unix_socket(sock);
                }
                
                if (FD_ISSET(sigfd, &tmp)) {
                    read_signal_fd(sigfd);
                    break;
                }
            } else if (n == 0) {
                continue;
            } else {
                perror("select");
                break;
            }
        }

        s_ofs << "\n]" << std::endl;
    }
}

inline std::tuple<const char*, const char *> parse_compile_command(int argc, char * argv[]) {

    std::tuple<const char*, const char *> ret;
    const char *input = nullptr, *output = nullptr;
    int i;

    // 找到 gcc 或 g++ 的输出文件
    for (i = 0; i < argc; ++i) {
        auto const arg = argv[i];
        if (arg == std::string_view{"-o"} && i + 1 < argc) {
            break;
        }
    }

    if (i >= argc) {
        return ret;
    }

    output = argv[i + 1];

    // 找到 gcc 或 g++ 的输入文件
    i = 0;
    for (; i < argc; ++i) {
        if (strstr(argv[i], ".c")) {
            break;
        } else if (strstr(argv[i], ".cpp")) {
            break;
        } else if (strstr(argv[i], ".cc")) {
            break;
        } else if (strstr(argv[i], ".cxx")) {
            break;
        } else {
            continue;
        }
    }

    if (i >= argc) {
        return ret;
    }

    input = argv[i];
    ret = std::make_tuple(input, output);
    return ret;
}

void send_message(int sock, std::string_view pwd, std::string_view cmdline, std::string_view input) {
    // 分配足够的空间
    auto const len = 32 + pwd.size() + cmdline.size() + input.size();
    auto const buff = static_cast<char *>(alloca(len));
    auto p = buff;

    // 写入当前工作目录的路径
    p = static_cast<char *>(varint_encode(p, pwd.size()));
    memcpy(p, pwd.data(), pwd.size());
    p += pwd.size();

    // 写入命令行
    p = static_cast<char *>(varint_encode(p, cmdline.size()));
    memcpy(p, cmdline.data(), cmdline.size());
    p += cmdline.size();

    // 写入输入文件的路径
    p = static_cast<char *>(varint_encode(p, input.size()));
    memcpy(p, input.data(), input.size());
    p += input.size();

    // 获取 unix domain socket 的路径
    auto const socket_path = getenv("SBEARE_SOCKET_PATH");
    if (!socket_path) {
        std::cerr << "SBEARE_SOCKET_PATH not set" << std::endl;
        return;
    }

    // 构造 unix domain socket 地址
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_path);

    // 发送消息
    auto const buf_size = p - buff;
    auto const n = sendto(sock,
                          buff,
                          buf_size,
                          0,
                          reinterpret_cast<struct sockaddr *>(&addr),
                          sizeof addr);
    if (n != buf_size) {
        perror("send");
    }
}

inline void do_compile(int argc, char * argv[]) {
    // 解析编译命令
    auto [input, output] = parse_compile_command(argc, argv);
    if (input && output) {
        // 打开 unix domain socket
        auto const sock = socket(AF_UNIX, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("socket");
            return;
        }

        // 发送编译命令
        auto const pwd = strdupa(get_current_dir_name());
        auto const cmdline = strdupa(get_cmdline(argc, argv, 0));
        input = strdupa(get_abs_path(input));
        send_message(sock, pwd, cmdline, input);

        // 关闭 unix domain socket
        close(sock);
    }

    // 执行编译命令
    execvp(argv[0], argv);
}

int main(int argc, char * argv[]) {
    auto const i = parse_args(argc, argv);
    auto const command = std::string_view{argv[i]};

    if (command == "make") {
        do_make(argv[0], argc - i, argv + i);
    } else if (is_compile_tool(command)) {
        do_compile(argc - i, argv + i);
    } else {
        std::cerr << "Unknown command: " << command << std::endl;
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
