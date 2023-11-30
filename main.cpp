#include <cstddef>
#include <limits.h>
#include <unistd.h>

#include <cassert>
#include <cstdlib>
#include <cstring>

#include <iostream>
#include <string>
#include <string_view>

static std::string_view s_output_file;

inline void print_usage(const char * arg0) {
    std::cerr << "Usage: " << arg0 << " [-o <output-file>] -- <command> [<args>...]\n";
}

inline int parse_args(int argc, char * argv[]) {
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


inline const char * get_cmdline(int argc, char * argv[], int i, const char * extra_args = nullptr) {
    static char buff[PATH_MAX];
    auto p = buff;
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
}

inline const char * get_abs_path(const char * filename) {
    static char buff[PATH_MAX];
    realpath(filename, buff);
    return buff;
}

inline const char * get_make_cc_cxx_args(const char * arg0) {
    static char buff[PATH_MAX];
    auto const abs_arg0 = get_abs_path(arg0);
    auto const err = snprintf(buff, sizeof buff, "CC=\"%s gcc\" CXX=\"%s g++\"", abs_arg0, abs_arg0);
    assert(0 < err && static_cast<size_t>(err) < sizeof buff);
    return buff;
}

static void do_make(const char * prog, int argc, char * argv[]) {
    auto const cmdline = static_cast<char **>(alloca((argc + 2) * sizeof(char *)));
    for (int j = 0; j < argc; ++j) {
        cmdline[j] = argv[j];
    }
    cmdline[argc] = strdupa(get_make_cc_cxx_args(prog));
    cmdline[argc + 1] = nullptr;

    // 构造 unix domain socket 路径
    char socket_path[PATH_MAX];
    auto const err = snprintf(socket_path, sizeof socket_path, "/tmp/sbeare-%u.sock", getpid());
    assert(0 < err && static_cast<size_t>(sizeof socket_path));

    // 将 unix domain socket 的路径保存到环境变量中
    if (setenv("SBEARE_SOCKET_PATH", socket_path, 1) != 0) {
        perror("setenv");
        exit(EXIT_FAILURE);
    }

    auto const pid = fork();
    if (pid == 0) {
        execvp("make", cmdline);
    } else {
        // TODO: 监听 unix domain socket

        // TODO: 等待 make 进程退出
    }
}

static void do_compile(int argc, char * argv[]) {

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