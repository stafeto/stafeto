// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Sergey Subbotin <ssubbotin@gmail.com>

// The entry of the dEQP programs of stafeto. The image of a probe fixes the
// arguments of a program when it is built, so the arguments of a batch of
// cases (the case list file, the log file, the options) are lines of a file
// in the image, /etc/deqp.args, one argument a line. This main reads it and
// runs the main of the framework (tcuMain.cpp, whose symbol
// tools/build-deqp.py renames to deqp_main) with those arguments after the
// program name; with no such file the arguments of the program are the ones.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>
#include <vector>

extern "C" int deqp_main(int argc, char **argv);

// The log of the framework (the `qpa` file, --deqp-log-filename) goes to the
// standard output of the program: the image has no file that names the
// console, and a log kept in a file would be lost with a process that dies
// in a case. The program is linked with --wrap=fopen (tests/deqp/build.rs);
// the framework's open of /dev/stdout becomes a stream on a copy of
// descriptor 1, and every other open is the C library's.
extern "C" FILE *__real_fopen(const char *path, const char *mode);

extern "C" FILE *__wrap_fopen(const char *path, const char *mode)
{
    if (strcmp(path, "/dev/stdout") == 0)
    {
        const int copy = dup(1);
        if (copy < 0)
            return nullptr;
        FILE *stream = fdopen(copy, mode);
        if (stream == nullptr)
            close(copy);
        return stream;
    }
    return __real_fopen(path, mode);
}

int main(int argc, char **argv)
{
    std::vector<std::string> lines;
    if (FILE *file = fopen("/etc/deqp.args", "r"))
    {
        std::string line;
        for (int c = fgetc(file); c != EOF; c = fgetc(file))
        {
            if (c == '\n')
            {
                if (!line.empty())
                    lines.push_back(line);
                line.clear();
            }
            else if (c != '\r')
                line.push_back(char(c));
        }
        if (!line.empty())
            lines.push_back(line);
        fclose(file);
    }
    if (lines.empty())
        return deqp_main(argc, argv);
    std::vector<char *> args;
    args.push_back(argc > 0 ? argv[0] : const_cast<char *>("deqp"));
    for (std::string &line : lines)
        args.push_back(&line[0]);
    args.push_back(nullptr);
    return deqp_main(int(args.size() - 1), args.data());
}
