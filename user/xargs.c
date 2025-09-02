#include "kernel/types.h"
#include "kernel/param.h"
#include "kernel/stat.h"
#include "user/user.h"

#define MAX_LINE_LENGTH 512

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(2, "usage: xargs <command> [args...]\n");
        exit(1);
    }

    char line[MAX_LINE_LENGTH];
    char *args[MAXARG];
    int n;
    char c;
    int line_index = 0;
    for (int i = 1; i < argc; i++) {
        args[i - 1] = argv[i];
    }
    while ((n = read(0, &c, 1)) > 0) {
        if (c == '\n') {
            if (line_index > 0) {
                line[line_index] = '\0'; 
                args[argc - 1] = line;
                args[argc] = 0; 
                int pid = fork();
                if (pid < 0) {
                    fprintf(2, "xargs: fork failed\n");
                    exit(1);
                }

                if (pid == 0) {
                    exec(args[0], args);
                    fprintf(2, "xargs: exec %s failed\n", args[0]);
                    exit(1);
                } else {
                    wait(0);
                }
                line_index = 0;
            }
        } else {
            if (line_index < MAX_LINE_LENGTH - 1) {
                line[line_index++] = c;
            } else {
                while (read(0, &c, 1) > 0 && c != '\n') {
                }
                fprintf(2, "xargs: line too long, skipping\n");
                line_index = 0;
            }
        }
    }
    if (line_index > 0) {
        line[line_index] = '\0';
        args[argc - 1] = line;
        args[argc] = 0;
        int pid = fork();
        if (pid < 0) {
            fprintf(2, "xargs: fork failed\n");
            exit(1);
        }
        if (pid == 0) {
            exec(args[0], args);
            fprintf(2, "xargs: exec %s failed\n", args[0]);
            exit(1);
        } else {
            wait(0);
        }
    }
    exit(0);
}
