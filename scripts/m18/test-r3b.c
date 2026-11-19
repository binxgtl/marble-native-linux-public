#define _GNU_SOURCE
#include "shutdown-trace.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void task(int pid, const char *comm, char state, unsigned flags)
{
    char dir[16], path[32];
    snprintf(dir, sizeof dir, "%d", pid);
    assert(mkdir(dir, 0700) == 0);
    snprintf(path, sizeof path, "%s/stat", dir);
    FILE *file = fopen(path, "w");
    assert(file);
    assert(fprintf(file, "%d (%s) %c 1 2 3 4 5 %u 0 0\n", pid, comm, state, flags) > 0);
    assert(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    assert(argc == 2 && chdir(argv[1]) == 0);
    task(1, "pid-one", 'S', 0);
    task(2, "worker )\nname", 'D', 0);
    task(3, "kernel", 'I', 0x00200000u);
    task(4, "spinner", 'S', 0);
    task(5, "zombie", 'Z', 0);
    assert(mkdir("6", 0700) == 0); /* exited between readdir and open */
    assert(m18_shutdown_snapshot(".", "shutdown.log", 4) == 0);
    FILE *file = fopen("shutdown.log", "r");
    assert(file);
    char line[256];
    assert(fgets(line, sizeof line, file));
    assert(strstr(line, "M18 procs count=1 skipped=1 limited=0 error=0 2:D:worker___name\n"));
    assert(!fgets(line, sizeof line, file));
    assert(fclose(file) == 0);
    struct stat st;
    assert(stat("shutdown.log", &st) == 0 && (st.st_mode & 0777) == 0600);
    assert(symlink("shutdown.log", "link") == 0);
    assert(m18_shutdown_snapshot(".", "link", 4) < 0);
    assert(m18_shutdown_snapshot("missing", "shutdown.log", 4) < 0);
    return 0;
}
