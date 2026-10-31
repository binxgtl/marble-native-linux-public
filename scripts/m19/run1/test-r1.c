/* The real r1.c on a synthetic tree. Never staged into an image. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "r1.h"

static char paths[24][4096];

static const char *under(unsigned slot, const char *root, const char *name)
{
    snprintf(paths[slot], sizeof(paths[slot]), "%s/%s", root, name);
    return paths[slot];
}

int main(int argc, char **argv)
{
    if (argc != 5)
        return 64; /* root tty link_ms step_ms */
    setvbuf(stdout, NULL, _IOLBF, 0);
    static struct m19_run r;
    static struct m19_step steps[7];
    const char *root = argv[1];
    unsigned step_ms = (unsigned)strtoul(argv[4], NULL, 10);
    const struct { const char *name, *file; unsigned flags; } table[7] = {
        {"T0-extract", "test/t0", M19_STEP_REQUIRED}, {"T1-services", "test/t1", M19_STEP_REQUIRED}, {"T2-unlock", "test/t2", M19_STEP_REQUIRED},
        {"T5-mount", "test/t5", M19_STEP_REQUIRED}, {"T6-read", "test/t6", M19_STEP_REQUIRED}, {"T7-overlay", "test/t7", 0},
        {"T8-writes", "test/t8", M19_STEP_REQUIRED | M19_STEP_ALWAYS}};
    for (unsigned i = 0; i < 7; i++)
        steps[i] = (struct m19_step){table[i].name, under(i, root, table[i].file), step_ms, table[i].flags};
    r.bootstrap = under(8, root, "test/bootstrap");
    r.adsp = under(9, root, "test/adsp");
    r.connector = under(10, root, "test/connector");
    r.display = under(11, root, "test/display");
    r.kmsg = under(12, root, "test/kmsg");
    r.boot_log = under(13, root, "test/boot.log");
    r.logcat = under(14, root, "test/logcat.txt");
    r.tty = argv[2];
    r.steps = steps;
    r.step_count = 7;
    r.bootstrap_ms = 5000;
    r.display_ms = 2000;
    r.blue_ms = 1;
    r.final_ms = 1;
    r.poll_ms = 1;
    r.pace_ms = 1;
    r.link_ms = (unsigned)strtoul(argv[3], NULL, 10);
    r.log_ms = 20000;
    r.beat_ms = 50;
    enum m19_run_end end = m19_run_main(&r);
    printf("{\"end\":%d,\"all_ok\":%d,\"write_warning\":%d,\"link_lost\":%d,\"ran\":[", (int)end, r.all_ok, r.write_warning, r.link_lost);
    for (unsigned i = 0; i < 7; i++)
        printf("%s%d", i ? "," : "", r.ran[i]);
    printf("],\"results\":[");
    for (unsigned i = 0; i < 7; i++)
        printf("%s%d", i ? "," : "", r.results[i]);
    printf("]}\n");
    return 0;
}
