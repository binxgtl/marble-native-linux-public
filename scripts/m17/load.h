/* M17 G5: the modules the native path still needs after the selector (docs/m17-g5.md).
 *
 * The selector loaded its list (/m17/modules.list: the display without the two touch modules, then the keys). M19's
 * bootstrap loads the first 102 rows of its closure (manifests/m19-run4-closure.tsv) and counts 95, 100 and 102. On
 * the native path the closure's rows are loaded in its order, each one the kernel already has skipped, by name and by
 * EEXIST alike, so the touch modules (M7's, from the payload) load with the panel still lit. Afterwards every closure
 * row and every listed module must be loaded, and nothing else: the count is the union's. */
#ifndef M17_LOAD_H
#define M17_LOAD_H

#include <stddef.h>

#define M17_LOAD_ROWS 102u  /* M19's bootstrap closure: phase 0, M8's tail, the heaps */
#define M17_LOAD_TOTAL 104u /* those and the selector's two key-only modules, reboot-mode and qcom-pon */
#define M17_LOAD_MAX 160u

struct m17_load {
    const char *closure;      /* the closure TSV: a header with a "module" column, then one row a module */
    const char *list;         /* the selector's list, one name a line */
    const char *proc_modules; /* "/proc/modules" */
    const char *lib;          /* "/lib/modules" */
    unsigned rows, total;
    /* finit_module(2) in production; returns 0 or -errno. */
    int (*finit)(int fd, const char *params);
    void (*log)(const char *line);
    /* Filled in. */
    unsigned loaded, already, union_count, present;
};

/* "qcom-pon.ko" and "qcom_pon" name the same module: the kernel's name has underscores and no suffix. */
void m17_module_key(const char *file, char *key, size_t room);

/* 0 when the closure's rows and the list are all loaded and the kernel holds exactly the union; 1 otherwise. */
int m17_load_run(struct m17_load *l);

#endif
