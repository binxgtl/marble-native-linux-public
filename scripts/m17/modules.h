/* M17 selector: its modules, loaded in the list's order from the vendor ramdisk, each with the options the kernel
 * command line gives it, as Android's libmodprobe passes them (docs/m17-g4.md). Every module on the list is one
 * Android loads itself, byte for byte the copy it loads; a module already loaded counts as loaded. */
#ifndef M17_MODULES_H
#define M17_MODULES_H

#include <stddef.h>

struct m17_modules {
    const char *dir;     /* "/lib/modules" */
    const char *cmdline; /* /proc/cmdline's text */
    int (*load)(const char *path, const char *params); /* finit_module, or a test's: 0 or -errno */
    void (*log)(const char *line);
};

/* "<module>.<option>" words of the command line for this module file (".ko" dropped, '-' and '_' alike), joined
 * by spaces in their order. 0, or -ENAMETOOLONG when they do not fit. */
int m17_module_params(const char *cmdline, const char *module_file, char *out, size_t room);

/* Loads every name in `list` (one file name a line; blank lines and '#' lines ignored). Returns how many failed;
 * loaded and already count the rest. */
int m17_load_modules(const struct m17_modules *m, const char *list, unsigned *loaded, unsigned *already);

#endif
