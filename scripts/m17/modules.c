/* M17 selector modules (modules.h). */
#define _GNU_SOURCE
#include "modules.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

/* The canonical module name: no directory, no ".ko", '-' as '_'. */
static void canonical(const char *in, size_t n, char *out, size_t room) {
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < room; i++) out[j++] = in[i] == '-' ? '_' : in[i];
    out[j] = 0;
}

int m17_module_params(const char *cmdline, const char *module_file, char *out, size_t room) {
    char want[128], have[128];
    const char *base = strrchr(module_file, '/') ? strrchr(module_file, '/') + 1 : module_file;
    size_t blen = strlen(base);
    if (blen > 3 && !strcmp(base + blen - 3, ".ko")) blen -= 3;
    canonical(base, blen, want, sizeof want);
    size_t used = 0;
    out[0] = 0;
    const char *s = cmdline ? cmdline : "";
    while (*s) {
        while (*s == ' ' || *s == '\t' || *s == '\n') s++;
        const char *start = s;
        int quoted = 0;
        while (*s && (quoted || (*s != ' ' && *s != '\t' && *s != '\n'))) {
            if (*s == '"') quoted = !quoted;
            s++;
        }
        size_t len = (size_t)(s - start);
        if (!len) break;
        const char *eq = memchr(start, '=', len), *dot = memchr(start, '.', len);
        if (!dot || (eq && eq < dot) || dot == start) continue;
        canonical(start, (size_t)(dot - start), have, sizeof have);
        if (strcmp(have, want)) continue;
        size_t option = len - (size_t)(dot - start) - 1;
        if (!option) continue;
        if (used + (used ? 1 : 0) + option + 1 > room) return -ENAMETOOLONG;
        if (used) out[used++] = ' ';
        memcpy(out + used, dot + 1, option);
        used += option;
        out[used] = 0;
    }
    return 0;
}

int m17_load_modules(const struct m17_modules *m, const char *list, unsigned *loaded, unsigned *already) {
    int failed = 0;
    *loaded = *already = 0;
    const char *s = list;
    while (*s) {
        const char *end = strchr(s, '\n');
        size_t len = end ? (size_t)(end - s) : strlen(s);
        char name[128], path[PATH_MAX], params[1024], line[PATH_MAX + 1200];
        while (len && (s[len - 1] == '\r' || s[len - 1] == ' ')) len--;
        if (len && s[0] != '#') {
            if (len >= sizeof name || memchr(s, '/', len)) {
                failed++;
                if (m->log) m->log("M17SEL module bad-name");
            } else {
                memcpy(name, s, len);
                name[len] = 0;
                int rc = snprintf(path, sizeof path, "%s/%s", m->dir, name) >= (int)sizeof path ? -ENAMETOOLONG
                         : m17_module_params(m->cmdline, name, params, sizeof params);
                if (!rc) rc = m->load(path, params);
                if (rc == -EEXIST) (*already)++;
                else if (rc) failed++;
                else (*loaded)++;
                if (rc && rc != -EEXIST && m->log) {
                    snprintf(line, sizeof line, "M17SEL module %s rc=%d", name, rc);
                    m->log(line);
                }
            }
        }
        if (!end) break;
        s = end + 1;
    }
    return failed;
}
