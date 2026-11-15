/* M17 G5: the modules the native path still needs after the selector (load.h). */
#define _GNU_SOURCE
#include "load.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NAME_ROOM 64u
#define TEXT_ROOM (64u * 1024u)

struct names {
    unsigned count;
    char name[M17_LOAD_MAX][NAME_ROOM];
};

__attribute__((format(printf, 2, 3))) static void say(const struct m17_load *l, const char *format, ...)
{
    char line[256];
    va_list a;
    va_start(a, format);
    vsnprintf(line, sizeof(line), format, a);
    va_end(a);
    if (l->log)
        l->log(line);
}

void m17_module_key(const char *file, char *key, size_t room)
{
    size_t length = strlen(file), at = 0;
    if (length > 3 && !strcmp(file + length - 3, ".ko"))
        length -= 3;
    for (size_t i = 0; i < length && at + 1 < room; i++)
        key[at++] = file[i] == '-' ? '_' : file[i];
    key[at] = 0;
}

static int plain_module(const char *name)
{
    size_t length = strlen(name);
    if (length <= 3 || length >= NAME_ROOM || name[0] == '.' || strcmp(name + length - 3, ".ko"))
        return 0;
    for (size_t i = 0; i < length; i++) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
            return 0;
    }
    return 1;
}

static int read_text(const char *path, char *text, size_t room)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -errno;
    size_t at = 0;
    for (;;) {
        if (at + 1 >= room) {
            close(fd);
            return -EFBIG;
        }
        ssize_t got = read(fd, text + at, room - 1 - at);
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            int error = -errno;
            close(fd);
            return error;
        }
        if (got == 0)
            break;
        at += (size_t)got;
    }
    close(fd);
    text[at] = 0;
    return 0;
}

static int add(struct names *n, const char *name)
{
    if (n->count >= M17_LOAD_MAX || strlen(name) >= NAME_ROOM)
        return -1;
    for (unsigned i = 0; i < n->count; i++)
        if (!strcmp(n->name[i], name))
            return -1; /* a name twice: refused */
    strcpy(n->name[n->count++], name);
    return 0;
}

static int has(const struct names *n, const char *name)
{
    for (unsigned i = 0; i < n->count; i++)
        if (!strcmp(n->name[i], name))
            return 1;
    return 0;
}

/* The first `rows` rows' module column. */
static int read_closure(const struct m17_load *l, struct names *out)
{
    static char text[TEXT_ROOM];
    if (read_text(l->closure, text, sizeof(text)))
        return -1;
    char *save = NULL, *line = strtok_r(text, "\n", &save);
    if (!line)
        return -1;
    int column = -1, index = 0;
    for (char *field = line, *end = NULL; field; field = end ? end + 1 : NULL, index++) {
        end = strchr(field, '\t');
        if (end)
            *end = 0;
        if (!strcmp(field, "module"))
            column = index;
    }
    if (column < 0)
        return -1;
    out->count = 0;
    while (out->count < l->rows && (line = strtok_r(NULL, "\n", &save))) {
        char *field = line;
        for (int i = 0; i < column && field; i++) {
            field = strchr(field, '\t');
            field = field ? field + 1 : NULL;
        }
        if (!field)
            return -1;
        field[strcspn(field, "\t\r")] = 0;
        if (!plain_module(field) || add(out, field))
            return -1;
    }
    return out->count == l->rows ? 0 : -1;
}

static int read_list(const struct m17_load *l, struct names *out)
{
    static char text[TEXT_ROOM];
    if (read_text(l->list, text, sizeof(text)))
        return -1;
    out->count = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save))
        if (!plain_module(line) || add(out, line))
            return -1;
    return out->count ? 0 : -1;
}

/* The kernel's names, the first field of each line. */
static int read_loaded(const struct m17_load *l, struct names *out)
{
    static char text[TEXT_ROOM];
    if (read_text(l->proc_modules, text, sizeof(text)))
        return -1;
    out->count = 0;
    char *save = NULL;
    for (char *line = strtok_r(text, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        line[strcspn(line, " ")] = 0;
        if (!*line || add(out, line))
            return -1;
    }
    return 0;
}

int m17_load_run(struct m17_load *l)
{
    static struct names closure, list, loaded;
    l->loaded = l->already = l->union_count = l->present = 0;
    if (read_closure(l, &closure) || read_list(l, &list) || read_loaded(l, &loaded)) {
        say(l, "M17 load inputs unreadable or malformed");
        return 1;
    }
    char key[NAME_ROOM];
    for (unsigned i = 0; i < closure.count; i++) {
        m17_module_key(closure.name[i], key, sizeof(key));
        if (has(&loaded, key)) {
            l->already++;
            continue;
        }
        char path[512];
        if ((size_t)snprintf(path, sizeof(path), "%s/%s", l->lib, closure.name[i]) >= sizeof(path))
            return 1;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
            say(l, "M17 load %s open errno=%d", closure.name[i], errno);
            return 1;
        }
        int rc = l->finit(fd, "");
        close(fd);
        say(l, "M17 load %s rc=%d", closure.name[i], rc);
        if (rc == -EEXIST)
            l->already++;
        else if (rc)
            return 1;
        else
            l->loaded++;
    }
    /* What the kernel holds now: exactly the closure's rows and the list. */
    static struct names all;
    all.count = 0;
    for (unsigned i = 0; i < closure.count; i++) {
        m17_module_key(closure.name[i], key, sizeof(key));
        if (!has(&all, key) && add(&all, key))
            return 1;
    }
    for (unsigned i = 0; i < list.count; i++) {
        m17_module_key(list.name[i], key, sizeof(key));
        if (!has(&all, key) && add(&all, key))
            return 1;
    }
    l->union_count = all.count;
    if (read_loaded(l, &loaded))
        return 1;
    for (unsigned i = 0; i < all.count; i++)
        l->present += has(&loaded, all.name[i]);
    int ok = l->present == all.count && loaded.count == all.count && all.count == l->total;
    say(l, "M17 load closure=%u list=%u loaded=%u already=%u union=%u present=%u kernel=%u %s", closure.count, list.count, l->loaded,
        l->already, all.count, l->present, loaded.count, ok ? "OK" : "FAIL");
    return ok ? 0 : 1;
}
