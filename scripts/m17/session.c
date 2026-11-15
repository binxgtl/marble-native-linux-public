/* M17 G5: the daily session's starter and its record (session.h). */
#define _GNU_SOURCE
#include "session.h"

#include "cmd.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RECORD_LIMIT (256u * 1024u)

static int read_small(const char *path, char *text, size_t room)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return -1;
    ssize_t got = read(fd, text, room - 1);
    close(fd);
    if (got < 0)
        return -1;
    text[got] = 0;
    return (int)got;
}

/* A process whose comm is exactly `comm`. */
static int running(const char *proc, const char *comm)
{
    DIR *directory = opendir(proc);
    if (!directory)
        return 0;
    int found = 0;
    for (struct dirent *entry; !found && (entry = readdir(directory));) {
        if (entry->d_name[0] < '1' || entry->d_name[0] > '9')
            continue;
        char path[512], text[64];
        snprintf(path, sizeof(path), "%s/%s/comm", proc, entry->d_name);
        if (read_small(path, text, sizeof(text)) <= 0)
            continue;
        text[strcspn(text, "\n")] = 0;
        found = !strcmp(text, comm);
    }
    closedir(directory);
    return found;
}

/* The value of "key=" at a line's start in text, its first word. */
static void value_of(const char *text, const char *key, char *word, size_t room)
{
    size_t length = strlen(key);
    for (const char *line = text; line && *line; line = strchr(line, '\n') ? strchr(line, '\n') + 1 : NULL) {
        if (!strncmp(line, key, length) && line[length] == '=') {
            m17_first_word(line + length + 1, word, room);
            return;
        }
    }
    m17_first_word("", word, room);
}

static int systemctl(const struct m17_session *s, const char *verb, const char *unit, char *word, size_t room)
{
    char out[256];
    const char *argv[] = {s->systemctl, verb, unit, NULL};
    int rc = m17_run(argv, NULL, out, sizeof(out), s->command_ms);
    if (word)
        m17_first_word(out, word, room);
    return rc;
}

/* The keypad's line, "M19_CE status=WORD ...": the word only, upper case and underscores. */
static void ce_status(const char *text, char *status, size_t room)
{
    static const char head[] = "M19_CE status=";
    snprintf(status, room, "none");
    if (strncmp(text, head, sizeof(head) - 1))
        return;
    const char *word = text + sizeof(head) - 1;
    size_t length = strcspn(word, " \n");
    for (size_t i = 0; i < length; i++)
        if (!((word[i] >= 'A' && word[i] <= 'Z') || word[i] == '_'))
            return;
    if (length && length < room) {
        memcpy(status, word, length);
        status[length] = 0;
    }
}

static void record(const struct m17_session *s, const char *line)
{
    char text[1024], uptime[64] = "0";
    if (read_small("/proc/uptime", uptime, sizeof(uptime)) > 0)
        uptime[strcspn(uptime, " \n")] = 0;
    snprintf(text, sizeof(text), "%s %s\n", uptime, line);
    int rc = m17_append(s->log, text, RECORD_LIMIT);
    if (rc)
        fprintf(stderr, "M17 session record rc=%d\n", rc);
    fputs(text, stderr);
}

int m17_session_main(const struct m17_session *s, struct m17_session_result *r)
{
    memset(r, 0, sizeof(*r));
    r->sink_rc = r->pulse_rc = r->ce_rc = -1;
    snprintf(r->sink_state, sizeof(r->sink_state), "none");
    snprintf(r->ce_status, sizeof(r->ce_status), "none");
    uint64_t start = m17_cmd_now_ms();
    for (;;) {
        r->x_ok = !access(s->x_socket, F_OK);
        r->desktop_ok = r->x_ok && running(s->proc, s->panel_comm) && running(s->proc, s->desktop_comm);
        if (r->desktop_ok || m17_cmd_now_ms() >= start + s->desktop_ms)
            break;
        (void)poll(NULL, 0, (int)s->poll_ms);
    }
    unsigned long long desktop_s = (m17_cmd_now_ms() - start) / 1000;
    if (r->desktop_ok) {
        /* R6 to R9's order: the sink, once; PulseAudio once it streams; the keypad last. */
        r->sink_rc = systemctl(s, "start", s->sink_unit, NULL, 0);
        uint64_t end = m17_cmd_now_ms() + s->sink_ms;
        static char text[8192];
        while (r->sink_rc == 0) {
            if (read_small(s->sink_report, text, sizeof(text)) > 0) {
                value_of(text, "state", r->sink_state, sizeof(r->sink_state));
                if (strcmp(r->sink_state, "pre") && strcmp(r->sink_state, "none"))
                    break;
            }
            if (m17_cmd_now_ms() >= end)
                break;
            (void)poll(NULL, 0, (int)s->poll_ms);
        }
        r->streaming = !strcmp(r->sink_state, "streaming");
        if (r->streaming) {
            r->pulse_rc = systemctl(s, "start", s->pulse_unit, NULL, 0);
            end = m17_cmd_now_ms() + s->pulse_ms;
            while (r->pulse_rc == 0 && !r->pulse_sink) {
                const char *argv[] = {s->pactl, "list", "short", "sinks", NULL};
                if (m17_run(argv, s->pulse_env, text, sizeof(text), s->command_ms) == 0)
                    r->pulse_sink = strstr(text, s->sink_name) != NULL;
                if (r->pulse_sink || m17_cmd_now_ms() >= end)
                    break;
                (void)poll(NULL, 0, (int)s->poll_ms);
            }
        }
        r->ce_rc = systemctl(s, "start", s->ce_unit, NULL, 0);
    }
    char boot[64] = "", release[96] = "", line[768];
    if (read_small(s->boot_id, boot, sizeof(boot)) > 0)
        boot[strcspn(boot, "\n")] = 0;
    if (read_small(s->osrelease, release, sizeof(release)) > 0)
        release[strcspn(release, "\n")] = 0;
    snprintf(line, sizeof(line),
             "M17 session start boot=%s release=%s x=%d desktop=%d desktop_s=%llu sink_rc=%d sink=%s pulse_rc=%d pulse_sink=%d ce_rc=%d",
             boot, release, r->x_ok, r->desktop_ok, desktop_s, r->sink_rc, r->sink_state, r->pulse_rc, r->pulse_sink, r->ce_rc);
    record(s, line);
    /* The owner's answer, or the wait running out. */
    uint64_t began = m17_cmd_now_ms(), end = began + s->ce_ms;
    while (r->ce_rc == 0) {
        char text[512];
        if (read_small(s->ce_result, text, sizeof(text)) > 0) {
            r->ce_seen = 1;
            ce_status(text, r->ce_status, sizeof(r->ce_status));
            break;
        }
        if (m17_cmd_now_ms() >= end)
            break;
        (void)poll(NULL, 0, (int)s->poll_ms);
    }
    char system[32], keys[32], guard[32], network[32] = "none", out[256];
    (void)systemctl(s, "is-system-running", NULL, system, sizeof(system));
    (void)systemctl(s, "is-active", s->keys_unit, keys, sizeof(keys));
    (void)systemctl(s, "is-active", s->guard_unit, guard, sizeof(guard));
    const char *nmcli[] = {s->nmcli, "-t", "-f", "STATE", "general", NULL};
    if (m17_run(nmcli, NULL, out, sizeof(out), s->command_ms) == 0)
        m17_first_word(out, network, sizeof(network));
    snprintf(line, sizeof(line), "M17 session settled ce=%s ce_seen=%d ce_s=%llu system=%s keys=%s guard=%s guard_tripped=%d network=%s",
             r->ce_status, r->ce_seen, (unsigned long long)((m17_cmd_now_ms() - began) / 1000), system, keys, guard,
             !access(s->guard_marker, F_OK), network);
    record(s, line);
    return r->desktop_ok && r->streaming && r->pulse_sink ? 0 : 1;
}
