/* M17 G5: commands and records for the session's helpers (session.c, volkeys.c). */
#ifndef M17_CMD_H
#define M17_CMD_H

#include <stddef.h>
#include <stdint.h>

uint64_t m17_cmd_now_ms(void);
/* Runs argv with env (NULL: this process's), stdin and stderr /dev/null, its stdout into out (NUL-terminated, cut
 * at room), killed after ms. Its exit status, or -1 when it could not run, timed out or was signalled. */
int m17_run(const char *const argv[], const char *const env[], char *out, size_t room, unsigned ms);
/* Appends text to path (never through a link, 0600, synced); a file at or over limit bytes is first moved to
 * path.1. 0 or -errno. */
int m17_append(const char *path, const char *text, size_t limit);
/* The first word of text, cut at room, restricted to [A-Za-z0-9_-]; "none" when there is none. */
void m17_first_word(const char *text, char *word, size_t room);

#endif
