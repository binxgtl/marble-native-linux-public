/* M18 R3: the shutdown's spinner and its timeline (bye.h). */
#define _GNU_SOURCE
#include "bye.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

uint32_t m18_bye_level(unsigned frame, unsigned dot) {
    const unsigned head = (frame / M18_BYE_STEP_FRAMES) % M18_BYE_DOTS;
    const unsigned behind = (head + M18_BYE_DOTS - dot % M18_BYE_DOTS) % M18_BYE_DOTS;
    const int level = 255 - 20 * (int)behind;
    return (uint32_t)(level < 40 ? 40 : level);
}

void m18_bye_frame(uint32_t *pixels, uint32_t width, uint32_t height, uint32_t pitch, unsigned frame, int full) {
    if (!pixels || !width || !height || pitch < width)
        return;
    const int cx = (int)width / 2, cy = (int)height / 2;
    const int box = (int)(M18_BYE_RING + M18_BYE_DOT + 2);
    int x0 = 0, y0 = 0, x1 = (int)width, y1 = (int)height;
    if (!full) {
        x0 = cx - box < 0 ? 0 : cx - box;
        y0 = cy - box < 0 ? 0 : cy - box;
        x1 = cx + box > (int)width ? (int)width : cx + box;
        y1 = cy + box > (int)height ? (int)height : cy + box;
    }
    for (int y = y0; y < y1; y++)
        memset(pixels + (size_t)y * pitch + x0, 0, (size_t)(x1 - x0) * sizeof(uint32_t));
    const int r = (int)M18_BYE_DOT;
    for (unsigned d = 0; d < M18_BYE_DOTS; d++) {
        /* dot 0 at the top, then clockwise */
        const double a = 2.0 * M_PI * d / M18_BYE_DOTS;
        const int dx = (int)lround(M18_BYE_RING * sin(a)), dy = (int)lround(-(double)M18_BYE_RING * cos(a));
        const uint32_t g = m18_bye_level(frame, d), colour = (g << 16) | (g << 8) | g;
        for (int y = cy + dy - r; y <= cy + dy + r; y++) {
            if (y < 0 || y >= (int)height)
                continue;
            for (int x = cx + dx - r; x <= cx + dx + r; x++) {
                if (x < 0 || x >= (int)width)
                    continue;
                const int ex = x - (cx + dx), ey = y - (cy + dy);
                if (ex * ex + ey * ey <= r * r)
                    pixels[(size_t)y * pitch + x] = colour;
            }
        }
    }
}

int m18_bye_log(const char *path, const char *what) {
    struct timespec t;
    clock_gettime(CLOCK_BOOTTIME, &t);
    char line[160];
    int n = snprintf(line, sizeof line, "%lld.%02ld M18 bye %s\n", (long long)t.tv_sec, t.tv_nsec / 10000000, what);
    if (n < 0 || (size_t)n >= sizeof line)
        return -EOVERFLOW;
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -errno;
    int rc = write(fd, line, (size_t)n) == n ? 0 : -EIO;
    if (close(fd) && !rc)
        rc = -errno;
    return rc;
}
