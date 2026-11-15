/* M18 R3: the spinner's frames and the timeline's lines (bye.h), on memory and a temporary directory. No device. */
#define _GNU_SOURCE
#include "bye.h"

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;
#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) {                                                                                                 \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond);                                   \
            failures++;                                                                                                \
        }                                                                                                              \
    } while (0)

static uint32_t at(const uint32_t *p, uint32_t pitch, int x, int y) { return p[(size_t)y * pitch + (size_t)x]; }

static void test_levels(void) {
    /* the head is dot (frame / 3) % 12 at 255; behind it 20 less a dot; never under 40; the ring turns clockwise */
    CHECK(m18_bye_level(0, 0) == 255 && m18_bye_level(0, 11) == 235 && m18_bye_level(0, 10) == 215);
    CHECK(m18_bye_level(0, 1) == 40 && m18_bye_level(0, 2) == 55);
    CHECK(m18_bye_level(2, 0) == 255 && m18_bye_level(3, 1) == 255 && m18_bye_level(3, 0) == 235);
    CHECK(m18_bye_level(3 * 12, 0) == 255 && m18_bye_level(3 * 12 + 2, 0) == 255);
    unsigned heads = 0;
    for (unsigned d = 0; d < 12; d++)
        heads += m18_bye_level(7, d) == 255;
    CHECK(heads == 1);
}

static void test_frame(void) {
    const uint32_t w = M18_BYE_W, h = M18_BYE_H, pitch = w + 8;
    uint32_t *p = malloc((size_t)pitch * h * sizeof(uint32_t));
    CHECK(p != NULL);
    if (!p) return;
    memset(p, 0xab, (size_t)pitch * h * sizeof(uint32_t));
    m18_bye_frame(p, w, h, pitch, 0, 1);
    const int cx = (int)w / 2, cy = (int)h / 2;
    /* the head (dot 0) at the top of the ring is white; dot 3 at the right is dim; the centre and corners black */
    CHECK(at(p, pitch, cx, cy - (int)M18_BYE_RING) == 0xffffff);
    CHECK(at(p, pitch, cx + (int)M18_BYE_RING, cy) == 0x4b4b4b); /* 9 behind: 255 - 180 */
    CHECK(at(p, pitch, cx, cy) == 0 && at(p, pitch, 0, 0) == 0 && at(p, pitch, (int)w - 1, (int)h - 1) == 0);
    /* the pitch's padding is never written */
    CHECK(p[w] == 0xabababab && p[(size_t)(h - 1) * pitch + w + 7] == 0xabababab);
    /* a later partial frame moves the head, clears the spinner's whole square and leaves the outside alone */
    p[0] = 0x123456;
    p[(size_t)(cy + 120) * pitch + (size_t)(cx + 120)] = 0x777777; /* inside the square, on no dot */
    m18_bye_frame(p, w, h, pitch, 3, 0);
    CHECK(p[0] == 0x123456);
    CHECK(at(p, pitch, cx + 120, cy + 120) == 0);
    const int dx = (int)lround(M18_BYE_RING * 0.5), dy = (int)lround(-(double)M18_BYE_RING * 0.8660254037844386);
    CHECK(at(p, pitch, cx + dx, cy + dy) == 0xffffff);
    CHECK(at(p, pitch, cx, cy - (int)M18_BYE_RING) == 0xebebeb);
    /* dot edges: a point just inside the dot is lit, just outside is black */
    CHECK(at(p, pitch, cx, cy - (int)M18_BYE_RING - (int)M18_BYE_DOT) != 0);
    CHECK(at(p, pitch, cx, cy - (int)M18_BYE_RING - (int)M18_BYE_DOT - 1) == 0);
    /* small or bad buffers: nothing written outside, nothing at all for a bad pitch */
    static uint32_t guarded[16 * 16 + 4096];
    uint32_t *tiny = guarded;
    memset(guarded, 0xab, sizeof guarded);
    m18_bye_frame(tiny, 16, 16, 16, 0, 1);
    CHECK(tiny[0] == 0);
    int intact = 1;
    for (size_t i = 16 * 16; i < sizeof guarded / sizeof guarded[0]; i++)
        intact &= guarded[i] == 0xabababab;
    CHECK(intact); /* the ring lies far outside a 16 x 16 buffer: nothing past it written */
    memset(guarded, 0xab, sizeof guarded);
    m18_bye_frame(tiny, 16, 16, 8, 0, 1);
    CHECK(tiny[0] == 0xabababab);
    m18_bye_frame(NULL, 16, 16, 16, 0, 1);
    free(p);
}

static void test_log(void) {
    char dir[256], path[300], link[300], text[512];
    snprintf(dir, sizeof dir, "%s/m18-r3-%d", getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp", (int)getpid());
    CHECK(!mkdir(dir, 0700));
    snprintf(path, sizeof path, "%s/m18-shutdown.log", dir);
    CHECK(m18_bye_log(path, "start") == 0 && m18_bye_log(path, "alive") == 0);
    FILE *f = fopen(path, "r");
    size_t n = f ? fread(text, 1, sizeof text - 1, f) : 0;
    if (f) fclose(f);
    text[n] = 0;
    char *second = strchr(text, '\n');
    CHECK(strstr(text, " M18 bye start\n") == second - strlen(" M18 bye start") && second && strstr(second, " M18 bye alive\n"));
    struct stat s;
    CHECK(!stat(path, &s) && (s.st_mode & 0777) == 0600);
    snprintf(link, sizeof link, "%s/link.log", dir);
    CHECK(!symlink(path, link) && m18_bye_log(link, "x") < 0);
    CHECK(m18_bye_log("/nonexistent-m18/x.log", "x") == -ENOENT);
    char cmd[400];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir);
    CHECK(!system(cmd));
}

int main(void) {
    test_levels();
    test_frame();
    test_log();
    if (failures) {
        fprintf(stderr, "M18 R3 tests: %d failed\n", failures);
        return 1;
    }
    printf("M18 R3 spinner and timeline PASS\n");
    return 0;
}
