/* A DRM card for present-probe.c's vblank and crtc modes in CI, preloaded into the probe. It answers
 * WAIT_VBLANK, GETRESOURCES and GETCRTC on any fd, and the next read of the fd an event was queued on
 * returns that event. A simulated clock of M19_FAKE_PERIOD_US (8333 when unset) drives the vblanks.
 *
 *   M19_FAKE_LAG=N    every vblank a wait or an event waits for arrives N frames late
 *   M19_FAKE_FLIPS=1  CRTC 31 alternates between framebuffers 76 and 77, as page flips do
 *   M19_FAKE_FAIL=X   one request fails: wait, event, deliver, resources, crtc or fb
 *
 * Test-only: never built into an image. */
#define _GNU_SOURCE
/* Ubuntu's compiler fortifies read with an inline wrapper; this file defines read itself. */
#undef _FORTIFY_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

union fake_wait_vblank {
    struct { uint32_t type, sequence; unsigned long signal; } request;
    struct { uint32_t type, sequence; long sec, usec; } reply;
};
struct fake_event_vblank { uint32_t type, length; uint64_t user_data; uint32_t sec, usec, sequence, crtc_id; };
struct fake_card_res {
    uint64_t fbs, crtcs, connectors, encoders;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders, min_width, max_width, min_height, max_height;
};
struct fake_crtc { uint64_t set_connectors; uint32_t count_connectors, crtc_id, fb_id, x, y, gamma_size, mode_valid; uint32_t clock;
                   uint16_t timings[10]; uint32_t vrefresh, flags, type; char name[32]; };
#define FAKE_WAIT_VBLANK _IOWR('d', 0x3a, union fake_wait_vblank)
#define FAKE_GET_RESOURCES _IOWR('d', 0xa0, struct fake_card_res)
struct fake_fb { uint32_t fb_id, width, height, pitch, bpp, depth, handle; };
#define FAKE_GET_CRTC _IOWR('d', 0xa1, struct fake_crtc)
#define FAKE_GET_FB _IOWR('d', 0xad, struct fake_fb)

static unsigned long long origin;
static int event_fd = -1;
static struct fake_event_vblank pending;
static unsigned crtc_calls;

static unsigned long long now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}

static unsigned long long period(void)
{
    const char *text = getenv("M19_FAKE_PERIOD_US");
    return text ? strtoull(text, NULL, 10) : 8333ull;
}

static uint32_t lag(void)
{
    const char *text = getenv("M19_FAKE_LAG");
    return text ? (uint32_t)strtoul(text, NULL, 10) : 0;
}

static int failing(const char *name)
{
    const char *fail = getenv("M19_FAKE_FAIL");
    return fail && !strcmp(fail, name);
}

/* Vblank 1000 falls at the first request; the count advances once a period. */
static uint32_t current(void)
{
    if (!origin)
        origin = now_us();
    return 1000u + (uint32_t)((now_us() - origin) / period());
}

static unsigned long long time_of(uint32_t sequence)
{
    return origin + (unsigned long long)(sequence - 1000u) * period();
}

static void sleep_until(uint32_t sequence)
{
    unsigned long long at = time_of(sequence), now;
    while ((now = now_us()) < at) {
        struct timespec pause = {(time_t)((at - now) / 1000000ull), (long)((at - now) % 1000000ull) * 1000L};
        (void)nanosleep(&pause, NULL);
    }
}

int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    va_start(arguments, request);
    void *arg = va_arg(arguments, void *);
    va_end(arguments);
    if (request == FAKE_WAIT_VBLANK) {
        union fake_wait_vblank *v = arg;
        uint32_t now = current(), type = v->request.type, sequence = v->request.sequence;
        uint32_t target = type & 0x1u ? now + sequence : sequence;
        if (failing("wait") || ((type & 0x4000000u) && failing("event"))) {
            errno = EINVAL;
            return -1;
        }
        if (type & 0x4000000u) {
            /* A vblank already past is sent at once, with the count it went at. */
            memset(&pending, 0, sizeof(pending));
            pending.type = 1;
            pending.length = sizeof(pending);
            pending.user_data = v->request.signal;
            pending.sequence = (target > now ? target : now) + lag();
            pending.crtc_id = 31;
            event_fd = fd;
            return 0;
        }
        if (target > now) {
            target += lag();
            sleep_until(target);
        } else {
            target = now;
        }
        unsigned long long at = time_of(target);
        v->reply.sequence = target;
        v->reply.sec = (long)(at / 1000000ull);
        v->reply.usec = (long)(at % 1000000ull);
        return 0;
    }
    if (request == FAKE_GET_RESOURCES) {
        if (failing("resources")) {
            errno = EINVAL;
            return -1;
        }
        struct fake_card_res *res = arg;
        static const uint32_t ids[] = {32, 31};
        if (res->crtcs && res->count_crtcs >= 2)
            memcpy((void *)(uintptr_t)res->crtcs, ids, sizeof(ids));
        res->count_crtcs = 2;
        res->count_fbs = res->count_connectors = res->count_encoders = 0;
        return 0;
    }
    if (request == FAKE_GET_CRTC) {
        struct fake_crtc *c = arg;
        if (failing("crtc") || (c->crtc_id != 31 && c->crtc_id != 32)) {
            errno = EINVAL;
            return -1;
        }
        /* CRTC 32 is off; CRTC 31 drives the panel. */
        int on = c->crtc_id == 31;
        memset(c, 0, sizeof(*c));
        c->crtc_id = on ? 31 : 32;
        c->mode_valid = (uint32_t)on;
        c->fb_id = on ? 76u + (getenv("M19_FAKE_FLIPS") ? crtc_calls++ % 2 : 0) : 0;
        c->vrefresh = on ? 120 : 0;
        if (on)
            memcpy(c->name, "1080x2400x120 vid", 17);
        return 0;
    }
    if (request == FAKE_GET_FB) {
        /* Framebuffers 76 and 77: the panel's size, rows padded to 64 bytes. */
        struct fake_fb *f = arg;
        if (failing("fb") || (f->fb_id != 76 && f->fb_id != 77)) {
            errno = EINVAL;
            return -1;
        }
        f->width = 1080;
        f->height = 2400;
        f->pitch = 4352;
        f->bpp = 32;
        f->depth = 24;
        return 0;
    }
    int (*real)(int, unsigned long, ...) = (int (*)(int, unsigned long, ...))dlsym(RTLD_NEXT, "ioctl");
    return real(fd, request, arg);
}

ssize_t read(int fd, void *buffer, size_t count)
{
    ssize_t (*real)(int, void *, size_t) = (ssize_t (*)(int, void *, size_t))dlsym(RTLD_NEXT, "read");
    if (fd != event_fd || event_fd < 0)
        return real(fd, buffer, count);
    event_fd = -1;
    if (failing("deliver") || count < sizeof(pending))
        return 0;
    sleep_until(pending.sequence);
    unsigned long long at = time_of(pending.sequence);
    pending.sec = (uint32_t)(at / 1000000ull);
    pending.usec = (uint32_t)(at % 1000000ull);
    memcpy(buffer, &pending, sizeof(pending));
    return (ssize_t)sizeof(pending);
}
