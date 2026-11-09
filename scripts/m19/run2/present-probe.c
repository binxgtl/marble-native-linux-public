/* M19 R4c: how the X server completes Present requests, measured without Mesa. A window gets one
 * PresentPixmap per frame, each aimed at the vblank after the last completion, and the probe waits for
 * each CompleteNotify before sending the next. It reports how many completions were copies or flips, how
 * many MSCs each frame took, and the time per frame by the server's UST and by the wall clock.
 *
 *   copy N       a 256x256 window: the copy path every windowed program takes
 *   flip N       a window covering the screen: the path where modesetting may page-flip
 *   compositor   (R4d) who owns _NET_WM_CM_S0, the selection a running compositing manager holds
 *   vblank N C   (R4e) the kernel's vblanks on CRTC 0 of card C, without X: N one-frame waits, then N events,
 *                each queued for the vblank after the last, as the X server queues Present's
 *   crtc N C     (R4e) the framebuffer the first active CRTC of card C scans out, sampled N times 10 ms apart:
 *                it changes on every page flip; (R4f) its pitch, which a pixmap must match to be flipped to
 *   root         (R4e) what the X server holds for the whole screen: the share of pixels that are not black
 *
 * Both windows are override-redirect, so no window manager moves or decorates them. Built against libxcb
 * and libxcb-present; it needs nothing else, libdrm included. card is only read: no mode is set. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <xcb/present.h>
#include <xcb/xcb.h>

#define WAIT_MS 1000

/* The DRM ABI from include/uapi/drm/drm.h and drm_mode.h: stable, defined here so no libdrm is needed. */
union m19_wait_vblank {
    struct { uint32_t type, sequence; unsigned long signal; } request;
    struct { uint32_t type, sequence; long sec, usec; } reply;
};
struct m19_event_vblank { uint32_t type, length; uint64_t user_data; uint32_t sec, usec, sequence, crtc_id; };
struct m19_card_res {
    uint64_t fbs, crtcs, connectors, encoders;
    uint32_t count_fbs, count_crtcs, count_connectors, count_encoders, min_width, max_width, min_height, max_height;
};
struct m19_mode_info {
    uint32_t clock;
    uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew, vdisplay, vsync_start, vsync_end, vtotal, vscan;
    uint32_t vrefresh, flags, type;
    char name[32];
};
struct m19_crtc { uint64_t set_connectors; uint32_t count_connectors, crtc_id, fb_id, x, y, gamma_size, mode_valid; struct m19_mode_info mode; };
struct m19_fb { uint32_t fb_id, width, height, pitch, bpp, depth, handle; };
#define M19_WAIT_VBLANK _IOWR('d', 0x3a, union m19_wait_vblank)
#define M19_GET_RESOURCES _IOWR('d', 0xa0, struct m19_card_res)
#define M19_GET_CRTC _IOWR('d', 0xa1, struct m19_crtc)
#define M19_GET_FB _IOWR('d', 0xad, struct m19_fb)
#define M19_VBLANK_RELATIVE 0x1u
#define M19_VBLANK_EVENT 0x4000000u
#define M19_EVENT_VBLANK 0x01u
#define M19_CRTCS 16

static unsigned long long now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (unsigned long long)t.tv_sec * 1000000ull + (unsigned long long)t.tv_nsec / 1000ull;
}

/* The next Present CompleteNotify for this window and serial, or NULL after WAIT_MS. */
static xcb_present_complete_notify_event_t *wait_complete(xcb_connection_t *c, uint8_t opcode, uint32_t serial)
{
    unsigned long long end = now_us() + WAIT_MS * 1000ull;
    for (;;) {
        xcb_generic_event_t *event;
        while ((event = xcb_poll_for_event(c))) {
            if ((event->response_type & 0x7f) == XCB_GE_GENERIC) {
                xcb_ge_generic_event_t *generic = (xcb_ge_generic_event_t *)event;
                if (generic->extension == opcode && generic->event_type == XCB_PRESENT_COMPLETE_NOTIFY) {
                    xcb_present_complete_notify_event_t *complete = (xcb_present_complete_notify_event_t *)event;
                    if (complete->serial == serial)
                        return complete;
                }
            }
            free(event);
        }
        if (xcb_connection_has_error(c))
            return NULL;
        unsigned long long now = now_us();
        if (now >= end)
            return NULL;
        struct pollfd p = {xcb_get_file_descriptor(c), POLLIN, 0};
        (void)poll(&p, 1, (int)((end - now) / 1000ull) + 1);
    }
}

/* The owner of screen 0's compositing-manager selection: none when nothing composites. */
static int compositor(void)
{
    xcb_connection_t *c = xcb_connect(NULL, NULL);
    if (xcb_connection_has_error(c)) {
        printf("M19 PRESENT compositor FAIL connect\n");
        return 1;
    }
    static const char name[] = "_NET_WM_CM_S0";
    xcb_intern_atom_reply_t *atom = xcb_intern_atom_reply(c, xcb_intern_atom(c, 0, sizeof(name) - 1, name), NULL);
    xcb_get_selection_owner_reply_t *owner = atom ? xcb_get_selection_owner_reply(c, xcb_get_selection_owner(c, atom->atom), NULL) : NULL;
    int ok = owner != NULL;
    printf("M19 PRESENT compositor owner=0x%08x\n", ok ? owner->owner : 0u);
    free(atom);
    free(owner);
    xcb_disconnect(c);
    if (!ok) {
        printf("M19 PRESENT compositor FAIL query\n");
        return 1;
    }
    printf("M19 PRESENT compositor ok\n");
    return 0;
}

static double kernel_us(long sec, long usec)
{
    return (double)sec * 1e6 + (double)usec;
}

/* The vblank event queued with user_data serial, or 0 after WAIT_MS. */
static int read_event(int fd, uint64_t serial, struct m19_event_vblank *event)
{
    struct pollfd p = {fd, POLLIN, 0};
    if (poll(&p, 1, WAIT_MS) != 1)
        return 0;
    ssize_t n = read(fd, event, sizeof(*event));
    return n == (ssize_t)sizeof(*event) && event->type == M19_EVENT_VBLANK && event->user_data == serial;
}

static int vblank(long frames, const char *card)
{
    int fd = open(card, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("M19 PRESENT vblank FAIL open errno=%d\n", errno);
        return 1;
    }
    /* Blocking waits of one frame each: what a vblank costs when nothing is queued. */
    union m19_wait_vblank v;
    uint32_t first = 0, last = 0;
    double start = 0, stop = 0;
    for (long i = 0; i < frames; i++) {
        memset(&v, 0, sizeof(v));
        v.request.type = M19_VBLANK_RELATIVE;
        v.request.sequence = 1;
        if (ioctl(fd, M19_WAIT_VBLANK, &v)) {
            printf("M19 PRESENT vblank FAIL wait errno=%d\n", errno);
            close(fd);
            return 1;
        }
        last = v.reply.sequence;
        stop = kernel_us(v.reply.sec, v.reply.usec);
        if (!i) {
            first = last;
            start = stop;
        }
    }
    double wait_seq = (double)(uint32_t)(last - first) / (double)(frames - 1), wait_us = (stop - start) / (double)(frames - 1);

    /* Events, each for the vblank after the last one: the X server's own path for a Present request. */
    memset(&v, 0, sizeof(v));
    v.request.type = M19_VBLANK_RELATIVE;
    if (ioctl(fd, M19_WAIT_VBLANK, &v)) {
        printf("M19 PRESENT vblank FAIL query errno=%d\n", errno);
        close(fd);
        return 1;
    }
    uint32_t target = v.reply.sequence + 1;
    long late = 0;
    unsigned long long wall = 0;
    for (long i = 0; i < frames; i++) {
        memset(&v, 0, sizeof(v));
        v.request.type = M19_VBLANK_EVENT;
        v.request.sequence = target;
        v.request.signal = (unsigned long)i + 1;
        unsigned long long queued = now_us();
        if (ioctl(fd, M19_WAIT_VBLANK, &v)) {
            printf("M19 PRESENT vblank FAIL queue errno=%d\n", errno);
            close(fd);
            return 1;
        }
        struct m19_event_vblank event;
        if (!read_event(fd, (uint64_t)i + 1, &event)) {
            printf("M19 PRESENT vblank FAIL event after %ld\n", i);
            close(fd);
            return 1;
        }
        wall += now_us() - queued;
        late += event.sequence != target;
        last = event.sequence;
        stop = kernel_us((long)event.sec, (long)event.usec);
        if (!i) {
            first = last;
            start = stop;
        }
        target = event.sequence + 1;
    }
    close(fd);
    printf("M19 PRESENT vblank frames=%ld wait_seq=%.2f wait_us=%.0f event_seq=%.2f event_us=%.0f event_wall_us=%.0f late=%ld\n", frames, wait_seq,
           wait_us, (double)(uint32_t)(last - first) / (double)(frames - 1), (stop - start) / (double)(frames - 1), (double)wall / (double)frames, late);
    printf("M19 PRESENT vblank ok\n");
    return 0;
}

static int crtc(long samples, const char *card)
{
    int fd = open(card, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        printf("M19 PRESENT crtc FAIL open errno=%d\n", errno);
        return 1;
    }
    uint32_t ids[M19_CRTCS] = {0};
    struct m19_card_res res;
    memset(&res, 0, sizeof(res));
    int ok = !ioctl(fd, M19_GET_RESOURCES, &res);
    uint32_t count = res.count_crtcs < M19_CRTCS ? res.count_crtcs : M19_CRTCS;
    memset(&res, 0, sizeof(res));
    res.crtcs = (uint64_t)(uintptr_t)ids;
    res.count_crtcs = count;
    if (!ok || ioctl(fd, M19_GET_RESOURCES, &res)) {
        printf("M19 PRESENT crtc FAIL resources errno=%d\n", errno);
        close(fd);
        return 1;
    }
    struct m19_crtc c;
    uint32_t id = 0;
    for (uint32_t i = 0; !id && i < count; i++) {
        memset(&c, 0, sizeof(c));
        c.crtc_id = ids[i];
        if (!ioctl(fd, M19_GET_CRTC, &c) && c.mode_valid && c.fb_id)
            id = ids[i];
    }
    if (!id) {
        printf("M19 PRESENT crtc FAIL no active crtc\n");
        close(fd);
        return 1;
    }
    char mode[sizeof(c.mode.name) + 1];
    size_t n = strnlen(c.mode.name, sizeof(c.mode.name));
    for (size_t i = 0; i < n; i++)
        mode[i] = c.mode.name[i] > ' ' && c.mode.name[i] < 127 && c.mode.name[i] != '=' ? c.mode.name[i] : '_';
    mode[n] = 0;
    uint32_t refresh = c.mode.vrefresh, fb = c.fb_id, previous = fb, seen[8] = {fb};
    long distinct = 1, changes = 0, pitch = -1, bpp = -1;
    /* Bytes a row of the scanned-out buffer: modesetting flips only to a pixmap of the same pitch. */
    struct m19_fb f;
    memset(&f, 0, sizeof(f));
    f.fb_id = fb;
    if (!ioctl(fd, M19_GET_FB, &f)) {
        pitch = f.pitch;
        bpp = f.bpp;
    }
    for (long i = 0; i < samples; i++) {
        struct timespec pause = {0, 10000000};
        (void)nanosleep(&pause, NULL);
        memset(&c, 0, sizeof(c));
        c.crtc_id = id;
        if (ioctl(fd, M19_GET_CRTC, &c)) {
            printf("M19 PRESENT crtc FAIL sample errno=%d\n", errno);
            close(fd);
            return 1;
        }
        changes += c.fb_id != previous;
        previous = c.fb_id;
        int known = 0;
        for (long j = 0; j < distinct; j++)
            known |= seen[j] == c.fb_id;
        if (!known && distinct < 8)
            seen[distinct++] = c.fb_id;
    }
    close(fd);
    printf("M19 PRESENT crtc id=%u mode=%s refresh=%u fb=%u fbs=%ld changes=%ld samples=%ld pitch=%ld bpp=%ld\n", id, n ? mode : "none", refresh, fb,
           distinct, changes, samples, pitch, bpp);
    printf("M19 PRESENT crtc ok\n");
    return 0;
}

static int root(void)
{
    xcb_connection_t *c = xcb_connect(NULL, NULL);
    if (xcb_connection_has_error(c)) {
        printf("M19 PRESENT root FAIL connect\n");
        return 1;
    }
    xcb_screen_t *screen = xcb_setup_roots_iterator(xcb_get_setup(c)).data;
    uint16_t width = screen->width_in_pixels, height = screen->height_in_pixels;
    unsigned long long nonblack = 0, sum = 0, pixels = (unsigned long long)width * height;
    for (uint16_t y = 0; y < height; y += 64) {
        uint16_t rows = height - y < 64 ? (uint16_t)(height - y) : 64;
        xcb_get_image_reply_t *image =
            xcb_get_image_reply(c, xcb_get_image(c, XCB_IMAGE_FORMAT_Z_PIXMAP, screen->root, 0, (int16_t)y, width, rows, ~0u), NULL);
        /* 32 bits a pixel, blue, green, red and a pad byte: depth 24 on every server this runs on. */
        if (!image || xcb_get_image_data_length(image) != (int)width * rows * 4) {
            printf("M19 PRESENT root FAIL image at %u\n", y);
            free(image);
            xcb_disconnect(c);
            return 1;
        }
        const uint8_t *p = xcb_get_image_data(image);
        for (int i = 0; i < width * rows; i++, p += 4) {
            uint8_t top = p[0] > p[1] ? p[0] : p[1];
            top = top > p[2] ? top : p[2];
            nonblack += top > 24;
            sum += (unsigned)p[0] + p[1] + p[2];
        }
        free(image);
    }
    xcb_disconnect(c);
    printf("M19 PRESENT root width=%u height=%u nonblack=%llu mean=%llu\n", width, height, pixels ? nonblack * 1000 / pixels : 0,
           pixels ? sum / (3 * pixels) : 0);
    printf("M19 PRESENT root ok\n");
    return 0;
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (argc == 2 && !strcmp(argv[1], "compositor"))
        return compositor();
    if (argc == 2 && !strcmp(argv[1], "root"))
        return root();
    int card = argc == 4 && (!strcmp(argv[1], "vblank") || !strcmp(argv[1], "crtc"));
    int flip = argc == 3 && !strcmp(argv[1], "flip"), copy = argc == 3 && !strcmp(argv[1], "copy");
    long frames = argc == 3 || card ? strtol(argv[2], NULL, 10) : 0;
    if ((!flip && !copy && !card) || frames < 2 || frames > 10000) {
        fprintf(stderr, "usage: m19-present-probe copy|flip FRAMES, vblank|crtc COUNT CARD, compositor or root\n");
        return 64;
    }
    if (card)
        return argv[1][0] == 'v' ? vblank(frames, argv[3]) : crtc(frames, argv[3]);
    const char *mode = flip ? "flip" : "copy";
    xcb_connection_t *c = xcb_connect(NULL, NULL);
    if (xcb_connection_has_error(c)) {
        printf("M19 PRESENT %s FAIL connect\n", mode);
        return 1;
    }
    const xcb_query_extension_reply_t *extension = xcb_get_extension_data(c, &xcb_present_id);
    if (!extension || !extension->present) {
        printf("M19 PRESENT %s FAIL no Present extension\n", mode);
        return 1;
    }
    xcb_present_query_version_reply_t *version = xcb_present_query_version_reply(c, xcb_present_query_version(c, 1, 2), NULL);
    printf("M19 PRESENT %s version=%u.%u\n", mode, version ? version->major_version : 0, version ? version->minor_version : 0);
    free(version);

    xcb_screen_t *screen = xcb_setup_roots_iterator(xcb_get_setup(c)).data;
    uint16_t width = flip ? screen->width_in_pixels : 256, height = flip ? screen->height_in_pixels : 256;
    int16_t x = flip ? 0 : 64, y = flip ? 0 : 64;
    xcb_window_t window = xcb_generate_id(c);
    uint32_t values[] = {screen->black_pixel, 1};
    xcb_create_window(c, XCB_COPY_FROM_PARENT, window, screen->root, x, y, width, height, 0, XCB_WINDOW_CLASS_INPUT_OUTPUT, screen->root_visual,
                      XCB_CW_BACK_PIXEL | XCB_CW_OVERRIDE_REDIRECT, values);
    xcb_map_window(c, window);

    /* Two pixmaps of different colours, so every frame changes what is shown. */
    xcb_pixmap_t pixmaps[2];
    xcb_gcontext_t gc = xcb_generate_id(c);
    xcb_create_gc(c, gc, window, 0, NULL);
    for (int i = 0; i < 2; i++) {
        pixmaps[i] = xcb_generate_id(c);
        xcb_create_pixmap(c, screen->root_depth, pixmaps[i], window, width, height);
        uint32_t colour = i ? 0x00ff00ffu : 0x0000ffffu;
        xcb_change_gc(c, gc, XCB_GC_FOREGROUND, &colour);
        xcb_rectangle_t all = {0, 0, width, height};
        xcb_poly_fill_rectangle(c, pixmaps[i], gc, 1, &all);
    }
    xcb_present_event_t eid = xcb_generate_id(c);
    xcb_present_select_input(c, eid, window, XCB_PRESENT_EVENT_MASK_COMPLETE_NOTIFY);
    xcb_flush(c);

    /* The current MSC, from a NotifyMSC that completes at once. */
    uint32_t serial = 1;
    xcb_present_notify_msc(c, window, serial, 0, 0, 0);
    xcb_flush(c);
    xcb_present_complete_notify_event_t *first = wait_complete(c, extension->major_opcode, serial);
    if (!first) {
        printf("M19 PRESENT %s FAIL no msc\n", mode);
        return 1;
    }
    uint64_t msc = first->msc, msc_start = first->msc, ust_start = first->ust, ust = first->ust;
    free(first);

    long done = 0, copies = 0, flips = 0, skips = 0, others = 0;
    unsigned long long wall_start = now_us();
    for (long i = 0; i < frames; i++) {
        serial++;
        xcb_present_pixmap(c, window, pixmaps[i & 1], serial, 0, 0, 0, 0, 0, 0, 0, XCB_PRESENT_OPTION_NONE, msc + 1, 0, 0, 0, NULL);
        xcb_flush(c);
        xcb_present_complete_notify_event_t *complete = wait_complete(c, extension->major_opcode, serial);
        if (!complete)
            break;
        done++;
        switch (complete->mode) {
        case XCB_PRESENT_COMPLETE_MODE_COPY: copies++; break;
        case XCB_PRESENT_COMPLETE_MODE_FLIP: flips++; break;
        case XCB_PRESENT_COMPLETE_MODE_SKIP: skips++; break;
        default: others++; break;
        }
        msc = complete->msc;
        ust = complete->ust;
        free(complete);
    }
    unsigned long long wall = now_us() - wall_start;
    double msc_per_frame = done ? (double)(msc - msc_start) / (double)done : 0;
    double us_per_frame = done ? (double)(ust - ust_start) / (double)done : 0;
    double wall_per_frame = done ? (double)wall / (double)done : 0;
    printf("M19 PRESENT %s frames=%ld done=%ld copies=%ld flips=%ld skips=%ld others=%ld msc_per_frame=%.2f us_per_frame=%.0f wall_us_per_frame=%.0f\n",
           mode, frames, done, copies, flips, skips, others, msc_per_frame, us_per_frame, wall_per_frame);
    xcb_disconnect(c);
    if (done != frames) {
        printf("M19 PRESENT %s FAIL timeout after %ld\n", mode, done);
        return 1;
    }
    printf("M19 PRESENT %s ok\n", mode);
    return 0;
}
