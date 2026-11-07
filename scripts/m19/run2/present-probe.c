/* M19 R4c: how the X server completes Present requests, measured without Mesa. A window gets one
 * PresentPixmap per frame, each aimed at the vblank after the last completion, and the probe waits for
 * each CompleteNotify before sending the next. It reports how many completions were copies or flips, how
 * many MSCs each frame took, and the time per frame by the server's UST and by the wall clock.
 *
 *   copy N   a 256x256 window: the copy path every windowed program takes
 *   flip N   a window covering the screen: the path where modesetting may page-flip
 *
 * Both windows are override-redirect, so no window manager moves or decorates them. Built against libxcb
 * and libxcb-present; it needs nothing else. */
#define _POSIX_C_SOURCE 200809L
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <xcb/present.h>
#include <xcb/xcb.h>

#define WAIT_MS 1000

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

int main(int argc, char **argv)
{
    int flip = argc == 3 && !strcmp(argv[1], "flip"), copy = argc == 3 && !strcmp(argv[1], "copy");
    long frames = argc == 3 ? strtol(argv[2], NULL, 10) : 0;
    if ((!flip && !copy) || frames < 2 || frames > 10000) {
        fprintf(stderr, "usage: m19-present-probe copy|flip FRAMES\n");
        return 64;
    }
    setvbuf(stdout, NULL, _IOLBF, 0);
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
