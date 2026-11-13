/* m19-ce-prompt <socket> <result>: the keypad the owner taps in the R7 session to unlock Android's CE
 * storage (docs/m19-r7.md). Full screen, keyboard and pointer grabbed, so no other client sees a key. Dots only on
 * screen. The PIN goes once to the broker's socket, then is wiped; the broker's one-line status goes to <result>.
 * Synthetic events (XSendEvent) are ignored. */
#define _GNU_SOURCE
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/keysym.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "prompt.h"

#define REPLY_MS 180000
#define DONE_MS 8000

static struct {
    struct m19_prompt prompt;
    char message[32];
    char keys[8];
} __attribute__((aligned(4096))) secret;

static Display *display;
static Window window;
static GC gc;
static struct m19_prompt_layout layout;
static unsigned long color_back, color_key, color_text, color_ok, color_bad;
static int width, height;

static unsigned long rgb(Colormap map, unsigned short r, unsigned short g, unsigned short b)
{
    XColor color = {.red = r, .green = g, .blue = b, .flags = DoRed | DoGreen | DoBlue};
    return XAllocColor(display, map, &color) ? color.pixel : BlackPixel(display, DefaultScreen(display));
}

static void text(int x, int y, int scale, const char *string, unsigned long color)
{
    XSetForeground(display, gc, color);
    for (; *string; string++, x += 6 * scale) {
        const uint8_t *rows = m19_prompt_glyph(*string);
        for (int r = 0; rows && r < 7; r++)
            for (int c = 0; c < 5; c++)
                if (rows[r] & (16 >> c))
                    XFillRectangle(display, window, gc, x + c * scale, y + r * scale, (unsigned)scale, (unsigned)scale);
    }
}

static void centered(const struct m19_rect *r, int scale, const char *string, unsigned long color)
{
    int length = (int)strlen(string);
    while (scale > 1 && length * 6 * scale > r->w)
        scale--;
    text(r->x + (r->w - length * 6 * scale) / 2, r->y + (r->h - 7 * scale) / 2, scale, string, color);
}

static void draw(void)
{
    const struct m19_prompt *p = &secret.prompt;
    XSetForeground(display, gc, color_back);
    XFillRectangle(display, window, gc, 0, 0, (unsigned)width, (unsigned)height);
    for (int i = 0; i < M19_PROMPT_KEYS; i++) {
        const struct m19_rect *r = &layout.keys[i];
        XSetForeground(display, gc, color_key);
        XFillRectangle(display, window, gc, r->x, r->y, (unsigned)r->w, (unsigned)r->h);
        char label[8] = {layout.labels[i], 0};
        if (label[0] == 'B')
            strcpy(label, "<");
        else if (label[0] == 'C')
            strcpy(label, "X");
        else if (label[0] == 'U')
            strcpy(label, "UNLOCK");
        centered(r, layout.scale * 2, label, color_text);
    }
    char dots[M19_PROMPT_PIN_MAX + 1] = {0};
    memset(dots, '*', p->size);
    struct m19_rect title = layout.dots;
    title.y -= title.h;
    centered(&title, layout.scale, "ANDROID PIN", color_text);
    centered(&layout.dots, layout.scale * 2, p->size ? dots : "____", color_text);
    if (p->state == M19_PROMPT_SENDING)
        centered(&layout.message, layout.scale, "UNLOCKING", color_text);
    else if (p->state == M19_PROMPT_DONE)
        centered(&layout.message, layout.scale, p->ok ? "UNLOCKED" : p->status, p->ok ? color_ok : color_bad);
    XFlush(display);
}

static long long now_ms(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static void record(const char *path, const char *line)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0)
        return;
    dprintf(fd, "%s\n", line);
    close(fd);
}

/* One message, one reply. The PIN copy is wiped as soon as it is sent. */
static void unlock(const char *socket_path, const char *result_path)
{
    struct m19_prompt *p = &secret.prompt;
    char reply[160] = {0};
    int length = m19_prompt_message(p, secret.message, sizeof(secret.message));
    m19_prompt_wipe(p->pin, sizeof(p->pin));
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
    if (length < 0 || fd < 0 || connect(fd, (struct sockaddr *)&address, sizeof(address)) ||
        send(fd, secret.message, (size_t)length, MSG_NOSIGNAL) != length) {
        snprintf(reply, sizeof(reply), "M19_CE status=NO_BROKER");
    } else {
        m19_prompt_wipe(secret.message, sizeof(secret.message));
        struct pollfd wait = {.fd = fd, .events = POLLIN};
        int ready;
        do
            ready = poll(&wait, 1, REPLY_MS);
        while (ready < 0 && errno == EINTR);
        ssize_t got = ready == 1 ? recv(fd, reply, sizeof(reply) - 1, 0) : -1;
        if (got <= 0)
            snprintf(reply, sizeof(reply), "M19_CE status=NO_REPLY");
        else
            reply[got] = 0;
    }
    m19_prompt_wipe(secret.message, sizeof(secret.message));
    if (fd >= 0)
        close(fd);
    p->size = 0;
    p->ok = m19_prompt_reply(reply, p->status, sizeof(p->status));
    if (!p->status[0])
        snprintf(p->status, sizeof(p->status), "FAILED");
    p->state = M19_PROMPT_DONE;
    record(result_path, reply);
}

static int grab(void)
{
    for (int tries = 0; tries < 50; tries++) {
        if (XGrabKeyboard(display, window, True, GrabModeAsync, GrabModeAsync, CurrentTime) == GrabSuccess &&
            XGrabPointer(display, window, True, ButtonPressMask, GrabModeAsync, GrabModeAsync, window, None, CurrentTime) == GrabSuccess)
            return 0;
        usleep(100000);
    }
    return -1;
}

int main(int argc, char **argv)
{
    if (argc != 3)
        return 64;
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    (void)mlock(&secret, sizeof(secret));
    display = XOpenDisplay(NULL);
    if (!display) {
        record(argv[2], "M19_CE status=NO_DISPLAY");
        return 1;
    }
    int screen = DefaultScreen(display);
    width = DisplayWidth(display, screen);
    height = DisplayHeight(display, screen);
    Colormap map = DefaultColormap(display, screen);
    color_back = rgb(map, 0x1000, 0x1400, 0x1c00);
    color_key = rgb(map, 0x3000, 0x3800, 0x4400);
    color_text = rgb(map, 0xf000, 0xf000, 0xf000);
    color_ok = rgb(map, 0x4000, 0xd000, 0x6000);
    color_bad = rgb(map, 0xf000, 0x5000, 0x4000);
    XSetWindowAttributes attributes = {.override_redirect = True, .background_pixel = color_back,
                                       .event_mask = ExposureMask | KeyPressMask | ButtonPressMask};
    window = XCreateWindow(display, RootWindow(display, screen), 0, 0, (unsigned)width, (unsigned)height, 0, CopyFromParent, InputOutput,
                           CopyFromParent, CWOverrideRedirect | CWBackPixel | CWEventMask, &attributes);
    XStoreName(display, window, "m19-ce-prompt");
    XMapRaised(display, window);
    gc = XCreateGC(display, window, 0, NULL);
    m19_prompt_layout(width, height, &layout);
    XSync(display, False);
    if (grab()) {
        record(argv[2], "M19_CE status=NO_GRAB");
        XCloseDisplay(display);
        return 1;
    }
    draw();
    long long done_at = 0;
    for (;;) {
        if (secret.prompt.state == M19_PROMPT_DONE && now_ms() - done_at > DONE_MS)
            break;
        if (!XPending(display)) {
            struct pollfd wait = {.fd = ConnectionNumber(display), .events = POLLIN};
            (void)poll(&wait, 1, 200);
            continue;
        }
        XEvent event;
        XNextEvent(display, &event);
        if (event.xany.send_event)
            continue;
        char key = 0;
        if (event.type == Expose) {
            draw();
        } else if (event.type == ButtonPress && event.xbutton.button == Button1) {
            key = m19_prompt_hit(&layout, event.xbutton.x, event.xbutton.y);
        } else if (event.type == KeyPress) {
            KeySym sym = NoSymbol;
            int got = XLookupString(&event.xkey, secret.keys, sizeof(secret.keys), &sym, NULL);
            if (got == 1 && secret.keys[0] >= '0' && secret.keys[0] <= '9')
                key = secret.keys[0];
            else if (sym == XK_BackSpace)
                key = 'B';
            else if (sym == XK_Return || sym == XK_KP_Enter)
                key = 'U';
            else if (sym == XK_Escape)
                key = 'C';
            m19_prompt_wipe(secret.keys, sizeof(secret.keys));
            m19_prompt_wipe(&event, sizeof(event));
        }
        if (!key)
            continue;
        enum m19_prompt_action action = m19_prompt_key(&secret.prompt, key);
        key = 0;
        if (action == M19_PROMPT_EXIT)
            break;
        if (action == M19_PROMPT_CANCEL) {
            record(argv[2], "M19_CE status=CANCELLED");
            break;
        }
        if (action == M19_PROMPT_REDRAW)
            draw();
        if (action == M19_PROMPT_SEND) {
            draw();
            unlock(argv[1], argv[2]);
            done_at = now_ms();
            draw();
        }
    }
    int ok = secret.prompt.ok;
    m19_prompt_wipe(&secret, sizeof(secret));
    XUngrabKeyboard(display, CurrentTime);
    XUngrabPointer(display, CurrentTime);
    XCloseDisplay(display);
    return ok ? 0 : 1;
}
