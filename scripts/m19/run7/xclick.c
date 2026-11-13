/* xclick <keys>: taps the keypad of a running m19-ce-prompt through XTEST, as a touchscreen's emulated
 * pointer would. Waits for the prompt's window first. Test only, never staged. */
#include <X11/Xlib.h>
#include <X11/extensions/XTest.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "prompt.h"

static int named(Display *display, Window root)
{
    Window parent, *children = NULL;
    unsigned count = 0;
    int found = 0;
    if (!XQueryTree(display, root, &root, &parent, &children, &count))
        return 0;
    for (unsigned i = 0; i < count && !found; i++) {
        char *name = NULL;
        if (XFetchName(display, children[i], &name) && name) {
            found = !strcmp(name, "m19-ce-prompt");
            XFree(name);
        }
    }
    if (children)
        XFree(children);
    return found;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 64;
    Display *display = XOpenDisplay(NULL);
    if (!display)
        return 2;
    int screen = DefaultScreen(display);
    for (int tries = 0; !named(display, RootWindow(display, screen)); tries++) {
        if (tries > 100)
            return 3;
        usleep(100000);
    }
    usleep(500000);
    struct m19_prompt_layout layout;
    m19_prompt_layout(DisplayWidth(display, screen), DisplayHeight(display, screen), &layout);
    for (const char *k = argv[1]; *k; k++) {
        for (int i = 0; i < M19_PROMPT_KEYS; i++) {
            if (layout.labels[i] != *k)
                continue;
            const struct m19_rect *r = &layout.keys[i];
            XTestFakeMotionEvent(display, screen, r->x + r->w / 2, r->y + r->h / 2, 0);
            XTestFakeButtonEvent(display, 1, True, 0);
            XTestFakeButtonEvent(display, 1, False, 0);
            XSync(display, False);
            usleep(50000);
        }
    }
    XCloseDisplay(display);
    return 0;
}
