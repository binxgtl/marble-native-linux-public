/* M19 R4k: a preload library for one GL program at a time, never for the X server or the session.
 *
 * R4j proved every part of DRI3 on its own and left two causes for programs showing black: the X server not
 * seeing what is drawn into a buffer after it imported it, or the X server copying a frame before the GPU has
 * drawn it. The tree's Mesa does no implicit sync on KGSL, and freedreno on KGSL submits through a deferred
 * queue. This library tests the second cause: it wraps glXSwapBuffers and calls glFinish first, so every frame
 * is drawn, and waited for, before it is presented. If the program then shows, ordering is the cause.
 *
 * It changes no file and no state, and it says once, on stderr, that it is in the program. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

typedef void (*finish_fn)(void);
typedef void (*swap_fn)(void *display, unsigned long drawable);

void glXSwapBuffers(void *display, unsigned long drawable)
{
    static finish_fn finish;
    static swap_fn real;
    static int told;
    if (!finish)
        finish = (finish_fn)dlsym(RTLD_NEXT, "glFinish");
    if (!real)
        real = (swap_fn)dlsym(RTLD_NEXT, "glXSwapBuffers");
    if (!told) {
        told = 1;
        fprintf(stderr, "M19 GLFINISH first swap: glFinish %s, glXSwapBuffers %s\n", finish ? "found" : "missing", real ? "found" : "missing");
    }
    if (finish)
        finish();
    if (real)
        real(display, drawable);
}
