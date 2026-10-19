/* B3 cross-check driver: one hex-encoded cmdline per stdin line -> m11_entry_cmdline_summary() per
 * stdout line (test-cmdline-summary.py compares it with cmdline_summary.py). No device. */
#ifndef M11_CUSTODIAN_NATIVE
#error "test-cmdline-summary.c builds only with M11_CUSTODIAN_NATIVE"
#endif
#define _GNU_SOURCE
#include "custodian_entry_native.h"
#include <stdio.h>
#include <string.h>

static int hexval(int c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; }

int main(void) {
    static char line[2 * 4096 + 8], text[4096];
    while (fgets(line, sizeof line, stdin)) {
        size_t n = strcspn(line, "\n"), k = 0;
        if (n % 2 || n / 2 > sizeof text - 1) return 2;
        for (size_t i = 0; i < n; i += 2) {
            int hi = hexval(line[i]), lo = hexval(line[i + 1]);
            if (hi < 0 || lo < 0) return 2;
            text[k++] = (char)(hi * 16 + lo);
        }
        text[k] = 0;
        char out[112];
        (void)m11_entry_cmdline_summary(text, out, sizeof out);
        puts(out);
    }
    return 0;
}
