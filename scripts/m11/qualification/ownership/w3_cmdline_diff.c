/* TEST-ONLY W3 differential: m11_custodian_cmdline_allowed() vs a reference built from
 * VERBATIM pinned-ACK kernel code (ack_ref.inc: _ctype/isspace, skip_spaces, next_arg,
 * parameq) driven exactly like kernel/params.c parse_args() (stop at a bare "--").
 *   ref_nostop : same loop without the "--" stop. The custodian must EQUAL it.
 *   ref_kernel : real kernel loop. The custodian must NEVER be more permissive.
 * Inputs on which the pinned next_arg() is undefined (final token a lone '"') are never
 * executed by the reference; the custodian must REJECT every one of them.
 * Usage: w3_cmdline_diff <random_cases> <seed>; ack_ref.inc comes from gen_ack_ref.py and
 * is never committed (GPL kernel source). */
#include "m11_custodian.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define _ctype m11_ack_ctype   /* avoid clashing with the C runtime's own _ctype symbol */
#include "ack_ref.inc"

#define REF_MAX 8192
static int ref_gate(const char *s, bool stop_at_dashdash) {
    static char buf[REF_MAX];
    size_t n = strlen(s);
    if (n >= REF_MAX) return -1;
    memcpy(buf, s, n + 1);
    char *args = skip_spaces(buf);
    while (*args) {
        char *param, *val;
        /* Pinned ACK next_arg() (lib/cmdline.c:238) evaluates args[i-1] with unsigned
         * i == 0 when a token is exactly one '"' at the end of the string: an
         * out-of-bounds read ~4 GiB past the buffer (and a write if that byte is '"').
         * Upstream master guards it with "i > 0". Do not execute UB; report the input. */
        if (args[0] == '"' && args[1] == '\0') return -2;
        args = next_arg(args, &param, &val);
        if (stop_at_dashdash && !val && strcmp(param, "--") == 0) return 1; /* rest goes to init */
        if (parameq(param, "iommu.strict")) { if (!val || strcmp(val, "1") != 0) return 0; }
        else if (parameq(param, "iommu.passthrough")) { if (!val || strcmp(val, "0") != 0) return 0; }
    }
    return 1;
}
static void put_escaped(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p >= 32 && *p < 127) putchar(*p);
        else printf("\\x%02x", *p);
    }
    putchar('"');
}
static unsigned long long checked, equal_nostop, stricter, permissive, stricter_dd, mismatch_nostop;
static unsigned long long ub_inputs, ub_custodian_accepts;
static bool has_dashdash_token(const char *s) {
    /* conservative detector: a bare "--" token as produced by the reference tokenizer */
    static char buf[REF_MAX];
    size_t n = strlen(s); if (n >= REF_MAX) return false;
    memcpy(buf, s, n + 1);
    char *args = skip_spaces(buf);
    while (*args) { char *p, *v; args = next_arg(args, &p, &v); if (!v && !strcmp(p, "--")) return true; }
    return false;
}
static void check(const char *s, const char *origin) {
    int got = m11_custodian_cmdline_allowed(s) ? 1 : 0;
    int rn = ref_gate(s, false), rk = ref_gate(s, true);
    if (rn == -2 || rk == -2) { /* kernel behavior undefined: classify, never compare */
        ub_inputs++; if (got) ub_custodian_accepts++;
        if (ub_inputs <= 5) { printf("KERNEL-UB-INPUT %s custodian=%d ", origin, got); put_escaped(s); putchar('\n'); }
        return;
    }
    checked++;
    if (got == rn) equal_nostop++;
    else {
        if (++mismatch_nostop <= 10) { printf("MISMATCH(nostop) %s got=%d ref=%d ", origin, got, rn); put_escaped(s); putchar('\n'); }
    }
    if (got > rk) { if (++permissive <= 10) { printf("MORE-PERMISSIVE %s got=%d kernel=%d ", origin, got, rk); put_escaped(s); putchar('\n'); } }
    else if (got < rk) { stricter++; if (has_dashdash_token(s)) stricter_dd++; }
}
static uint64_t rng;
static uint64_t xr(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }

int main(int argc, char **argv) {
    unsigned long long n_random = argc > 1 ? strtoull(argv[1], NULL, 0) : 1000000ull;
    rng = argc > 2 ? strtoull(argv[2], NULL, 0) : 0x9e3779b97f4a7c15ull;
    if (!rng) rng = 1;
    /* 1. The fixed cases of test_custodian.c, with their expected decisions. */
    static const char *good[] = {"console=null iommu.strict=1","console=null","iommu.strict=\"1\"",
        "\"iommu.strict=1\"","iommu.passthrough=0","  iommu.strict=1   ","iommu_strict=0",
        "foo=\"a iommu.strict=0\"","iommu.strict=1 iommu.passthrough=0"};
    static const char *bad[] = {"iommu.strict=0","iommu.strict=false","iommu.strict=off",
        "iommu.strict=1 iommu.strict=0","iommu.strict=", "iommu.strict=1garbage",
        "\"iommu.strict=0\"","iommu.strict=\"0\"","x\tiommu.strict=0",("x\xa0" "iommu.strict=0"),
        "iommu.passthrough=1","iommu.passthrough=y","iommu.passthrough=on","iommu.passthrough",
        "iommu.strict","a -- iommu.strict=0"};
    /* Pinned next_arg() UB inputs (must REJECT) and their safe neighbours (must ACCEPT). */
    static const char *ub[] = {"\"","console=null \"","foo=bar \"","iommu.strict=1 \"","\t\""};
    static const char *near_ub[] = {"console=null \"x\"","a \"   ","foo=\"","foo=bar \"\""};
    unsigned fixed_ok = 0, fixed_n = 0;
    printf("%-4s %-8s %-6s %-10s %-10s %s\n", "#", "expect", "got", "ref_nostop", "ref_kernel", "cmdline");
    for (unsigned k = 0; k < sizeof(good)/sizeof(good[0]); k++) {
        int got = m11_custodian_cmdline_allowed(good[k]);
        int rn = ref_gate(good[k], false), rk = ref_gate(good[k], true);
        fixed_n++; if (got == 1 && rn == 1) fixed_ok++;
        printf("%-4u %-8s %-6d %-10d %-10d ", fixed_n, "ACCEPT", got, rn, rk); put_escaped(good[k]); putchar('\n');
    }
    { /* NULL: the custodian must reject; the kernel reference has no NULL input. */
        int got = m11_custodian_cmdline_allowed(NULL);
        fixed_n++; if (got == 0) fixed_ok++;
        printf("%-4u %-8s %-6d %-10s %-10s NULL\n", fixed_n, "REJECT", got, "n/a", "n/a");
    }
    for (unsigned k = 0; k < sizeof(bad)/sizeof(bad[0]); k++) {
        int got = m11_custodian_cmdline_allowed(bad[k]);
        int rn = ref_gate(bad[k], false), rk = ref_gate(bad[k], true);
        fixed_n++; if (got == 0 && rn == 0) fixed_ok++;
        printf("%-4u %-8s %-6d %-10d %-10d ", fixed_n, "REJECT", got, rn, rk); put_escaped(bad[k]); putchar('\n');
    }
    { static char overlong[5000]; memset(overlong, 'a', sizeof(overlong) - 1);
        int got = m11_custodian_cmdline_allowed(overlong);
        fixed_n++; if (got == 0) fixed_ok++;
        printf("%-4u %-8s %-6d %-10s %-10s <4999 x 'a'>\n", fixed_n, "REJECT", got, "n/a", "n/a"); }
    for (unsigned k = 0; k < sizeof(ub)/sizeof(ub[0]); k++) {
        int got = m11_custodian_cmdline_allowed(ub[k]);
        int rn = ref_gate(ub[k], false), rk = ref_gate(ub[k], true);
        fixed_n++; if (got == 0 && rn == -2 && rk == -2) fixed_ok++;
        printf("%-4u %-8s %-6d %-10d %-10d ", fixed_n, "REJ-UB", got, rn, rk); put_escaped(ub[k]); putchar('\n');
    }
    for (unsigned k = 0; k < sizeof(near_ub)/sizeof(near_ub[0]); k++) {
        int got = m11_custodian_cmdline_allowed(near_ub[k]);
        int rn = ref_gate(near_ub[k], false), rk = ref_gate(near_ub[k], true);
        fixed_n++; if (got == 1 && rn == 1 && rk == 1) fixed_ok++;
        printf("%-4u %-8s %-6d %-10d %-10d ", fixed_n, "ACCEPT", got, rn, rk); put_escaped(near_ub[k]); putchar('\n');
    }
    printf("FIXED: %u/%u cases match expectation (13 accept, 17 reject, 1 overlong, 5 kernel-UB reject)\n",
           fixed_ok, fixed_n);
    for (unsigned k = 0; k < sizeof(good)/sizeof(good[0]); k++) check(good[k], "fixed");
    for (unsigned k = 0; k < sizeof(bad)/sizeof(bad[0]); k++) check(bad[k], "fixed");
    for (unsigned k = 0; k < sizeof(ub)/sizeof(ub[0]); k++) check(ub[k], "fixed");
    for (unsigned k = 0; k < sizeof(near_ub)/sizeof(near_ub[0]); k++) check(near_ub[k], "fixed");

    /* 2. Every byte 1..255 as a separator before a relaxed or a strict option. */
    static char s[REF_MAX];
    for (int b = 1; b < 256; b++) {
        snprintf(s, sizeof s, "x%ciommu.strict=0", (char)b); check(s, "sep-sweep");
        snprintf(s, sizeof s, "iommu.strict=1%ciommu.passthrough=1", (char)b); check(s, "sep-sweep");
        snprintf(s, sizeof s, "iommu.strict=1%c", (char)b); check(s, "sep-sweep");
    }
    /* 3. One and two double quotes at every position of option tokens. */
    static const char *bases[] = {"iommu.strict=0","iommu.strict=1","iommu.passthrough=1",
        "iommu.passthrough=0","foo=bar iommu.strict=0","iommu.strict=1 iommu.passthrough=1",
        "a -- iommu.strict=0","=iommu.strict=0","iommu-strict=0","iommu_passthrough=1"};
    for (unsigned k = 0; k < sizeof(bases)/sizeof(bases[0]); k++) {
        size_t L = strlen(bases[k]);
        for (size_t i = 0; i <= L; i++) {
            snprintf(s, sizeof s, "%.*s\"%s", (int)i, bases[k], bases[k] + i); check(s, "quote1");
            for (size_t j = i; j <= L; j++) {
                snprintf(s, sizeof s, "%.*s\"%.*s\"%s", (int)i, bases[k], (int)(j - i), bases[k] + i, bases[k] + j);
                check(s, "quote2");
            }
        }
    }
    /* 4. Random structured cmdlines. */
    static const char *frag[] = {"iommu.strict","iommu.passthrough","iommu_strict","iommu-strict",
        "iommu.passthroug","iommu.strictx","=","=","\"","\""," "," ","\t","\n","\r","\v","\f",
        "\xa0","0","1","y","n","on","off","t","f","--","-","_","foo","x","1garbage","==","\"\"",
        "console=null","a=b","iommu.strict=1","iommu.strict=0","iommu.passthrough=0","iommu.passthrough=1"};
    const unsigned nf = sizeof(frag)/sizeof(frag[0]);
    for (unsigned long long it = 0; it < n_random; it++) {
        size_t len = 0; unsigned parts = (unsigned)(xr() % 14u);
        s[0] = '\0';
        for (unsigned p = 0; p < parts; p++) {
            const char *f; char raw[2];
            if (xr() % 9u == 0) { raw[0] = (char)(1 + xr() % 255u); raw[1] = '\0'; f = raw; }
            else f = frag[xr() % nf];
            size_t fl = strlen(f);
            if (len + fl + 1 >= 900) break;
            memcpy(s + len, f, fl + 1); len += fl;
        }
        check(s, "random");
    }
    printf("DIFF: checked=%llu equal_to_ref_nostop=%llu mismatch_nostop=%llu "
           "more_permissive_than_kernel=%llu stricter_than_kernel=%llu (of which with bare \"--\": %llu)\n",
           checked, equal_nostop, mismatch_nostop, permissive, stricter, stricter_dd);
    printf("KERNEL-UB inputs (final token is a lone '\"'; pinned ACK lacks upstream i>0 guard): "
           "%llu generated, custodian accepted %llu of them\n", ub_inputs, ub_custodian_accepts);
    bool ok = fixed_ok == fixed_n && fixed_n == 36 && mismatch_nostop == 0 && permissive == 0 &&
              stricter == stricter_dd && ub_inputs > 0 && ub_custodian_accepts == 0;
    puts(ok ? "PASS W3: gate equals verbatim ACK next_arg/parameq tokenizer; stricter only after a bare \"--\";"
              " rejects every kernel-UB input"
            : "FAIL W3");
    return ok ? 0 : 1;
}
