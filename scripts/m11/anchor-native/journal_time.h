/* Journal timestamps at /proc/uptime's granularity (fix for the Run22 strict-evidence defect,
 * docs/m11-run22-result.md). The shell journal (instrumentation/journal.sh) stamps a record with
 * the first field of /proc/uptime, which fs/proc/uptime.c prints as CLOCK_BOOTTIME floored to
 * centiseconds ("%lu.%02lu", tv_nsec / (NSEC_PER_SEC / 100)). Run22's runner stamped its records
 * with CLOCK_MONOTONIC in nanoseconds (12.623805880), so the later journal_finish record (12.62)
 * compared lower and evidence.py rejected the journal. Every C record now uses the same clock
 * and the same floor: a shell record made later can never compare lower. */
#ifndef M11_JOURNAL_TIME_H
#define M11_JOURNAL_TIME_H
#include <stdio.h>
#include <time.h>

/* "<seconds>.<centiseconds>" from t, floored; length, or -1 on an invalid time or short buffer. */
static inline int m11_journal_format(char *b, size_t cap, const struct timespec *t) {
    if (!b || !cap || !t || t->tv_sec<0 || t->tv_nsec<0 || t->tv_nsec>=1000000000L) return -1;
    int n=snprintf(b,cap,"%lld.%02ld",(long long)t->tv_sec,(long)(t->tv_nsec/10000000L));
    return n>0 && (size_t)n<cap?n:-1;
}
static inline int m11_journal_stamp(char *b, size_t cap) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME,&t)) return -1;
    return m11_journal_format(b,cap,&t);
}
#endif
