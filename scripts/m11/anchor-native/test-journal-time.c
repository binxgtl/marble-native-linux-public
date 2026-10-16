/* journal_time.h: the C journal stamp never compares above a later /proc/uptime read (the Run22
 * strict-evidence defect). No arguments: format cases and a live stamp-then-uptime race check.
 * "append <journal> <first-seq> <count> cs|ns": append runner-format records (cs = journal_time.h,
 * ns = Run22's CLOCK_MONOTONIC nanoseconds), driven by test-journal-time.py with journal.sh. */
#define _GNU_SOURCE
#include "journal_time.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static long long centis(const char *s) { /* "<s>.<cc>" or "<s>.<ns>" -> floored centiseconds */
    char *end; long long sec=strtoll(s,&end,10); assert(*end=='.');
    const char *f=end+1; size_t digits=strspn(f,"0123456789"); assert(digits>=2);
    return sec*100+(f[0]-'0')*10+(f[1]-'0');
}
static long long uptime_centis(void) {
    char b[128]; FILE *f=fopen("/proc/uptime","r"); assert(f);
    assert(fgets(b,sizeof(b),f)); fclose(f);
    *strchr(b,' ')=0; return centis(b);
}
static int append(int argc, char **argv) {
    if (argc!=6) return 2;
    FILE *j=fopen(argv[2],"a"); if (!j) return 3;
    unsigned seq=(unsigned)strtoul(argv[3],NULL,10); int count=atoi(argv[4]);
    for (int i=0;i<count;i++) {
        char stamp[32];
        if (!strcmp(argv[5],"cs")) { if (m11_journal_stamp(stamp,sizeof(stamp))<0) return 4; }
        else { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);
               snprintf(stamp,sizeof(stamp),"%lld.%09ld",(long long)t.tv_sec,t.tv_nsec); }
        /* runner.c record(): payload "ok" hex-encoded. */
        if (fprintf(j,"M11I1 %u %s session runner_step metadata 0 6f6b\n",seq+i,stamp)<0) return 5;
    }
    return fclose(j)?6:0;
}
int main(int argc, char **argv) {
    if (argc>1 && !strcmp(argv[1],"append")) return append(argc,argv);
    char b[32];
    struct timespec t={12,623805880};
    assert(m11_journal_format(b,sizeof(b),&t)==5 && !strcmp(b,"12.62"));
    t=(struct timespec){0,0}; assert(m11_journal_format(b,sizeof(b),&t)==4 && !strcmp(b,"0.00"));
    t=(struct timespec){5,999999999}; assert(m11_journal_format(b,sizeof(b),&t)>0 && !strcmp(b,"5.99"));
    t=(struct timespec){7,9999999}; assert(m11_journal_format(b,sizeof(b),&t)>0 && !strcmp(b,"7.00"));
    t=(struct timespec){7,1000000000L}; assert(m11_journal_format(b,sizeof(b),&t)==-1);
    t=(struct timespec){-1,0}; assert(m11_journal_format(b,sizeof(b),&t)==-1);
    t=(struct timespec){123,0}; assert(m11_journal_format(b,6,&t)==-1); /* "123.00" needs 7 */
    assert(m11_journal_format(b,7,&t)==6);
    /* The Run22 pair: the ns stamp compares above the later centisecond uptime record. */
    assert(strtod("12.623805880",NULL)>strtod("12.62",NULL));
    long long last=-1; unsigned long rounds=0;
    for (int i=0;i<200000;i++) {
        assert(m11_journal_stamp(b,sizeof(b))>0);
        long long c=centis(b), u=uptime_centis();
        assert(c>=last); assert(u>=c); last=c; rounds++;
    }
    printf("PASS journal stamp: CLOCK_BOOTTIME floored to centiseconds; %lu live stamp-then-/proc/uptime "
           "reads, none above the later uptime; format edge cases\n",rounds);
    return 0;
}
