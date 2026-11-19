#ifndef M18_SHUTDOWN_TRACE_H
#define M18_SHUTDOWN_TRACE_H

#include <sys/types.h>

/* Append one bounded snapshot of live userspace tasks. No command-line arguments are read. */
int m18_shutdown_snapshot(const char *proc, const char *log, pid_t spinner);

#endif
