/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_NATIVE_IO_H
#define M15_NATIVE_IO_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
struct read_fact {ssize_t count;int error,close_error;};
/* Worker-only: nonblocking does not bound a vendor sysfs callback. */
struct read_fact read_attribute(const char *,char *,size_t);
struct klog {uint64_t first,last;size_t bytes;int have,failed;};
int klog_record(struct klog *,const unsigned char *,size_t,size_t);
int klog_read(int,struct klog *,unsigned char *,size_t,size_t,struct read_fact *);
int configured_pc(const char *,size_t);
#endif
