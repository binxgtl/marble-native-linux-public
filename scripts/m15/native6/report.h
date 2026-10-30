/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_REPORT_H
#define M15_REPORT_H
#include "qr.h"
#include <stddef.h>
#include <stdint.h>
#define M15_REPORT_PAGES 16
#define M15_REPORT_ERROR 160
/* The failing line, then the journal tail, error-level kernel lines and the kernel tail.
 * Missing files are named, never treated as empty success. */
size_t m15_report_text(const char *dir,char *out,size_t cap,char error[M15_REPORT_ERROR]);
/* Splits at line ends. start[pages] is the end of the text. Returns the page count. */
unsigned m15_report_paginate(const char *text,size_t n,size_t start[M15_REPORT_PAGES+1]);
/* Fills one page with its "M15 RED p/n" header. Returns its length. */
size_t m15_report_page(const char *text,const size_t start[M15_REPORT_PAGES+1],unsigned page,unsigned pages,char *out,size_t cap);
/* "M15 ERROR:" text, the QR and its page marks, over the red screen. */
void m15_report_show(void *map,uint32_t pitch,const char *error,const unsigned char m[M15_QR_SIZE][M15_QR_SIZE],unsigned page,unsigned pages);
/* RED screen: cycles every page. Never returns, releases nothing. */
_Noreturn void m15_report_loop(void *map,uint32_t pitch,const char *dir);
#endif
