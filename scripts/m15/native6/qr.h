/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M15_QR_H
#define M15_QR_H
#include <stddef.h>
/* One fixed symbol: QR version 30, level L, mask 0, byte mode. */
#define M15_QR_SIZE 137
#define M15_QR_CAPACITY 1732
/* modules[y][x] is nonzero for a dark module. Returns -1 if n exceeds the capacity. */
int m15_qr_encode(const void *text,size_t n,unsigned char modules[M15_QR_SIZE][M15_QR_SIZE]);
#endif
