/* M17 selector KMS (kms.c, docs/m17-g4.md). */
#ifndef M17_KMS_H
#define M17_KMS_H

#include <stdint.h>

#define M17_KMS_OK 0
#define M17_KMS_FAILED 1
#define M17_KMS_UNSAFE_ROLLBACK 2

struct m17_kms {
	int fd;
	uint32_t connector, crtc, plane, blob, pitch;
	uint64_t size;
	uint32_t props[13];
	uint64_t values[13];
	struct {
		uint32_t handle, fb;
		void *map;
	} buf[2];
	int committed;
};

/* Finds the DSI panel's 1080x2400@60 mode, a free XRGB8888 primary plane and its CRTC as M7 D4 did, makes two
 * dumb buffers and their framebuffers, and tests both the enable and the disable. 0, or -1 with everything freed. */
int m17_kms_open(struct m17_kms *k, const char *card_path);
/* Buffer i (0 or 1) for drawing; pitch in pixels. */
uint32_t *m17_kms_pixels(struct m17_kms *k, int i, uint32_t *pitch_pixels);
/* Scans out buffer i: the first time with a modeset, then plain commits. 0 or -1. */
int m17_kms_show(struct m17_kms *k, int i);
/* Disables and verifies by readback, then frees: M17_KMS_OK, M17_KMS_FAILED (never opened) or
 * M17_KMS_UNSAFE_ROLLBACK (the disable could not be verified; the buffers are kept). */
int m17_kms_close(struct m17_kms *k);

#endif
