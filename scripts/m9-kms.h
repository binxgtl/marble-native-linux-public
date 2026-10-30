#ifndef MARBLE_M9_KMS_H
#define MARBLE_M9_KMS_H

#include <stdint.h>

struct m9_kms_buffer {
	int dma_buf_fd;
	uint32_t width;
	uint32_t height;
	uint32_t pitch;
	uint32_t offset;
};

#define M9_KMS_OK 0
#define M9_KMS_FAILED 1
#define M9_KMS_UNSAFE_ROLLBACK 2

typedef int (*m9_kms_checkpoint_fn)(void *opaque);

/*
 * Scan out a LINEAR XRGB8888 dma-buf using the frozen M7 D4 discovery,
 * atomic-property and rollback contract. Returns zero only after a successful
 * commit, bounded hold and verified atomic disable. An unsafe rollback has a
 * distinct result so the caller can hold without releasing live storage.
 */
int m9_kms_scanout(const char *card_path, const struct m9_kms_buffer *buffer,
		unsigned hold_ms);

/*
 * Run the same scanout contract, but call checkpoint() after PRIME, ADDFB2 and
 * both TEST_ONLY commits have succeeded and before the real atomic commit.
 * The imported GPU buffer, GEM handle, FB and mode blob remain owned by this
 * function across the callback.  A non-zero callback result fails closed
 * without issuing the real commit.
 */
int m9_kms_scanout_observed(const char *card_path,
		const struct m9_kms_buffer *buffer, unsigned hold_ms,
		m9_kms_checkpoint_fn checkpoint, void *opaque);

/* CPU-only M7 D4-derived control pulse. Uses a DRM dumb handle directly on
 * the owning card fd: no dma-heap, PRIME import, Vulkan or KGSL path. */
int m9_kms_cpu_checkpoint(const char *card_path, uint32_t xrgb8888,
		unsigned hold_ms);

#endif
