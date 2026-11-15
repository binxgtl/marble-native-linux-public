/* M18 R3 (docs/m18-r3.md): the shutdown's spinner and its timeline. Twelve dots on a ring, the brightest one going
 * round, on black: symmetric, so it reads the same whichever way the phone is held. Drawn into the selector's KMS
 * buffers (scripts/m17/kms.c) once the X server has stopped, until the reset. */
#ifndef M18_BYE_INCLUDED
#define M18_BYE_INCLUDED

#include <stdint.h>

#define M18_BYE_W 1080u
#define M18_BYE_H 2400u
#define M18_BYE_DOTS 12u
#define M18_BYE_RING 110u      /* ring radius, pixels */
#define M18_BYE_DOT 13u        /* dot radius, pixels */
#define M18_BYE_FRAME_MS 33u   /* about 30 frames a second */
#define M18_BYE_STEP_FRAMES 3u /* the head moves one dot every 3 frames: a turn in about 1.2 s */

/* The grey level of dot `dot` at frame `frame`: 255 for the head, then 20 less per dot behind it, never under 40. */
uint32_t m18_bye_level(unsigned frame, unsigned dot);
/* Frame `frame` into an XRGB8888 buffer of width x height, pitch in pixels. With `full`, the whole buffer is cleared
 * to black first; otherwise only the spinner's square. Nothing is drawn outside the buffer. */
void m18_bye_frame(uint32_t *pixels, uint32_t width, uint32_t height, uint32_t pitch, unsigned frame, int full);
/* "<boot clock> M18 bye <what>\n" appended to path (0600, never through a link). 0 or -errno; a read-only root at the
 * end of the shutdown makes it fail, which is how the timeline ends. */
int m18_bye_log(const char *path, const char *what);

#endif
