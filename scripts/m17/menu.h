/* M17 selector menu: what the 10 s window shows, drawn by the CPU into an XRGB8888 buffer (docs/m17-g4.md).
 * Pure: no device. The selector draws a frame into a scan-out buffer each second. */
#ifndef M17_MENU_INCLUDED
#define M17_MENU_INCLUDED

#include <stdint.h>

#define M17_MENU_W 1080u
#define M17_MENU_H 2400u
#define M17_MENU_BG 0x00101828u
#define M17_MENU_TEXT 0x00ffffffu
#define M17_MENU_ANDROID 0x0030a050u
#define M17_MENU_NATIVE 0x00e07020u
#define M17_MENU_BAR 0x00f0f0f0u
#define M17_MENU_BAR_Y 2100u
#define M17_MENU_BAR_H 60u
#define M17_MENU_BAR_X 90u
#define M17_MENU_BAR_W 900u

/* Draws the whole menu: the title, Volume Up for Android, Volume Down for Ubuntu (or that Ubuntu is not in this
 * build), the seconds left, and a bar as wide as the time left. pitch is in pixels. */
void m17_menu_draw(uint32_t *pixels, uint32_t pitch, unsigned left_ms, unsigned total_ms, int native_available);
/* A line of text at (x, y), each 5x7 glyph scaled by `scale`; unknown characters are blank. */
void m17_menu_text(uint32_t *pixels, uint32_t pitch, unsigned x, unsigned y, unsigned scale, uint32_t colour, const char *text);
/* The bar's lit width for the time left: M17_MENU_BAR_W when full, 0 when none. */
unsigned m17_menu_bar_width(unsigned left_ms, unsigned total_ms);

#endif
