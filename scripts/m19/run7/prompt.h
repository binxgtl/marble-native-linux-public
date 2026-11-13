/* The R7 keypad's logic (docs/m19-r7.md), apart from X11 so it can be tested on its own. */
#ifndef M19_PROMPT_H
#define M19_PROMPT_H

#include <stddef.h>
#include <stdint.h>

#define M19_PROMPT_PIN_MIN 4
#define M19_PROMPT_PIN_MAX 16
#define M19_PROMPT_KEYS 13

struct m19_rect {
    int x, y, w, h;
};

struct m19_prompt_layout {
    struct m19_rect keys[M19_PROMPT_KEYS]; /* "123456789C0B" in a 4x3 grid, then U (unlock) below it */
    char labels[M19_PROMPT_KEYS];
    struct m19_rect dots, message;
    int scale;
};

enum m19_prompt_state { M19_PROMPT_EDITING, M19_PROMPT_SENDING, M19_PROMPT_DONE };
enum m19_prompt_action { M19_PROMPT_NONE, M19_PROMPT_REDRAW, M19_PROMPT_SEND, M19_PROMPT_CANCEL, M19_PROMPT_EXIT };

struct m19_prompt {
    char pin[M19_PROMPT_PIN_MAX + 1];
    size_t size;
    enum m19_prompt_state state;
    int ok;
    char status[48];
};

void m19_prompt_layout(int width, int height, struct m19_prompt_layout *layout);
/* The key under (x, y): '0'..'9', 'B' backspace, 'C' cancel, 'U' unlock, or 0. */
char m19_prompt_hit(const struct m19_prompt_layout *layout, int x, int y);
/* One key from a tap or the keyboard. Digits and backspace only while editing; one SEND per run. */
enum m19_prompt_action m19_prompt_key(struct m19_prompt *prompt, char key);
/* "PIN:<digits>" into out; its length, or -1. */
int m19_prompt_message(const struct m19_prompt *prompt, char *out, size_t capacity);
/* The broker's reply: 1 for "M19_CE status=OK ...", 0 otherwise; status receives the status word. */
int m19_prompt_reply(const char *reply, char *status, size_t capacity);
/* 5x7 glyph rows for the characters the keypad draws; NULL for any other. */
const uint8_t *m19_prompt_glyph(char c);
void m19_prompt_wipe(void *data, size_t size);

#endif
