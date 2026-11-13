/* The R7 keypad's logic: layout, hit testing, one PIN edit, the message and the reply (docs/m19-r7.md). */
#include <string.h>

#include "prompt.h"

void m19_prompt_wipe(void *data, size_t size)
{
    volatile uint8_t *bytes = data;
    while (size--)
        *bytes++ = 0;
}

void m19_prompt_layout(int width, int height, struct m19_prompt_layout *layout)
{
    static const char labels[] = "123456789C0BU";
    memset(layout, 0, sizeof(*layout));
    memcpy(layout->labels, labels, M19_PROMPT_KEYS);
    int landscape = width > height;
    /* The keypad takes the right half in landscape and the lower part in portrait. */
    int area_x = landscape ? width / 2 : 0, area_y = landscape ? 0 : height / 3;
    int area_w = landscape ? width - width / 2 : width, area_h = landscape ? height : height - height / 3;
    int cell = area_w / 3 < area_h / 5 ? area_w / 3 : area_h / 5;
    int gap = cell / 12 > 2 ? cell / 12 : 2;
    int grid_x = area_x + (area_w - 3 * cell) / 2, grid_y = area_y + (area_h - 5 * cell) / 2;
    for (int i = 0; i < 12; i++) {
        layout->keys[i] = (struct m19_rect){grid_x + (i % 3) * cell + gap, grid_y + (i / 3) * cell + gap, cell - 2 * gap, cell - 2 * gap};
    }
    layout->keys[12] = (struct m19_rect){grid_x + gap, grid_y + 4 * cell + gap, 3 * cell - 2 * gap, cell - 2 * gap};
    int info_x = landscape ? 0 : 0, info_w = landscape ? width / 2 : width, info_h = landscape ? height : height / 3;
    layout->scale = cell / 14 > 1 ? cell / 14 : 1;
    layout->dots = (struct m19_rect){info_x + info_w / 10, info_h / 3, info_w * 8 / 10, info_h / 6};
    layout->message = (struct m19_rect){info_x + info_w / 10, info_h * 3 / 5, info_w * 8 / 10, info_h / 6};
}

char m19_prompt_hit(const struct m19_prompt_layout *layout, int x, int y)
{
    for (int i = 0; i < M19_PROMPT_KEYS; i++) {
        const struct m19_rect *r = &layout->keys[i];
        if (x >= r->x && x < r->x + r->w && y >= r->y && y < r->y + r->h)
            return layout->labels[i];
    }
    return 0;
}

enum m19_prompt_action m19_prompt_key(struct m19_prompt *prompt, char key)
{
    if (prompt->state == M19_PROMPT_DONE)
        return M19_PROMPT_EXIT;
    if (prompt->state != M19_PROMPT_EDITING)
        return M19_PROMPT_NONE;
    if (key >= '0' && key <= '9') {
        if (prompt->size >= M19_PROMPT_PIN_MAX)
            return M19_PROMPT_NONE;
        prompt->pin[prompt->size++] = key;
        return M19_PROMPT_REDRAW;
    }
    if (key == 'B') {
        if (!prompt->size)
            return M19_PROMPT_NONE;
        prompt->pin[--prompt->size] = 0;
        return M19_PROMPT_REDRAW;
    }
    if (key == 'C') {
        m19_prompt_wipe(prompt->pin, sizeof(prompt->pin));
        prompt->size = 0;
        return M19_PROMPT_CANCEL;
    }
    if (key == 'U' && prompt->size >= M19_PROMPT_PIN_MIN) {
        prompt->state = M19_PROMPT_SENDING;
        return M19_PROMPT_SEND;
    }
    return M19_PROMPT_NONE;
}

int m19_prompt_message(const struct m19_prompt *prompt, char *out, size_t capacity)
{
    if (prompt->size < M19_PROMPT_PIN_MIN || prompt->size > M19_PROMPT_PIN_MAX || capacity < 4 + prompt->size)
        return -1;
    for (size_t i = 0; i < prompt->size; i++)
        if (prompt->pin[i] < '0' || prompt->pin[i] > '9')
            return -1;
    memcpy(out, "PIN:", 4);
    memcpy(out + 4, prompt->pin, prompt->size);
    return (int)(4 + prompt->size);
}

int m19_prompt_reply(const char *reply, char *status, size_t capacity)
{
    static const char head[] = "M19_CE status=";
    status[0] = 0;
    if (strncmp(reply, head, sizeof(head) - 1))
        return 0;
    const char *word = reply + sizeof(head) - 1;
    size_t length = strcspn(word, " \n");
    if (!length || length >= capacity)
        return 0;
    for (size_t i = 0; i < length; i++)
        if (!((word[i] >= 'A' && word[i] <= 'Z') || word[i] == '_'))
            return 0;
    memcpy(status, word, length);
    status[length] = 0;
    return !strcmp(status, "OK");
}

/* Rows of 5 bits, the top row first, the most significant of the five on the left. */
static const struct {
    char c;
    uint8_t rows[7];
} GLYPHS[] = {
    {'0', {14, 17, 19, 21, 25, 17, 14}}, {'1', {4, 12, 4, 4, 4, 4, 14}},    {'2', {14, 17, 1, 2, 4, 8, 31}},
    {'3', {31, 2, 4, 2, 1, 17, 14}},     {'4', {2, 6, 10, 18, 31, 2, 2}},   {'5', {31, 16, 30, 1, 1, 17, 14}},
    {'6', {6, 8, 16, 30, 17, 17, 14}},   {'7', {31, 1, 2, 4, 8, 8, 8}},     {'8', {14, 17, 17, 14, 17, 17, 14}},
    {'9', {14, 17, 17, 15, 1, 2, 12}},   {'A', {14, 17, 17, 31, 17, 17, 17}}, {'B', {30, 17, 17, 30, 17, 17, 30}},
    {'C', {14, 17, 16, 16, 16, 17, 14}}, {'D', {28, 18, 17, 17, 17, 18, 28}}, {'E', {31, 16, 16, 30, 16, 16, 31}},
    {'F', {31, 16, 16, 30, 16, 16, 16}}, {'G', {14, 17, 16, 23, 17, 17, 15}}, {'H', {17, 17, 17, 31, 17, 17, 17}},
    {'I', {14, 4, 4, 4, 4, 4, 14}},      {'K', {17, 18, 20, 24, 20, 18, 17}}, {'L', {16, 16, 16, 16, 16, 16, 31}},
    {'M', {17, 27, 21, 21, 17, 17, 17}}, {'N', {17, 17, 25, 21, 19, 17, 17}}, {'O', {14, 17, 17, 17, 17, 17, 14}},
    {'P', {30, 17, 17, 30, 16, 16, 16}}, {'R', {30, 17, 17, 30, 20, 18, 17}}, {'S', {15, 16, 16, 14, 1, 1, 30}},
    {'T', {31, 4, 4, 4, 4, 4, 4}},       {'U', {17, 17, 17, 17, 17, 17, 14}}, {'W', {17, 17, 17, 21, 21, 21, 10}},
    {'Y', {17, 17, 10, 4, 4, 4, 4}},     {'_', {0, 0, 0, 0, 0, 0, 31}},     {' ', {0, 0, 0, 0, 0, 0, 0}},
    {'.', {0, 0, 0, 0, 0, 12, 12}},      {'*', {0, 4, 21, 14, 21, 4, 0}},   {'<', {2, 4, 8, 16, 8, 4, 2}},
    {'X', {17, 17, 10, 4, 10, 17, 17}},
};

const uint8_t *m19_prompt_glyph(char c)
{
    for (size_t i = 0; i < sizeof(GLYPHS) / sizeof(GLYPHS[0]); i++)
        if (GLYPHS[i].c == c)
            return GLYPHS[i].rows;
    return NULL;
}
