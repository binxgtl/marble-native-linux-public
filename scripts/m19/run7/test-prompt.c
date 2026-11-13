/* prompt.c on its own: layout, hit testing, one edit, the message and the reply. Test only. */
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "prompt.h"

static void check_layout(int width, int height)
{
    struct m19_prompt_layout layout;
    m19_prompt_layout(width, height, &layout);
    for (int i = 0; i < M19_PROMPT_KEYS; i++) {
        const struct m19_rect *r = &layout.keys[i];
        assert(r->w > 40 && r->h > 40 && r->x >= 0 && r->y >= 0 && r->x + r->w <= width && r->y + r->h <= height);
        /* The centre of every key finds that key, and keys never overlap. */
        assert(m19_prompt_hit(&layout, r->x + r->w / 2, r->y + r->h / 2) == layout.labels[i]);
        for (int j = 0; j < i; j++) {
            const struct m19_rect *o = &layout.keys[j];
            assert(r->x >= o->x + o->w || o->x >= r->x + r->w || r->y >= o->y + o->h || o->y >= r->y + r->h);
        }
    }
    assert(m19_prompt_hit(&layout, 0, 0) == 0);
    assert(layout.scale >= 1);
}

int main(void)
{
    check_layout(2400, 1080);
    check_layout(1080, 2400);
    check_layout(640, 480);

    struct m19_prompt p;
    memset(&p, 0, sizeof(p));
    char out[32];
    assert(m19_prompt_key(&p, 'U') == M19_PROMPT_NONE);
    assert(m19_prompt_key(&p, 'B') == M19_PROMPT_NONE);
    for (const char *k = "4829"; *k; k++)
        assert(m19_prompt_key(&p, *k) == M19_PROMPT_REDRAW);
    assert(m19_prompt_key(&p, 'B') == M19_PROMPT_REDRAW && p.size == 3 && p.pin[3] == 0);
    assert(m19_prompt_key(&p, 'U') == M19_PROMPT_NONE);
    assert(m19_prompt_key(&p, '1') == M19_PROMPT_REDRAW);
    assert(m19_prompt_message(&p, out, sizeof(out)) == 8 && !memcmp(out, "PIN:4821", 8));
    assert(m19_prompt_message(&p, out, 7) == -1);
    assert(m19_prompt_key(&p, 'U') == M19_PROMPT_SEND && p.state == M19_PROMPT_SENDING);
    /* One send per run: nothing edits or sends again. */
    assert(m19_prompt_key(&p, '5') == M19_PROMPT_NONE && m19_prompt_key(&p, 'U') == M19_PROMPT_NONE && p.size == 4);
    p.state = M19_PROMPT_DONE;
    assert(m19_prompt_key(&p, '5') == M19_PROMPT_EXIT);

    memset(&p, 0, sizeof(p));
    for (int i = 0; i < 20; i++)
        (void)m19_prompt_key(&p, '7');
    assert(p.size == M19_PROMPT_PIN_MAX);
    assert(m19_prompt_key(&p, 'x') == M19_PROMPT_NONE);
    assert(m19_prompt_key(&p, 'C') == M19_PROMPT_CANCEL && p.size == 0 && p.pin[0] == 0 && p.pin[15] == 0);

    memset(&p, 0, sizeof(p));
    memcpy(p.pin, "12a4", 4);
    p.size = 4;
    assert(m19_prompt_message(&p, out, sizeof(out)) == -1);

    char status[48];
    assert(m19_prompt_reply("M19_CE status=OK detail=0 version=3 timeout=0", status, sizeof(status)) == 1 && !strcmp(status, "OK"));
    assert(m19_prompt_reply("M19_CE status=GK_REJECTED detail=-1", status, sizeof(status)) == 0 && !strcmp(status, "GK_REJECTED"));
    assert(m19_prompt_reply("M19_CE status=OKAY", status, sizeof(status)) == 0 && !strcmp(status, "OKAY"));
    assert(m19_prompt_reply("M19_CE status=ok", status, sizeof(status)) == 0 && !status[0]);
    assert(m19_prompt_reply("status=OK", status, sizeof(status)) == 0 && !status[0]);
    assert(m19_prompt_reply("M19_CE status=", status, sizeof(status)) == 0);
    assert(m19_prompt_reply("M19_CE status=OK", status, 2) == 0);

    for (const char *c = "0123456789ANDROIDPINUNLOCKINGEDFAILRCTSHKMWY_ X<*."; *c; c++)
        assert(m19_prompt_glyph(*c));
    assert(!m19_prompt_glyph('a') && !m19_prompt_glyph('#'));
    printf("prompt logic PASS\n");
    return 0;
}
