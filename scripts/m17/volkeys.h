/* M17 G5: the volume keys in the Ubuntu session (docs/m17-g5.md). The operator's request: "ở ubuntu cải thiện cả 2 nút
 * tăng giảm âm lượng ... combo phím chụp ảnh ... hoặc là thật sự tăng giảm luôn".
 *
 * Volume Up and Volume Down step PulseAudio's default sink by 5 %, up to 100 %; held, they repeat. Both down together
 * take a screenshot of the whole screen into /root/Pictures. The X server never sees these keys: the session's /dev
 * has no node for them, and this daemon makes its own under /dev/m17.
 *
 * The decision is a state machine of its own, so tests drive it with synthetic times:
 *  - a press waits `grace_ms` for the other key; a tap shorter than that steps once on its release;
 *  - the other key down while one is down is the chord: one screenshot, then nothing until both are up;
 *  - a key still alone after `grace_ms` steps once, then after `delay_ms` again every `repeat_ms` while held;
 *  - the kernel's own auto-repeat is ignored. */
#ifndef M17_VOLKEYS_H
#define M17_VOLKEYS_H

#include <stdint.h>

enum m17_vk_action { M17_VK_NONE = 0, M17_VK_UP, M17_VK_DOWN, M17_VK_SHOT };

struct m17_vk {
    unsigned grace_ms, delay_ms, repeat_ms;
    int up, down;       /* each key's state */
    unsigned pending;   /* the key waiting out the grace, or 0 */
    unsigned held;      /* the key repeating, or 0 */
    int chord;          /* both went down: nothing more until both are up */
    uint64_t due_ms;    /* when the pending or held key acts next */
};

void m17_vk_init(struct m17_vk *v, unsigned grace_ms, unsigned delay_ms, unsigned repeat_ms);
/* One EV_KEY event for Volume Up (115) or Volume Down (114): value 1 press, 0 release, 2 repeat (ignored). */
enum m17_vk_action m17_vk_key(struct m17_vk *v, unsigned code, int value, uint64_t now_ms);
enum m17_vk_action m17_vk_tick(struct m17_vk *v, uint64_t now_ms);
/* When m17_vk_tick next matters; 0 when nothing waits. */
uint64_t m17_vk_due(const struct m17_vk *v);
/* Both keys up, nothing pending: after SYN_DROPPED or a device lost. */
void m17_vk_reset(struct m17_vk *v);

/* The new volume for a step from `now` (percent), 5 a step, within 0..100. */
int m17_vk_volume(int now, enum m17_vk_action action);
/* The first "NN%" in pactl's get-sink-volume output, or -1. */
int m17_vk_parse_volume(const char *text);

struct m17_volkeys {
    const char *sys, *dev;          /* "/sys" and "/dev/m17": the nodes are made at <dev>/input/eventN */
    const char *pactl, *shooter;    /* /usr/bin/pactl, /usr/bin/xfce4-screenshooter */
    const char *shots;              /* "/root/Pictures" */
    const char *log;                /* "/var/lib/m19/m17-keys.log": one line an action, under 256 KiB, one older kept */
    const char *kmsg;
    const char *const *pulse_env;   /* the session's PulseAudio, as root */
    const char *const *x_env;       /* the session's display, as root */
    const char *session_bus;        /* "/run/m19/session-bus": the session's D-Bus address, added for the screenshot */
    unsigned find_ms, command_ms;
    /* 1 on the phone: the nodes are made from sysfs's numbers and must be those character devices. Tests give 0 and
     * put FIFOs where the nodes would be. */
    int make_nodes;
};

/* The daemon: never returns while both keys can be read; 1 when they cannot be found or opened. */
int m17_volkeys_main(const struct m17_volkeys *k);

#endif
