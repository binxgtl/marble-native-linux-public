/* M17 selector: the 10 s choice between Android and native at every normal boot, and what it reads to make it
 * (docs/m17-dual-boot-selector.md, option A).
 *
 * Every undecided branch goes to Android. Only a Volume Down press edge inside the window reaches native:
 *  - a key already down when the window opens gives no press edge, so a stuck or held key never chooses;
 *  - Volume Up's press chooses Android at once;
 *  - Volume Down pressed while Volume Up is down chooses Android;
 *  - auto-repeat is ignored;
 *  - a boot that is not normal (charger, alarm, FFBM), a key device missing, the menu failing, a key device failing
 *    during the window, or the window running out: Android. */
#ifndef M17_SELECT_H
#define M17_SELECT_H

#include <stddef.h>
#include <stdint.h>

#define M17_KEY_VOLUMEDOWN 114u
#define M17_KEY_VOLUMEUP 115u
#define M17_WINDOW_MS 10000u
/* The stock input devices (runtime DT and the stock audit's evdev names): Volume Up on gpio-keys, Volume Down on
 * PMK8350 PON's resin, which qcom-pon creates. */
#define M17_UP_DEVICE "gpio-keys"
#define M17_DOWN_DEVICE "pmic_resin"

enum m17_choice { M17_UNDECIDED = -1, M17_ANDROID = 0, M17_NATIVE = 1 };

enum m17_reason {
    M17_WHY_NONE = 0,
    M17_WHY_MODE,        /* not a normal boot */
    M17_WHY_NO_KEYS,     /* a key device missing, ambiguous, or without its key */
    M17_WHY_NO_MENU,     /* the menu could not be shown, or failed during the window */
    M17_WHY_TIMEOUT,     /* no choice inside the window */
    M17_WHY_VOLUME_UP,   /* Volume Up pressed */
    M17_WHY_VOLUME_DOWN, /* Volume Down pressed alone: the only way to native */
    M17_WHY_BOTH,        /* Volume Down pressed while Volume Up was down */
    M17_WHY_READ_ERROR,  /* a key device failed, vanished or returned a broken event */
};

struct m17_window {
    uint64_t deadline_ms;
    int up_down;         /* Volume Up is down: held when the window opened, or pressed since */
    enum m17_choice choice;
    enum m17_reason why;
};

const char *m17_choice_name(enum m17_choice choice);
const char *m17_reason_name(enum m17_reason why);

/* 1 when the kernel command line and the bootconfig both describe a normal boot: no androidboot.mode, or only
 * "normal", and no androidboot.alarmboot that is true. Either text may be NULL (absent). */
int m17_normal_boot(const char *cmdline, const char *bootconfig);

void m17_window_open(struct m17_window *w, uint64_t now_ms, unsigned window_ms, int up_held);
/* One EV_KEY event (value 1 press, 0 release, 2 repeat). Returns the choice once made, M17_UNDECIDED before. */
enum m17_choice m17_window_key(struct m17_window *w, unsigned code, int value);
enum m17_choice m17_window_tick(struct m17_window *w, uint64_t now_ms);
enum m17_choice m17_window_fail(struct m17_window *w, enum m17_reason why);
unsigned m17_window_left_ms(const struct m17_window *w, uint64_t now_ms);

/* A key device found by its stable name and its key, never by its event index. */
struct m17_key_dev {
    int fd;
    unsigned code;
    char node[96];
};

/* Finds the one input device in <sys_root>/class/input named `name` whose key capability has `code`, and opens its
 * <dev_root>/input/eventN read-only and nonblocking. With require_chr, the node must be a character device whose
 * number is the one sysfs gives. 0, or -ENOENT (none), -EEXIST (more than one), -ENODEV (node wrong) or -errno. */
int m17_key_open(const char *sys_root, const char *dev_root, const char *name, unsigned code, int require_chr, struct m17_key_dev *out);
/* The lookup alone: the one matching eventN in `found`. 0, -ENOENT or -EEXIST. */
int m17_key_find(const char *sys_root, const char *name, unsigned code, char found[16]);
/* Makes <dev_root>/input/<event> as the character device sysfs numbers (an existing node is kept). */
int m17_key_node(const char *sys_root, const char *dev_root, const char *event);

struct m17_loop {
    const char *sys_root, *dev_root;
    unsigned window_ms;
    int require_chr;
    uint64_t (*now_ms)(void);
    /* Shows the menu with the seconds left; called when the window opens and at each whole second. <0: failed. */
    int (*menu)(void *user, unsigned seconds_left);
    void *user;
};

/* Opens both keys, shows the menu and runs the window to its choice. Closes what it opened. */
enum m17_choice m17_run_window(const struct m17_loop *loop, struct m17_window *w);

uint64_t m17_monotonic_ms(void);

#endif
