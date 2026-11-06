/* M19 R3c: a preload library for Xorg, and only for Xorg.
 *
 * 1. The fix. xserver 21.1's modesetting reads p->atoms[0] for every connector property in
 *    drmmode_output_set_property, but creates atoms only for RANGE and ENUM properties. SDE's
 *    connectors carry other kinds, so Xorg read address 0 in R3a and R3b. This library wraps
 *    drmModeGetConnector and drmModeGetConnectorCurrent and drops every connector property that is
 *    not RANGE, ENUM or BLOB, logging each one it drops.
 * 2. The diagnostic. A fault's signal, address, PC, LR and the executable mappings go to stderr
 *    (the journal) before anything else, and Xorg may not replace this handler.
 *
 * It changes no file and no kernel state. libdrm's types are restated from xf86drmMode.h, a
 * stable ABI, so no libdrm headers are needed to build it. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

#define M19_PROP_RANGE (1u << 1)
#define M19_PROP_ENUM (1u << 3)
#define M19_PROP_BLOB (1u << 4)

struct m19_property {
    uint32_t prop_id, flags;
    char name[32];
    int count_values;
    uint64_t *values;
    int count_enums;
    void *enums;
    int count_blobs;
    uint32_t *blob_ids;
};

struct m19_connector {
    uint32_t connector_id, encoder_id, connector_type, connector_type_id;
    int connection;
    uint32_t mm_width, mm_height;
    int subpixel, count_modes;
    void *modes;
    int count_props;
    uint32_t *props;
    uint64_t *prop_values;
    int count_encoders;
    uint32_t *encoders;
};

typedef struct m19_connector *(*get_connector_fn)(int, uint32_t);
typedef struct m19_property *(*get_property_fn)(int, uint32_t);
typedef void (*free_property_fn)(struct m19_property *);
typedef int (*sigaction_fn)(int, const struct sigaction *, struct sigaction *);

static sigaction_fn real_sigaction;
static volatile sig_atomic_t guarded, faulting;

/* Async-signal-safe: vsnprintf on a stack buffer and one write. */
__attribute__((format(printf, 1, 2)))
static void say(const char *format, ...)
{
    char text[256];
    va_list arguments;
    va_start(arguments, format);
    int n = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (n <= 0)
        return;
    ssize_t put = write(2, text, (size_t)n < sizeof(text) ? (size_t)n : sizeof(text) - 1);
    (void)put;
}

static void filter(int fd, struct m19_connector *c)
{
    static get_property_fn get_property;
    static free_property_fn free_property;
    if (!get_property)
        get_property = (get_property_fn)dlsym(RTLD_NEXT, "drmModeGetProperty");
    if (!free_property)
        free_property = (free_property_fn)dlsym(RTLD_NEXT, "drmModeFreeProperty");
    if (!c || c->count_props <= 0 || !c->props || !get_property || !free_property)
        return;
    int kept = 0;
    for (int i = 0; i < c->count_props; i++) {
        struct m19_property *p = get_property(fd, c->props[i]);
        int keep = p && (p->flags & (M19_PROP_RANGE | M19_PROP_ENUM | M19_PROP_BLOB));
        if (!keep)
            say("M19 SHIM connector %u drops property %u %.32s flags=%#x\n", c->connector_id, c->props[i], p ? p->name : "(unreadable)",
                p ? p->flags : 0u);
        if (p)
            free_property(p);
        if (keep) {
            c->props[kept] = c->props[i];
            if (c->prop_values)
                c->prop_values[kept] = c->prop_values[i];
            kept++;
        }
    }
    c->count_props = kept;
}

struct m19_connector *drmModeGetConnector(int fd, uint32_t connector_id)
{
    static get_connector_fn real;
    if (!real)
        real = (get_connector_fn)dlsym(RTLD_NEXT, "drmModeGetConnector");
    struct m19_connector *c = real ? real(fd, connector_id) : NULL;
    filter(fd, c);
    return c;
}

struct m19_connector *drmModeGetConnectorCurrent(int fd, uint32_t connector_id)
{
    static get_connector_fn real;
    if (!real)
        real = (get_connector_fn)dlsym(RTLD_NEXT, "drmModeGetConnectorCurrent");
    struct m19_connector *c = real ? real(fd, connector_id) : NULL;
    filter(fd, c);
    return c;
}

static void maps(void)
{
    char buffer[4096], line[512];
    size_t at = 0;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return;
    for (;;) {
        ssize_t n = read(fd, buffer, sizeof(buffer));
        if (n <= 0)
            break;
        for (ssize_t i = 0; i < n; i++) {
            if (at < sizeof(line) - 1)
                line[at++] = buffer[i];
            if (buffer[i] != '\n')
                continue;
            line[at] = 0;
            /* Only executable mappings place an address in a library. */
            char *perms = strchr(line, ' ');
            if (perms && perms[3] == 'x')
                say("M19 SHIM map %s", line);
            at = 0;
        }
    }
    close(fd);
}

static void fault(int number, siginfo_t *info, void *context)
{
    if (faulting)
        _exit(128 + number);
    faulting = 1;
    ucontext_t *uc = context;
    unsigned long pc = 0, lr = 0, sp = 0, fp = 0;
#if defined(__aarch64__)
    pc = uc->uc_mcontext.pc;
    lr = uc->uc_mcontext.regs[30];
    fp = uc->uc_mcontext.regs[29];
    sp = uc->uc_mcontext.sp;
#elif defined(__x86_64__)
    pc = (unsigned long)uc->uc_mcontext.gregs[REG_RIP];
    fp = (unsigned long)uc->uc_mcontext.gregs[REG_RBP];
    sp = (unsigned long)uc->uc_mcontext.gregs[REG_RSP];
#endif
    say("M19 SHIM fault signal=%d code=%d addr=%p pc=%#lx lr=%#lx sp=%#lx fp=%#lx\n", number, info->si_code, info->si_addr, pc, lr, sp, fp);
    maps();
#if defined(__aarch64__)
    /* The frame record chain: [fp] is the caller's fp, [fp + 8] its return address. A bad link faults
     * again, and the guard above ends the process then; everything before it is already logged. */
    for (int depth = 0; depth < 24 && fp && !(fp & 7); depth++) {
        unsigned long *record = (unsigned long *)fp;
        say("M19 SHIM frame %d ret=%#lx\n", depth, record[1]);
        if (record[0] <= fp)
            break;
        fp = record[0];
    }
#endif
    struct sigaction plain;
    memset(&plain, 0, sizeof(plain));
    plain.sa_handler = SIG_DFL;
    if (real_sigaction)
        real_sigaction(number, &plain, NULL);
    /* The handler runs with this signal blocked; unblocked, raise delivers it at once with the default
     * action, so the process ends by the signal itself and systemd records it as one. */
    sigset_t only;
    sigemptyset(&only);
    sigaddset(&only, number);
    sigprocmask(SIG_UNBLOCK, &only, NULL);
    raise(number);
    _exit(128 + number);
}

static int trapped(int number)
{
    return number == SIGSEGV || number == SIGBUS || number == SIGILL || number == SIGFPE;
}

/* Xorg installs its own fatal-signal handler, which swallowed R3a's and R3b's crash. Not here. */
int sigaction(int number, const struct sigaction *act, struct sigaction *old)
{
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!real_sigaction)
        return -1;
    if (guarded && act && trapped(number))
        return real_sigaction(number, NULL, old);
    return real_sigaction(number, act, old);
}

__attribute__((constructor)) static void install(void)
{
    static char stack[65536];
    if (!real_sigaction)
        real_sigaction = (sigaction_fn)dlsym(RTLD_NEXT, "sigaction");
    if (!real_sigaction)
        return;
    stack_t alternate = {.ss_sp = stack, .ss_size = sizeof(stack), .ss_flags = 0};
    (void)sigaltstack(&alternate, NULL);
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = fault;
    act.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&act.sa_mask);
    int numbers[] = {SIGSEGV, SIGBUS, SIGILL, SIGFPE};
    for (unsigned i = 0; i < sizeof(numbers) / sizeof(numbers[0]); i++)
        real_sigaction(numbers[i], &act, NULL);
    guarded = 1;
    say("M19 SHIM loaded: connector properties other than RANGE, ENUM and BLOB are dropped; faults are logged\n");
}
