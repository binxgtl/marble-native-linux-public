/* M19 R3c and R4c: a preload library for Xorg, and only for Xorg.
 *
 * 1. The fix. xserver 21.1's modesetting reads p->atoms[0] for every connector property in
 *    drmmode_output_set_property, but creates atoms only for RANGE and ENUM properties. SDE's
 *    connectors carry other kinds, so Xorg read address 0 in R3a and R3b. This library wraps
 *    drmModeGetConnector and drmModeGetConnectorCurrent and drops every connector property that is
 *    not RANGE, ENUM or BLOB, logging each one it drops.
 * 2. The diagnostic. A fault's signal, address, PC, LR and the executable mappings go to stderr
 *    (the journal) before anything else, and Xorg may not replace this handler.
 * 3. The glamor bridge (R4c), only with M19_SHIM_GBM=1. The tree's Mesa renders on /dev/kgsl-3d0 even
 *    for a GBM device made on card0, and with FD_KGSL_ENABLE_DMABUF its scan-out buffers are linear
 *    dma-heap buffers. But GBM reports the KGSL handle as the buffer's KMS handle, which card0 does not
 *    know, so modesetting's AddFB would fail. The bridge hands modesetting card0's own handle instead:
 *    the buffer's dma-buf imported into the GBM device's DRM fd through PRIME, as M9 scanned out a
 *    dma-heap buffer. Imports are cached per buffer and plane, and closed when the buffer is destroyed.
 *
 * It changes no file and no kernel state. libdrm's types are restated from xf86drmMode.h, a
 * stable ABI, so no libdrm headers are needed to build it. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
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

/* libgbm's handle union, restated from gbm.h: a stable ABI. */
union m19_gbm_handle {
    void *ptr;
    int32_t s32;
    uint32_t u32;
    int64_t s64;
    uint64_t u64;
};
struct gbm_bo;
struct gbm_device;
typedef union m19_gbm_handle (*bo_handle_fn)(struct gbm_bo *);
typedef union m19_gbm_handle (*bo_plane_handle_fn)(struct gbm_bo *, int);
typedef int (*bo_plane_fd_fn)(struct gbm_bo *, int);
typedef struct gbm_device *(*bo_device_fn)(struct gbm_bo *);
typedef int (*device_fd_fn)(struct gbm_device *);
typedef void (*bo_destroy_fn)(struct gbm_bo *);

/* DRM_IOCTL_PRIME_FD_TO_HANDLE and DRM_IOCTL_GEM_CLOSE, from include/uapi/drm/drm.h: stable ABI. */
struct m19_prime_handle {
    uint32_t handle, flags;
    int32_t fd;
};
struct m19_gem_close {
    uint32_t handle, pad;
};
#define M19_PRIME_FD_TO_HANDLE _IOWR('d', 0x2e, struct m19_prime_handle)
#define M19_GEM_CLOSE _IOW('d', 0x09, struct m19_gem_close)
#define M19_BRIDGE_SLOTS 64

static int bridge_on;
static unsigned bridge_logged;
static pthread_mutex_t bridge_lock = PTHREAD_MUTEX_INITIALIZER;
static struct {
    struct gbm_bo *bo;
    int plane, kms;
    uint32_t handle;
} bridge[M19_BRIDGE_SLOTS];

/* card0's handle for a buffer plane: cached, or imported now. Anything that fails keeps GBM's own. */
static union m19_gbm_handle bridge_handle(struct gbm_bo *bo, int plane, union m19_gbm_handle original)
{
    static bo_plane_fd_fn plane_fd;
    static bo_device_fn device_of;
    static device_fd_fn device_fd;
    if (!plane_fd)
        plane_fd = (bo_plane_fd_fn)dlsym(RTLD_NEXT, "gbm_bo_get_fd_for_plane");
    if (!device_of)
        device_of = (bo_device_fn)dlsym(RTLD_NEXT, "gbm_bo_get_device");
    if (!device_fd)
        device_fd = (device_fd_fn)dlsym(RTLD_NEXT, "gbm_device_get_fd");
    if (!bridge_on || !bo || !plane_fd || !device_of || !device_fd)
        return original;
    union m19_gbm_handle out = original;
    int slot = -1;
    pthread_mutex_lock(&bridge_lock);
    for (int i = 0; i < M19_BRIDGE_SLOTS; i++) {
        if (bridge[i].bo == bo && bridge[i].plane == plane) {
            out.u64 = 0;
            out.u32 = bridge[i].handle;
            pthread_mutex_unlock(&bridge_lock);
            return out;
        }
        if (!bridge[i].bo && slot < 0)
            slot = i;
    }
    struct gbm_device *device = device_of(bo);
    int kms = device ? device_fd(device) : -1, dmabuf = plane_fd(bo, plane);
    struct m19_prime_handle prime = {.handle = 0, .flags = 0, .fd = dmabuf};
    int rc = kms >= 0 && dmabuf >= 0 && slot >= 0 ? ioctl(kms, M19_PRIME_FD_TO_HANDLE, &prime) : -1;
    int error = rc ? errno : 0;
    if (dmabuf >= 0)
        close(dmabuf);
    if (rc) {
        say("M19 SHIM gbm plane %d keeps handle %u: kms=%d dmabuf=%d slot=%d errno=%d\n", plane, original.u32, kms, dmabuf, slot, error);
    } else {
        bridge[slot].bo = bo;
        bridge[slot].plane = plane;
        bridge[slot].kms = kms;
        bridge[slot].handle = prime.handle;
        if (bridge_logged++ < 8)
            say("M19 SHIM gbm plane %d handle %u -> kms %u\n", plane, original.u32, prime.handle);
        out.u64 = 0;
        out.u32 = prime.handle;
    }
    pthread_mutex_unlock(&bridge_lock);
    return out;
}

union m19_gbm_handle gbm_bo_get_handle(struct gbm_bo *bo)
{
    static bo_handle_fn real;
    if (!real)
        real = (bo_handle_fn)dlsym(RTLD_NEXT, "gbm_bo_get_handle");
    union m19_gbm_handle original = {.u64 = 0};
    if (real)
        original = real(bo);
    return bridge_handle(bo, 0, original);
}

union m19_gbm_handle gbm_bo_get_handle_for_plane(struct gbm_bo *bo, int plane)
{
    static bo_plane_handle_fn real;
    if (!real)
        real = (bo_plane_handle_fn)dlsym(RTLD_NEXT, "gbm_bo_get_handle_for_plane");
    union m19_gbm_handle original = {.u64 = 0};
    if (real)
        original = real(bo, plane);
    return bridge_handle(bo, plane, original);
}

/* Each card0 handle is closed once, when the last plane holding it goes. */
void gbm_bo_destroy(struct gbm_bo *bo)
{
    static bo_destroy_fn real;
    if (!real)
        real = (bo_destroy_fn)dlsym(RTLD_NEXT, "gbm_bo_destroy");
    pthread_mutex_lock(&bridge_lock);
    for (int i = 0; i < M19_BRIDGE_SLOTS; i++) {
        if (!bo || bridge[i].bo != bo)
            continue;
        int kms = bridge[i].kms;
        uint32_t handle = bridge[i].handle;
        bridge[i].bo = NULL;
        int shared = 0;
        for (int j = 0; j < M19_BRIDGE_SLOTS; j++)
            shared |= bridge[j].bo && bridge[j].kms == kms && bridge[j].handle == handle;
        if (!shared) {
            struct m19_gem_close gem = {.handle = handle, .pad = 0};
            if (ioctl(kms, M19_GEM_CLOSE, &gem))
                say("M19 SHIM gbm close of kms %u failed errno=%d\n", handle, errno);
        }
    }
    pthread_mutex_unlock(&bridge_lock);
    if (real)
        real(bo);
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
    const char *gbm = getenv("M19_SHIM_GBM");
    bridge_on = gbm && !strcmp(gbm, "1");
    say("M19 SHIM loaded: connector properties other than RANGE, ENUM and BLOB are dropped; faults are logged; gbm bridge %s\n",
        bridge_on ? "on" : "off");
}
