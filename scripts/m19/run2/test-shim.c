/* Driver for xorg-shim.c on the fake libdrm. Never staged. Modes:
 *   filter     print what drmModeGetConnector and drmModeGetConnectorCurrent return
 *   null-call  install its own SIGSEGV handler, as Xorg does, then call a NULL function pointer
 *   null-read  the same, then read address 0
 *   gbm        ask for buffer handles as modesetting does; this program's own ioctl stands in for card0's
 *              PRIME import and GEM close, so it must be linked with -rdynamic
 *   dirty      call drmModeDirtyFB twice, as modesetting's setup and block handler do */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

struct fake_connector {
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

struct fake_connector *drmModeGetConnector(int fd, uint32_t id);
struct fake_connector *drmModeGetConnectorCurrent(int fd, uint32_t id);
void drmModeFreeConnector(struct fake_connector *c);
int drmModeDirtyFB(int fd, uint32_t buffer_id, void *clips, uint32_t num_clips);
extern int fake_dirty_calls;

union fake_gbm_handle {
    void *ptr;
    int32_t s32;
    uint32_t u32;
    int64_t s64;
    uint64_t u64;
};
struct gbm_bo;
struct gbm_bo *fake_gbm_bo_new(int id, int exportable);
void fake_gbm_set_kms_fd(int fd);
union fake_gbm_handle gbm_bo_get_handle(struct gbm_bo *bo);
union fake_gbm_handle gbm_bo_get_handle_for_plane(struct gbm_bo *bo, int plane);
void gbm_bo_destroy(struct gbm_bo *bo);
extern int fake_gbm_destroyed;

struct fake_prime {
    uint32_t handle, flags;
    int32_t fd;
};
struct fake_gem_close {
    uint32_t handle, pad;
};
#define FAKE_PRIME _IOWR('d', 0x2e, struct fake_prime)
#define FAKE_GEM_CLOSE _IOW('d', 0x09, struct fake_gem_close)
static unsigned imports, closes;
/* As the kernel does: one GEM handle per imported file, until it is closed. */
static struct {
    dev_t device;
    ino_t inode;
    uint32_t handle;
} imported[16];

/* card0, as far as the shim can tell: PRIME import of a live dma-buf, and GEM close. */
int ioctl(int fd, unsigned long request, ...)
{
    va_list arguments;
    va_start(arguments, request);
    void *argument = va_arg(arguments, void *);
    va_end(arguments);
    if (request == FAKE_PRIME) {
        struct fake_prime *prime = argument;
        if (getenv("FAKE_PRIME_FAIL") || prime->fd < 0 || fcntl(prime->fd, F_GETFD) < 0) {
            errno = EINVAL;
            return -1;
        }
        struct stat file;
        if (fstat(prime->fd, &file))
            return -1;
        unsigned slot = 16;
        for (unsigned i = 0; i < 16; i++) {
            if (imported[i].handle && imported[i].device == file.st_dev && imported[i].inode == file.st_ino) {
                prime->handle = imported[i].handle;
                printf("prime kms=%d handle %u again\n", fd, prime->handle);
                return 0;
            }
            if (!imported[i].handle && slot == 16)
                slot = i;
        }
        if (slot == 16)
            abort();
        prime->handle = 0x500u + ++imports;
        imported[slot].device = file.st_dev;
        imported[slot].inode = file.st_ino;
        imported[slot].handle = prime->handle;
        printf("prime kms=%d handle %u\n", fd, prime->handle);
        return 0;
    }
    if (request == FAKE_GEM_CLOSE) {
        uint32_t handle = ((struct fake_gem_close *)argument)->handle;
        closes++;
        for (unsigned i = 0; i < 16; i++)
            if (imported[i].handle == handle)
                imported[i].handle = 0;
        printf("gem-close kms=%d handle %u\n", fd, handle);
        return 0;
    }
    errno = ENOTTY;
    return -1;
}

static int gbm_mode(void)
{
    int kms = open("/dev/null", O_RDONLY | O_CLOEXEC);
    fake_gbm_set_kms_fd(kms);
    struct gbm_bo *a = fake_gbm_bo_new(1, 1), *b = fake_gbm_bo_new(2, 0);
    printf("a %u\n", gbm_bo_get_handle(a).u32);
    printf("a again %u\n", gbm_bo_get_handle(a).u32);
    printf("a plane1 %u\n", gbm_bo_get_handle_for_plane(a, 1).u32);
    printf("b %u\n", gbm_bo_get_handle(b).u32);
    gbm_bo_destroy(a);
    /* Often at the address a just had: a stale cache entry would answer for it. */
    struct gbm_bo *c = fake_gbm_bo_new(3, 1);
    printf("c %u\n", gbm_bo_get_handle(c).u32);
    gbm_bo_destroy(b);
    gbm_bo_destroy(c);
    printf("imports %u closes %u destroyed %d kms %d\n", imports, closes, fake_gbm_destroyed, kms);
    return 0;
}

static void own_handler(int number)
{
    static const char text[] = "own-handler\n";
    ssize_t put = write(1, text, sizeof(text) - 1);
    (void)put;
    _exit(100 + number);
}

static void print(const char *name, struct fake_connector *c)
{
    printf("%s count %d\n", name, c->count_props);
    for (int i = 0; i < c->count_props; i++)
        printf("%s prop %u %llu\n", name, c->props[i], (unsigned long long)c->prop_values[i]);
    drmModeFreeConnector(c);
}

int main(int argc, char **argv)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2)
        return 64;
    if (!strcmp(argv[1], "gbm"))
        return gbm_mode();
    if (!strcmp(argv[1], "dirty")) {
        int setup = drmModeDirtyFB(3, 175, NULL, 0), frame = drmModeDirtyFB(3, 175, NULL, 0);
        printf("dirty %d %d calls %d\n", setup, frame, fake_dirty_calls);
        return 0;
    }
    if (!strcmp(argv[1], "filter")) {
        print("get", drmModeGetConnector(3, 42));
        print("current", drmModeGetConnectorCurrent(3, 43));
        return 0;
    }
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = own_handler;
    printf("installed %d\n", sigaction(SIGSEGV, &act, NULL));
    if (!strcmp(argv[1], "null-call")) {
        void (*volatile call)(void) = NULL;
        call();
    } else if (!strcmp(argv[1], "null-read")) {
        volatile int *volatile pointer = NULL;
        printf("%d\n", *pointer);
    }
    return 65;
}
