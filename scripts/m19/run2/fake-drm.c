/* A stand-in for the libdrm calls xorg-shim.c wraps, with one connector carrying every kind of
 * property SDE might: RANGE, ENUM, BLOB, BITMASK, OBJECT, SIGNED_RANGE and an unreadable one.
 * Built only for the offline tests. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct fake_property {
    uint32_t prop_id, flags;
    char name[32];
    int count_values;
    uint64_t *values;
    int count_enums;
    void *enums;
    int count_blobs;
    uint32_t *blob_ids;
};

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

static const struct {
    uint32_t id, flags;
    const char *name;
} table[] = {
    {1, 1u << 1, "non-desktop"}, {2, 1u << 3, "DPMS"}, {3, 1u << 4, "EDID"}, {4, 1u << 5, "sde_bitmask"},
    {5, 1u << 6, "CRTC_ID"}, {6, 2u << 6, "signed_range"}, {7, 0, NULL}, {8, (1u << 3) | (1u << 2), "panel_mode"},
};
#define COUNT (sizeof(table) / sizeof(table[0]))

static struct fake_connector *make(uint32_t id)
{
    struct fake_connector *c = calloc(1, sizeof(*c));
    if (!c)
        return NULL;
    c->connector_id = id;
    c->count_props = (int)COUNT;
    c->props = calloc(COUNT, sizeof(*c->props));
    c->prop_values = calloc(COUNT, sizeof(*c->prop_values));
    if (!c->props || !c->prop_values)
        abort();
    for (unsigned i = 0; i < COUNT; i++) {
        c->props[i] = table[i].id;
        c->prop_values[i] = 100 + table[i].id;
    }
    return c;
}

struct fake_connector *drmModeGetConnector(int fd, uint32_t id)
{
    (void)fd;
    return make(id);
}

struct fake_connector *drmModeGetConnectorCurrent(int fd, uint32_t id)
{
    (void)fd;
    return make(id);
}

/* R4g: drmModeDirtyFB as a kernel that takes it, counting the calls. */
int fake_dirty_calls;
int drmModeDirtyFB(int fd, uint32_t buffer_id, void *clips, uint32_t num_clips)
{
    (void)fd;
    (void)buffer_id;
    (void)clips;
    (void)num_clips;
    fake_dirty_calls++;
    return 0;
}

struct fake_property *drmModeGetProperty(int fd, uint32_t id)
{
    (void)fd;
    for (unsigned i = 0; i < COUNT; i++) {
        if (table[i].id != id || !table[i].name)
            continue;
        struct fake_property *p = calloc(1, sizeof(*p));
        if (!p)
            return NULL;
        p->prop_id = id;
        p->flags = table[i].flags;
        strncpy(p->name, table[i].name, sizeof(p->name) - 1);
        return p;
    }
    return NULL;
}

void drmModeFreeProperty(struct fake_property *p)
{
    free(p);
}

void drmModeFreeConnector(struct fake_connector *c)
{
    if (!c)
        return;
    free(c->props);
    free(c->prop_values);
    free(c);
}

/* R4b: the libgbm calls the glamor bridge wraps. A buffer's GBM handle is 0x1000 + 16 * id + plane, as
 * KGSL's would be. An exportable buffer has one backing file, as a dma-buf would, and every plane's fd
 * is a dup of it, so card0's PRIME import gives all its planes one handle. */
union fake_gbm_handle {
    void *ptr;
    int32_t s32;
    uint32_t u32;
    int64_t s64;
    uint64_t u64;
};
struct gbm_device {
    int fd;
};
struct gbm_bo {
    int id, backing;
    struct gbm_device *device;
};
static struct gbm_device fake_device = {.fd = -1};
int fake_gbm_destroyed;

void fake_gbm_set_kms_fd(int fd)
{
    fake_device.fd = fd;
}

struct gbm_bo *fake_gbm_bo_new(int id, int exportable)
{
    struct gbm_bo *bo = calloc(1, sizeof(*bo));
    if (!bo)
        abort();
    bo->id = id;
    bo->backing = -1;
    if (exportable) {
        char name[] = "/tmp/fake-dmabuf-XXXXXX";
        bo->backing = mkstemp(name);
        if (bo->backing < 0)
            abort();
        unlink(name);
    }
    bo->device = &fake_device;
    return bo;
}

union fake_gbm_handle gbm_bo_get_handle_for_plane(struct gbm_bo *bo, int plane)
{
    union fake_gbm_handle h = {.u64 = 0};
    h.u32 = 0x1000u + 16u * (uint32_t)bo->id + (uint32_t)plane;
    return h;
}

union fake_gbm_handle gbm_bo_get_handle(struct gbm_bo *bo)
{
    return gbm_bo_get_handle_for_plane(bo, 0);
}

int gbm_bo_get_fd_for_plane(struct gbm_bo *bo, int plane)
{
    (void)plane;
    return bo->backing >= 0 ? dup(bo->backing) : -1;
}

struct gbm_device *gbm_bo_get_device(struct gbm_bo *bo)
{
    return bo->device;
}

int gbm_device_get_fd(struct gbm_device *device)
{
    return device->fd;
}

void gbm_bo_destroy(struct gbm_bo *bo)
{
    fake_gbm_destroyed++;
    if (bo->backing >= 0)
        close(bo->backing);
    free(bo);
}
