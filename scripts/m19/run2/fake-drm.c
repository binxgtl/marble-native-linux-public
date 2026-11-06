/* A stand-in for the libdrm calls xorg-shim.c wraps, with one connector carrying every kind of
 * property SDE might: RANGE, ENUM, BLOB, BITMASK, OBJECT, SIGNED_RANGE and an unreadable one.
 * Built only for the offline tests. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
