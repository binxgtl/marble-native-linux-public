/* M17 selector KMS: the menu on the panel, by M7 D4's contract as scripts/m9-kms.c implements it, which M19 painted
 * with in every run (docs/m17-g4.md). Its discovery, property, TEST_ONLY and verified-disable code is copied from
 * scripts/m9-kms.c unchanged; what is new is two CPU dumb buffers, so the countdown redraws one while the other is
 * scanned out, each shown by a plain atomic commit after the first modeset.
 * The selector must leave no plane lit for Android: m17_kms_close() disables twice if need be and verifies by
 * readback, as m9-kms does, and reports an unsafe rollback distinctly. */
#define _GNU_SOURCE
#include "kms.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define M9_IOC(dir, nr, type) \
	(((unsigned long)(dir) << 30) | ((unsigned long)sizeof(type) << 16) | \
	 ((unsigned long)'d' << 8) | (unsigned long)(nr))
#define M9_IOW(nr, type) M9_IOC(1, nr, type)
#define M9_IOWR(nr, type) M9_IOC(3, nr, type)

#define DRM_DISPLAY_MODE_LEN 32
#define DRM_PROP_NAME_LEN 32
#define DRM_CLIENT_CAP_UNIVERSAL_PLANES 2
#define DRM_CLIENT_CAP_ATOMIC 3
#define DRM_MODE_CONNECTED 1
#define DRM_MODE_CONNECTOR_DSI 16
#define DRM_MODE_OBJECT_CRTC 0xccccccccu
#define DRM_MODE_OBJECT_CONNECTOR 0xc0c0c0c0u
#define DRM_MODE_OBJECT_PLANE 0xeeeeeeeeu
#define DRM_MODE_ATOMIC_TEST_ONLY 0x0100u
#define DRM_MODE_ATOMIC_ALLOW_MODESET 0x0400u
#define DRM_PLANE_TYPE_PRIMARY 1
#define DRM_CLOEXEC 0x01
#define DRM_RDWR 0x02
#define DRM_FORMAT_XRGB8888 \
	((uint32_t)'X' | ((uint32_t)'R' << 8) | ((uint32_t)'2' << 16) | ((uint32_t)'4' << 24))

struct drm_mode_modeinfo {
	uint32_t clock;
	uint16_t hdisplay, hsync_start, hsync_end, htotal, hskew;
	uint16_t vdisplay, vsync_start, vsync_end, vtotal, vscan;
	uint32_t vrefresh, flags, type;
	char name[DRM_DISPLAY_MODE_LEN];
};
struct drm_mode_card_res {
	uint64_t fb_id_ptr, crtc_id_ptr, connector_id_ptr, encoder_id_ptr;
	uint32_t count_fbs, count_crtcs, count_connectors, count_encoders;
	uint32_t min_width, max_width, min_height, max_height;
};
struct drm_mode_get_encoder {
	uint32_t encoder_id, encoder_type, crtc_id, possible_crtcs, possible_clones;
};
struct drm_mode_get_connector {
	uint64_t encoders_ptr, modes_ptr, props_ptr, prop_values_ptr;
	uint32_t count_modes, count_props, count_encoders;
	uint32_t encoder_id, connector_id, connector_type, connector_type_id;
	uint32_t connection, mm_width, mm_height, subpixel, pad;
};
struct drm_mode_get_plane {
	uint32_t plane_id, crtc_id, fb_id, possible_crtcs, gamma_size;
	uint32_t count_format_types;
	uint64_t format_type_ptr;
};
struct drm_mode_get_plane_res {
	uint64_t plane_id_ptr;
	uint32_t count_planes;
};
struct drm_mode_get_property {
	uint64_t values_ptr, enum_blob_ptr;
	uint32_t prop_id, flags;
	char name[DRM_PROP_NAME_LEN];
	uint32_t count_values, count_enum_blobs;
};
struct drm_mode_obj_get_properties {
	uint64_t props_ptr, prop_values_ptr;
	uint32_t count_props, obj_id, obj_type;
};
struct drm_mode_fb_cmd2 {
	uint32_t fb_id, width, height, pixel_format, flags;
	uint32_t handles[4], pitches[4], offsets[4];
	uint64_t modifier[4];
};
struct drm_mode_atomic {
	uint32_t flags, count_objs;
	uint64_t objs_ptr, count_props_ptr, props_ptr, prop_values_ptr;
	uint64_t reserved, user_data;
};
struct drm_mode_create_blob { uint64_t data; uint32_t length, blob_id; };
struct drm_mode_destroy_blob { uint32_t blob_id; };
struct drm_set_client_cap { uint64_t capability, value; };
struct drm_prime_handle { uint32_t handle, flags; int32_t fd; };
struct drm_gem_close { uint32_t handle, pad; };
struct drm_mode_create_dumb {
	uint32_t height, width, bpp, flags, handle, pitch;
	uint64_t size;
};
struct drm_mode_map_dumb { uint32_t handle, pad; uint64_t offset; };
struct drm_mode_destroy_dumb { uint32_t handle; };

#define DRM_IOCTL_SET_CLIENT_CAP M9_IOW(0x0d, struct drm_set_client_cap)
#define DRM_IOCTL_GEM_CLOSE M9_IOW(0x09, struct drm_gem_close)
#define DRM_IOCTL_PRIME_FD_TO_HANDLE M9_IOWR(0x2e, struct drm_prime_handle)
#define DRM_IOCTL_MODE_GETRESOURCES M9_IOWR(0xa0, struct drm_mode_card_res)
#define DRM_IOCTL_MODE_GETENCODER M9_IOWR(0xa6, struct drm_mode_get_encoder)
#define DRM_IOCTL_MODE_GETCONNECTOR M9_IOWR(0xa7, struct drm_mode_get_connector)
#define DRM_IOCTL_MODE_GETPROPERTY M9_IOWR(0xaa, struct drm_mode_get_property)
#define DRM_IOCTL_MODE_RMFB M9_IOWR(0xaf, uint32_t)
#define DRM_IOCTL_MODE_GETPLANERESOURCES M9_IOWR(0xb5, struct drm_mode_get_plane_res)
#define DRM_IOCTL_MODE_GETPLANE M9_IOWR(0xb6, struct drm_mode_get_plane)
#define DRM_IOCTL_MODE_ADDFB2 M9_IOWR(0xb8, struct drm_mode_fb_cmd2)
#define DRM_IOCTL_MODE_OBJ_GETPROPERTIES M9_IOWR(0xb9, struct drm_mode_obj_get_properties)
#define DRM_IOCTL_MODE_ATOMIC M9_IOWR(0xbc, struct drm_mode_atomic)
#define DRM_IOCTL_MODE_CREATEPROPBLOB M9_IOWR(0xbd, struct drm_mode_create_blob)
#define DRM_IOCTL_MODE_DESTROYPROPBLOB M9_IOWR(0xbe, struct drm_mode_destroy_blob)
#define DRM_IOCTL_MODE_CREATE_DUMB M9_IOWR(0xb2, struct drm_mode_create_dumb)
#define DRM_IOCTL_MODE_MAP_DUMB M9_IOWR(0xb3, struct drm_mode_map_dumb)
#define DRM_IOCTL_MODE_DESTROY_DUMB M9_IOWR(0xb4, struct drm_mode_destroy_dumb)

#define MAX_CRTCS 8
#define MAX_CONNECTORS 16
#define MAX_ENCODERS 16
#define MAX_MODES 32
#define MAX_PLANES 64
#define MAX_FORMATS 64
#define MAX_PROPS 64

struct props {
	uint32_t ids[MAX_PROPS];
	uint64_t values[MAX_PROPS];
	uint32_t count;
};
struct named_prop { uint32_t id; uint64_t value; };

static int get_props(int fd, uint32_t id, uint32_t type, struct props *out) {
	struct drm_mode_obj_get_properties q = {.obj_id = id, .obj_type = type};
	if (ioctl(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &q) || q.count_props > MAX_PROPS)
		return -1;
	out->count = q.count_props;
	q.props_ptr = (uintptr_t)out->ids;
	q.prop_values_ptr = (uintptr_t)out->values;
	if (ioctl(fd, DRM_IOCTL_MODE_OBJ_GETPROPERTIES, &q) || q.count_props > out->count)
		return -1;
	out->count = q.count_props;
	return 0;
}

static int named_prop(int fd, const struct props *props, const char *name,
		struct named_prop *out) {
	for (uint32_t i = 0; i < props->count; ++i) {
		struct drm_mode_get_property p = {.prop_id = props->ids[i]};
		if (!ioctl(fd, DRM_IOCTL_MODE_GETPROPERTY, &p) && !strcmp(p.name, name)) {
			out->id = props->ids[i];
			out->value = props->values[i];
			return 0;
		}
	}
	return -1;
}

static int prop_value(const struct props *props, uint32_t id, uint64_t *value) {
	for (uint32_t i = 0; i < props->count; ++i) {
		if (props->ids[i] == id) {
			*value = props->values[i];
			return 0;
		}
	}
	return -1;
}

static int get_connector(int fd, uint32_t id, struct drm_mode_get_connector *q,
		struct drm_mode_modeinfo *modes, uint32_t *encoders) {
	uint32_t props[MAX_PROPS];
	uint64_t values[MAX_PROPS];
	*q = (struct drm_mode_get_connector){.connector_id = id};
	if (ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, q) || q->count_modes > MAX_MODES ||
		q->count_props > MAX_PROPS || q->count_encoders > MAX_ENCODERS)
		return -1;
	q->modes_ptr = (uintptr_t)modes;
	q->encoders_ptr = (uintptr_t)encoders;
	q->props_ptr = (uintptr_t)props;
	q->prop_values_ptr = (uintptr_t)values;
	return ioctl(fd, DRM_IOCTL_MODE_GETCONNECTOR, q);
}

static int atomic_commit(int fd, uint32_t connector, uint32_t crtc, uint32_t plane,
		const uint32_t *counts, const uint32_t *props, const uint64_t *values,
		uint32_t flags) {
	uint32_t objects[3] = {connector, crtc, plane};
	struct drm_mode_atomic a = {
		.flags = flags, .count_objs = 3, .objs_ptr = (uintptr_t)objects,
		.count_props_ptr = (uintptr_t)counts, .props_ptr = (uintptr_t)props,
		.prop_values_ptr = (uintptr_t)values,
	};
	return ioctl(fd, DRM_IOCTL_MODE_ATOMIC, &a);
}

static bool verify_disabled(int fd, uint32_t connector, uint32_t crtc,
		uint32_t plane, const uint32_t *ids) {
	struct props current[3];
	const uint32_t objects[3] = {connector, crtc, plane};
	const uint32_t types[3] = {DRM_MODE_OBJECT_CONNECTOR, DRM_MODE_OBJECT_CRTC,
		DRM_MODE_OBJECT_PLANE};
	const uint32_t first[3] = {0, 1, 3};
	const uint32_t count[3] = {1, 2, 2};
	for (uint32_t o = 0; o < 3; ++o) {
		if (get_props(fd, objects[o], types[o], &current[o])) return false;
		for (uint32_t i = first[o]; i < first[o] + count[o]; ++i) {
			uint64_t value;
			if (prop_value(&current[o], ids[i], &value) || value != 0) return false;
		}
	}
	return true;
}


static void kms_free(struct m17_kms *k) {
	for (int i = 0; i < 2; ++i) {
		if (k->buf[i].map && k->buf[i].map != MAP_FAILED) munmap(k->buf[i].map, k->size);
		if (k->buf[i].fb) ioctl(k->fd, DRM_IOCTL_MODE_RMFB, &k->buf[i].fb);
		if (k->buf[i].handle)
			ioctl(k->fd, DRM_IOCTL_MODE_DESTROY_DUMB, &(struct drm_mode_destroy_dumb){.handle = k->buf[i].handle});
		k->buf[i].map = NULL;
		k->buf[i].fb = k->buf[i].handle = 0;
	}
	if (k->blob) ioctl(k->fd, DRM_IOCTL_MODE_DESTROYPROPBLOB, &(struct drm_mode_destroy_blob){k->blob});
	k->blob = 0;
	if (k->fd >= 0) close(k->fd);
	k->fd = -1;
}

int m17_kms_open(struct m17_kms *k, const char *card_path) {
	uint32_t crtcs[MAX_CRTCS], connectors[MAX_CONNECTORS], encoders[MAX_ENCODERS];
	uint32_t connector_encoders[MAX_ENCODERS], planes[MAX_PLANES], formats[MAX_FORMATS];
	struct drm_mode_modeinfo modes[MAX_MODES], mode = {0};
	struct drm_mode_get_connector connector;
	struct drm_mode_card_res res = {0};
	struct drm_mode_get_plane_res plane_res = {0};
	uint32_t crtc_index = 0;
	struct props cp, rp, pp;
	struct named_prop conn_crtc, crtc_mode, crtc_active, plane_fb, plane_crtc;
	struct named_prop src_x, src_y, src_w, src_h, dst_x, dst_y, dst_w, dst_h, plane_type;
	uint32_t counts[3] = {1, 2, 10}, disable_counts[3] = {1, 2, 2};
	uint64_t disabled[5] = {0};

	memset(k, 0, sizeof *k);
	k->fd = open(card_path, O_RDWR | O_CLOEXEC);
	if (k->fd < 0) return -1;
	struct drm_set_client_cap client = {DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1};
	if (ioctl(k->fd, DRM_IOCTL_SET_CLIENT_CAP, &client)) goto fail;
	client.capability = DRM_CLIENT_CAP_ATOMIC;
	if (ioctl(k->fd, DRM_IOCTL_SET_CLIENT_CAP, &client)) goto fail;
	for (int i = 0; i < 2; ++i) {
		struct drm_mode_create_dumb dumb = {.width = 1080, .height = 2400, .bpp = 32};
		struct drm_mode_map_dumb map = {0};
		if (ioctl(k->fd, DRM_IOCTL_MODE_CREATE_DUMB, &dumb) || !dumb.handle || !dumb.pitch ||
			dumb.size < (uint64_t)dumb.pitch * 2400 || (i && (dumb.pitch != k->pitch || dumb.size != k->size))) {
			if (dumb.handle) k->buf[i].handle = dumb.handle;
			goto fail;
		}
		k->buf[i].handle = dumb.handle;
		k->pitch = dumb.pitch;
		k->size = dumb.size;
		map.handle = dumb.handle;
		if (ioctl(k->fd, DRM_IOCTL_MODE_MAP_DUMB, &map)) goto fail;
		k->buf[i].map = mmap(NULL, dumb.size, PROT_READ | PROT_WRITE, MAP_SHARED, k->fd, (off_t)map.offset);
		if (k->buf[i].map == MAP_FAILED) goto fail;
		memset(k->buf[i].map, 0, dumb.size);
	}

	if (ioctl(k->fd, DRM_IOCTL_MODE_GETRESOURCES, &res) || res.count_crtcs > MAX_CRTCS ||
		res.count_connectors > MAX_CONNECTORS || res.count_encoders > MAX_ENCODERS) goto fail;
	res.crtc_id_ptr = (uintptr_t)crtcs;
	res.connector_id_ptr = (uintptr_t)connectors;
	res.encoder_id_ptr = (uintptr_t)encoders;
	if (ioctl(k->fd, DRM_IOCTL_MODE_GETRESOURCES, &res)) goto fail;
	for (uint32_t i = 0; i < res.count_connectors && !k->connector; ++i) {
		if (get_connector(k->fd, connectors[i], &connector, modes, connector_encoders)) continue;
		if (connector.connector_type != DRM_MODE_CONNECTOR_DSI ||
			connector.connection != DRM_MODE_CONNECTED) continue;
		for (uint32_t j = 0; j < connector.count_modes; ++j) {
			if (modes[j].hdisplay == 1080 && modes[j].vdisplay == 2400 &&
				modes[j].vrefresh == 60 && !strcmp(modes[j].name, "1080x2400x60vid")) {
				k->connector = connector.connector_id;
				mode = modes[j];
				break;
			}
		}
	}
	if (!k->connector) goto fail;
	for (uint32_t i = 0; i < connector.count_encoders && !k->crtc; ++i) {
		struct drm_mode_get_encoder e = {.encoder_id = connector_encoders[i]};
		if (ioctl(k->fd, DRM_IOCTL_MODE_GETENCODER, &e)) continue;
		for (uint32_t j = 0; j < res.count_crtcs; ++j) {
			if (e.possible_crtcs & (1u << j)) { k->crtc = crtcs[j]; crtc_index = j; break; }
		}
	}
	if (!k->crtc || ioctl(k->fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &plane_res) ||
		plane_res.count_planes > MAX_PLANES) goto fail;
	plane_res.plane_id_ptr = (uintptr_t)planes;
	if (ioctl(k->fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &plane_res)) goto fail;
	for (uint32_t i = 0; i < plane_res.count_planes && !k->plane; ++i) {
		struct drm_mode_get_plane p = {.plane_id = planes[i]};
		bool xrgb = false;
		if (ioctl(k->fd, DRM_IOCTL_MODE_GETPLANE, &p) ||
			!(p.possible_crtcs & (1u << crtc_index)) || p.count_format_types > MAX_FORMATS) continue;
		p.format_type_ptr = (uintptr_t)formats;
		if (ioctl(k->fd, DRM_IOCTL_MODE_GETPLANE, &p)) continue;
		for (uint32_t j = 0; j < p.count_format_types; ++j) xrgb |= formats[j] == DRM_FORMAT_XRGB8888;
		if (!xrgb || get_props(k->fd, p.plane_id, DRM_MODE_OBJECT_PLANE, &pp) ||
			named_prop(k->fd, &pp, "type", &plane_type) || plane_type.value != DRM_PLANE_TYPE_PRIMARY ||
			named_prop(k->fd, &pp, "FB_ID", &plane_fb) || named_prop(k->fd, &pp, "CRTC_ID", &plane_crtc) ||
			plane_fb.value || plane_crtc.value) continue;
		k->plane = p.plane_id;
	}
	if (!k->plane || get_props(k->fd, k->connector, DRM_MODE_OBJECT_CONNECTOR, &cp) ||
		get_props(k->fd, k->crtc, DRM_MODE_OBJECT_CRTC, &rp) ||
		get_props(k->fd, k->plane, DRM_MODE_OBJECT_PLANE, &pp) ||
		named_prop(k->fd, &cp, "CRTC_ID", &conn_crtc) || named_prop(k->fd, &rp, "MODE_ID", &crtc_mode) ||
		named_prop(k->fd, &rp, "ACTIVE", &crtc_active) || named_prop(k->fd, &pp, "FB_ID", &plane_fb) ||
		named_prop(k->fd, &pp, "CRTC_ID", &plane_crtc) || named_prop(k->fd, &pp, "SRC_X", &src_x) ||
		named_prop(k->fd, &pp, "SRC_Y", &src_y) || named_prop(k->fd, &pp, "SRC_W", &src_w) ||
		named_prop(k->fd, &pp, "SRC_H", &src_h) || named_prop(k->fd, &pp, "CRTC_X", &dst_x) ||
		named_prop(k->fd, &pp, "CRTC_Y", &dst_y) || named_prop(k->fd, &pp, "CRTC_W", &dst_w) ||
		named_prop(k->fd, &pp, "CRTC_H", &dst_h)) goto fail;
	if (plane_fb.value || plane_crtc.value || (conn_crtc.value && conn_crtc.value != k->crtc)) goto fail;

	for (int i = 0; i < 2; ++i) {
		struct drm_mode_fb_cmd2 fb = {.width = 1080, .height = 2400, .pixel_format = DRM_FORMAT_XRGB8888};
		fb.handles[0] = k->buf[i].handle;
		fb.pitches[0] = k->pitch;
		if (ioctl(k->fd, DRM_IOCTL_MODE_ADDFB2, &fb) || !fb.fb_id) goto fail;
		k->buf[i].fb = fb.fb_id;
	}
	struct drm_mode_create_blob blob = {.data = (uintptr_t)&mode, .length = sizeof(mode)};
	if (ioctl(k->fd, DRM_IOCTL_MODE_CREATEPROPBLOB, &blob) || !blob.blob_id) goto fail;
	k->blob = blob.blob_id;
	k->props[0] = conn_crtc.id; k->props[1] = crtc_mode.id; k->props[2] = crtc_active.id;
	k->props[3] = plane_fb.id; k->props[4] = plane_crtc.id; k->props[5] = src_x.id;
	k->props[6] = src_y.id; k->props[7] = src_w.id; k->props[8] = src_h.id;
	k->props[9] = dst_x.id; k->props[10] = dst_y.id; k->props[11] = dst_w.id; k->props[12] = dst_h.id;
	k->values[0] = k->crtc; k->values[1] = k->blob; k->values[2] = 1;
	k->values[3] = k->buf[0].fb; k->values[4] = k->crtc; k->values[5] = 0; k->values[6] = 0;
	k->values[7] = (uint64_t)1080 << 16; k->values[8] = (uint64_t)2400 << 16;
	k->values[9] = 0; k->values[10] = 0; k->values[11] = 1080; k->values[12] = 2400;
	if (atomic_commit(k->fd, k->connector, k->crtc, k->plane, counts, k->props, k->values,
		DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET)) goto fail;
	if (atomic_commit(k->fd, k->connector, k->crtc, k->plane, disable_counts, k->props, disabled,
		DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET)) goto fail;
	return 0;
fail:
	kms_free(k);
	return -1;
}

uint32_t *m17_kms_pixels(struct m17_kms *k, int i, uint32_t *pitch_pixels) {
	*pitch_pixels = k->pitch / 4u;
	return (uint32_t *)k->buf[i & 1].map;
}

int m17_kms_show(struct m17_kms *k, int i) {
	uint32_t counts[3] = {1, 2, 10};
	k->values[3] = k->buf[i & 1].fb;
	if (atomic_commit(k->fd, k->connector, k->crtc, k->plane, counts, k->props, k->values,
		k->committed ? 0 : DRM_MODE_ATOMIC_ALLOW_MODESET)) return -1;
	k->committed = 1;
	return 0;
}

int m17_kms_close(struct m17_kms *k) {
	uint32_t disable_counts[3] = {1, 2, 2};
	uint64_t disabled[5] = {0};
	int verified = 1;
	if (k->fd < 0) return M17_KMS_FAILED;
	if (k->committed) {
		if (atomic_commit(k->fd, k->connector, k->crtc, k->plane, disable_counts, k->props, disabled,
			DRM_MODE_ATOMIC_ALLOW_MODESET) &&
			atomic_commit(k->fd, k->connector, k->crtc, k->plane, disable_counts, k->props, disabled,
			DRM_MODE_ATOMIC_ALLOW_MODESET)) verified = 0;
		if (verified) verified = verify_disabled(k->fd, k->connector, k->crtc, k->plane, k->props);
		/* An unverified disable keeps the buffers: freeing what may still be scanned out is worse. */
		if (!verified) {
			close(k->fd);
			k->fd = -1;
			return M17_KMS_UNSAFE_ROLLBACK;
		}
	}
	kms_free(k);
	return M17_KMS_OK;
}
