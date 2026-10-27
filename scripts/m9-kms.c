#define _GNU_SOURCE
#include "m9-kms.h"

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

static void sleep_ms(unsigned ms) {
	struct timespec ts = {.tv_sec = ms / 1000, .tv_nsec = (long)(ms % 1000) * 1000000L};
	while (nanosleep(&ts, &ts) && errno == EINTR) {}
}

static int m9_kms_run(const char *card_path, const struct m9_kms_buffer *buffer,
		uint32_t cpu_color, unsigned hold_ms,
		m9_kms_checkpoint_fn checkpoint, void *opaque) {
	int fd = -1, rc = -1;
	bool committed = false, rollback_ok = false, cpu = buffer == NULL;
	void *cpu_map = MAP_FAILED;
	struct m9_kms_buffer cpu_buffer = {0};
	struct drm_mode_create_dumb dumb = {.width = 1080, .height = 2400, .bpp = 32};
	struct drm_mode_map_dumb dumb_map = {0};
	uint32_t crtcs[MAX_CRTCS], connectors[MAX_CONNECTORS], encoders[MAX_ENCODERS];
	uint32_t connector_encoders[MAX_ENCODERS], planes[MAX_PLANES], formats[MAX_FORMATS];
	struct drm_mode_modeinfo modes[MAX_MODES], mode = {0};
	struct drm_mode_get_connector connector;
	struct drm_mode_card_res res = {0};
	struct drm_mode_get_plane_res plane_res = {0};
	uint32_t connector_id = 0, crtc_id = 0, plane_id = 0, crtc_index = 0;
	struct props cp, rp, pp;
	struct named_prop conn_crtc, crtc_mode, crtc_active, plane_fb, plane_crtc;
	struct named_prop src_x, src_y, src_w, src_h, dst_x, dst_y, dst_w, dst_h, plane_type;
	/* CPU control deliberately passes NULL: never dereference it here. */
	struct drm_prime_handle prime = {.fd = buffer ? buffer->dma_buf_fd : -1, .flags = 0};
	struct drm_mode_fb_cmd2 fb = {0};
	struct drm_mode_create_blob blob = {0};
	uint32_t counts[3] = {1, 2, 10}, disable_counts[3] = {1, 2, 2};
	uint32_t props[13];
	uint64_t values[13], disabled[5] = {0};

	if (!cpu && (buffer->width != 1080 || buffer->height != 2400 || !buffer->pitch)) {
		fprintf(stderr, "M9KMS: invalid buffer geometry\n");
		return -1;
	}
	fd = open(card_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) { perror("M9KMS: open card0"); return -1; }
	struct drm_set_client_cap client = {DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1};
	if (ioctl(fd, DRM_IOCTL_SET_CLIENT_CAP, &client)) goto out;
	client.capability = DRM_CLIENT_CAP_ATOMIC;
	if (ioctl(fd, DRM_IOCTL_SET_CLIENT_CAP, &client)) goto out;
	if (cpu) {
		if (ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &dumb) || !dumb.handle ||
			!dumb.pitch || dumb.size < (uint64_t)dumb.pitch * 2400) goto out;
		dumb_map.handle = dumb.handle;
		if (ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &dumb_map)) goto out;
		cpu_map = mmap(NULL, dumb.size, PROT_READ | PROT_WRITE, MAP_SHARED,
			fd, (off_t)dumb_map.offset);
		if (cpu_map == MAP_FAILED) goto out;
		for (uint32_t y = 0; y < 2400; ++y) {
			uint32_t *row = (uint32_t *)((uint8_t *)cpu_map + (uint64_t)y * dumb.pitch);
			for (uint32_t x = 0; x < 1080; ++x) row[x] = cpu_color;
		}
		prime.handle = dumb.handle;
		cpu_buffer = (struct m9_kms_buffer){
			.width = 1080, .height = 2400, .pitch = dumb.pitch, .offset = 0,
		};
		buffer = &cpu_buffer;
		printf("M9KMS: CPU dumb handle=%u pitch=%u color=%08x\n",
			dumb.handle, dumb.pitch, cpu_color);
	} else {
		if (ioctl(fd, DRM_IOCTL_PRIME_FD_TO_HANDLE, &prime) || !prime.handle) goto out;
		printf("M9KMS: PRIME import handle=%u\n", prime.handle);
	}

	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res) || res.count_crtcs > MAX_CRTCS ||
		res.count_connectors > MAX_CONNECTORS || res.count_encoders > MAX_ENCODERS) goto out;
	res.crtc_id_ptr = (uintptr_t)crtcs;
	res.connector_id_ptr = (uintptr_t)connectors;
	res.encoder_id_ptr = (uintptr_t)encoders;
	if (ioctl(fd, DRM_IOCTL_MODE_GETRESOURCES, &res)) goto out;
	for (uint32_t i = 0; i < res.count_connectors && !connector_id; ++i) {
		if (get_connector(fd, connectors[i], &connector, modes, connector_encoders)) continue;
		if (connector.connector_type != DRM_MODE_CONNECTOR_DSI ||
			connector.connection != DRM_MODE_CONNECTED) continue;
		for (uint32_t j = 0; j < connector.count_modes; ++j) {
			if (modes[j].hdisplay == 1080 && modes[j].vdisplay == 2400 &&
				modes[j].vrefresh == 60 && !strcmp(modes[j].name, "1080x2400x60vid")) {
				connector_id = connector.connector_id;
				mode = modes[j];
				break;
			}
		}
	}
	if (!connector_id) goto out;
	for (uint32_t i = 0; i < connector.count_encoders && !crtc_id; ++i) {
		struct drm_mode_get_encoder e = {.encoder_id = connector_encoders[i]};
		if (ioctl(fd, DRM_IOCTL_MODE_GETENCODER, &e)) continue;
		for (uint32_t j = 0; j < res.count_crtcs; ++j) {
			if (e.possible_crtcs & (1u << j)) { crtc_id = crtcs[j]; crtc_index = j; break; }
		}
	}
	if (!crtc_id || ioctl(fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &plane_res) ||
		plane_res.count_planes > MAX_PLANES) goto out;
	plane_res.plane_id_ptr = (uintptr_t)planes;
	if (ioctl(fd, DRM_IOCTL_MODE_GETPLANERESOURCES, &plane_res)) goto out;
	for (uint32_t i = 0; i < plane_res.count_planes && !plane_id; ++i) {
		struct drm_mode_get_plane p = {.plane_id = planes[i]};
		bool xrgb = false;
		if (ioctl(fd, DRM_IOCTL_MODE_GETPLANE, &p) ||
			!(p.possible_crtcs & (1u << crtc_index)) || p.count_format_types > MAX_FORMATS) continue;
		p.format_type_ptr = (uintptr_t)formats;
		if (ioctl(fd, DRM_IOCTL_MODE_GETPLANE, &p)) continue;
		for (uint32_t j = 0; j < p.count_format_types; ++j) xrgb |= formats[j] == DRM_FORMAT_XRGB8888;
		if (!xrgb || get_props(fd, p.plane_id, DRM_MODE_OBJECT_PLANE, &pp) ||
			named_prop(fd, &pp, "type", &plane_type) || plane_type.value != DRM_PLANE_TYPE_PRIMARY ||
			named_prop(fd, &pp, "FB_ID", &plane_fb) || named_prop(fd, &pp, "CRTC_ID", &plane_crtc) ||
			plane_fb.value || plane_crtc.value) continue;
		plane_id = p.plane_id;
	}
	if (!plane_id || get_props(fd, connector_id, DRM_MODE_OBJECT_CONNECTOR, &cp) ||
		get_props(fd, crtc_id, DRM_MODE_OBJECT_CRTC, &rp) ||
		get_props(fd, plane_id, DRM_MODE_OBJECT_PLANE, &pp) ||
		named_prop(fd, &cp, "CRTC_ID", &conn_crtc) || named_prop(fd, &rp, "MODE_ID", &crtc_mode) ||
		named_prop(fd, &rp, "ACTIVE", &crtc_active) || named_prop(fd, &pp, "FB_ID", &plane_fb) ||
		named_prop(fd, &pp, "CRTC_ID", &plane_crtc) || named_prop(fd, &pp, "SRC_X", &src_x) ||
		named_prop(fd, &pp, "SRC_Y", &src_y) || named_prop(fd, &pp, "SRC_W", &src_w) ||
		named_prop(fd, &pp, "SRC_H", &src_h) || named_prop(fd, &pp, "CRTC_X", &dst_x) ||
		named_prop(fd, &pp, "CRTC_Y", &dst_y) || named_prop(fd, &pp, "CRTC_W", &dst_w) ||
		named_prop(fd, &pp, "CRTC_H", &dst_h)) goto out;
	if (plane_fb.value || plane_crtc.value || (conn_crtc.value && conn_crtc.value != crtc_id)) goto out;

	fb.width = buffer->width; fb.height = buffer->height; fb.pixel_format = DRM_FORMAT_XRGB8888;
	fb.handles[0] = prime.handle; fb.pitches[0] = buffer->pitch; fb.offsets[0] = buffer->offset;
	if (ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &fb) || !fb.fb_id) goto out;
	printf("M9KMS: framebuffer id=%u format=XRGB8888 modifier=LINEAR pitch=%u\n", fb.fb_id, buffer->pitch);
	blob.data = (uintptr_t)&mode; blob.length = sizeof(mode);
	if (ioctl(fd, DRM_IOCTL_MODE_CREATEPROPBLOB, &blob) || !blob.blob_id) goto out;
	props[0] = conn_crtc.id; props[1] = crtc_mode.id; props[2] = crtc_active.id;
	props[3] = plane_fb.id; props[4] = plane_crtc.id; props[5] = src_x.id;
	props[6] = src_y.id; props[7] = src_w.id; props[8] = src_h.id;
	props[9] = dst_x.id; props[10] = dst_y.id; props[11] = dst_w.id; props[12] = dst_h.id;
	values[0] = crtc_id; values[1] = blob.blob_id; values[2] = 1;
	values[3] = fb.fb_id; values[4] = crtc_id; values[5] = 0; values[6] = 0;
	values[7] = (uint64_t)buffer->width << 16; values[8] = (uint64_t)buffer->height << 16;
	values[9] = 0; values[10] = 0; values[11] = buffer->width; values[12] = buffer->height;
	if (atomic_commit(fd, connector_id, crtc_id, plane_id, counts, props, values,
		DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET)) goto out;
	if (atomic_commit(fd, connector_id, crtc_id, plane_id, disable_counts, props, disabled,
		DRM_MODE_ATOMIC_TEST_ONLY | DRM_MODE_ATOMIC_ALLOW_MODESET)) goto out;
	if (cpu) printf("M9KMS: CPU dumb + ADDFB2 + TEST_ONLY enable/disable PASS\n");
	else printf("M9KMS: PRIME + ADDFB2 + TEST_ONLY enable/disable PASS\n");
	if (checkpoint && checkpoint(opaque)) {
		fprintf(stderr, "M9KMS: pre-commit checkpoint failed\n");
		goto out;
	}
	if (atomic_commit(fd, connector_id, crtc_id, plane_id, counts, props, values,
		DRM_MODE_ATOMIC_ALLOW_MODESET)) goto out;
	committed = true;
	printf("M9KMS: atomic commit result=0 hold_ms=%u\n", hold_ms);
	sleep_ms(hold_ms);
	if (atomic_commit(fd, connector_id, crtc_id, plane_id, disable_counts, props, disabled,
		DRM_MODE_ATOMIC_ALLOW_MODESET) &&
		atomic_commit(fd, connector_id, crtc_id, plane_id, disable_counts, props, disabled,
		DRM_MODE_ATOMIC_ALLOW_MODESET)) goto out;
	rollback_ok = verify_disabled(fd, connector_id, crtc_id, plane_id, props);
	printf("M9KMS: teardown readback disabled=%s\n", rollback_ok ? "yes" : "no");
	if (rollback_ok) rc = 0;
out:
	if ((!committed || rollback_ok) && blob.blob_id)
		ioctl(fd, DRM_IOCTL_MODE_DESTROYPROPBLOB, &(struct drm_mode_destroy_blob){blob.blob_id});
	if ((!committed || rollback_ok) && fb.fb_id) ioctl(fd, DRM_IOCTL_MODE_RMFB, &fb.fb_id);
	if ((!committed || rollback_ok) && !cpu && prime.handle)
		ioctl(fd, DRM_IOCTL_GEM_CLOSE, &(struct drm_gem_close){.handle = prime.handle});
	if ((!committed || rollback_ok) && cpu_map != MAP_FAILED)
		munmap(cpu_map, dumb.size);
	if ((!committed || rollback_ok) && cpu && dumb.handle)
		ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB,
			&(struct drm_mode_destroy_dumb){.handle = dumb.handle});
	if (fd >= 0) close(fd);
	if (rc) fprintf(stderr, "M9KMS: failed committed=%d rollback=%d errno=%d\n",
		committed, rollback_ok, errno);
	if (committed && !rollback_ok) return M9_KMS_UNSAFE_ROLLBACK;
	return rc ? M9_KMS_FAILED : M9_KMS_OK;
}

int m9_kms_scanout_observed(const char *card_path,
		const struct m9_kms_buffer *buffer, unsigned hold_ms,
		m9_kms_checkpoint_fn checkpoint, void *opaque) {
	return m9_kms_run(card_path, buffer, 0, hold_ms, checkpoint, opaque);
}

int m9_kms_scanout(const char *card_path, const struct m9_kms_buffer *buffer,
		unsigned hold_ms) {
	return m9_kms_scanout_observed(card_path, buffer, hold_ms, NULL, NULL);
}

int m9_kms_cpu_checkpoint(const char *card_path, uint32_t xrgb8888,
		unsigned hold_ms) {
	return m9_kms_run(card_path, NULL, xrgb8888, hold_ms, NULL, NULL);
}
