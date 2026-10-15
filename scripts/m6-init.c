/*
 * M6 phase 1 init for marble: storage bring-up from a native initramfs.
 *
 * Freestanding aarch64, no libc, direct syscalls, same discipline as
 * scripts/m5-init.c. M5 proved this program runs as PID 1 on the device with
 * the M3 kernel and nothing of Android's. M6 asks the next question: can it
 * bring UFS up itself and read the firmware partitions.
 *
 * It loads exactly the modules in the audited closure and no others. The
 * closure is computed by scripts/m6-module-closure.py from modules.dep plus
 * the stock supplier device links, and verified against the kernel's own
 * Module.symvers by scripts/m6-verify-closure-kmi.py before any of this runs.
 * The .ko files themselves are not carried here: the bootloader concatenates
 * the untouched vendor_boot ramdisk ahead of our archive, so /lib/modules is
 * already in the rootfs. Nothing proprietary is copied anywhere.
 *
 * Everything it mounts is read-only, twice over:
 *
 *   - BLKROSET on the block device before the mount, so the block layer itself
 *     refuses writes and there is no path by which a filesystem bug or a
 *     journal replay could reach the flash;
 *   - MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC on the mount, and "norecovery"
 *     for ext4, because a plain read-only ext4 mount still replays the journal
 *     and that would be a write to an internal partition.
 *
 * /data is never touched. No partition is written. No partition other than the
 * three firmware ones is opened.
 *
 * Two channels report the outcome, because M6 still has no console:
 *
 *   M6_ACTION_EXEC=0  the delay before reboot encodes how far we got, which
 *                     works even when nothing else can be read. Needs no
 *                     Android and no root.
 *   M6_ACTION_EXEC=1  hand over to /init.stock the way the M5 E4 wrapper did,
 *                     so Android boots and the same boot's dmesg carries every
 *                     M6: line. Needs the M4 kernel for root, which makes that
 *                     image a diagnostic carrier and not a baseline.
 */

#ifndef M6_BASE_SECONDS
#define M6_BASE_SECONDS 20
#endif
#ifndef M6_UNIT_SECONDS
#define M6_UNIT_SECONDS 10
#endif
#ifndef M6_ACTION_EXEC
#define M6_ACTION_EXEC 0
#endif
/* Per-stage patience. Stock reaches its first mount in about three seconds. */
#ifndef M6_WAIT_SECONDS
#define M6_WAIT_SECONDS 15
#endif

/*
 * Diagnostic narrowing, used only after run D failed with no output at all.
 *
 * M6_MODULE_PREFIX  how many of the closure to load, taken from the front of the
 *                   stock-order list. -1 means all of them. The list is never
 *                   reordered and nothing is ever added to it: a prefix is a
 *                   prefix.
 * M6_BISECT         stop after the module phase and hand over, so no UFS wait,
 *                   no partition search and no mount happens. The block
 *                   read-only handling is untouched because it is never
 *                   reached.
 *
 * Every insmod is logged before and after, so a prefix that survives yields a
 * complete record. A prefix that does not survive yields nothing, which is why
 * the boundary is found by which prefixes come back rather than by reading a
 * log. The module at the boundary is where the failure becomes visible, not
 * necessarily the module at fault: proving that needs its own experiment.
 */
#ifndef M6_MODULE_PREFIX
#define M6_MODULE_PREFIX (-1)
#endif
#ifndef M6_BISECT
#define M6_BISECT 0
#endif

/*
 * M6_SUPPLIER_DUMP  observability only. After the controller-bind check, dump
 *                   the driver core's own view of why it did or did not bind,
 *                   then hand over. No LUN scan, no partition search, no mount.
 *
 * D2 established that every module in the closure loads and ufshcd-qcom still
 * does not bind.
 * Naming a culprit from the 26 modules Android loads next would be a guess, so
 * this reads what the kernel already tracks instead.
 *
 * Checked against the pinned ACK's drivers/base/core.c rather than assumed.
 * device_links_check_suppliers() defers a probe for exactly two reasons:
 *
 *   dev->fwnode->suppliers is non-empty - a device-tree phandle whose supplier
 *   device does not exist at all. Exposed as waiting_for_supplier, which is
 *   created in device_add_attrs() and *removed in device_links_driver_bound()*.
 *   Its absence on a bound device therefore means nothing; on an unbound one it
 *   is the answer. Reading only the stock device would have concluded the
 *   kernel does not expose it.
 *
 *   a managed device_link whose status is not "available", unless the link is
 *   sync-state-only. Exposed per link as status, one of "not tracked",
 *   "dormant", "available", "consumer probing", "active", "supplier
 *   unbinding".
 *
 * So both are logged, per link, one atomic line each, alongside whether the
 * supplier itself has a driver bound. Nothing here interprets beyond those
 * primitives.
 */
#ifndef M6_SUPPLIER_DUMP
#define M6_SUPPLIER_DUMP 0
#endif

/*
 * M6 phase 2: the remoteprocs, one at a time.
 *
 * M6_PHASE    which closure the image carries. 1 is the frozen M6a storage set,
 *             2 is the M6b superset that adds the remoteproc drivers. M6a is
 *             hardware-proven, so phase 2 is a superset of it and never a
 *             revision of it.
 * M6_RPROC    which single remoteproc to bring up. NONE is the control: the
 *             larger closure loads and the storage stages run exactly as in
 *             M6a, every remoteproc the kernel has is logged, and none is
 *             started. ADSP, CDSP, SLPI and MSS each start exactly one. There
 *             is deliberately no way to ask for two.
 */
#ifndef M6_PHASE
#define M6_PHASE 1
#endif

#define M6_RPROC_NONE 0
#define M6_RPROC_ADSP 1
#define M6_RPROC_CDSP 2
#define M6_RPROC_SLPI 3
#define M6_RPROC_MSS 4
#ifndef M6_RPROC
#define M6_RPROC M6_RPROC_NONE
#endif
#if M6_RPROC != M6_RPROC_NONE && M6_PHASE != 2
#error "starting a remoteproc needs the phase 2 closure"
#endif

/*
 * M6_RPROC_DUMP  observability only, the R2 experiment.
 *
 * The control run loaded all 52 modules, passed every storage stage, and still
 * broke the boot: three of the four remoteproc probes failed at 0.56 s and the
 * driver freed them, so only ADSP existed for the rest of the boot and the
 * sensor stack never came up. The probes ran while Android's own first stage
 * was still loading qcom_ipcc, qcom_tsens and rpmh-regulator, and they were not
 * retried - so they did not return -EPROBE_DEFER.
 *
 * That distinction is the whole question, and the kernel already answers it:
 * devices_deferred lists exactly the devices the driver core will retry. A
 * device on that list was early; a device missing from it failed hard. This
 * build waits past the probe window, dumps the link graph for all four
 * remoteproc devices, reads devices_deferred, and hands over. It starts
 * nothing and adds no module.
 */
#ifndef M6_RPROC_DUMP
#define M6_RPROC_DUMP 0
#endif
#if M6_RPROC_DUMP && (M6_PHASE != 2 || M6_RPROC != M6_RPROC_NONE)
#error "the observability build starts nothing and needs the phase 2 closure"
#endif

/* The modem's firmware load is 109 MB off a vfat filesystem. */
#ifndef M6_RPROC_WAIT_SECONDS
#define M6_RPROC_WAIT_SECONDS 30
#endif

#define UFSHC_SYSFS "/sys/devices/platform/soc/1d84000.ufshc"

/*
 * The stage ladder, and the only value that counts as a pass:
 *
 *   0  init ran; a module failed to load
 *   1  every module in the closure loaded
 *   2  ufshcd-qcom bound 1d84000.ufshc
 *   3  all six UFS LUNs enumerated
 *   4  modem_a, bluetooth_a and dsp_a found by PARTNAME
 *   5  all three mounted read-only under /m6
 *   6  all three listed a non-empty directory
 *
 * and, only when this image selects a remoteproc, four more:
 *
 *   7  the direct firmware loader points at the mounted image directory
 *   8  the selected remoteproc exists, is offline, and so is every sibling
 *   9  its firmware name is set and the named file is readable
 *  10  it started and reached "running"
 *  11  it stopped again and is back to "offline"
 */
#define M6_STORAGE_PASS 6
#define M6_RPROC_PASS 11
#if M6_RPROC == M6_RPROC_NONE
#define M6_STAGE_PASS M6_STORAGE_PASS
#else
#define M6_STAGE_PASS M6_RPROC_PASS
#endif

#define M6_MAGIC1 0xfee1deadu
#define M6_MAGIC2 0x28121969u
#define M6_CMD_RESTART 0x01234567u

typedef unsigned long ulong;
typedef long slong;

static inline slong sys(slong n, ulong a, ulong b, ulong c, ulong d, ulong e)
{
	register ulong x8 __asm__("x8") = (ulong)n;
	register ulong x0 __asm__("x0") = a;
	register ulong x1 __asm__("x1") = b;
	register ulong x2 __asm__("x2") = c;
	register ulong x3 __asm__("x3") = d;
	register ulong x4 __asm__("x4") = e;
	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4)
			 : "memory", "cc");
	return (slong)x0;
}

#define SYS_ioctl 29
#define SYS_mknodat 33
#define SYS_mkdirat 34
#define SYS_unlinkat 35
#define SYS_umount2 39
#define SYS_mount 40
#define SYS_openat 56
#define SYS_close 57
#define SYS_getdents64 61
#define SYS_readlinkat 78
#define SYS_read 63
#define SYS_write 64
#define SYS_nanosleep 101
#define SYS_reboot 142
#define SYS_getpid 172
#define SYS_execve 221
#define SYS_finit_module 273

#define AT_FDCWD -100
#define AT_REMOVEDIR 0x200
#define O_RDONLY 0
#define O_WRONLY 1
/* arm64 overrides asm-generic here: arch/arm64/include/uapi/asm/fcntl.h
 * makes O_DIRECTORY 040000 and gives 0200000 to O_DIRECT, which sysfs
 * rejects with EINVAL. The asm-generic value silently opened nothing. */
#define O_DIRECTORY 040000
#define MS_RDONLY 1
#define MS_NOSUID 2
#define MS_NODEV 4
#define MS_NOEXEC 8
#define BLKROSET 0x125d
#define BLKROGET 0x125e
#define S_IFBLK 0060000
#define S_IFCHR 0020000

static slong s_open(const char *p, int fl) { return sys(SYS_openat, (ulong)AT_FDCWD, (ulong)p, (ulong)fl, 0, 0); }
static void s_close(int fd) { sys(SYS_close, (ulong)fd, 0, 0, 0, 0); }
static slong s_write(int fd, const void *b, ulong n) { return sys(SYS_write, (ulong)fd, (ulong)b, n, 0, 0); }
static slong s_mkdir(const char *p, ulong m) { return sys(SYS_mkdirat, (ulong)AT_FDCWD, (ulong)p, m, 0, 0); }
static slong s_unlink(const char *p) { return sys(SYS_unlinkat, (ulong)AT_FDCWD, (ulong)p, 0, 0, 0); }
static slong s_mknod(const char *p, ulong m, ulong dev) { return sys(SYS_mknodat, (ulong)AT_FDCWD, (ulong)p, m, dev, 0); }

struct timespec_ { slong tv_sec; slong tv_nsec; };
static void s_sleep_ms(slong ms)
{
	struct timespec_ req;
	req.tv_sec = ms / 1000;
	req.tv_nsec = (ms % 1000) * 1000000L;
	while (sys(SYS_nanosleep, (ulong)&req, 0, 0, 0, 0) == -4)
		;
}

/* clang may synthesise these even under -ffreestanding. */
void *memset(void *d, int c, ulong n)
{
	unsigned char *p = d;
	while (n--)
		*p++ = (unsigned char)c;
	return d;
}
void *memcpy(void *d, const void *s, ulong n)
{
	unsigned char *a = d;
	const unsigned char *b = s;
	while (n--)
		*a++ = *b++;
	return d;
}

static char *scat(char *dst, const char *src)
{
	while (*src) *dst++ = *src++;
	*dst = 0;
	return dst;
}

static int kmsg_fd = -1;

/*
 * One write per line, buffered until the newline.
 *
 * Every write to /dev/kmsg becomes its own record, so a line assembled from
 * several calls arrives as several records and reads as gibberish. Worse,
 * /dev/kmsg is rate limited per file description - ten messages in five
 * seconds unless printk.devkmsg=on - so splitting one line three ways spends
 * that budget three times as fast. The first full-prefix run lost its RESULT
 * line to exactly that.
 */
static char lbuf[256];
static ulong llen;

static void emit(const char *s)
{
	for (; *s; s++) {
		if (llen < sizeof(lbuf) - 1)
			lbuf[llen++] = *s;
		if (*s == '\n') {
			if (kmsg_fd >= 0)
				s_write(kmsg_fd, lbuf, llen);
			llen = 0;
		}
	}
}

static void say(const char *s)
{
	emit(s);
}

static void say_num(const char *prefix, slong value, const char *suffix)
{
	char buf[96], *p = buf;
	int negative = value < 0;
	unsigned long magnitude = negative ? (unsigned long)-value : (unsigned long)value;
	char digits[24];
	int n = 0;

	p = scat(p, prefix);
	if (negative) *p++ = '-';
	do { digits[n++] = (char)('0' + magnitude % 10); magnitude /= 10; } while (magnitude);
	while (n) *p++ = digits[--n];
	*p = 0;
	scat(p, suffix);
	emit(buf);
}

/* ------------------------------------------------------------------ modules */

/*
 * The load order is the stock first-stage order restricted to the closure, so
 * every module's dependencies are already loaded when it is reached. Generated
 * by scripts/m6-module-closure.py --load-list and pasted here rather than read
 * at run time, so the set this image loads is fixed at build time and visible
 * in review.
 */
static const char *const CLOSURE[] = {
#if M6_PHASE == 2
#include "m6b-closure-load-order.inc"
#else
#include "m6-closure-load-order.inc"
#endif
};
#define CLOSURE_COUNT ((int)(sizeof(CLOSURE) / sizeof(CLOSURE[0])))

static int module_limit(void)
{
	int limit = M6_MODULE_PREFIX;
	if (limit < 0 || limit > CLOSURE_COUNT)
		limit = CLOSURE_COUNT;
	return limit;
}

/* Index and name before the call, return value after it, one line each. */
static void say_mod(int index, const char *name, const char *tail, slong rc, int with_rc)
{
	say_num("M6: insmod[", index, "] ");
	say(name);
	if (with_rc)
		say_num(tail, rc, "\n");
	else {
		say(tail);
		say("\n");
	}
}

static int load_modules(int *loaded)
{
	char path[128];
	const int limit = module_limit();
	int i;

	*loaded = 0;
	say_num("M6: module prefix=", limit, "");
	say_num(" of ", CLOSURE_COUNT, "\n");
	for (i = 0; i < limit; i++) {
		slong fd, rc;
		char *p = scat(path, "/lib/modules/");
		scat(p, CLOSURE[i]);
		say_mod(i, CLOSURE[i], " begin", 0, 0);
		fd = s_open(path, O_RDONLY);
		if (fd < 0) {
			say_mod(i, CLOSURE[i], " open rc=", fd, 1);
			return i;
		}
		rc = sys(SYS_finit_module, (ulong)fd, (ulong)"", 0, 0, 0);
		s_close((int)fd);
		say_mod(i, CLOSURE[i], " rc=", rc, 1);
		if (rc != 0)
			return i;
		*loaded = i + 1;
	}
	say_num("M6: modules loaded count=", *loaded, "\n");
	return -1;
}

/* -------------------------------------------------------------------- sysfs */

#if !M6_BISECT
/*
 * Everything from here to the handover is storage work. A narrowing build does
 * not compile it at all, so "the bisection does not touch UFS" is a property of
 * the binary rather than a promise about control flow.
 */
static slong s_rmdir(const char *p) { return sys(SYS_unlinkat, (ulong)AT_FDCWD, (ulong)p, AT_REMOVEDIR, 0, 0); }
static slong s_umount(const char *p) { return sys(SYS_umount2, (ulong)p, 0, 0, 0, 0); }
static slong s_mount(const char *src, const char *tgt, const char *fs, ulong fl, const void *data)
{
	return sys(SYS_mount, (ulong)src, (ulong)tgt, (ulong)fs, fl, (ulong)data);
}
static slong s_read(int fd, void *b, ulong n) { return sys(SYS_read, (ulong)fd, (ulong)b, n, 0, 0); }
static ulong slen(const char *s) { ulong n = 0; while (s[n]) n++; return n; }

static int seq(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

static int exists(const char *path)
{
	slong fd = s_open(path, O_RDONLY);
	if (fd < 0)
		return 0;
	s_close((int)fd);
	return 1;
}

static int wait_for(const char *path, int seconds)
{
	int i;
	for (i = 0; i < seconds * 10; i++) {
		if (exists(path))
			return 1;
		s_sleep_ms(100);
	}
	return 0;
}

struct dirent64_ {
	unsigned long long d_ino;
	long long d_off;
	unsigned short d_reclen;
	unsigned char d_type;
	char d_name[];
};

/* Read a whole small sysfs file. Returns length, or a negative errno. */
static slong slurp(const char *path, char *buf, ulong cap)
{
	slong fd = s_open(path, O_RDONLY), n;
	if (fd < 0)
		return fd;
	n = s_read((int)fd, buf, cap - 1);
	s_close((int)fd);
	if (n < 0)
		return n;
	buf[n] = 0;
	return n;
}

/* Value of KEY= in a uevent buffer, copied into out. 1 on success. */
static int uevent_get(const char *buf, const char *key, char *out, ulong cap)
{
	const char *p = buf;
	ulong klen = slen(key);

	while (*p) {
		const char *line = p, *q;
		ulong i;
		while (*p && *p != '\n') p++;
		for (i = 0; i < klen && line[i] == key[i]; i++)
			;
		if (i == klen && line[klen] == '=') {
			q = line + klen + 1;
			i = 0;
			while (q + i < p && i + 1 < cap) { out[i] = q[i]; i++; }
			out[i] = 0;
			return 1;
		}
		if (*p) p++;
	}
	return 0;
}

static slong to_num(const char *s)
{
	slong v = 0;
	if (!*s) return -1;
	while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
	return *s ? -1 : v;
}

/* ------------------------------------------------------- supplier dump (D3) */

#if M6_SUPPLIER_DUMP || M6_RPROC_DUMP

/*
 * One line per device link, assembled and written once so it cannot be torn
 * apart into separate kmsg records. Only primitives the kernel actually
 * exposes: the link's own status and sync_state_only, the resolved supplier
 * path, and whether that supplier has a driver bound. open() follows the
 * symlink chain, so "<consumer>/supplier:<x>/supplier/driver" answers the last
 * question without any path arithmetic.
 */
static void trim(char *s)
{
	while (*s && *s != '\n')
		s++;
	*s = 0;
}

static void dump_field(const char *dir, const char *leaf, char *out, ulong cap)
{
	char path[512];
	char *p = scat(path, dir);
	p = scat(p, "/");
	scat(p, leaf);
	if (slurp(path, out, cap) <= 0)
		scat(out, "-");
	else
		trim(out);
}

static void dump_links(const char *devpath, int depth)
{
	char dbuf[4096], link[512], target[256], status[48], sso[16];
	slong fd = s_open(devpath, O_RDONLY | O_DIRECTORY), n;
	int plain = 0;

	if (fd < 0) {
		/*
		 * Record the errno rather than assume a cause, and retry without
		 * O_DIRECTORY so one run distinguishes "the flag is the problem"
		 * from "the path is". getdents64 still returns ENOTDIR if the
		 * target is not a directory, so nothing is lost by dropping it.
		 */
		slong first = fd;
		fd = s_open(devpath, O_RDONLY);
		plain = fd >= 0;
		say("M6: dump open ");
		say(devpath);
		say_num(" o_directory_rc=", first, "");
		say_num(" plain_rc=", fd, "\n");
		if (fd < 0)
			return;
	}
	if (plain)
		say("M6: dump proceeding without O_DIRECTORY\n");
	{
		slong probe = sys(SYS_getdents64, (ulong)fd, (ulong)dbuf, sizeof(dbuf), 0, 0);
		if (probe <= 0)
			say_num("M6: dump getdents rc=", probe, "\n");
		n = probe;
	}
	for (; n > 0; n = sys(SYS_getdents64, (ulong)fd, (ulong)dbuf, sizeof(dbuf), 0, 0)) {
		slong off = 0;
		while (off < n) {
			struct dirent64_ *de = (struct dirent64_ *)(dbuf + off);
			char *p;
			slong len;
			int bound;

			off += de->d_reclen;
			/* "supplier:" and nothing else; consumer: links point the
			 * other way and are not what blocks this probe. */
			if (de->d_name[0] != 's' || de->d_name[1] != 'u' ||
			    de->d_name[2] != 'p' || de->d_name[8] != ':')
				continue;

			p = scat(link, devpath);
			p = scat(p, "/");
			scat(p, de->d_name);
			dump_field(link, "status", status, sizeof(status));
			dump_field(link, "sync_state_only", sso, sizeof(sso));

			{
				char sp[512];
				char *q = scat(sp, link);
				char *r = scat(q, "/supplier");
				len = sys(SYS_readlinkat, (ulong)AT_FDCWD, (ulong)sp,
					  (ulong)target, sizeof(target) - 1, 0);
				target[len > 0 ? len : 0] = 0;
				if (len <= 0)
					scat(target, "-");
				/* Append to the end of "/supplier", not over it: the
				 * first D3 run checked the devlink's own driver and
				 * reported no for every link, including active ones. */
				scat(r, "/driver");
				bound = exists(sp);
			}
			say("M6: link depth=");
			say(depth ? "0 " : "1 ");
			say(de->d_name);
			say(" status=");
			say(status);
			say(" sync_state_only=");
			say(sso);
			say(" supplier_bound=");
			say(bound ? "yes" : "no");
			say(" target=");
			say(target);
			say("\n");

			/* Only unbound suppliers are worth descending into. */
			if (depth > 0 && !bound) {
				char sub[512];
				char *q = scat(sub, link);
				scat(q, "/supplier");
				dump_links(sub, depth - 1);
			}
		}
	}
	s_close((int)fd);
}

static void dump_consumer(const char *devpath)
{
	char value[64], path[512];
	char *p = scat(path, devpath);

	scat(p, "/driver");
	say("M6: dump consumer=");
	say(devpath);
	say(" driver_bound=");
	say(exists(path) ? "yes" : "no");
	p = scat(path, devpath);
	scat(p, "/waiting_for_supplier");
	if (slurp(path, value, sizeof(value)) > 0) {
		trim(value);
		say(" waiting_for_supplier=");
		say(value);
	} else {
		/* Removed by device_links_driver_bound(), so absent means bound,
		 * not unsupported. Recorded as absent, not interpreted here. */
		say(" waiting_for_supplier=absent");
	}
	say("\n");
	dump_links(devpath, 1);
	say("M6: dump end\n");
}

#if M6_RPROC_DUMP

/*
 * The one thing the link graph cannot say: did the probe defer, or fail.
 *
 * devices_deferred is the driver core's own list of what it will retry. A
 * device on it returned -EPROBE_DEFER and its supplier was merely late; a
 * device missing from it failed hard and will never be probed again, which is
 * exactly what happened to three remoteprocs in the control run. The reason
 * column is only populated when the driver used dev_err_probe(), so the
 * membership is the datum and the text is a bonus.
 *
 * debugfs is a virtual filesystem mounted read-only under the sysfs tree this
 * init already mounts, and unmounted again first. No block device is involved.
 */
static void dump_deferred(void)
{
	char buf[4096], *line, *p;
	slong n, rc;

	rc = s_mount("debugfs", "/sys/kernel/debug", "debugfs",
		     MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, 0);
	say_num("M6: debugfs mount rc=", rc, "\n");
	if (rc != 0)
		return;
	n = slurp("/sys/kernel/debug/devices_deferred", buf, sizeof(buf));
	say_num("M6: devices_deferred bytes=", n, "\n");
	for (line = buf, p = buf; n > 0 && *p; p++) {
		if (*p != '\n')
			continue;
		*p = 0;
		say("M6: deferred ");
		say(line);
		say("\n");
		line = p + 1;
	}
	rc = s_umount("/sys/kernel/debug");
	say_num("M6: debugfs umount rc=", rc, "\n");
}

/*
 * By name, never by index: the reboot after the control run brought the four
 * up in a different order than the snapshot before it.
 */
static void dump_remoteprocs(void)
{
	static const char *const DEVICES[] = {
		"/sys/bus/platform/devices/3000000.remoteproc-adsp",
		"/sys/bus/platform/devices/32300000.remoteproc-cdsp",
		"/sys/bus/platform/devices/4080000.remoteproc-mss",
		"/sys/bus/platform/devices/2400000.remoteproc-slpi",
	};
	int i;

	for (i = 0; i < (int)(sizeof(DEVICES) / sizeof(DEVICES[0])); i++)
		dump_consumer(DEVICES[i]);
	dump_deferred();
}

#endif /* M6_RPROC_DUMP */

#endif /* M6_SUPPLIER_DUMP || M6_RPROC_DUMP */

/*
 * Find a GPT partition by its label. There is no devtmpfs and no ueventd here,
 * so the name has to come from the block uevent, which carries PARTNAME
 * alongside MAJOR and MINOR. Reading it back is also the check: we mount what
 * the kernel says is named modem_a, never a hardcoded minor number.
 */
static int find_partition(const char *want, slong *major, slong *minor)
{
	char dbuf[4096], pbuf[4096], path[256], uevent[1024], value[64];
	slong dfd = s_open("/sys/block", O_RDONLY | O_DIRECTORY);
	slong n;

	if (dfd < 0)
		return 0;
	while ((n = sys(SYS_getdents64, (ulong)dfd, (ulong)dbuf, sizeof(dbuf), 0, 0)) > 0) {
		slong off = 0;
		while (off < n) {
			struct dirent64_ *de = (struct dirent64_ *)(dbuf + off);
			off += de->d_reclen;
			if (de->d_name[0] != 's' || de->d_name[1] != 'd')
				continue;
			char *p = scat(path, "/sys/block/");
			p = scat(p, de->d_name);
			slong pfd = s_open(path, O_RDONLY | O_DIRECTORY);
			slong m;
			if (pfd < 0)
				continue;
			while ((m = sys(SYS_getdents64, (ulong)pfd, (ulong)pbuf, sizeof(pbuf), 0, 0)) > 0) {
				slong poff = 0;
				while (poff < m) {
					struct dirent64_ *pe = (struct dirent64_ *)(pbuf + poff);
					poff += pe->d_reclen;
					if (pe->d_name[0] != 's' || pe->d_name[1] != 'd')
						continue;
					char *q = scat(path, "/sys/block/");
					q = scat(q, de->d_name);
					q = scat(q, "/");
					q = scat(q, pe->d_name);
					scat(q, "/uevent");
					if (slurp(path, uevent, sizeof(uevent)) <= 0)
						continue;
					if (!uevent_get(uevent, "PARTNAME", value, sizeof(value)))
						continue;
					if (!seq(value, want))
						continue;
					if (!uevent_get(uevent, "MAJOR", value, sizeof(value)))
						continue;
					*major = to_num(value);
					if (!uevent_get(uevent, "MINOR", value, sizeof(value)))
						continue;
					*minor = to_num(value);
					s_close((int)pfd);
					s_close((int)dfd);
					return (*major >= 0 && *minor >= 0);
				}
			}
			s_close((int)pfd);
		}
	}
	s_close((int)dfd);
	return 0;
}

/* --------------------------------------------------------------- mounting */

/*
 * Set the block device's read-only flag and read it back, so the log records
 * the state the kernel actually holds rather than the fact that an ioctl
 * returned zero. Returns 1 only if the readback agrees.
 *
 * This flag is an in-memory attribute of the block device for this boot. It
 * writes nothing to flash, changes no partition, and is gone at the next
 * reboot. It is set for the window in which we have a filesystem mounted and
 * cleared again afterwards, so the state handed on is the state we found.
 */
static int blkro(const char *node, const char *label, int want, const char *phase)
{
	slong fd, rc;
	int value = want, readback = -1;

	fd = s_open(node, O_RDONLY);
	if (fd < 0) {
		say("M6: blkro open failed ");
		say(label);
		say_num(" rc=", fd, "\n");
		return 0;
	}
	rc = sys(SYS_ioctl, (ulong)fd, BLKROSET, (ulong)&value, 0, 0);
	if (rc == 0)
		sys(SYS_ioctl, (ulong)fd, BLKROGET, (ulong)&readback, 0, 0);
	s_close((int)fd);

	say("M6: blkro ");
	say(label);
	say(" ");
	say(phase);
	say_num(" want=", want, "");
	say_num(" rc=", rc, "");
	say_num(" readback=", readback, "\n");
	return rc == 0 && readback == want;
}

/*
 * Read-only at the block layer first. If BLKROSET does not take, we do not
 * mount: the guarantee that nothing can write to an internal partition is not
 * something to proceed without.
 */
static int mount_ro(const char *label, slong major, slong minor,
		    const char *node, const char *point,
		    const char *fstype, const char *data)
{
	slong rc;

	s_unlink(node);
	rc = s_mknod(node, S_IFBLK | 0600, (ulong)((major << 8) | (minor & 0xff) |
						   ((minor & ~0xffUL) << 12)));
	if (rc != 0) {
		say("M6: mknod failed ");
		say(label);
		say_num(" rc=", rc, "\n");
		return 0;
	}
	if (!blkro(node, label, 1, "before-mount"))
		return 0;
	s_mkdir(point, 0755);
	rc = s_mount(node, point, fstype,
		     MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, data);
	if (rc != 0) {
		say("M6: mount failed ");
		say(label);
		say_num(" rc=", rc, "\n");
		return 0;
	}
	say("M6: mounted ");
	say(label);
	say(" as ");
	say(fstype);
	say_num(" ro at major=", major, "");
	say_num(" minor=", minor, "\n");
	return 1;
}

/* Proof the filesystem was really parsed, not just that mount returned 0. */
static int count_entries(const char *point)
{
	char buf[8192];
	slong fd = s_open(point, O_RDONLY | O_DIRECTORY), n;
	int count = 0;

	if (fd < 0)
		return -1;
	while ((n = sys(SYS_getdents64, (ulong)fd, (ulong)buf, sizeof(buf), 0, 0)) > 0) {
		slong off = 0;
		while (off < n) {
			struct dirent64_ *de = (struct dirent64_ *)(buf + off);
			off += de->d_reclen;
			if (!seq(de->d_name, ".") && !seq(de->d_name, ".."))
				count++;
		}
	}
	s_close((int)fd);
	return count;
}

struct target {
	const char *label;
	const char *partname;
	const char *node;
	const char *point;
	const char *fstype;
	const char *data;
};

/*
 * Exactly the three firmware partitions M7 and the remoteproc work will need,
 * with the filesystem types stock's own fstab.qcom declares. norecovery on the
 * ext4 one is not optional: a read-only ext4 mount replays the journal without
 * it, and that would be a write.
 */
static const struct target TARGETS[] = {
	{ "modem",     "modem_a",     "/m6/dev/modem", "/m6/modem", "vfat", 0 },
	{ "bluetooth", "bluetooth_a", "/m6/dev/bt",    "/m6/bt",    "vfat", 0 },
	{ "dsp",       "dsp_a",       "/m6/dev/dsp",   "/m6/dsp",   "ext4", "norecovery" },
};
#define TARGET_COUNT ((int)(sizeof(TARGETS) / sizeof(TARGETS[0])))

/*
 * Leave nothing behind. Everything M6 touched lives under /m6, so the whole
 * subtree goes, and the block flag is put back the way it was found and read
 * back again. Android must inherit the rootfs and the block layer unchanged.
 */
static int sysfs_mounted;

static void unmount_all(void)
{
	int i;
	for (i = TARGET_COUNT - 1; i >= 0; i--) {
		slong rc = s_umount(TARGETS[i].point);
		say("M6: umount ");
		say(TARGETS[i].label);
		say_num(" rc=", rc, "\n");
		if (exists(TARGETS[i].node))
			blkro(TARGETS[i].node, TARGETS[i].label, 0, "after-umount");
		s_rmdir(TARGETS[i].point);
		s_unlink(TARGETS[i].node);
	}
	s_rmdir("/m6/dev");
	s_rmdir("/m6");
	/* Last, and only if it was ours: Android must inherit the mount table it
	 * would have had. Leaving /proc and /sys behind is what broke the
	 * handover the first time. */
	if (sysfs_mounted) {
		slong rc = s_umount("/sys");
		sysfs_mounted = rc != 0;
		say_num("M6: umount /sys rc=", rc, "\n");
	}
	say("M6: /m6 removed, block flags restored, mount table as found\n");
}

/* --------------------------------------------------------------- remoteproc */

#if M6_PHASE == 2

/*
 * The image directory is on modem_a, which stage 5 already mounted read-only at
 * /m6/modem. Nothing new is mounted for this phase.
 */
#define FW_PARAM "/sys/module/firmware_class/parameters/path"
#define FW_DIR "/m6/modem/image"
#define RPROC_CLASS "/sys/class/remoteproc"

static void trim_nl(char *s)
{
	while (*s && *s != '\n')
		s++;
	*s = 0;
}

static void join(char *out, const char *dir, const char *leaf)
{
	char *p = scat(out, dir);
	p = scat(p, "/");
	scat(p, leaf);
}

/* 1 and the trimmed value on success, 0 and an empty string otherwise. */
static int attr_get(const char *dir, const char *leaf, char *out, ulong cap)
{
	char path[256];

	join(path, dir, leaf);
	if (slurp(path, out, cap) <= 0) {
		out[0] = 0;
		return 0;
	}
	trim_nl(out);
	return 1;
}

/*
 * Log every remoteproc the kernel has, and hand back the sysfs directory of the
 * one whose device symlink names want_device.
 *
 * Logging all of them is the sibling check. Only one node may ever leave
 * "offline" in a run, and the only way to know that held is to record what all
 * of them were doing before and after. The index is not the identity: probe
 * order decides which node is remoteproc0, and ours need not match stock's, so
 * the match is on the device name behind the symlink.
 */
static int rproc_scan(char *out, ulong cap, const char *want_device)
{
	char dbuf[4096], node[192], target[256], state[32], firmware[64];
	slong fd = s_open(RPROC_CLASS, O_RDONLY | O_DIRECTORY), n;
	int count = 0, found = 0;

	if (fd < 0) {
		say_num("M6: remoteproc class open rc=", fd, "\n");
		return 0;
	}
	while ((n = sys(SYS_getdents64, (ulong)fd, (ulong)dbuf, sizeof(dbuf), 0, 0)) > 0) {
		slong off = 0;
		while (off < n) {
			struct dirent64_ *de = (struct dirent64_ *)(dbuf + off);
			char path[256], *device = target;
			slong len;
			char *p;

			off += de->d_reclen;
			if (de->d_name[0] != 'r' || de->d_name[1] != 'e')
				continue;
			join(node, RPROC_CLASS, de->d_name);
			join(path, node, "device");
			len = sys(SYS_readlinkat, (ulong)AT_FDCWD, (ulong)path,
				  (ulong)target, sizeof(target) - 1, 0);
			if (len <= 0)
				continue;
			target[len] = 0;
			for (p = target; *p; p++)
				if (*p == '/')
					device = p + 1;
			attr_get(node, "state", state, sizeof(state));
			attr_get(node, "firmware", firmware, sizeof(firmware));
			count++;

			say("M6: rproc ");
			say(de->d_name);
			say(" device=");
			say(device);
			say(" state=");
			say(state);
			say(" firmware=");
			say(firmware);
			say("\n");

			if (want_device && seq(device, want_device)) {
				found = 1;
				if (out) {
					ulong i = 0;
					while (node[i] && i < cap - 1) {
						out[i] = node[i];
						i++;
					}
					out[i] = 0;
				}
			}
		}
	}
	s_close((int)fd);
	say_num("M6: rproc nodes=", count, "\n");
	return found;
}

#if M6_RPROC != M6_RPROC_NONE

/* Writing is compiled in only for a build that selects a node: the control
 * cannot change a kernel attribute even by mistake. */
static slong sysfs_put(const char *path, const char *value, ulong len)
{
	slong fd = s_open(path, O_WRONLY), rc;

	if (fd < 0)
		return fd;
	rc = s_write((int)fd, value, len);
	s_close((int)fd);
	return rc;
}

static slong attr_put(const char *dir, const char *leaf, const char *value)
{
	char path[256];

	join(path, dir, leaf);
	return sysfs_put(path, value, slen(value));
}

struct rproc_target {
	const char *key;
	const char *device;
	const char *firmware;
};

/*
 * The firmware name is set here rather than taken from the driver, and that is
 * not a convenience.
 *
 * The device tree carries neither firmware-name nor qcom,auto-boot on any of
 * the four nodes, so the driver falls back to its own per-compatible table.
 * That table says adsp.mdt and slpi.mdt, and neither file exists on this ROM:
 * the images are adsp2.mdt and slpi2.mdt. Stock reaches them through loader
 * modules - sensors_ssc calls rproc_set_firmware("slpi2.mdt") before booting
 * SLPI, cdsp-loader boots CDSP - and those loaders are deliberately not in the
 * closure. So the name is written to the node's own firmware attribute, which
 * the pinned ACK exports as rproc_set_firmware and accepts while offline, and
 * then read back. CDSP and MSS already match their default; they are written
 * anyway so all four runs prove the same thing the same way.
 */
#if M6_RPROC == M6_RPROC_ADSP
static const struct rproc_target RPROC = {
	"adsp", "3000000.remoteproc-adsp", "adsp2.mdt" };
#elif M6_RPROC == M6_RPROC_CDSP
static const struct rproc_target RPROC = {
	"cdsp", "32300000.remoteproc-cdsp", "cdsp.mdt" };
#elif M6_RPROC == M6_RPROC_SLPI
static const struct rproc_target RPROC = {
	"slpi", "2400000.remoteproc-slpi", "slpi2.mdt" };
#elif M6_RPROC == M6_RPROC_MSS
static const struct rproc_target RPROC = {
	"mss", "4080000.remoteproc-mss", "modem.mdt" };
#else
#error "M6_RPROC must name one of the four remoteprocs"
#endif

static char fw_path_saved[256];
static int fw_path_changed;

static int poll_state(const char *node, const char *want, char *value, ulong cap)
{
	int i;

	for (i = 0; i < M6_RPROC_WAIT_SECONDS * 10; i++) {
		if (attr_get(node, "state", value, cap) && seq(value, want))
			return 1;
		s_sleep_ms(100);
	}
	attr_get(node, "state", value, cap);
	return seq(value, want);
}

/*
 * Bring up exactly one remoteproc and put it back. Returns the highest stage
 * reached, so a failure says where it stopped rather than only that it did.
 */
static int rproc_bringup(void)
{
	char value[256], node[192], file[256];
	slong rc;
	ulong i;

	/*
	 * Stage 7. /lib/firmware does not exist in this rootfs and the loader's
	 * path parameter is empty, so a direct load would find nothing; and with
	 * CONFIG_FW_LOADER_USER_HELPER_FALLBACK unset there is no userspace
	 * helper to fall back to the way stock's ueventd is. fw_path_para is
	 * searched ahead of every built-in path and the parameter is mode 0644,
	 * so pointing it at the directory we mounted is the whole fix. It is a
	 * global, so the old value is saved and put back before the handover.
	 */
	if (slurp(FW_PARAM, value, sizeof(value)) < 0) {
		say("M6: " FW_PARAM " absent\n");
		return M6_STORAGE_PASS;
	}
	trim_nl(value);
	for (i = 0; value[i] && i < sizeof(fw_path_saved) - 1; i++)
		fw_path_saved[i] = value[i];
	fw_path_saved[i] = 0;
	say("M6: fw_path saved=\"");
	say(fw_path_saved);
	say("\"\n");

	fw_path_changed = 1; /* before the call: a partial write still changed it */
	rc = sysfs_put(FW_PARAM, FW_DIR, slen(FW_DIR));
	say_num("M6: fw_path set rc=", rc, "\n");
	if (slurp(FW_PARAM, value, sizeof(value)) < 0)
		return M6_STORAGE_PASS;
	trim_nl(value);
	say("M6: fw_path readback=\"");
	say(value);
	say("\"\n");
	if (!seq(value, FW_DIR))
		return M6_STORAGE_PASS;

	/* Stage 8: the node exists, and every node's state is on the record. */
	if (!rproc_scan(node, sizeof(node), RPROC.device)) {
		say("M6: no remoteproc for ");
		say(RPROC.device);
		say("\n");
		return 7;
	}
	if (!attr_get(node, "state", value, sizeof(value)) || !seq(value, "offline")) {
		say("M6: ");
		say(RPROC.key);
		say(" is not offline, refusing to touch it: ");
		say(value);
		say("\n");
		return 7;
	}

	/* Stage 9: the firmware name, and proof the named file resolves. */
	rc = attr_put(node, "firmware", RPROC.firmware);
	say_num("M6: firmware set rc=", rc, "\n");
	attr_get(node, "firmware", value, sizeof(value));
	say("M6: firmware readback=");
	say(value);
	say("\n");
	if (!seq(value, RPROC.firmware))
		return 8;
	join(file, FW_DIR, RPROC.firmware);
	if (!exists(file)) {
		say("M6: firmware unreadable at ");
		say(file);
		say("\n");
		return 8;
	}
	say("M6: firmware readable at ");
	say(file);
	say("\n");

	/*
	 * Stage 10. The write is synchronous: rproc_boot loads every segment and
	 * waits for the processor to signal start before it returns, so its
	 * return value is the load result and the poll only confirms it.
	 */
	say("M6: starting ");
	say(RPROC.key);
	say("\n");
	rc = attr_put(node, "state", "start");
	say_num("M6: start write rc=", rc, "\n");
	if (!poll_state(node, "running", value, sizeof(value))) {
		say("M6: state after start=");
		say(value);
		say("\n");
		return 9;
	}
	say("M6: ");
	say(RPROC.key);
	say(" is running\n");

	/*
	 * Stage 11. Android must inherit all four offline, exactly as it would
	 * from a cold boot, so what we started we stop.
	 */
	rc = attr_put(node, "state", "stop");
	say_num("M6: stop write rc=", rc, "\n");
	if (!poll_state(node, "offline", value, sizeof(value))) {
		say("M6: state after stop=");
		say(value);
		say("\n");
		return 10;
	}
	say("M6: ");
	say(RPROC.key);
	say(" is offline again\n");
	return M6_RPROC_PASS;
}

/*
 * Put the loader parameter back and record what every node ended up as. Called
 * on every path, so a run that failed halfway still hands over a kernel in the
 * state it found.
 */
static void rproc_restore(void)
{
	char value[256];
	slong rc;

	rproc_scan(0, 0, 0);
	if (!fw_path_changed)
		return;
	/*
	 * Restoring an empty value takes a one-byte write. sysfs discards a
	 * zero-length write before the store method is reached, and
	 * param_set_copystring copies the buffer verbatim, so a single NUL byte
	 * is what puts the parameter back to the empty string a newline would
	 * not.
	 */
	if (fw_path_saved[0])
		rc = sysfs_put(FW_PARAM, fw_path_saved, slen(fw_path_saved));
	else
		rc = sysfs_put(FW_PARAM, "", 1);
	say_num("M6: fw_path restore rc=", rc, "");
	if (slurp(FW_PARAM, value, sizeof(value)) >= 0) {
		trim_nl(value);
		say(" readback=\"");
		say(value);
		say("\"");
	}
	say("\n");
}

#endif /* M6_RPROC != M6_RPROC_NONE */
#endif /* M6_PHASE == 2 */

#endif /* !M6_BISECT */

/* ------------------------------------------------------------------- main */

int m6_main(ulong *sp)
{
	int stage = 0, failed, loaded = 0;
#if !M6_BISECT
	int i, mounted = 0, readable = 0;
#endif

	/*
	 * Only what is actually needed, and nothing that outlives us. The E4
	 * wrapper handed over to Android successfully while mounting nothing at
	 * all; this init mounted /proc and /sys and left them mounted, and the
	 * handover stopped working. /proc was never read, so it is gone. /sys is
	 * needed to find the controller and the partitions, so it is mounted
	 * only where that work happens and unmounted again before the handover.
	 */
	s_mkdir("/dev", 0755);
	s_mknod("/dev/kmsg", S_IFCHR | 0600, (1u << 8) | 11u);
	kmsg_fd = (int)s_open("/dev/kmsg", O_WRONLY);

	say("M6: init entered\n");
	say_num("M6: pid=", sys(SYS_getpid, 0, 0, 0, 0, 0), "\n");

	/* Stage 1: every module in the closure loaded. */
	failed = load_modules(&loaded);
	if (failed >= 0) {
		say_num("M6: stopped at module index ", failed, "\n");
		goto done;
	}
	stage = 1;

#if M6_BISECT
	/*
	 * Narrowing build: the question is only whether the device survives
	 * this prefix, so nothing touches UFS or any filesystem here.
	 */
	goto done;
#else
	s_mkdir("/sys", 0755);
	if (s_mount("sysfs", "/sys", "sysfs", 0, 0) != 0) {
		say("M6: sysfs mount failed\n");
		goto done;
	}
	sysfs_mounted = 1;

	/* Stage 2: the UFS host controller bound its driver. */
	if (!wait_for("/sys/bus/platform/drivers/ufshcd-qcom/1d84000.ufshc",
		      M6_WAIT_SECONDS)) {
		say("M6: ufshcd-qcom did not bind 1d84000.ufshc\n");
#if M6_SUPPLIER_DUMP
		dump_consumer(UFSHC_SYSFS);
#endif
		goto done;
	}
	say("M6: ufs controller bound\n");
	stage = 2;
#if M6_SUPPLIER_DUMP
	/* Observability build: record the bound state too, for the pre/post
	 * diff, then stop before any storage work. */
	dump_consumer(UFSHC_SYSFS);
	goto done;
#endif

	/*
	 * Stage 3: the UFS device enumerated all six LUNs. Checked separately
	 * from the partitions because a controller that binds but finds no
	 * device, or finds fewer LUNs than stock reports, is a different
	 * failure from a partition table that does not parse.
	 */
	{
		static const char *const LUNS[] = {
			"/sys/block/sda", "/sys/block/sdb", "/sys/block/sdc",
			"/sys/block/sdd", "/sys/block/sde", "/sys/block/sdf",
		};
		const int lun_count = (int)(sizeof(LUNS) / sizeof(LUNS[0]));
		int present = 0, tries;
		for (tries = 0; tries < M6_WAIT_SECONDS * 10; tries++) {
			present = 0;
			for (i = 0; i < lun_count; i++)
				present += exists(LUNS[i]);
			if (present == lun_count)
				break;
			s_sleep_ms(100);
		}
		say_num("M6: luns present=", present, "");
		say_num(" expected=", lun_count, "\n");
		if (present < lun_count)
			goto done;
		stage = 3;
	}

	/* Stage 4: the partitions we need are enumerated and named. */
	{
		slong major[TARGET_COUNT], minor[TARGET_COUNT];
		int found = 0, tries;
		for (tries = 0; tries < M6_WAIT_SECONDS * 10 && found < TARGET_COUNT; tries++) {
			found = 0;
			for (i = 0; i < TARGET_COUNT; i++)
				if (find_partition(TARGETS[i].partname, &major[i], &minor[i]))
					found++;
			if (found < TARGET_COUNT)
				s_sleep_ms(100);
		}
		if (found < TARGET_COUNT) {
			say_num("M6: only located partitions: ", found, "\n");
			goto done;
		}
		say("M6: all three firmware partitions located by PARTNAME\n");
		stage = 4;

		/*
		 * Stage 5: all three mounted read-only, in our own namespace
		 * under /m6. Stock's mount points are deliberately not reused:
		 * Android owns those paths and nothing here should look like a
		 * partial version of its first-stage mount.
		 */
		s_mkdir("/m6", 0755);
		s_mkdir("/m6/dev", 0755);
		for (i = 0; i < TARGET_COUNT; i++)
			mounted += mount_ro(TARGETS[i].label, major[i], minor[i],
					    TARGETS[i].node, TARGETS[i].point,
					    TARGETS[i].fstype, TARGETS[i].data);
		if (mounted < TARGET_COUNT) {
			say_num("M6: mounted only ", mounted, "\n");
			goto done;
		}
		stage = 5;
	}

	/* Stage 6: each filesystem really parsed and lists entries. */
	for (i = 0; i < TARGET_COUNT; i++) {
		int n = count_entries(TARGETS[i].point);
		say("M6: entries in ");
		say(TARGETS[i].label);
		say_num(" = ", n, "\n");
		if (n > 0)
			readable++;
	}
	if (readable < TARGET_COUNT) {
		say_num("M6: readable filesystems ", readable, "\n");
		goto done;
	}
	stage = M6_STORAGE_PASS;

#if M6_PHASE == 2
#if M6_RPROC_DUMP
	/*
	 * R2. Past the probe window before reading anything: the control read
	 * the class directory at 0.5365 s and the probes did not run until
	 * 0.565 s, so its "nodes=0" said nothing at all. Nothing in this rootfs
	 * binds a driver after this point, so three seconds is a settled state
	 * rather than a guess.
	 */
	s_sleep_ms(3000);
	rproc_scan(0, 0, 0);
	dump_remoteprocs();
#elif M6_RPROC == M6_RPROC_NONE
	/*
	 * The control. The fourteen added modules are loaded and the storage
	 * chain is unchanged, so all this run has to show is that the driver
	 * bound every remoteproc and that none of them started by itself.
	 */
	rproc_scan(0, 0, 0);
#else
	stage = rproc_bringup();
#endif
#endif
#endif /* !M6_BISECT */

done:
#if M6_BISECT
	/*
	 * A narrowing build has no verdict to give. Surviving to here at all is
	 * the datum; the count says how much of the prefix actually loaded.
	 */
	say_num("M6: RESULT=BISECT prefix=", module_limit(), "");
	say_num(" loaded=", loaded, "\n");
	(void)stage;
	/* Nothing was mounted and there is no unmount path compiled in. */
#else
	/*
	 * Loading the modules is not the result. M6a passes only if the whole
	 * chain held, up to and including listing a directory on each of the
	 * three filesystems.
	 */
	say_num("M6: stage=", stage, "");
	say_num(" of ", M6_STAGE_PASS, "\n");
	if (stage == M6_STAGE_PASS)
		say("M6: RESULT=PASS\n");
	else
		say_num("M6: RESULT=FAIL at stage ", stage, "\n");
#if M6_PHASE == 2 && M6_RPROC != M6_RPROC_NONE
	/* Before the unmount, which takes /sys with it. */
	if (sysfs_mounted)
		rproc_restore();
#endif
	unmount_all();
#endif

#if M6_ACTION_EXEC
	{
		/* aarch64 process entry: sp[0] = argc, then argv, NUL, then envp.
		 * Both are passed through untouched so Android's first-stage init
		 * sees exactly what the kernel would have given it. */
		slong argc = (slong)sp[0];
		char **argv = (char **)(sp + 1);
		char **envp = argv + argc + 1;

		say("M6: exec /init.stock\n");
		if (kmsg_fd >= 0) { s_close(kmsg_fd); kmsg_fd = -1; }
		s_unlink("/dev/kmsg");
		sys(SYS_execve, (ulong)"/init.stock", (ulong)argv, (ulong)envp, 0, 0);
	}
	/* Only here if the exec failed; return the device rather than hang. */
	s_sleep_ms(15000);
	sys(SYS_reboot, M6_MAGIC1, M6_MAGIC2, M6_CMD_RESTART, 0, 0);
#else
	(void)sp; /* the timing variant never execs, so it never reads the stack */
	say_num("M6: signalling delay ",
		(slong)M6_BASE_SECONDS + (slong)stage * (slong)M6_UNIT_SECONDS, " s\n");
	s_sleep_ms(((slong)M6_BASE_SECONDS + (slong)stage * (slong)M6_UNIT_SECONDS) * 1000);
	sys(SYS_reboot, M6_MAGIC1, M6_MAGIC2, M6_CMD_RESTART, 0, 0);
#endif

	for (;;) /* PID 1 may not exit. */
		s_sleep_ms(3600000);
	return 0;
}

__asm__(".section .text\n"
	".global _start\n"
	"_start:\n"
	"  mov x29, #0\n"
	"  mov x30, #0\n"
	"  mov x0, sp\n" /* argv and envp must survive for the exec variant */
	"  bl m6_main\n"
	"  mov x8, #93\n"
	"  mov x0, #1\n"
	"  svc #0\n");
