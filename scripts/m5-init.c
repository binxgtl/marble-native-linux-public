/*
 * M5 native PID 1 for marble.
 *
 * Freestanding aarch64: no libc, no dynamic loader, direct syscalls only. It is
 * built with the same pinned Android clang the kernel uses, so the initramfs
 * introduces no new toolchain input and stays reproducible.
 *
 * This device has no observation channel that works without vendor modules:
 * the GKI kernel contains no msm_geni serial driver, no USB PHY driver, and no
 * framebuffer, and the device tree's ramoops node carries neither reg nor size.
 * So this init cannot print anything an operator can read while it runs.
 *
 * It therefore reports through the only channel the hardware leaves open —
 * *when* and *how* the machine goes away:
 *
 *   delay = M5_BASE_SECONDS + popcount(assertions) * M5_UNIT_SECONDS
 *   then  M5_ACTION_POWEROFF ? PSCI SYSTEM_OFF : PSCI SYSTEM_RESET
 *
 * Three images that differ only in M5_BASE_SECONDS turn that into a controlled
 * experiment. A hardware watchdog, a bootloader timeout, or any other
 * platform-fixed behaviour produces a return time independent of the constant;
 * only code that actually ran can make the return time track it.
 *
 * Writes to /dev/kmsg are made for the day a log sink exists. They are NOT
 * evidence at M5 and nothing in the exit criteria depends on them, because the
 * kernel log buffer does not survive the reboot this program performs.
 */

#define M5_MAGIC1 0xfee1deadu
#define M5_MAGIC2 0x28121969u
#define M5_CMD_RESTART 0x01234567u
#define M5_CMD_POWER_OFF 0x4321fedcu

#ifndef M5_BASE_SECONDS
#define M5_BASE_SECONDS 20
#endif
#ifndef M5_UNIT_SECONDS
#define M5_UNIT_SECONDS 5
#endif
#ifndef M5_ACTION_POWEROFF
#define M5_ACTION_POWEROFF 0
#endif

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

#define SYS_getdents64 61
#define SYS_read 63
#define SYS_write 64
#define SYS_openat 56
#define SYS_close 57
#define SYS_mkdirat 34
#define SYS_mknodat 33
#define SYS_mount 40
#define SYS_nanosleep 101
#define SYS_getpid 172
#define SYS_reboot 142
#define SYS_exit 93

#define AT_FDCWD -100

static slong s_write(int fd, const void *b, ulong n) { return sys(SYS_write, (ulong)fd, (ulong)b, n, 0, 0); }
static slong s_open(const char *p, int fl) { return sys(SYS_openat, (ulong)AT_FDCWD, (ulong)p, (ulong)fl, 0, 0); }
static slong s_read(int fd, void *b, ulong n) { return sys(SYS_read, (ulong)fd, (ulong)b, n, 0, 0); }
static void s_close(int fd) { sys(SYS_close, (ulong)fd, 0, 0, 0, 0); }
static void s_mkdir(const char *p, ulong m) { sys(SYS_mkdirat, (ulong)AT_FDCWD, (ulong)p, m, 0, 0); }
static void s_mknod(const char *p, ulong m, ulong dev) { sys(SYS_mknodat, (ulong)AT_FDCWD, (ulong)p, m, dev, 0); }
static slong s_mount(const char *src, const char *tgt, const char *fs, ulong fl, const void *data)
{
	return sys(SYS_mount, (ulong)src, (ulong)tgt, (ulong)fs, fl, (ulong)data);
}
static slong s_getpid(void) { return sys(SYS_getpid, 0, 0, 0, 0, 0); }

struct timespec_ { slong tv_sec; slong tv_nsec; };
static void s_sleep(slong seconds)
{
	struct timespec_ req;
	req.tv_sec = seconds;
	req.tv_nsec = 0;
	/* Restart on interruption so the measured delay stays deterministic. */
	while (sys(SYS_nanosleep, (ulong)&req, 0, 0, 0, 0) == -4)
		;
}

static ulong slen(const char *s)
{
	ulong n = 0;
	while (s[n])
		n++;
	return n;
}

static int kmsg_fd = -1;

/* Best-effort only. Nothing here is evidence; see the file header. */
static void say(const char *s)
{
	if (kmsg_fd >= 0)
		s_write(kmsg_fd, s, slen(s));
}

static void say_file(const char *path, const char *label)
{
	char buf[512];
	slong fd, n;

	say(label);
	fd = s_open(path, 0 /* O_RDONLY */);
	if (fd < 0) {
		say("<unreadable>\n");
		return;
	}
	n = s_read((int)fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = 0;
		if (kmsg_fd >= 0)
			s_write(kmsg_fd, buf, (ulong)n);
	}
	s_close((int)fd);
	say("\n");
}

static int readable(const char *path)
{
	slong fd = s_open(path, 0);
	if (fd < 0)
		return 0;
	s_close((int)fd);
	return 1;
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

static void reboot_now(void)
{
#if M5_ACTION_POWEROFF
	sys(SYS_reboot, M5_MAGIC1, M5_MAGIC2, M5_CMD_POWER_OFF, 0, 0);
#else
	sys(SYS_reboot, M5_MAGIC1, M5_MAGIC2, M5_CMD_RESTART, 0, 0);
#endif
}

int m5_main(void)
{
	int bits = 0;
	slong delay;

	/* No CONFIG_DEVTMPFS in this kernel, so every node is created by hand. */
	s_mkdir("/proc", 0755);
	s_mkdir("/sys", 0755);
	s_mkdir("/dev", 0755);
	s_mount("proc", "/proc", "proc", 0, 0);
	s_mount("sysfs", "/sys", "sysfs", 0, 0);
	s_mount("devtmpfs_or_tmpfs", "/dev", "tmpfs", 0, 0);

	s_mknod("/dev/console", 0020600, (5u << 8) | 1u);
	s_mknod("/dev/null", 0020666, (1u << 8) | 3u);
	s_mknod("/dev/kmsg", 0020600, (1u << 8) | 11u);
	kmsg_fd = (int)s_open("/dev/kmsg", 1 /* O_WRONLY */);

	say("marble-m5: native init running\n");

	/* Assertion 0: we really are PID 1, not a helper the kernel spawned. */
	if (s_getpid() == 1)
		bits |= 1;
	/* Assertion 1: procfs is mounted and usable. */
	if (readable("/proc/version"))
		bits |= 2;
	/* Assertion 2: sysfs is mounted and usable. */
	if (readable("/sys/kernel/notes") || readable("/sys/class/net"))
		bits |= 4;
	/*
	 * Assertion 3: the untouched vendor_boot ramdisk was concatenated into
	 * our initramfs by the bootloader. Recorded because it is true and
	 * worth knowing; deliberately never loaded, because M5 carries no
	 * vendor modules.
	 */
	if (readable("/lib/modules/modules.load"))
		bits |= 8;

	say_file("/proc/version", "marble-m5: version: ");
	say_file("/proc/cmdline", "marble-m5: cmdline: ");
	say("marble-m5: entering signalling delay\n");

	delay = (slong)M5_BASE_SECONDS + (slong)(__builtin_popcount((unsigned)bits)) * (slong)M5_UNIT_SECONDS;
	s_sleep(delay);

	say("marble-m5: signalling now\n");
	reboot_now();

	/* Unreachable unless reboot is refused; never return, PID 1 may not exit. */
	for (;;)
		s_sleep(3600);
	return 0;
}

__asm__(".section .text\n"
	".global _start\n"
	"_start:\n"
	"  mov x29, #0\n"
	"  mov x30, #0\n"
	"  bl m5_main\n"
	"  mov x8, #93\n" /* exit, only if m5_main ever returns */
	"  mov x0, #0\n"
	"  svc #0\n");
