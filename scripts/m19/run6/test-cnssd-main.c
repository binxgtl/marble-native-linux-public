/* M19 R6c: m19-cnssd's admission (cnssd-main.c), on real socket pairs and real processes. Never QRTR: main is left
 * out. The owner is the parent that created the pair; init, a grandparent, another creator, a stream socket, another
 * user and M12's malformed arguments are refused with M12's status, 2. */
#define M19_CNSSD_NO_MAIN
#include "cnssd-main.c"

#include <assert.h>
#include <sys/wait.h>

static uid_t me;

/* In a child: admission with this argv over its own parent, as m19-cnssd's main calls it. */
static int admitted_in_child(int argc, char **argv, pid_t parent_override, uid_t euid, uid_t owner)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid) {
        struct linux_io l = {.qrtr = -1, .supervisor = -1, .seed_fd = -1, .origin_fd = -1};
        pid_t parent = parent_override ? parent_override : getppid();
        _exit(m19_cnssd_admit(argc, argv, parent, euid, owner, &l) ? 2 : (l.supervisor == atoi(argv[1]) ? 0 : 9));
    }
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    return WEXITSTATUS(status);
}

/* A grandchild admitted over its parent (the child), while this process created the pair. */
static int admitted_in_grandchild(char **argv)
{
    pid_t pid = fork();
    assert(pid >= 0);
    if (!pid)
        _exit(admitted_in_child(2, argv, 0, me, me));
    int status = 0;
    assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status));
    return WEXITSTATUS(status);
}

static int pair_of(int type, char *fd, size_t room)
{
    int pair[2];
    assert(!socketpair(AF_UNIX, type, 0, pair));
    /* The daemon's end at a number of at least 3, as M12's argument check requires. */
    snprintf(fd, room, "%d", pair[1]);
    return pair[0];
}

int main(void)
{
    me = getuid();
    char fd[16], *argv[] = {"m19-cnssd", fd, NULL};
    pair_of(SOCK_SEQPACKET, fd, sizeof(fd));
    /* The owner: the parent that created the pair. */
    assert(admitted_in_child(2, argv, 0, me, me) == 0);
    /* Never init: the parent recorded as 1, as an orphan's. */
    assert(admitted_in_child(2, argv, 1, me, me) == 2);
    /* Never a grandparent: the pair's creator is not the caller's parent. */
    assert(admitted_in_grandchild(argv) == 2);
    /* Another user, as the caller or as the owner. */
    assert(admitted_in_child(2, argv, 0, me + 1, me) == 2);
    assert(admitted_in_child(2, argv, 0, me + 1, me + 1) == 2);
    /* M12's argument counts and descriptor numbers. */
    assert(admitted_in_child(1, argv, 0, me, me) == 2);
    assert(admitted_in_child(3, argv, 0, me, me) == 2);
    /* "4x" for descriptor 4: a number with anything after it is no number, even when its digits name the pair. */
    char junkfd[20];
    snprintf(junkfd, sizeof(junkfd), "%sx", fd);
    char *low[] = {"m19-cnssd", "2", NULL}, *junk[] = {"m19-cnssd", junkfd, NULL}, *closed[] = {"m19-cnssd", "900", NULL};
    assert(admitted_in_child(2, low, 0, me, me) == 2);
    assert(admitted_in_child(2, junk, 0, me, me) == 2);
    assert(admitted_in_child(2, closed, 0, me, me) == 2);
    /* A stream or datagram socket is not M12's supervisor. */
    char stream[16], *sargv[] = {"m19-cnssd", stream, NULL};
    pair_of(SOCK_STREAM, stream, sizeof(stream));
    assert(admitted_in_child(2, sargv, 0, me, me) == 2);
    char gram[16], *gargv[] = {"m19-cnssd", gram, NULL};
    pair_of(SOCK_DGRAM, gram, sizeof(gram));
    assert(admitted_in_child(2, gargv, 0, me, me) == 2);
    /* A regular descriptor, not a socket. */
    int null = open("/dev/null", O_RDONLY);
    assert(null >= 3);
    char file[16], *fargv[] = {"m19-cnssd", file, NULL};
    snprintf(file, sizeof(file), "%d", null);
    assert(admitted_in_child(2, fargv, 0, me, me) == 2);
    /* M12's seeded form, kept: well formed it is admitted; a zero size, a reused descriptor or a malformed digest
     * is refused as in M12. */
    char *hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    char *seeded[] = {"m19-cnssd", fd, "900", "3", hex, "901", hex, NULL};
    assert(admitted_in_child(7, seeded, 0, me, me) == 0);
    char *seeded_bad[] = {"m19-cnssd", fd, fd, "0", "x", fd, "y", NULL};
    assert(admitted_in_child(7, seeded_bad, 0, me, me) == 2);
    char *seeded_origin[] = {"m19-cnssd", fd, "900", "3", hex, "901", "y", NULL};
    assert(admitted_in_child(7, seeded_origin, 0, me, me) == 2);
    puts("m19-cnssd admission: 16 cases PASS");
    return 0;
}
