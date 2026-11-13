/* SPDX-License-Identifier: GPL-2.0-only
 * M19 R6c: m19-cnssd, M12's CNSS daemon for an owner that is not PID 1 (docs/m19-r6.md).
 *
 * M12 ran m12-cnssd under its own PID 1, and that daemon's entry admits only PID 1 as its owner: getppid() == 1, and
 * the supervisor socket's peer (SO_PEERCRED) is PID 1 (scripts/m12/next/cnssd-linux.c). In the Ubuntu session PID 1
 * is systemd, which cannot own the daemon: R6a's daemon refused m19-wifi as its parent, R6b's as its socket's peer.
 * This entry admits its parent as its owner instead: the parent created the socket pair (SO_PEERCRED pid equal to
 * getppid()), is not init (an orphan never starts), and is root, with M12's SOCK_SEQPACKET and argument checks.
 * Everything after admission is M12's main, line for line, over M12's protocol core (cnssd.c) and Linux adapter
 * (cnssd-linux.c), which this file includes and links unchanged. */
#define M12_CNSSD_NO_MAIN
#include "../../m12/next/cnssd-linux.c"

/* 0 when this process may run under its caller as owner; 2 (M12's launch-guard status) otherwise. Production passes
 * getppid(), geteuid() and owner uid 0; the tests' stand-in daemon calls it with its own user. */
int m19_cnssd_admit(int argc, char **argv, pid_t parent, uid_t euid, uid_t owner_uid, struct linux_io *l)
{
    /* M12: getppid()!=1 || geteuid()!=0 || (argc!=2 && argc!=7). The owner is the parent, which is never init. */
    if (parent <= 1 || euid != owner_uid || (argc != 2 && argc != 7))
        return 2;
    if (number(argv[1], &l->supervisor))
        return 2;
    struct ucred cred;
    socklen_t len = sizeof(cred);
    int type = 0;
    socklen_t tlen = sizeof(type);
    /* M12: cred.pid!=1. The pair's creator, the owner, is the parent itself. */
    if (getsockopt(l->supervisor, SOL_SOCKET, SO_PEERCRED, &cred, &len) || len != sizeof(cred) || cred.pid != parent ||
        cred.uid != owner_uid || getsockopt(l->supervisor, SOL_SOCKET, SO_TYPE, &type, &tlen) || type != SOCK_SEQPACKET)
        return 2;
    /* M12's seeded CalDB form, unchanged; M19 never passes it. */
    if (argc == 7) {
        char *end;
        errno = 0;
        unsigned long n = strtoul(argv[3], &end, 10);
        if (errno || !*argv[3] || *end || !n || n > M12_CALDB_MAX || number(argv[2], &l->seed_fd) || l->seed_fd == l->supervisor ||
            number(argv[5], &l->origin_fd) || l->origin_fd == l->supervisor || l->origin_fd == l->seed_fd || digest(argv[4], l->hash) ||
            digest(argv[6], l->origin))
            return 2;
        l->seed_size = (size_t)n;
    }
    return 0;
}

#ifndef M19_CNSSD_NO_MAIN
int main(int argc, char **argv)
{
    struct linux_io l = {.qrtr = -1, .supervisor = -1, .seed_fd = -1, .origin_fd = -1};
    if (m19_cnssd_admit(argc, argv, getppid(), geteuid(), 0, &l))
        return 2;
    /* From here on, M12's main (scripts/m12/next/cnssd-linux.c), line for line. */
    socklen_t len;
    (void)signal(SIGTERM,SIG_IGN);(void)signal(SIGINT,SIG_IGN);
    l.qrtr=socket(AF_QIPCRTR,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);
    if(l.qrtr<0)return 3; /* No registration attempted. */
    /* An unconnected QRTR socket's local node is available via getsockname;
     * bind port 0 allocates the ephemeral port on that local node. */
    struct sockaddr_qrtr local={0};len=sizeof(local);
    if(getsockname(l.qrtr,(void *)&local,&len) || len!=sizeof(local) || local.sq_family!=AF_QIPCRTR ||
       bind(l.qrtr,(void *)&local,sizeof(local))) { close(l.qrtr);return 3; }
    unsigned char *ram=calloc(1,M12_CALDB_MAX);
    if(!ram) { close(l.qrtr);return 3; }
    struct m12_daemon state;
    struct m12_daemon_io io={&l,monotonic,wait_input,tx,record,seed};
    int rc=m12_cnssd_run(&state,&io,local.sq_node,ram,M12_CALDB_MAX);
    /* Event loop returns only after explicit retirement or pre-TX invalid
     * arguments/clock. No timeout/parent EOF drops a registered owner. */
    memset(ram,0,M12_CALDB_MAX);free(ram);close(l.qrtr);
    if(l.seed_fd>=0)close(l.seed_fd);
    if(l.origin_fd>=0)close(l.origin_fd);
    close(l.supervisor);return rc?1:0;
}
#endif
