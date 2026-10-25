/* SPDX-License-Identifier: GPL-2.0-only */
#include "owner-supervisor.h"
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
int m12_owner_receive(struct m12_owner_supervisor *s,unsigned ms) {
    if(ms>5000)return -EINVAL;
    struct pollfd p={.fd=s->fd,.events=POLLIN};
    int rc=poll(&p,1,(int)ms);
    if(rc<0) {
        if(errno==EINTR)return 0;
        s->poisoned=1;return -errno;
    }
    if(!rc)return 0; /* Timeout is not clean exit and never closes/kills. */
    struct m12_owner_record r={0};
    ssize_t n=recv(s->fd,&r,sizeof(r),MSG_DONTWAIT|MSG_TRUNC);
    if(n<0 && (errno==EINTR || errno==EAGAIN))return 0;
    if(n!=sizeof(r) || r.magic!=M12_OWNER_MAGIC || r.version!=M12_OWNER_VERSION ||
       r.sequence!=s->sequence+1 || r.event<M12_DISCOVERY || r.event>M12_STATE ||
       r.phase>M12_DB_FAILED || r.seed_verified>1 || r.ram_valid>1 || r.size>M12_CALDB_MAX ||
       r.qmi_result>65535 || r.qmi_error>65535 || r.transaction>65535 ||
       (r.event==M12_READY && (r.phase!=M12_DB_IDLE || r.rc || r.waiting_message ||
         r.qmi_result || r.qmi_error || !r.port || r.ram_valid!=r.seed_verified ||
         (r.seed_verified && !r.size) || (!r.seed_verified && r.size))) ||
       (r.event==M12_RETIRED && (!s->stop_sent || r.ram_valid || r.size))) {
        s->poisoned=1;return n==0?-EPIPE:-EPROTO;
    }
    s->sequence=r.sequence;s->latest=r;
    if(r.event==M12_POISON)s->poisoned=1;
    if(r.event==M12_STOP_DENIED)s->stop_sent=0;
    if(r.event==M12_RETIRED) { s->final_received=1;if(r.rc)s->poisoned=1; }
    return 1;
}
int m12_owner_stop(struct m12_owner_supervisor *s,int qca,int cnss,int unresolved,int pending) {
    if(qca!=1 || cnss!=1 || unresolved!=0 || pending!=0)return -EBUSY;
    if(s->stop_sent || s->final_received || s->reaped)return -EALREADY;
    struct m12_owner_stop p={M12_OWNER_MAGIC,1,1,1,0,0};
    ssize_t n=send(s->fd,&p,sizeof(p),MSG_DONTWAIT|MSG_NOSIGNAL);
    if(n!=sizeof(p)) { s->poisoned=1;return n<0?-errno:-EIO; }
    s->stop_sent=1;return 0;
}
int m12_owner_reap(struct m12_owner_supervisor *s) {
    if(s->child<=0)return -EINVAL;
    if(s->reaped)return -EALREADY;
    int status=0;s->wait_calls++;pid_t got=waitpid(s->child,&status,WNOHANG);
    s->reap_errno=got<0?errno:0;
    if(got<0)return errno==EINTR?0:-errno;
    if(!got)return 0;
    s->reaped=1;s->exit_status=status;
    if(s->poisoned || !s->final_received || !WIFEXITED(status) || WEXITSTATUS(status)) {
        s->poisoned=1;return -ECHILD;
    }
    return 1;
}
int m12_owner_finish(struct m12_owner_supervisor *s) {
    if(s->terminal_checked)return -EALREADY;
    if(s->fd<0 || !s->stop_sent || !s->final_received || !s->reaped)return -EINVAL;
    s->terminal_checked=1;
    /* Nonblocking, after reap: no deadline or second waitpid is needed.
     * A surviving inherited descriptor fails rather than waiting indefinitely. */
    unsigned char b;
    ssize_t n=recv(s->fd,&b,sizeof(b),MSG_DONTWAIT|MSG_TRUNC);
    if(n<0)s->terminal_rc=(errno==EAGAIN || errno==EWOULDBLOCK)?-EBUSY:-errno;
    else if(n>0)s->terminal_rc=-EPROTO;
    else {
        s->eof_verified=1;
        s->terminal_rc=(s->poisoned || s->latest.event!=M12_RETIRED || s->latest.rc ||
          !WIFEXITED(s->exit_status) || WEXITSTATUS(s->exit_status))?-EPROTO:0;
    }
    if(s->terminal_rc)s->poisoned=1;
    return s->terminal_rc;
}
