#include "audio_runtime.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
struct encoded { char *p; size_t left, used; int failed; };
static void add(struct encoded *o, const char *fmt, ...) {
    if (o->failed) return;
    va_list a; va_start(a,fmt); int n=vsnprintf(o->p,o->left,fmt,a); va_end(a);
    if (n<0 || (size_t)n>=o->left) { o->failed=1; return; }
    o->p+=n; o->left-=(size_t)n; o->used+=(size_t)n;
}
static void bytes(struct encoded *o, const unsigned char *p, size_t n) {
    for (size_t i=0;i<n;i++) add(o,"%02x",(unsigned)p[i]);
}
int m11_audio_status_encode(const struct m11_audio_status *s, char *out, size_t cap) {
    if (!out || !cap) return -1;
    out[0]=0;
    if (!s || s->permits_playback || s->pd.count>M11_PD_RECORDS) return -1;
    struct encoded o={out,cap,0,0};
    add(&o,"{\"schema\":1,\"kind\":\"native-audio-pd-owner\",\"nonce\":\"");
    bytes(&o,s->capture_nonce,16); add(&o,"\",\"image_sha256\":\""); bytes(&o,s->image_sha256,32);
    add(&o,"\",\"token\":%" PRIu32 ",\"owner_pid\":%ld,\"endpoint_device\":%" PRIu64 ",\"census_ns\":%" PRIu64 ",",
        s->token,(long)s->owner_pid,s->endpoint_device,s->census_ns);
    add(&o,"\"acquired\":%d,\"pd_started\":%d,\"admitted\":%d,\"finished\":%d,\"poisoned\":%d,\"retired\":%d,",
        s->acquired,s->pd_started,s->admitted,s->finished,s->poisoned,s->retired);
    add(&o,"\"resources_quiescent\":%d,\"notifier_cleanup_complete\":%d,\"unresolved_worker\":%ld,\"helpers\":[",
        s->resources_quiescent,s->notifier_cleanup_complete,(long)s->unresolved_worker);
    for (unsigned i=0;i<2;i++) add(&o,"%s{\"pid\":%ld,\"start\":%" PRIu64 ",\"inode\":%" PRIu64 ",\"device\":%" PRIu64 "}",
        i?",":"",(long)s->helper_pid[i],s->helper_start[i],s->helper_inode[i],s->helper_device[i]);
    const struct m11_pd *p=&s->pd;
    add(&o,"],\"pd\":{\"path\":\"" M11_PD_PATH "\",\"instance\":%u,\"phase\":%u,\"fault\":%u,\"invalid\":%d,\"state\":%" PRIu32 ",",
        M11_PD_INSTANCE,(unsigned)p->phase,(unsigned)p->fault,p->invalid,p->state);
    add(&o,"\"node\":%" PRIu32 ",\"port\":%" PRIu32 ",\"deadline_ns\":%" PRIu64 ",\"ack_deferred\":%d,\"ack_txn\":%u,\"unregister_ok\":%d,\"truncated\":%d,\"wire\":[",
        p->node,p->port,p->deadline,p->ack_deferred,(unsigned)p->ack_txn,p->unregister_ok,p->truncated);
    for (unsigned i=0;i<p->count;i++) {
        const struct m11_pd_record *r=&p->records[i];
        if (r->size>M11_PD_WIRE_MAX) { o.failed=1; break; }
        add(&o,"%s{\"ns\":%" PRIu64 ",\"tx\":%" PRIu32 ",\"node\":%" PRIu32 ",\"port\":%" PRIu32 ",\"rc\":%d,\"hex\":\"",
            i?",":"",r->ns,r->tx,r->node,r->port,r->rc);
        bytes(&o,r->bytes,r->size); add(&o,"\"}");
    }
    add(&o,"]},\"runtime_transport\":\"UNKNOWN\",\"permits_playback\":false,\"amplifier_enable_permitted\":false}");
    if (o.failed) { out[0]=0; return -1; }
    return (int)o.used;
}
