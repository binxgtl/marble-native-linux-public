#include "gpr_native.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

struct output { char *p; size_t left, used; int error; };
static void emit(struct output *o, const char *format, ...) {
    if (o->error) return;
    va_list args; va_start(args,format);
    int n=vsnprintf(o->p,o->left,format,args); va_end(args);
    if (n<0 || (size_t)n>=o->left) { o->error=1; return; }
    o->p+=n; o->left-=(size_t)n; o->used+=(size_t)n;
}
static void hex(struct output *o, const unsigned char *p, size_t n) {
    static const char digits[]="0123456789abcdef";
    if (o->error || o->left<=2*n) { o->error=1; return; }
    for (size_t i=0;i<n;i++) { *o->p++=digits[p[i]>>4]; *o->p++=digits[p[i]&15]; }
    o->left-=2*n; o->used+=2*n; *o->p=0;
}
int m11_gpr_result_encode(const struct m11_gpr_result *r, char *buffer, size_t size) {
    if (!r || !buffer || !size) return -1;
    buffer[0]=0;
    if (r->event_count>M11_GPR_EVENTS || r->permits_playback) return -1;
    struct output o={buffer,size,0,0};
    emit(&o,"{\"schema\":1,\"kind\":\"native-spf-query-evidence\",\"nonce\":\"");
    hex(&o,r->capture_nonce,16); emit(&o,"\",\"image_sha256\":\""); hex(&o,r->image_sha256,32);
    emit(&o,"\",\"token\":%" PRIu32 ",\"start_ns\":%" PRIu64 ",\"deadline_ns\":%" PRIu64 ",\"outcome\":%u,",
         r->token,r->start_ns,r->deadline_ns,(unsigned int)r->outcome);
    emit(&o,"\"worker_reaped\":%d,\"worker_exit_ok\":%d,\"close_returned\":%d,\"close_ok\":%d,\"ipc_complete\":%d,\"query_consistent\":%d,\"unresolved_worker\":%ld,",
         r->worker_reaped,r->worker_exit_ok,r->close_returned,r->close_ok,r->ipc_complete,r->query_consistent,(long)r->unresolved_worker);
    emit(&o,"\"runtime_transport\":\"UNKNOWN\",\"permits_playback\":false,\"amplifier_enable_permitted\":false,\"events\":[");
    for (unsigned int i=0;i<r->event_count;i++) {
        const struct m11_gpr_event *e=&r->events[i];
        if (e->size>M11_GPR_MAX) { o.error=1; break; }
        emit(&o,"%s{\"stage\":%" PRIu32 ",\"outcome\":%" PRIu32 ",\"rc\":%" PRId64 ",\"monotonic_ns\":%" PRIu64 ",\"packet_hex\":\"",
             i?",":"",e->stage,e->outcome,e->rc,e->monotonic_ns);
        hex(&o,e->packet,e->size); emit(&o,"\"}");
    }
    emit(&o,"]}");
    if (o.error) { buffer[0]=0; return -1; }
    return (int)o.used;
}
