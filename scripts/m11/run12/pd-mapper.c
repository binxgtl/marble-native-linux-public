/* SPDX-License-Identifier: BSD-3-Clause
 * Run12 locator only. Uses pinned linux-msm QMI codecs, not Android binaries.
 * All files written below are on /run tmpfs. No DSP boot or mixer operations.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libqrtr.h>
#include "json.h"
#include "servreg_loc.h"

#define MAX_MAPS 8
#define BASE "/run/m11/pd."
struct mapping { char service[256], domain[256]; unsigned instance; };
static struct mapping maps[MAX_MAPS];
static unsigned map_count, log_count;

static void note(const char *fmt, ...)
{
    if (log_count++ >= 128) return; /* bounded mapper log, not a stream worker */
    va_list ap;
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}

static long long now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return -1;
    return (long long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int marker(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    size_t n = strlen(text);
    ssize_t rc = write(fd, text, n);
    int cr = close(fd);
    return rc == (ssize_t)n && cr == 0 ? 0 : -1;
}

static int load_map(const char *path)
{
    char buf[8193];
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size <= 0 || st.st_size > 8192) {
        close(fd); return -1;
    }
    size_t n = 0;
    while (n < (size_t)st.st_size) {
        ssize_t rc = read(fd, buf+n, (size_t)st.st_size-n);
        if (rc < 0 && errno == EINTR) continue;
        if (rc <= 0) { close(fd); return -1; }
        n += (size_t)rc;
    }
    close(fd); buf[n] = 0;
    struct json_value *root = json_parse(buf);
    if (!root) return -1;
    if (root->type != JSON_TYPE_OBJECT) { json_free(root); return -1; }
    struct json_value *d = json_get_child(root, "sr_domain");
    struct json_value *services = json_get_child(root, "sr_service");
    int rc = -1;
    if (!d || d->type != JSON_TYPE_OBJECT || !services || services->type != JSON_TYPE_ARRAY) goto out;
    const char *soc = json_get_string(d,"soc"), *domain = json_get_string(d,"domain");
    const char *sub = json_get_string(d,"subdomain");
    double instance;
    if (!soc || !domain || !sub || strcmp(soc,"msm") || strcmp(domain,"adsp") ||
        (strcmp(sub,"audio_pd") && strcmp(sub,"root_pd")) ||
        json_get_number(d,"qmi_instance_id",&instance) || !(instance >= 0 && instance <= 65535) ||
        instance != (unsigned)instance) goto out;
    unsigned before = map_count;
    for (struct json_value *s=services->u.value; s; s=s->next) {
        if (s->type != JSON_TYPE_OBJECT || map_count == MAX_MAPS) goto out;
        const char *provider=json_get_string(s,"provider"), *service=json_get_string(s,"service");
        if (!provider || !service) goto out;
        struct mapping *m=&maps[map_count];
        int a=snprintf(m->service,sizeof(m->service),"%s/%s",provider,service);
        int b=snprintf(m->domain,sizeof(m->domain),"%s/%s/%s",soc,domain,sub);
        if (a <= 0 || a >= (int)sizeof(m->service) || b <= 0 || b >= (int)sizeof(m->domain)) goto out;
        m->instance=(unsigned)instance;
        for (unsigned i=0;i<map_count;i++)
            if (!strcmp(maps[i].service,m->service) && !strcmp(maps[i].domain,m->domain)) goto out;
        map_count++;
    }
    if (map_count == before) goto out;
    rc=0;
out:
    json_free(root); return rc;
}

static const struct mapping *audio_map(void)
{
    const struct mapping *found=NULL;
    for (unsigned i=0;i<map_count;i++) {
        if (!strcmp(maps[i].service,"avs/audio") && !strcmp(maps[i].domain,"msm/adsp/audio_pd")) {
            if (found) return NULL;
            found=&maps[i];
        }
    }
    return found;
}

static int receive_packet(int fd, struct qrtr_packet *p, char *buf, size_t size)
{
    struct sockaddr_qrtr sq={0}; socklen_t sl=sizeof(sq);
    ssize_t n=recvfrom(fd,buf,size,MSG_DONTWAIT | MSG_TRUNC,(void *)&sq,&sl);
    if (n < 0) return (errno == EAGAIN || errno == EINTR) ? 0 : -1;
    if ((size_t)n > size || sl != sizeof(sq) || sq.sq_family != AF_QIPCRTR) return 0;
    /* libqrtr expects a complete control structure, even for malformed input. */
    if (sq.sq_port == QRTR_PORT_CTRL && (size_t)n < sizeof(struct qrtr_ctrl_pkt)) return 0;
    return qrtr_decode(p,buf,(size_t)n,&sq) < 0 ? 0 : 1;
}

static int nonblock(int fd)
{
    int flags=fcntl(fd,F_GETFL);
    return flags < 0 ? -1 : fcntl(fd,F_SETFL,flags | O_NONBLOCK);
}

/* The pinned locator descriptor marks its top-level string VAR_LEN_ARRAY
 * without a preceding DATA_LEN element. That descriptor decodes requests,
 * but libqrtr's encoder rejects it before reaching QMI_STRING. Strings carry
 * their length in the top-level TLV; use NO_ARRAY for encoding only. */
static ssize_t encode_domain_request(struct qrtr_packet *pkt, unsigned txn,
                                    const struct servreg_loc_get_domain_list_req *req)
{
    struct qmi_elem_info ei[4];
    memcpy(ei,servreg_loc_get_domain_list_req_ei,sizeof(ei));
    ei[0].array_type=NO_ARRAY;
    return qmi_encode_message(pkt,QMI_REQUEST,SERVREG_LOC_GET_DOMAIN_LIST,txn,req,ei);
}

static int reply(int fd, const struct qrtr_packet *pkt)
{
    struct servreg_loc_get_domain_list_req req={0};
    struct servreg_loc_get_domain_list_resp resp={0};
    unsigned txn=0;
    if (qmi_decode_message(&req,&txn,pkt,QMI_REQUEST,SERVREG_LOC_GET_DOMAIN_LIST,
                           servreg_loc_get_domain_list_req_ei) < 0) {
        note("mapper malformed domain-list request"); return 0;
    }
    req.name[sizeof(req.name)-1]=0;
    unsigned offset=req.offset_valid ? req.offset : 0, matched=0;
    resp.result.result=QMI_RESULT_SUCCESS;
    resp.db_revision_valid=true; resp.db_revision=1;
    resp.total_domains_valid=true;
    for (unsigned i=0;i<map_count;i++) {
        if (strcmp(maps[i].service,req.name)) continue;
        if (matched++ < offset) continue;
        struct servreg_loc_domain_list_entry *entry=&resp.domain_list[resp.domain_list_len++];
        strcpy(entry->name,maps[i].domain);
        entry->name_len=strlen(entry->name); entry->instance_id=maps[i].instance;
    }
    resp.total_domains=matched;
    resp.domain_list_valid=resp.domain_list_len != 0;
    DEFINE_QRTR_PACKET(out,4096);
    ssize_t n=qmi_encode_message(&out,QMI_RESPONSE,SERVREG_LOC_GET_DOMAIN_LIST,txn,&resp,
                                 servreg_loc_get_domain_list_resp_ei);
    if (n < 0) { note("mapper encode rc=%zd",n); return -1; }
    int rc=qrtr_sendto(fd,pkt->node,pkt->port,out.data,out.data_len);
    note("mapper domain-list peer=%u:%u matches=%u offset=%u send_rc=%d errno=%d",
         pkt->node,pkt->port,matched,offset,rc,rc < 0 ? errno : 0);
    return 0; /* requester can disappear; do not turn that into a daemon failure */
}

static int serve(void)
{
    int fd=qrtr_open(0), rc=1;
    if (fd < 0) return 1;
    if (nonblock(fd) || qrtr_publish(fd,SERVREG_QMI_SERVICE,SERVREG_QMI_VERSION,SERVREG_QMI_INSTANCE)) goto out;
    struct sockaddr_qrtr sq={0}; socklen_t sl=sizeof(sq);
    char endpoint[80];
    if (getsockname(fd,(void *)&sq,&sl) || sl != sizeof(sq) || sq.sq_family != AF_QIPCRTR) goto out;
    snprintf(endpoint,sizeof(endpoint),"%u %u\n",sq.sq_node,sq.sq_port);
    if (marker(BASE "endpoint.tmp",endpoint) || rename(BASE "endpoint.tmp",BASE "endpoint")) goto out;
    note("mapper published endpoint=%u:%u maps=%u; readiness requires probe",sq.sq_node,sq.sq_port,map_count);
    for (;;) {
        if (access(BASE "stop",F_OK)==0) { rc=0; break; }
        if (errno != ENOENT) break;
        int n=qrtr_poll(fd,100);
        if (n < 0) { if (errno==EINTR) continue; break; }
        if (!n) continue;
        struct qrtr_packet pkt={0}; char buf[4096];
        n=receive_packet(fd,&pkt,buf,sizeof(buf));
        if (n < 0) break;
        if (n && pkt.type==QRTR_TYPE_DATA && reply(fd,&pkt)) break;
    }
    if (qrtr_bye(fd,SERVREG_QMI_SERVICE,SERVREG_QMI_VERSION,SERVREG_QMI_INSTANCE)) rc=1;
out:
    if (close(fd)) rc=1;
    if (!rc && marker(BASE "done","1\n")) rc=1;
    return rc;
}

/* Proves local NS discovery + actual mapper QMI response, not remote PDR UP. */
static int probe(void)
{
    unsigned node,port; char extra;
    FILE *f=fopen(BASE "endpoint","r");
    if (!f) return 1;
    int parsed=fscanf(f,"%u %u %c",&node,&port,&extra); fclose(f);
    if (parsed != 2) return 1;
    const struct mapping *expected=audio_map();
    int fd=qrtr_open(0),rc=1,sent=0;
    if (fd < 0) return 1;
    if (nonblock(fd) || qrtr_new_lookup(fd,SERVREG_QMI_SERVICE,SERVREG_QMI_VERSION,SERVREG_QMI_INSTANCE)) goto out;
    long long begin=now_ms();
    if (begin < 0) goto out;
    for (;;) {
        long long now=now_ms();
        if (now < 0 || now-begin >= 5000) break;
        int n=qrtr_poll(fd,100);
        if (n < 0) { if (errno==EINTR) continue; break; }
        if (!n) continue;
        struct qrtr_packet pkt={0}; char buf[4096];
        n=receive_packet(fd,&pkt,buf,sizeof(buf));
        if (n < 0) break;
        if (!n || pkt.node != node || pkt.port != port) continue;
        unsigned packed=SERVREG_QMI_VERSION | (SERVREG_QMI_INSTANCE << 8);
        if (!sent && pkt.type==QRTR_TYPE_NEW_SERVER && pkt.service==SERVREG_QMI_SERVICE &&
            pkt.version==(packed & 255) && pkt.instance==(packed >> 8)) {
            struct servreg_loc_get_domain_list_req req={0};
            strcpy(req.name,expected->service); req.name_len=strlen(req.name);
            DEFINE_QRTR_PACKET(outpkt,512);
            if (encode_domain_request(&outpkt,31337,&req) < 0 ||
                qrtr_sendto(fd,node,port,outpkt.data,outpkt.data_len)) break;
            sent=1;
        } else if (sent && pkt.type==QRTR_TYPE_DATA) {
            struct servreg_loc_get_domain_list_resp resp={0}; unsigned txn=0;
            if (qmi_decode_message(&resp,&txn,&pkt,QMI_RESPONSE,SERVREG_LOC_GET_DOMAIN_LIST,
                                   servreg_loc_get_domain_list_resp_ei) < 0 || txn != 31337) continue;
            if (resp.result.result || !resp.domain_list_valid || resp.domain_list_len != 1 ||
                !resp.total_domains_valid || resp.total_domains != 1) break;
            resp.domain_list[0].name[255]=0;
            if (!strcmp(resp.domain_list[0].name,expected->domain) &&
                resp.domain_list[0].instance_id==expected->instance) rc=0;
            break;
        }
    }
    note("mapper local lookup/QMI probe rc=%d request_sent=%d",rc,sent);
out:
    close(fd); return rc;
}

int main(int argc,char **argv)
{
    if (argc != 2) return 2;
    if (load_map("/m11/pdr/adspua.jsn") || load_map("/m11/pdr/adspr.jsn") || !audio_map()) {
        note("mapper map validation failed"); return 3;
    }
    if (!strcmp(argv[1],"--check-maps")) return 0;
    if (!strcmp(argv[1],"--serve")) return serve();
    if (!strcmp(argv[1],"--probe")) return probe();
    return 2;
}
