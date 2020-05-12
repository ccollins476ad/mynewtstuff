#include "os/mynewt.h"
#include "mn_socket/mn_socket.h"
#include "mn_socket/mn_socket_ops.h"
#include "base64/base64.h"
#include "tcpser_priv.h"

STAILQ_HEAD(, os_mbuf_pkthdr) tcpser_rxq = STAILQ_HEAD_INITIALIZER(tcpser_rxq);

static struct mn_socket tcpser_socket;
static struct os_mutex tcpser_mtx;
static struct os_sem tcpser_block_sem;
static int *tcpser_block_rc;

static void
tcpser_hold(int *status)
{
    os_mutex_pend(&tcpser_mtx, OS_WAIT_FOREVER);
    tcpser_block_rc = status;
    os_mutex_release(&tcpser_mtx);
}

static bool
tcpser_holding(void)
{
    bool holding;

    os_mutex_pend(&tcpser_mtx, OS_WAIT_FOREVER);
    holding = tcpser_block_rc != NULL;
    os_mutex_release(&tcpser_mtx);

    return holding;
}

static void
tcpser_block(void)
{
    assert(tcpser_holding());
    os_sem_pend(&tcpser_block_sem, OS_WAIT_FOREVER);
}

static void
tcpser_unblock(int status)
{
    os_mutex_pend(&tcpser_mtx, OS_WAIT_FOREVER);

    if (tcpser_block_rc != NULL) {
        *tcpser_block_rc = status;
        tcpser_block_rc = NULL;

        os_sem_release(&tcpser_block_sem);
    }

    os_mutex_release(&tcpser_mtx);
}

static int
tcpser_create(struct mn_socket **sock, uint8_t domain, uint8_t type,
              uint8_t protocol)
{
    int rc;

    if (domain != MN_PF_INET) {
        return MN_EAFNOSUPPORT;
    }

    if (type != MN_SOCK_STREAM) {
        return MN_EPROTONOSUPPORT;
    }

    rc = tsuart_init();
    if (rc != 0) {
        return rc;
    }

    *sock = &tcpser_socket;

    return 0;
}

static int
tcpser_close(struct mn_socket *sock)
{
    static const char *str = "disconnect\n";
    int rc;

    tcpser_hold(&rc);
    tsuart_write(str, strlen(str));
    tcpser_block();

    return rc;
}

static int
tcpser_bind(struct mn_socket *sock, struct mn_sockaddr *addr)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_connect(struct mn_socket *sock, struct mn_sockaddr *addr)
{
    const struct mn_sockaddr_in *sin;
    char buf[MN_INET_ADDRSTRLEN];
    const char *c;
    int len;
    int rc;

    if (addr->msa_family != MN_PF_INET) {
        return MN_EAFNOSUPPORT;
    }

    if (addr->msa_len < sizeof *sin) {
        return MN_EINVAL;
    }

    sin = (void *)addr;

    c = mn_inet_ntop(MN_PF_INET, &sin->msin_addr, buf, sizeof buf);
    if (c == NULL) {
        return MN_EINVAL;
    }

    tcpser_hold(&rc);

    tsuart_write("connect ", 8);
    tsuart_write(c, strlen(c));

    len = sprintf(buf, ":%d\n", ntohs(sin->msin_port));
    tsuart_write(buf, len);

    tcpser_block();

    mn_socket_writable(&tcpser_socket, rc);
    return rc;
}

static int
tcpser_listen(struct mn_socket *sock, uint8_t qlen)
{
    return MN_OPNOSUPPORT;
}

#define TCPSER_MAX_CHUNK_SZ 63

static int
tcpser_sendto(struct mn_socket *sock, struct os_mbuf *om, struct mn_sockaddr *to)
{
    char b64[BASE64_ENCODE_SIZE(TCPSER_MAX_CHUNK_SZ) + 1];
    struct os_mbuf *cur;
    int chunk_sz;
    int len;
    int rc;

    tcpser_hold(&rc);

    tsuart_write("tx ", 3);

    while (OS_MBUF_PKTLEN(om) > 0) {
        chunk_sz = TCPSER_MAX_CHUNK_SZ;
        if (chunk_sz > OS_MBUF_PKTLEN(om)) {
            chunk_sz = OS_MBUF_PKTLEN(om);
        }

        cur = os_mbuf_pullup(om, chunk_sz);
        len = base64_encode(cur->om_data, chunk_sz, b64,
                            chunk_sz == OS_MBUF_PKTLEN(om));
                            
        tsuart_write(b64, len);

        os_mbuf_adj(om, chunk_sz);
    }

    tsuart_write("\n", 1);

    os_mbuf_free_chain(om);

    tcpser_block();

    return rc;
}

static int
tcpser_recvfrom(struct mn_socket *sock, struct os_mbuf **om, struct mn_sockaddr *from)
{
    struct os_mbuf_pkthdr *omp;

    // XXX: Check connected state.

    os_mutex_pend(&tcpser_mtx, OS_WAIT_FOREVER);

    omp = STAILQ_FIRST(&tcpser_rxq);
    if (omp != NULL) {
        STAILQ_REMOVE_HEAD(&tcpser_rxq, omp_next);
    }

    os_mutex_release(&tcpser_mtx);

    if (omp == NULL) {
        return MN_EAGAIN;
    }

    *om = OS_MBUF_PKTHDR_TO_MBUF(omp);
    return 0;
}

static int
tcpser_getsockopt(struct mn_socket *sock, uint8_t level, uint8_t name, void *val)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_setsockopt(struct mn_socket *sock, uint8_t level, uint8_t name, void *val)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_getsockname(struct mn_socket *sock, struct mn_sockaddr *addr)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_getpeername(struct mn_socket *sock, struct mn_sockaddr *addr)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_itf_getnext(struct mn_itf *itf)
{
    return MN_OPNOSUPPORT;
}

static int
tcpser_itf_addr_getnext(struct mn_itf *itf, struct mn_itf_addr *addr)
{
    return MN_OPNOSUPPORT;
}

static const struct mn_socket_ops tcpser_ops = {
    .mso_create = tcpser_create,
    .mso_close = tcpser_close,
    .mso_bind = tcpser_bind,
    .mso_connect = tcpser_connect,
    .mso_listen = tcpser_listen,
    .mso_sendto = tcpser_sendto,
    .mso_recvfrom = tcpser_recvfrom,
    .mso_getsockopt = tcpser_getsockopt,
    .mso_setsockopt = tcpser_setsockopt,
    .mso_getsockname = tcpser_getsockname,
    .mso_getpeername = tcpser_getpeername,
    .mso_itf_getnext = tcpser_itf_getnext,
    .mso_itf_addr_getnext = tcpser_itf_addr_getnext,
};

static void
tcpser_rx_data(struct os_mbuf *om)
{
    struct base64_decoder dec;
    struct os_mbuf_pkthdr *omp;
    struct os_mbuf *cur;
    int delta;
    int len;

    omp = OS_MBUF_PKTHDR(om);

    memset(&dec, 0, sizeof dec);
    for (cur = om; cur != NULL; cur = SLIST_NEXT(cur, om_next)) {
        dec.src = (const char *)cur->om_data;
        dec.src_len = cur->om_len;
        dec.dst = cur->om_data;
        dec.dst_len = -1;

        len = base64_decoder_go(&dec);
        if (len < 0) {
            os_mbuf_free_chain(om);
            return;
        }

        delta = cur->om_len - len;
        cur->om_len = len;

        omp->omp_len -= delta;
    }

    os_mutex_pend(&tcpser_mtx, OS_WAIT_FOREVER);

    STAILQ_INSERT_TAIL(&tcpser_rxq, omp, omp_next);

    os_mutex_release(&tcpser_mtx);

    mn_socket_readable(&tcpser_socket, 0);
}

void
tcpser_rx_pkt(struct os_mbuf *om)
{
    char *cmdstr;
    char *c;
    int cmdlen;

    // XXX: Just assume the first token is fully contained in the leading
    // buffer.
    cmdstr = (char *)om->om_data;
    c = strchr(cmdstr, ' ');
    if (c != NULL) {
        cmdlen = c - cmdstr;
    } else {
        cmdlen = om->om_len;
    }

    if (strncmp(cmdstr, "ack", cmdlen) == 0) {
        tcpser_unblock(0);
        os_mbuf_free_chain(om);
        return;
    }

    if (strncmp(cmdstr, "error", cmdlen) == 0) {
        tcpser_unblock(-1);
        os_mbuf_free_chain(om);
        return;
    }

    if (strncmp(cmdstr, "rx", cmdlen) == 0) {
        os_mbuf_adj(om, cmdlen + 1);
        tcpser_rx_data(om);
        return;
    }
}

void
tcpser_init(void)
{
    int rc;

    rc = mn_socket_ops_reg(&tcpser_ops);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = os_mutex_init(&tcpser_mtx);
    SYSINIT_PANIC_ASSERT(rc == 0);
}
