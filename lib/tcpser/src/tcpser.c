#include "os/mynewt.h"
#include "mn_socket/mn_socket.h"
#include "mn_socket/mn_socket_ops.h"
#include "base64/base64.h"
#include "console/console.h"
#include "tcpser_priv.h"

STAILQ_HEAD(, os_mbuf_pkthdr) tcpser_rxq = STAILQ_HEAD_INITIALIZER(tcpser_rxq);

static struct os_mutex tcpser_state_mtx;
static struct os_mutex tcpser_op_mtx;
static struct os_sem tcpser_block_sem;
static int *tcpser_block_rc;

struct os_mempool tcpser_sock_pool;
static os_membuf_t tcpser_sock_buf[
    OS_MEMPOOL_SIZE(2, sizeof (struct mn_socket))
];

static struct mn_socket *tcpser_sock;
static struct mn_socket *tcpser_listener;

static void
tcpser_lock_op(void)
{
    int rc;

    rc = os_mutex_pend(&tcpser_op_mtx, OS_WAIT_FOREVER);
    assert(rc == 0);
}

static void
tcpser_unlock_op(void)
{
    int rc;

    rc = os_mutex_release(&tcpser_op_mtx);
    assert(rc == 0);
}

static void
tcpser_lock_state(void)
{
    int rc;

    rc = os_mutex_pend(&tcpser_state_mtx, OS_WAIT_FOREVER);
    assert(rc == 0);
}

static void
tcpser_unlock_state(void)
{
    int rc;

    rc = os_mutex_release(&tcpser_state_mtx);
    assert(rc == 0);
}

static void
tcpser_start_op(int *status)
{
    tcpser_lock_op();

    tcpser_lock_state();
    tcpser_block_rc = status;
    tcpser_unlock_state();
}

static void
tcpser_end_op(void)
{
    tcpser_unlock_op();
}

static bool
tcpser_op_is_active(void)
{
    bool active;

    tcpser_lock_state();
    active = tcpser_block_rc != NULL;
    tcpser_unlock_state();

    return active;
}

static void
tcpser_block(void)
{
    int rc;

    assert(tcpser_op_is_active());

    rc = os_sem_pend(&tcpser_block_sem, OS_WAIT_FOREVER);
    assert(rc == 0);
}

static void
tcpser_unblock(int status)
{
    int rc;

    tcpser_lock_state();

    if (tcpser_block_rc != NULL) {
        *tcpser_block_rc = status;
        tcpser_block_rc = NULL;

        rc = os_sem_release(&tcpser_block_sem);
        assert(rc == 0);
    }

    tcpser_unlock_state();
}

static int
tcpser_create(struct mn_socket **sock, uint8_t domain, uint8_t type,
              uint8_t protocol)
{
    if (domain != MN_PF_INET) {
        return MN_EAFNOSUPPORT;
    }

    if (type != MN_SOCK_STREAM) {
        return MN_EPROTONOSUPPORT;
    }

    *sock = os_memblock_get(&tcpser_sock_pool);
    if (*sock == NULL) {
        return MN_ENOBUFS;
    }

    return 0;
}

static int
tcpser_close(struct mn_socket *sock)
{
    static const char *str = "disconnect\n";
    bool is_sock;
    int rc;

    tcpser_start_op(&rc);

    tcpser_lock_state();

    if (sock == tcpser_sock) {
        is_sock = true;
    } else {
        assert(sock == tcpser_listener);
    }

    tcpser_unlock_state();

    if (is_sock) {
        tsuart_write(str, strlen(str));
        tcpser_sock = NULL;
    } else {
        tsuart_write("stop-listen\n", 12);
        tcpser_listener = NULL;
    }

    tcpser_block();

    os_memblock_put(&tcpser_sock_pool, sock);

    tcpser_end_op();

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
    bool already;
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

    tcpser_lock_state();
    already = tcpser_sock != NULL || tcpser_listener != NULL;
    if (!already) {
        tcpser_sock = sock;
    }
    tcpser_unlock_state();

    if (already) {
        return MN_ENOBUFS;
    }
    
    tcpser_start_op(&rc);

    tsuart_write("connect ", 8);
    tsuart_write(c, strlen(c));

    len = sprintf(buf, ":%d\n", ntohs(sin->msin_port));
    tsuart_write(buf, len);

    tcpser_block();

    if (rc != 0) {
        tcpser_lock_state();
        tcpser_sock = NULL;
        tcpser_unlock_state();
    }

    tcpser_end_op();

    mn_socket_writable(sock, rc);
    return rc;
}

static int
tcpser_listen(struct mn_socket *sock, uint8_t qlen)
{
    bool already;
    int rc;

    tcpser_lock_state();
    already = tcpser_sock != NULL || tcpser_listener != NULL;
    if (!already) {
        tcpser_listener = sock;
    }
    tcpser_unlock_state();

    if (already) {
        return MN_ENOBUFS;
    }

    tcpser_start_op(&rc);

    tsuart_write("listen 666\n", 11);
    tcpser_block();

    if (rc != 0) {
        tcpser_lock_state();
        tcpser_listener = NULL;
        tcpser_unlock_state();
    }

    tcpser_end_op();

    return rc;
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

    tcpser_start_op(&rc);

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

    tcpser_end_op();

    return rc;
}

static int
tcpser_recvfrom(struct mn_socket *sock, struct os_mbuf **om, struct mn_sockaddr *from)
{
    struct os_mbuf_pkthdr *omp;

    // XXX: Check connected state.

    tcpser_lock_state();

    omp = STAILQ_FIRST(&tcpser_rxq);
    if (omp != NULL) {
        STAILQ_REMOVE_HEAD(&tcpser_rxq, omp_next);
    }

    tcpser_unlock_state();

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
tcpser_rx_accept(void)
{
    int rc;

    tcpser_lock_state();

    assert(tcpser_sock == NULL);

    rc = mn_socket(&tcpser_sock, MN_PF_INET, MN_SOCK_STREAM, 0);
    assert(rc == 0);

    tcpser_unlock_state();

    mn_socket_newconn(tcpser_listener, tcpser_sock);
}

static void
tcpser_rx_close(void)
{
    tcpser_lock_state();

    if (tcpser_sock != NULL) {
        mn_socket_readable(tcpser_sock, MN_ECONNABORTED);
    }

    tcpser_unlock_state();
}

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

    tcpser_lock_state();

    STAILQ_INSERT_TAIL(&tcpser_rxq, omp, omp_next);

    tcpser_unlock_state();

    mn_socket_readable(tcpser_sock, 0);
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

    console_printf("cmd=%*s\n", cmdlen, cmdstr);

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

    if (strncmp(cmdstr, "accept", cmdlen) == 0) {
        tcpser_rx_accept();
        return;
    }

    if (strncmp(cmdstr, "close", cmdlen) == 0) {
        tcpser_rx_close();
        return;
    }
}

int
tcpser_reset(void)
{
    int rc;

    tcpser_start_op(&rc);

    tsuart_write("reset\n", 6);
    tcpser_block();

    tcpser_end_op();

    return rc;
}

void
tcpser_init(void)
{
    int rc;

    rc = mn_socket_ops_reg(&tcpser_ops);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = os_mutex_init(&tcpser_state_mtx);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = os_mutex_init(&tcpser_op_mtx);
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = os_mempool_init(&tcpser_sock_pool, 2,
                         sizeof (struct mn_socket), tcpser_sock_buf,
                         "tcpser_sock_pool");
    SYSINIT_PANIC_ASSERT(rc == 0);

    rc = tsuart_init();
    SYSINIT_PANIC_ASSERT(rc == 0);
}
