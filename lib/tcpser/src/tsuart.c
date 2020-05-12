#include "os/mynewt.h"
#include "uart/uart.h"
#include "tcpser_priv.h"

#define TSUART_TX_BUF_SZ   32
#define TSUART_RX_BUF_SZ   128

struct tsuart_ring {
    uint8_t head;
    uint8_t tail;
    uint16_t size;
    uint8_t *buf;
};

static struct uart_dev *tsuart_dev;

static uint8_t tsuart_rx_cr_buf[TSUART_RX_BUF_SZ];
static struct tsuart_ring tsuart_rx_cr;
static uint8_t tsuart_tx_cr_buf[TSUART_TX_BUF_SZ];
static struct tsuart_ring tsuart_tx_cr;

static volatile bool tsuart_rx_stalled;

static struct os_mbuf *tsuart_rx_line;

struct os_event tsuart_rx_ev;

static inline int
inc_and_wrap(int i, int max)
{
    return (i + 1) & (max - 1);
}

static void
tsuart_ring_add_char(struct tsuart_ring *cr, char ch)
{
    cr->buf[cr->head] = ch;
    cr->head = inc_and_wrap(cr->head, cr->size);
}

static uint8_t
tsuart_ring_pull_char(struct tsuart_ring *cr)
{
    uint8_t ch;

    ch = cr->buf[cr->tail];
    cr->tail = inc_and_wrap(cr->tail, cr->size);
    return ch;
}

static bool
tsuart_ring_is_full(const struct tsuart_ring *cr)
{
    return inc_and_wrap(cr->head, cr->size) == cr->tail;
}

static bool
tsuart_ring_is_empty(const struct tsuart_ring *cr)
{
    return cr->head == cr->tail;
}

static void
tsuart_queue_char(struct uart_dev *uart_dev, uint8_t ch)
{
    int sr;

    if (((uart_dev->ud_dev.od_flags & OS_DEV_F_STATUS_OPEN) == 0) ||
	((uart_dev->ud_dev.od_flags & OS_DEV_F_STATUS_SUSPENDED) != 0)) {
        return;
    }

    OS_ENTER_CRITICAL(sr);
    while (tsuart_ring_is_full(&tsuart_tx_cr)) {
        /* TX needs to drain */
        uart_start_tx(uart_dev);
        OS_EXIT_CRITICAL(sr);
        if (os_started()) {
            os_time_delay(1);
        }
        OS_ENTER_CRITICAL(sr);
    }
    tsuart_ring_add_char(&tsuart_tx_cr, ch);
    OS_EXIT_CRITICAL(sr);
}

static int
tsuart_handle_char(uint8_t byte)
{
    int rc;

    if (tsuart_rx_line == NULL) {
        tsuart_rx_line = os_msys_get_pkthdr(0, 0);
        if (tsuart_rx_line == NULL) {
            return -1;
        }
    }

    if (byte == '\n') {
        tcpser_rx_pkt(tsuart_rx_line);
        tsuart_rx_line = NULL;
        return 0;
    }

    rc = os_mbuf_append(tsuart_rx_line, &byte, 1);
    if (rc != 0) {
        assert(rc == OS_ENOMEM);

        os_mbuf_free_chain(tsuart_rx_line);
        tsuart_rx_line = NULL;

        return rc;
    }

    return 0;
}

static void
tsuart_rx_char_event(struct os_event *ev)
{
    static int b = -1;
    int sr;
    int ret;

    /* We may have unhandled character - try it first */
    if (b >= 0) {
        ret = tsuart_handle_char(b);
        if (ret < 0) {
            return;
        }
    }

    while (!tsuart_ring_is_empty(&tsuart_rx_cr)) {
        OS_ENTER_CRITICAL(sr);
        b = tsuart_ring_pull_char(&tsuart_rx_cr);
        OS_EXIT_CRITICAL(sr);

        /* If UART RX was stalled due to a full receive buffer, restart RX now
         * that we have removed a byte from the buffer.
         */
        if (tsuart_rx_stalled) {
            tsuart_rx_stalled = false;
            uart_start_rx(tsuart_dev);
        }

        ret = tsuart_handle_char(b);
        if (ret < 0) {
            return;
        }
    }

    b = -1;
}

static int
tsuart_rx_char(void *arg, uint8_t byte)
{
    if (tsuart_ring_is_full(&tsuart_rx_cr)) {
        tsuart_rx_stalled = true;
        return -1;
    }

    tsuart_ring_add_char(&tsuart_rx_cr, byte);

    if (!tsuart_rx_ev.ev_queued) {
        os_eventq_put(os_eventq_dflt_get(), &tsuart_rx_ev);
    }

    return 0;
}

static int
tsuart_tx_char(void *arg)
{
    if (tsuart_ring_is_empty(&tsuart_tx_cr)) {
        return -1;
    }
    return tsuart_ring_pull_char(&tsuart_tx_cr);
}

void
tsuart_write_char(int c)
{
    tsuart_queue_char(tsuart_dev, c);
    uart_start_tx(tsuart_dev);
}

void
tsuart_write(const void *buf, int len)
{
    const uint8_t *u8;
    int i;

    u8 = buf;
    for (i = 0; i < len; i++) {
        tsuart_write_char(u8[i]);
    }
}

int
tsuart_init(void)
{
    if (tsuart_dev != NULL) {
        return 0;
    }

    struct uart_conf uc = {
        .uc_speed = 115200,
        .uc_databits = 8,
        .uc_stopbits = 1,
        .uc_parity = UART_PARITY_NONE,
        .uc_flow_ctl = UART_FLOW_CTL_NONE,
        .uc_tx_char = tsuart_tx_char,
        .uc_rx_char = tsuart_rx_char,
    };

    tsuart_tx_cr.size = TSUART_TX_BUF_SZ;
    tsuart_tx_cr.buf = tsuart_tx_cr_buf;

    tsuart_rx_cr.size = TSUART_RX_BUF_SZ;
    tsuart_rx_cr.buf = tsuart_rx_cr_buf;

    tsuart_rx_ev.ev_cb = tsuart_rx_char_event;

    tsuart_dev = (void *)os_dev_open("uart0", OS_TIMEOUT_NEVER, &uc);
    if (tsuart_dev == NULL) {
        return SYS_ENODEV;
    }

    return 0;
}
