#ifndef H_TCPSER_PRIV_
#define H_TCPSER_PRIV_

int tsuart_init(void);
void tsuart_write(const void *buf, int len);

void tcpser_rx_pkt(struct os_mbuf *om);

#endif
