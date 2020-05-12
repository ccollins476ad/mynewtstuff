#ifndef H_TCPSER_
#define H_TCPSER_

int tsuart_init(void);
void tsuart_write(const void *buf, int len);

int tcpser_init(void);
void tcpser_rx_pkt(struct os_mbuf *om);

#endif
