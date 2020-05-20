#ifndef H_TCPSER_
#define H_TCPSER_

struct os_eventq;

int tcpser_reset(void);
struct os_eventq *tsuart_evq_get(void);
void tsuart_evq_set(struct os_eventq *evq);

#endif
