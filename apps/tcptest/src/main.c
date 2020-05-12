/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

#include "os/mynewt.h"
#include <bsp/bsp.h>
#include <hal/hal_gpio.h>
#include <console/console.h>
#include <assert.h>
#include <string.h>

#ifdef ARCH_sim
#include <mcu/mcu_sim.h>
#endif

#include "mn_socket/mn_socket.h"
#include "tcpser/tcpser.h"

/* Task 1 */
#define TASK1_PRIO (8)
#define TASK1_STACK_SIZE    OS_STACK_ALIGN(512)
#define MAX_CBMEM_BUF 600
static struct os_task task1;
static volatile int g_task1_loops;

/* Task 2 */
#define TASK2_PRIO (9)
#define TASK2_STACK_SIZE    OS_STACK_ALIGN(64)
static struct os_task task2;

static volatile int g_task2_loops;

/* Global test semaphore */
static struct os_sem g_test_sem;

/* For LED toggling */
static int g_led_pin;

static struct mn_socket *sock;

static uint8_t prevrx[4096];
static int prevrxlen;
static uint8_t curidx;
static int totalrx;
static bool started;

void
sock_readable(void *cb_arg, int err)
{
    struct os_mbuf *cur;
    struct os_mbuf *om;
    uint8_t val;
    int rc;
    int i;

    rc = mn_recvfrom(sock, &om, NULL);
    assert(rc == 0);

    for (cur = om; cur != NULL; cur = SLIST_NEXT(cur, om_next)) {
        for (i = 0; i < cur->om_len; i++) {
            val = cur->om_data[i];
            if (!started) {
                if (val == 0) {
                    started = true;
                }
            }

            if (started) {
                //console_printf("0x%02x\n", val);
                if (val != curidx) {
                    console_printf("BAD: [%d] have=0x%02x want=0x%02x\n", totalrx, val, curidx);
                }
                curidx = val + 1;
            }
            totalrx++;
        }
    }

    console_printf("%d\n", totalrx);

    os_mbuf_copydata(om, 0, OS_MBUF_PKTLEN(om), prevrx);
    prevrxlen = OS_MBUF_PKTLEN(om);

    os_mbuf_free_chain(om);
}

union mn_socket_cb sock_cbs = {
    .socket.readable = sock_readable,
};

static char req_str[2048];

void
task1_handler(void *arg)
{
    //const char *addr = "52.178.197.1";
    //const char *addr = "45.56.79.23";
    const char *addr = "127.0.0.1";
    //const uint16_t port = 80;
    const uint16_t port = 666;

    struct os_task *t;
    int rc;

    /* Set the led pin for the E407 devboard */
    g_led_pin = LED_BLINK_PIN;
    hal_gpio_init_out(g_led_pin, 1);

    rc = mn_socket(&sock, MN_PF_INET, MN_SOCK_STREAM, 0);
    assert(rc == 0);

    sock->ms_cbs = &sock_cbs;

    struct mn_sockaddr_in sin = {
        .msin_len = sizeof (struct mn_sockaddr_in),
        .msin_family = MN_PF_INET,
        .msin_port = htons(port),
    };

    rc = mn_inet_pton(MN_PF_INET, addr, &sin.msin_addr);
    assert(rc == 1);

    mn_close(sock);

    console_printf("connecting to %s\n", addr);
    rc = mn_connect(sock, (struct mn_sockaddr *)&sin);
    assert(rc == 0);
    console_printf("connected to %s\n", addr);

    struct os_mbuf *om = os_msys_get_pkthdr(0, 0);
    assert(om != NULL);

    rc = snprintf(req_str, sizeof req_str,
                  "GET /files/25525/25525-h/25525-h.htm HTTP/1.1\r\n"
                  "Host: %s\r\n"
                  "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0\r\n"
                  "Accept-Encoding: gzip\r\n\r\n",
                  addr);
    assert(rc < sizeof req_str);

    rc = os_mbuf_append(om, req_str, rc);
    assert(rc == 0);

    rc = mn_sendto(sock, om, NULL);
    assert(rc == 0);

    while (1) {
        t = os_sched_get_current_task();
        assert(t->t_func == task1_handler);

        ++g_task1_loops;

        /* Wait one second */
        os_time_delay(OS_TICKS_PER_SEC);

        /* Release semaphore to task 2 */
        os_sem_release(&g_test_sem);
    }
}

void
task2_handler(void *arg)
{
    struct os_task *t;

    while (1) {
        /* just for debug; task 2 should be the running task */
        t = os_sched_get_current_task();
        assert(t->t_func == task2_handler);

        /* Increment # of times we went through task loop */
        ++g_task2_loops;

        /* Wait for semaphore from ISR */
        os_sem_pend(&g_test_sem, OS_TIMEOUT_NEVER);
    }
}

/**
 * init_tasks
 *
 * Called by main.c after sysinit(). This function performs initializations
 * that are required before tasks are running.
 *
 * @return int 0 success; error otherwise.
 */
static void
init_tasks(void)
{
    os_stack_t *pstack;
    /* Initialize global test semaphore */
    os_sem_init(&g_test_sem, 0);

    pstack = malloc(sizeof(os_stack_t)*TASK1_STACK_SIZE);
    assert(pstack);

    os_task_init(&task1, "task1", task1_handler, NULL,
            TASK1_PRIO, OS_WAIT_FOREVER, pstack, TASK1_STACK_SIZE);

    pstack = malloc(sizeof(os_stack_t)*TASK2_STACK_SIZE);
    assert(pstack);

    os_task_init(&task2, "task2", task2_handler, NULL,
            TASK2_PRIO, OS_WAIT_FOREVER, pstack, TASK2_STACK_SIZE);
}

/**
 * main
 *
 * The main task for the project. This function initializes the packages, calls
 * init_tasks to initialize additional tasks (and possibly other objects),
 * then starts serving events from default event queue.
 *
 * @return int NOTE: this function should never return!
 */
int
main(int argc, char **argv)
{
    int rc;

#ifdef ARCH_sim
    mcu_sim_parse_args(argc, argv);
#endif

    sysinit();

    rc = tsuart_init();
    assert(rc == 0);

    rc = tcpser_init();
    assert(rc == 0);

    init_tasks();

    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }
    /* Never returns */

    return rc;
}
