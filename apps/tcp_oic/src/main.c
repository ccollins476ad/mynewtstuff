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

#define TCP_OIC_LISTEN

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
#include "oic/port/mynewt/tcp4.h"
#include "oic/oc_api.h"
#include "tcpser/tcpser.h"

/* Task 1 */
#define TASK1_PRIO (8)
#define TASK1_STACK_SIZE    OS_STACK_ALIGN(512)
static os_stack_t task1_stack[TASK1_STACK_SIZE];
static struct os_task task1;
static volatile int g_task1_loops;
static struct os_eventq task1_evq;

/* For LED toggling */
static int g_led_pin;

static struct mn_socket *tcp_oic_sock;
#ifdef TCP_OIC_LISTEN
static struct mn_socket *tcp_oic_listener;
#endif

static void tcp_oic_writable(void *cb_arg, int err);
static int tcp_oic_newconn(void *cb_arg, struct mn_socket *new);

#ifdef TCP_OIC_LISTEN
static void tcp_oic_listen(struct os_event *ev);
#endif

static struct os_event tcp_oic_ev_listen = {
    .ev_cb = tcp_oic_listen,
};

union mn_socket_cb tcp_oic_sock_cbs = {
    .socket.writable = tcp_oic_writable,
};

union mn_socket_cb tcp_oic_listener_cbs = {
    .listen.newconn = tcp_oic_newconn,
};

static void
on_conn_err(struct mn_socket *s, int status, void *arg)
{
    console_printf("on_conn_err: status=%d\n", status);
    assert(s == tcp_oic_sock);

#ifdef TCP_OIC_LISTEN
    os_eventq_put(os_eventq_dflt_get(), &tcp_oic_ev_listen);
#endif
}

static void
tcp_oic_writable(void *cb_arg, int err)
{
    int rc;

    rc = oc_tcp4_add_conn(tcp_oic_sock, on_conn_err, NULL);
    assert(rc == 0);
}

static int
tcp_oic_newconn(void *cb_arg, struct mn_socket *new)
{
    int rc;

    assert(tcp_oic_sock == NULL); tcp_oic_sock = new; 
    tcp_oic_sock->ms_cbs = &tcp_oic_sock_cbs;

    rc = oc_tcp4_add_conn(tcp_oic_sock, on_conn_err, NULL);
    assert(rc == 0);

    return 0;
}

static void
tcp_oic_close_all(void)
{
    if (tcp_oic_listener != NULL) {
        mn_close(tcp_oic_listener);
        tcp_oic_listener = NULL;
    }

    if (tcp_oic_sock != NULL) {
        //oc_tcp4_del_conn(tcp_oic_sock);
        mn_close(tcp_oic_sock);
        tcp_oic_sock = NULL;
    }
}

#ifndef TCP_OIC_LISTEN
static void
tcp_oic_connect(void)
{
    const char *addr = "54.202.65.55";
    const uint16_t port = 8081;

    int rc;

    rc = mn_socket(&tcp_oic_sock, MN_PF_INET, MN_SOCK_STREAM, 0);
    assert(rc == 0);

    tcp_oic_sock->ms_cbs = &tcp_oic_sock_cbs;

    struct mn_sockaddr_in sin = {
        .msin_len = sizeof (struct mn_sockaddr_in),
        .msin_family = MN_PF_INET,
        .msin_port = htons(port),
    };

    rc = mn_inet_pton(MN_PF_INET, addr, &sin.msin_addr);
    assert(rc == 1);

    console_printf("connecting to %s\n", addr);
    rc = mn_connect(tcp_oic_sock, (struct mn_sockaddr *)&sin);
    assert(rc == 0);
    console_printf("connected to %s\n", addr);
}
#else
static void
tcp_oic_listen(struct os_event *ev)
{
    int rc;

    tcp_oic_close_all();

    rc = mn_socket(&tcp_oic_listener, MN_PF_INET, MN_SOCK_STREAM, 0);
    assert(rc == 0);
    tcp_oic_listener->ms_cbs = &tcp_oic_listener_cbs;

    console_printf("listening\n");
    rc = mn_listen(tcp_oic_listener, 0);
    assert(rc == 0);
    console_printf("listen successful\n");
}
#endif

static void
task1_handler(void *arg)
{
    /* Set the led pin for the E407 devboard */
    g_led_pin = LED_BLINK_PIN;
    hal_gpio_init_out(g_led_pin, 1);

    while (1) {
        os_eventq_run(&task1_evq);
    }
}

/*
 * OIC platform/resource registration.
 */
static void
omgr_app_init(void)
{
    oc_init_platform("MyNewt", NULL, NULL);
}

static const oc_handler_t omgr_oc_handler = {
    .init = omgr_app_init,
};

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

    os_eventq_init(&task1_evq);

    os_task_init(&task1, "task1", task1_handler, NULL,
            TASK1_PRIO, OS_WAIT_FOREVER, task1_stack, TASK1_STACK_SIZE);

    oc_main_init((oc_handler_t *)&omgr_oc_handler);

    tsuart_evq_set(&task1_evq);

    tcpser_reset();

#ifdef TCP_OIC_LISTEN
    tcp_oic_listen(NULL);
#else
    tcp_oic_connect();
#endif

    while (1) {
        os_eventq_run(os_eventq_dflt_get());
    }
    /* Never returns */

    return rc;
}
