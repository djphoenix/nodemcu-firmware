#ifndef _TLSWRAP_H_
#define _TLSWRAP_H_

#include "osapi.h"
#include "lwip/tcp.h"
#include "stdlib.h"

struct tls_pcb;

typedef err_t (*tls_recv_fn)     (void *arg, struct tls_pcb *tpcb, struct pbuf *p, err_t err);
typedef err_t (*tls_sent_fn)     (void *arg, struct tls_pcb *tpcb, u16_t len);
typedef err_t (*tls_poll_fn)     (void *arg, struct tls_pcb *tpcb);
typedef void  (*tls_err_fn)      (void *arg, err_t err);
typedef err_t (*tls_connected_fn)(void *arg, struct tls_pcb *tpcb, err_t err);

struct tls_pcb *tls_new     ();
struct tcp_pcb *tls_getraw  (struct tls_pcb *pcb);
void            tls_arg     (struct tls_pcb *pcb, void *arg);
void            tls_recv    (struct tls_pcb *pcb, tls_recv_fn recv);
void            tls_sent    (struct tls_pcb *pcb, tls_sent_fn sent);
void            tls_poll    (struct tls_pcb *pcb, tls_poll_fn poll, u8_t interval);
void            tls_err     (struct tls_pcb *pcb, tls_err_fn err);
void            tls_hostname(struct tls_pcb *pcb, const char *hostname);
err_t           tls_connect (struct tls_pcb *pcb, ip_addr_t *ipaddr, u16_t port,
                             tls_connected_fn connected);
void            tls_abort   (struct tls_pcb *pcb);
err_t           tls_close   (struct tls_pcb *pcb);
err_t           tls_write   (struct tls_pcb *pcb, const void *dataptr, u16_t len,
                             u8_t apiflags);
void            tls_recved  (struct tls_pcb *pcb, u16_t len);

#endif
