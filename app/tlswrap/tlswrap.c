#include "platform.h"
#include "c_string.h"
#include "c_stdlib.h"
#include "c_types.h"
#include "mem.h"
#include "osapi.h"

#include "tlswrap.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/debug.h"

static mbedtls_entropy_context shared_entropy;
static mbedtls_ctr_drbg_context shared_ctr_drbg;
static mbedtls_ssl_config shared_config;
static mbedtls_x509_crt shared_castore;

static const char shared_reseed[] = "NodeMCU_SSL";
static const size_t tls_recv_buf_size = 512;

static void setup_config() {
  static int was_setup = 0;
  if (was_setup) return;
  was_setup = 1;

  mbedtls_ssl_config_init(&shared_config);
  mbedtls_ssl_config_defaults(
      &shared_config,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM,
      MBEDTLS_SSL_PRESET_DEFAULT
  );

  mbedtls_entropy_init(&shared_entropy);
  mbedtls_ctr_drbg_seed(
      &shared_ctr_drbg,
      mbedtls_entropy_func,
      &shared_entropy,
      shared_reseed, sizeof(shared_reseed)
  );
  mbedtls_ssl_conf_rng(&shared_config, mbedtls_ctr_drbg_random, &shared_ctr_drbg);
  mbedtls_ssl_conf_max_frag_len(&shared_config, MBEDTLS_SSL_MAX_FRAG_LEN_1024);

  mbedtls_x509_crt_init(&shared_castore);
  mbedtls_ssl_conf_ca_chain(&shared_config, &shared_castore, 0);

  mbedtls_ssl_conf_authmode(&shared_config, MBEDTLS_SSL_VERIFY_NONE);
}

struct tls_pcb {
  struct tcp_pcb *raw;
  void *cb_arg;
  mbedtls_ssl_context ctx;
  tls_connected_fn cb_conn;
  tls_recv_fn cb_recv;
  tls_sent_fn cb_sent;
  tls_poll_fn cb_poll;
  tls_err_fn cb_err;
  char *read_buf;
  size_t read_buf_len;
  int send_lock;
  int pend_error;
  os_timer_t tmr;
};

static void tls_handle(struct tls_pcb *pcb) {
  mbedtls_ssl_flush_output(&pcb->ctx);
  ets_timer_disarm(&pcb->tmr);
  if (pcb->ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
    // Handshake process
    system_soft_wdt_stop();
    int res = mbedtls_ssl_handshake_step(&pcb->ctx);
    system_soft_wdt_restart();
    if (res != 0 &&
        res != MBEDTLS_ERR_SSL_WANT_READ &&
        res != MBEDTLS_ERR_SSL_WANT_WRITE) {
      ets_printf("HANDSHAKE ERROR: %x\n", -res);
      if (pcb->cb_conn) pcb->cb_conn(pcb->cb_arg, pcb, ERR_ARG);
      if (pcb->pend_error == 0) tcp_abort(pcb->raw);
      ets_timer_disarm(&pcb->tmr);
      mbedtls_ssl_free(&pcb->ctx);
      os_free(pcb->read_buf);
      pcb->cb_err(pcb->cb_arg, ERR_BUF);
      os_free(pcb);
      return;
    } else if (pcb->ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
      if (pcb->cb_conn) pcb->cb_conn(pcb->cb_arg, pcb, ERR_OK);
    } else if (res != MBEDTLS_ERR_SSL_WANT_READ && res != MBEDTLS_ERR_SSL_WANT_WRITE) {
      ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
    }
  } else {
    // Read received data
    struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, tls_recv_buf_size, PBUF_RAM);
    int res = mbedtls_ssl_read(&pcb->ctx, p->payload, tls_recv_buf_size);
    err_t err = ERR_OK;
    if (res > 0 && pcb->cb_recv) {
      p->len = res;
      err = pcb->cb_recv(pcb->cb_arg, pcb, p, err);
    } else {
      pbuf_free(p);
      if (res == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || res == 0) {
        err = pcb->cb_recv(pcb->cb_arg, pcb, 0, ERR_OK);
      } else if (res != 0 &&
              res != MBEDTLS_ERR_SSL_WANT_READ &&
              res != MBEDTLS_ERR_SSL_WANT_WRITE) {
        if (pcb->pend_error == 0) tcp_abort(pcb->raw);
        ets_timer_disarm(&pcb->tmr);
        mbedtls_ssl_free(&pcb->ctx);
        os_free(pcb->read_buf);
        pcb->cb_err(pcb->cb_arg, ERR_BUF);
        os_free(pcb);
        return;
      }
    }
    // TODO: handle err
    if (pcb->read_buf_len > 0 || res == tls_recv_buf_size || (res > 0 && pcb->pend_error != 0)) {
      ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
    }
  }
}

static void tls_tcp_err(void *arg, err_t err) {
  if (!arg) return;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  pcb->pend_error = err | 0x80000000;
  ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
}

static err_t tls_tcp_conn(void *arg, struct tcp_pcb *tpcb, err_t err) {
  if (!arg) return ERR_ABRT;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
  return ERR_OK;
}

static err_t tls_tcp_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  if (!arg) return ERR_ABRT;
  if (!p || err != ERR_OK) {
    tls_tcp_err(arg, err);
    return err;
  }
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  pcb->read_buf = os_realloc(pcb->read_buf, pcb->read_buf_len + p->len);
  memcpy(pcb->read_buf + pcb->read_buf_len, p->payload, p->len);
  pcb->read_buf_len += p->len;
  pbuf_free(p);
  ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
  return ERR_OK;
}

static err_t tls_tcp_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  if (!arg) return ERR_ABRT;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  pcb->send_lock = 0;
  int res = ERR_OK;
  if (pcb->cb_sent) res = pcb->cb_sent(pcb->cb_arg, pcb, len);
  if (res == ERR_OK) {
    ets_timer_arm_new(&pcb->tmr, 1, 0, 1);
  }
  return res;
}

static err_t tls_tcp_poll(void *arg, struct tcp_pcb *tpcb) {
  if (!arg) return ERR_ABRT;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  if (pcb->cb_poll) return pcb->cb_poll(pcb->cb_arg, pcb);
  return 0;
}

static int tls_raw_send(void *arg, const unsigned char *buf, size_t size) {
  if (!arg) return MBEDTLS_ERR_SSL_CONN_EOF;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  if (pcb->pend_error != 0) return ERR_CONN;
  if (pcb->send_lock) return MBEDTLS_ERR_SSL_WANT_WRITE;
  err_t err = tcp_write(pcb->raw, buf, size, 0);
  pcb->send_lock = 1;
  return size;
}

static int tls_raw_recv(void *arg, unsigned char *buf, size_t size) {
  if (!arg) return MBEDTLS_ERR_SSL_CONN_EOF;
  struct tls_pcb *pcb = (struct tls_pcb*)arg;
  if (pcb->pend_error != 0 && pcb->pend_error != 0x80000000) return pcb->pend_error;
  if (size > pcb->read_buf_len) size = pcb->read_buf_len;
  if (size == 0) {
    if (pcb->pend_error == 0x80000000) return 0;
    if (pcb->pend_error != 0) return pcb->pend_error;
    return MBEDTLS_ERR_SSL_WANT_READ;
  }
  os_memcpy(buf, pcb->read_buf, size);
  os_memmove(pcb->read_buf, pcb->read_buf + size, pcb->read_buf_len - size);
  pcb->read_buf_len -= size;
  tcp_recved(pcb->raw, size);
  return size;
}

struct tls_pcb *tls_new() {
  struct tls_pcb *res = os_malloc(sizeof(struct tls_pcb));
  os_memset(res, 0, sizeof(*res));
  res->raw = tcp_new();
  if (!res->raw) {
    os_free(res);
    res = 0;
  }
  tcp_arg(res->raw, res);
  tcp_recv(res->raw, tls_tcp_recv);
  tcp_sent(res->raw, tls_tcp_sent);
  tcp_err(res->raw, tls_tcp_err);

  setup_config();
  mbedtls_ssl_init(&res->ctx);
  mbedtls_ssl_setup(&res->ctx, &shared_config);
  mbedtls_ssl_set_bio(&res->ctx, res, tls_raw_send, tls_raw_recv, 0);

  ets_timer_disarm(&res->tmr);
  ets_timer_setfn(&res->tmr, (ETSTimerFunc*)tls_handle, res);

  res->pend_error = 0;

  return res;
}

struct tcp_pcb *tls_getraw(struct tls_pcb *pcb) {
  if (!pcb) return 0;
  return pcb->raw;
}

void tls_arg(struct tls_pcb *pcb, void *arg) {
  if (!pcb) return;
  pcb->cb_arg = arg;
}

void tls_recv(struct tls_pcb *pcb, tls_recv_fn recv) {
  if (!pcb) return;
  pcb->cb_recv = recv;
}

void tls_sent(struct tls_pcb *pcb, tls_sent_fn sent) {
  if (!pcb) return;
  pcb->cb_sent = sent;
}

void tls_poll(struct tls_pcb *pcb, tls_poll_fn poll, u8_t interval) {
  if (!pcb) return;
  pcb->cb_poll = poll;
  tcp_poll(pcb->raw, tls_tcp_poll, interval);
}

void tls_err(struct tls_pcb *pcb, tls_err_fn err) {
  if (!pcb) return;
  pcb->cb_err = err;
}

void tls_recved(struct tls_pcb *pcb, u16_t len) {
  if (!pcb) return;
  // no-op
}

void tls_hostname(struct tls_pcb *pcb, const char *hostname) {
  if (!pcb) return;
  mbedtls_ssl_set_hostname(&pcb->ctx, hostname);
}

err_t tls_connect(struct tls_pcb *pcb, ip_addr_t *ipaddr, u16_t port, tls_connected_fn connected) {
  if (!pcb) return ERR_VAL;
  pcb->cb_conn = connected;
  return tcp_connect(pcb->raw, ipaddr, port, tls_tcp_conn);
}

void tls_abort(struct tls_pcb *pcb) {
  if (!pcb) return;
  tcp_abort(pcb->raw);
  ets_timer_disarm(&pcb->tmr);
  mbedtls_ssl_free(&pcb->ctx);
  os_free(pcb->read_buf);
  os_free(pcb);
}

err_t tls_close(struct tls_pcb *pcb) {
  if (!pcb) return ERR_VAL;
  int res = tcp_close(pcb->raw);
  if (res == ERR_OK) {
    ets_timer_disarm(&pcb->tmr);
    mbedtls_ssl_free(&pcb->ctx);
    os_free(pcb->read_buf);
    os_free(pcb);
  }
  return res;
}

err_t tls_write(struct tls_pcb *pcb, const void *dataptr, u16_t len, u8_t apiflags) {
  if (!pcb) return ERR_VAL;
  int ret = mbedtls_ssl_write(&pcb->ctx, dataptr, len);
  if (ret < 0) {
    ets_printf("WRITE ERR: %d\n", ret);
    return ERR_MEM;
  } else {
    return ERR_OK;
  }
}
