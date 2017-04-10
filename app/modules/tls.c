// Module for TLS

#include "user_config.h"

#ifdef CLIENT_SSL_ENABLE
#define LUA_USE_MODULES_TLS
#endif

#include "module.h"

#include "lauxlib.h"
#include "platform.h"
#include "lmem.h"

#include "c_string.h"
#include "c_stdlib.h"

#include "c_types.h"
#include "mem.h"
#include "lwip/ip_addr.h"
#include "../tlswrap/tlswrap.h"
#include "lwip/err.h"
#include "lwip/dns.h"

#ifdef HAVE_SSL_SERVER_CRT
#include HAVE_SSL_SERVER_CRT
#else
__attribute__((section(".servercert.flash"))) unsigned char tls_server_cert_area[INTERNAL_FLASH_SECTOR_SIZE];
#endif

__attribute__((section(".clientcert.flash"))) unsigned char tls_client_cert_area[INTERNAL_FLASH_SECTOR_SIZE];

extern int tls_socket_create( lua_State *L );
extern int lwip_lua_checkerr (lua_State *L, err_t err);
extern const LUA_REG_TYPE tls_cert_map[];

typedef struct {
  int self_ref;
  struct tls_pcb *pcb;
  int wait_dns;
  int cb_dns_ref;
  int cb_receive_ref;
  int cb_sent_ref;
  // Only for TCP:
  int hold;
  int cb_connect_ref;
  int cb_disconnect_ref;
  int cb_reconnect_ref;
} tls_socket_ud;

static void tls_err_cb(void *arg, err_t err) {
  tls_socket_ud *ud = (tls_socket_ud*)arg;
  if (!ud || ud->self_ref == LUA_NOREF) return;
  ud->pcb = NULL; // Will be freed at LWIP level
  lua_State *L = lua_getstate();
  int ref;
  if (err != ERR_OK && ud->cb_reconnect_ref != LUA_NOREF)
    ref = ud->cb_reconnect_ref;
  else ref = ud->cb_disconnect_ref;
  if (ref != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->self_ref);
    lua_pushinteger(L, err);
    lua_call(L, 2, 0);
  }
  if (ud->wait_dns == 0) {
    lua_gc(L, LUA_GCSTOP, 0);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
    ud->self_ref = LUA_NOREF;
    lua_gc(L, LUA_GCRESTART, 0);
  }
}

static err_t tls_connected_cb(void *arg, struct tls_pcb *tpcb, err_t err) {
  tls_socket_ud *ud = (tls_socket_ud*)arg;
  if (!ud || ud->pcb != tpcb) return ERR_ABRT;
  if (err != ERR_OK) {
    tls_err_cb(arg, err);
    return ERR_ABRT;
  }
  lua_State *L = lua_getstate();
  if (ud->self_ref != LUA_NOREF && ud->cb_connect_ref != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->cb_connect_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->self_ref);
    lua_call(L, 1, 0);
  }
  return ERR_OK;
}

static void tls_dns_cb(const char *name, ip_addr_t *ipaddr, void *arg) {
  ip_addr_t addr;
  if (ipaddr != NULL) addr = *ipaddr;
  else addr.addr = 0xFFFFFFFF;
  tls_socket_ud *ud = (tls_socket_ud*)arg;
  if (!ud) return;
  lua_State *L = lua_getstate();
  if (ud->self_ref != LUA_NOREF && ud->cb_dns_ref != LUA_NOREF) {
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->cb_dns_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->self_ref);
    if (addr.addr != 0xFFFFFFFF) {
      char iptmp[16];
      bzero(iptmp, 16);
      ets_sprintf(iptmp, IPSTR, IP2STR(&addr.addr));
      lua_pushstring(L, iptmp);
    } else {
      lua_pushnil(L);
    }
    lua_call(L, 2, 0);
  }
  ud->wait_dns --;
  struct tcp_pcb *rawpcb = tls_getraw(ud->pcb);
  if (ud->pcb && rawpcb->state == CLOSED) {
    tls_connect(ud->pcb, &addr, rawpcb->remote_port, tls_connected_cb);
  } else if (!ud->pcb && ud->wait_dns == 0) {
    lua_gc(L, LUA_GCSTOP, 0);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
    ud->self_ref = LUA_NOREF;
    lua_gc(L, LUA_GCRESTART, 0);
  }
}

static err_t tls_recv_cb(void *arg, struct tls_pcb *tpcb, struct pbuf *p, err_t err) {
  tls_socket_ud *ud = (tls_socket_ud*)arg;
  if (!ud || !ud->pcb || ud->self_ref == LUA_NOREF)
    return ERR_ABRT;
  if (!p) {
    tls_err_cb(arg, err);
    return tls_close(tpcb);
  }
  if (ud->cb_receive_ref != LUA_NOREF) {
    lua_State *L = lua_getstate();
    int num_args = 2;
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->cb_receive_ref);
    lua_rawgeti(L, LUA_REGISTRYINDEX, ud->self_ref);
    lua_pushlstring(L, p->payload, p->len);
    lua_call(L, num_args, 0);
  }
  pbuf_free(p);
  tls_recved(tpcb, ud->hold ? 0 : TCP_WND);
  return ERR_OK;
}

static err_t tls_sent_cb(void *arg, struct tls_pcb *tpcb, u16_t len) {
  tls_socket_ud *ud = (tls_socket_ud*)arg;
  if (!ud || !ud->pcb || ud->self_ref == LUA_NOREF) return ERR_ABRT;
  if (ud->cb_sent_ref == LUA_NOREF) return ERR_OK;
  lua_State *L = lua_getstate();
  lua_rawgeti(L, LUA_REGISTRYINDEX, ud->cb_sent_ref);
  lua_rawgeti(L, LUA_REGISTRYINDEX, ud->self_ref);
  lua_call(L, 1, 0);
  return ERR_OK;
}

int tls_socket_create( lua_State *L ) {
  tls_socket_ud *ud = (tls_socket_ud*) lua_newuserdata(L, sizeof(tls_socket_ud));
  luaL_getmetatable(L, "tls.socket");
  lua_setmetatable(L, -2);

  ud->self_ref = LUA_NOREF;
  ud->pcb = NULL;

  ud->cb_connect_ref = LUA_NOREF;
  ud->cb_reconnect_ref = LUA_NOREF;
  ud->cb_disconnect_ref = LUA_NOREF;
  ud->hold = 0;
  ud->wait_dns = 0;
  ud->cb_dns_ref = LUA_NOREF;
  ud->cb_receive_ref = LUA_NOREF;
  ud->cb_sent_ref = LUA_NOREF;

  return 1;
}

int tls_socket_connect( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (ud->pcb)
    return luaL_error(L, "already connected");
  uint16_t port = luaL_checkinteger(L, 2);
  if (port == 0)
    return luaL_error(L, "specify port");
  const char *domain = "127.0.0.1";
  if (lua_isstring(L, 3)) {
    size_t dl = 0;
    domain = luaL_checklstring(L, 3, &dl);
  }
  if (lua_gettop(L) > 3) {
    luaL_argcheck(L, lua_isfunction(L, 4) || lua_islightfunction(L, 4), 4, "not a function");
    lua_pushvalue(L, 4);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_connect_ref);
    ud->cb_connect_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  ud->pcb = tls_new();
  if (!ud->pcb)
    return luaL_error(L, "cannot allocate PCB");
  tls_arg(ud->pcb, ud);
  tls_err(ud->pcb, tls_err_cb);
  tls_recv(ud->pcb, tls_recv_cb);
  tls_sent(ud->pcb, tls_sent_cb);
  tls_getraw(ud->pcb)->remote_port = port;
  tls_hostname(ud->pcb, domain);
  ip_addr_t addr;
  ud->wait_dns ++;
  int unref = 0;
  if (ud->self_ref == LUA_NOREF) {
    unref = 1;
    lua_pushvalue(L, 1);
    ud->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  err_t err = dns_gethostbyname(domain, &addr, tls_dns_cb, ud);
  if (err == ERR_OK) {
    tls_dns_cb(domain, &addr, ud);
  } else if (err != ERR_INPROGRESS) {
    ud->wait_dns --;
    if (unref) {
      luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
      ud->self_ref = LUA_NOREF;
    }
    tls_abort(ud->pcb);
    ud->pcb = NULL;
    return lwip_lua_checkerr(L, err);
  }
  return 0;
}

int tls_socket_on( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  int *refptr = NULL;
  const char *name = luaL_checkstring(L, 2);
  if (!name) return luaL_error(L, "need callback name");
  if (strcmp("connection",name)==0) { refptr = &ud->cb_connect_ref; }
  if (strcmp("disconnection",name)==0) { refptr = &ud->cb_disconnect_ref; }
  if (strcmp("reconnection",name)==0) { refptr = &ud->cb_reconnect_ref; }
  if (strcmp("dns",name)==0) { refptr = &ud->cb_dns_ref; }
  if (strcmp("receive",name)==0) { refptr = &ud->cb_receive_ref; }
  if (strcmp("sent",name)==0) { refptr = &ud->cb_sent_ref; }
  if (refptr == NULL)
    return luaL_error(L, "invalid callback name");
  if (lua_isfunction(L, 3) || lua_islightfunction(L, 3)) {
    lua_pushvalue(L, 3);
    luaL_unref(L, LUA_REGISTRYINDEX, *refptr);
    *refptr = luaL_ref(L, LUA_REGISTRYINDEX);
  } else if (lua_isnil(L, 3)) {
    luaL_unref(L, LUA_REGISTRYINDEX, *refptr);
    *refptr = LUA_NOREF;
  } else {
    return luaL_error(L, "invalid callback function");
  }
  return 0;
}

int tls_socket_hold( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (!ud->hold && ud->pcb) {
    ud->hold = 1;
  }
  return 0;
}

int tls_socket_unhold( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (ud->hold && ud->pcb) {
    ud->hold = 0;
    tls_getraw(ud->pcb)->flags |= TF_ACK_NOW;
    tls_recved(ud->pcb, TCP_WND);
  }
  return 0;
}

int tls_socket_getpeer( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (!ud->pcb) {
    lua_pushnil(L);
    lua_pushnil(L);
    return 2;
  }
  struct tcp_pcb *rawpcb = tls_getraw(ud->pcb);
  uint16_t port = rawpcb->remote_port;
  ip_addr_t addr = rawpcb->remote_ip;
  if (port == 0) {
    lua_pushnil(L);
    lua_pushnil(L);
    return 2;
  }
  char addr_str[16];
  bzero(addr_str, 16);
  ets_sprintf(addr_str, IPSTR, IP2STR(&addr.addr));
  lua_pushinteger(L, port);
  lua_pushstring(L, addr_str);
  return 2;
}

int tls_socket_dns( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  size_t dl = 0;
  const char *domain = luaL_checklstring(L, 2, &dl);
  if (!domain)
    return luaL_error(L, "no domain specified");
  if (lua_isfunction(L, 3) || lua_islightfunction(L, 3)) {
    luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_dns_ref);
    lua_pushvalue(L, 3);
    ud->cb_dns_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  if (ud->cb_dns_ref == LUA_NOREF)
    return luaL_error(L, "no callback specified");
  ud->wait_dns ++;
  int unref = 0;
  if (ud->self_ref == LUA_NOREF) {
    unref = 1;
    lua_pushvalue(L, 1);
    ud->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  ip_addr_t addr;
  err_t err = dns_gethostbyname(domain, &addr, tls_dns_cb, ud);
  if (err == ERR_OK) {
    tls_dns_cb(domain, &addr, ud);
  } else if (err != ERR_INPROGRESS) {
    ud->wait_dns --;
    if (unref) {
      luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
      ud->self_ref = LUA_NOREF;
    }
    return lwip_lua_checkerr(L, err);
  }
  return 0;
}

int tls_socket_send( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  ip_addr_t addr;
  uint16_t port;
  const char *data;
  size_t datalen = 0;
  int stack = 2;
  data = luaL_checklstring(L, stack++, &datalen);
  if (!data || datalen == 0) return luaL_error(L, "no data to send");
  if (lua_isfunction(L, stack) || lua_islightfunction(L, stack)) {
    lua_pushvalue(L, stack++);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_sent_ref);
    ud->cb_sent_ref = luaL_ref(L, LUA_REGISTRYINDEX);
  }
  if (!ud->pcb || ud->self_ref == LUA_NOREF)
    return luaL_error(L, "not connected");
  err_t err = tls_write(ud->pcb, data, datalen, TCP_WRITE_FLAG_COPY);
  return lwip_lua_checkerr(L, err);
}

int tls_socket_close( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (ud->pcb) {
    if (ERR_OK != tls_close(ud->pcb)) {
      tls_arg(ud->pcb, NULL);
      tls_abort(ud->pcb);
    }
    ud->pcb = NULL;
  } else {
    return luaL_error(L, "not connected");
  }
  if (ud->pcb == NULL && ud->wait_dns == 0) {
    lua_gc(L, LUA_GCSTOP, 0);
    luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
    ud->self_ref = LUA_NOREF;
    lua_gc(L, LUA_GCRESTART, 0);
  }
  return 0;
}

int tls_socket_delete( lua_State *L ) {
  tls_socket_ud *ud = luaL_checkudata(L, 1, "tls.socket");
  if (ud->pcb) {
    tls_arg(ud->pcb, NULL);
    tls_abort(ud->pcb);
    ud->pcb = NULL;
  }
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_connect_ref);
  ud->cb_connect_ref = LUA_NOREF;
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_disconnect_ref);
  ud->cb_disconnect_ref = LUA_NOREF;
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_reconnect_ref);
  ud->cb_reconnect_ref = LUA_NOREF;
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_dns_ref);
  ud->cb_dns_ref = LUA_NOREF;
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_receive_ref);
  ud->cb_receive_ref = LUA_NOREF;
  luaL_unref(L, LUA_REGISTRYINDEX, ud->cb_sent_ref);
  ud->cb_sent_ref = LUA_NOREF;

  lua_gc(L, LUA_GCSTOP, 0);
  luaL_unref(L, LUA_REGISTRYINDEX, ud->self_ref);
  ud->self_ref = LUA_NOREF;
  lua_gc(L, LUA_GCRESTART, 0);
  return 0;
}


// Returns NULL on success, error message otherwise
static const char *append_pem_blob(const char *pem, const char *type, uint8_t **buffer_p, uint8_t *buffer_limit, const char *name) {
  char unb64[256];
  memset(unb64, 0xff, sizeof(unb64));
  int i;
  for (i = 0; i < 64; i++) {
    unb64["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
  }

  if (!pem) {
    return "No PEM blob";
  }

  // Scan for -----BEGIN CERT
  pem = strstr(pem, "-----BEGIN ");
  if (!pem) {
    return "No PEM header";
  }

  if (strncmp(pem + 11, type, strlen(type))) {
    return "Wrong PEM type";
  }

  pem = strchr(pem, '\n');
  if (!pem) {
    return "Incorrect PEM format";
  }
  //
  // Base64 encoded data starts here
  // Get all the base64 data into a single buffer....
  // We will use the back end of the buffer....
  //

  uint8_t *buffer = *buffer_p;

  uint8_t *dest = buffer + 32 + 2;  // Leave space for name and length
  int bitcount = 0;
  int accumulator = 0;
  for (; *pem && dest < buffer_limit; pem++) {
    int val = unb64[*(uint8_t*) pem];
    if (val & 0xC0) {
      // not a base64 character
      if (isspace(*(uint8_t*) pem)) {
	continue;
      }
      if (*pem == '=') {
	// just ignore -- at the end
	bitcount = 0;
	continue;
      }
      if (*pem == '-') {
	break;
      }
      return "Invalid character in PEM";
    } else {
      bitcount += 6;
      accumulator = (accumulator << 6) + val;
      if (bitcount >= 8) {
	bitcount -= 8;
	*dest++ = accumulator >> bitcount;
      }
    }
  }
  if (dest >= buffer_limit || strncmp(pem, "-----END ", 9) || strncmp(pem + 9, type, strlen(type)) || bitcount) {
    return "Invalid PEM format data";
  }
  size_t len = dest - (buffer + 32 + 2);

  memset(buffer, 0, 32);
  strcpy(buffer, name);
  buffer[32] = len & 0xff;
  buffer[33] = (len >> 8) & 0xff;
  *buffer_p = dest;
  return NULL;
}

static const char *fill_page_with_pem(lua_State *L, const unsigned char *flash_memory, int flash_offset, const char **types, const char **names) 
{
  uint8_t  *buffer = luaM_malloc(L, INTERNAL_FLASH_SECTOR_SIZE);
  uint8_t  *buffer_base = buffer;
  uint8_t  *buffer_limit = buffer + INTERNAL_FLASH_SECTOR_SIZE;

  int argno;

  for (argno = 1; argno <= lua_gettop(L) && types[argno - 1]; argno++) {
    const char *pem = lua_tostring(L, argno);

    const char *error = append_pem_blob(pem, types[argno - 1], &buffer, buffer_limit, names[argno - 1]);
    if (error) {
      luaM_free(L, buffer_base);
      return error;
    }
  }

  memset(buffer, 0xff, buffer_limit - buffer);

  // Lets see if it matches what is already there....
  if (c_memcmp(buffer_base, flash_memory, INTERNAL_FLASH_SECTOR_SIZE) != 0) {
    // Starts being dangerous
    if (platform_flash_erase_sector(flash_offset / INTERNAL_FLASH_SECTOR_SIZE) != PLATFORM_OK) {
      luaM_free(L, buffer_base);
      return "Failed to erase sector";
    }
    if (platform_s_flash_write(buffer_base, flash_offset, INTERNAL_FLASH_SECTOR_SIZE) != INTERNAL_FLASH_SECTOR_SIZE) {
      luaM_free(L, buffer_base);
      return "Failed to write sector";
    }
    // ends being dangerous
  }

  luaM_free(L, buffer_base);

  return NULL;
}

// Lua: tls.cert.auth(true / false | PEM data [, PEM data] )
static int tls_cert_auth(lua_State *L)
{
  int enable;

  uint32_t flash_offset = platform_flash_mapped2phys((uint32_t) &tls_client_cert_area[0]);
  if ((flash_offset & 0xfff) || flash_offset > 0xff000 || INTERNAL_FLASH_SECTOR_SIZE != 0x1000) {
    // THis should never happen
    return luaL_error( L, "bad offset" );
  }

  if (lua_type(L, 1) == LUA_TSTRING) {
    const char *types[3] = { "CERTIFICATE", "RSA PRIVATE KEY", NULL };
    const char *names[2] = { "certificate", "private_key" };
    const char *error = fill_page_with_pem(L, &tls_client_cert_area[0], flash_offset, types, names);
    if (error) {
      return luaL_error(L, error);
    }

    enable = 1;
  } else {
    enable = lua_toboolean(L, 1);
  }

  bool rc;

  if (enable) {
    // See if there is a cert there
    if (tls_client_cert_area[0] == 0x00 || tls_client_cert_area[0] == 0xff) {
      return luaL_error( L, "no certificates found" );
    }
//    rc = espconn_secure_cert_req_enable(1, flash_offset / INTERNAL_FLASH_SECTOR_SIZE);
  } else {
//    rc = espconn_secure_cert_req_disable(1);
  }

  lua_pushboolean(L, rc);
  return 1;
}

// Lua: tls.cert.verify(true / false | PEM data [, PEM data] )
static int tls_cert_verify(lua_State *L)
{
  int enable;

  uint32_t flash_offset = platform_flash_mapped2phys((uint32_t) &tls_server_cert_area[0]);
  if ((flash_offset & 0xfff) || flash_offset > 0xff000 || INTERNAL_FLASH_SECTOR_SIZE != 0x1000) {
    // THis should never happen
    return luaL_error( L, "bad offset" );
  }

  if (lua_type(L, 1) == LUA_TSTRING) {
    const char *types[2] = { "CERTIFICATE", NULL };
    const char *names[1] = { "certificate" };

    const char *error = fill_page_with_pem(L, &tls_server_cert_area[0], flash_offset, types, names);
    if (error) {
      return luaL_error(L, error);
    }

    enable = 1;
  } else {
    enable = lua_toboolean(L, 1);
  }

  bool rc;

  if (enable) {
    // See if there is a cert there
    if (tls_server_cert_area[0] == 0x00 || tls_server_cert_area[0] == 0xff) {
      return luaL_error( L, "no certificates found" );
    }
//    rc = espconn_secure_ca_enable(1, flash_offset / INTERNAL_FLASH_SECTOR_SIZE);
  } else {
//    rc = espconn_secure_ca_disable(1);
  }

  lua_pushboolean(L, rc);
  return 1;
}

static const LUA_REG_TYPE tls_socket_map[] = {
  { LSTRKEY( "connect" ), LFUNCVAL( tls_socket_connect ) },
  { LSTRKEY( "close" ),   LFUNCVAL( tls_socket_close ) },
  { LSTRKEY( "on" ),      LFUNCVAL( tls_socket_on ) },
  { LSTRKEY( "send" ),    LFUNCVAL( tls_socket_send ) },
  { LSTRKEY( "hold" ),    LFUNCVAL( tls_socket_hold ) },
  { LSTRKEY( "unhold" ),  LFUNCVAL( tls_socket_unhold ) },
  { LSTRKEY( "dns" ),     LFUNCVAL( tls_socket_dns ) },
  { LSTRKEY( "getpeer" ), LFUNCVAL( tls_socket_getpeer ) },
  { LSTRKEY( "__gc" ),    LFUNCVAL( tls_socket_delete ) },
  { LSTRKEY( "__index" ), LROVAL( tls_socket_map ) },
  { LNILKEY, LNILVAL }
};

const LUA_REG_TYPE tls_cert_map[] = {
  { LSTRKEY( "verify" ),           LFUNCVAL( tls_cert_verify ) },
  { LSTRKEY( "auth" ),             LFUNCVAL( tls_cert_auth ) },
  { LSTRKEY( "__index" ),          LROVAL( tls_cert_map ) },
  { LNILKEY, LNILVAL }
};

static const LUA_REG_TYPE tls_map[] = {
  { LSTRKEY( "createConnection" ), LFUNCVAL( tls_socket_create ) },
  { LSTRKEY( "cert" ),             LROVAL( tls_cert_map ) },
  { LSTRKEY( "__metatable" ),      LROVAL( tls_map ) },
  { LNILKEY, LNILVAL }
};

int luaopen_tls( lua_State *L ) {
  luaL_rometatable(L, "tls.socket", (void *)tls_socket_map);  // create metatable for net.server
  return 0;
}

NODEMCU_MODULE(TLS, "tls", tls_map, luaopen_tls);
