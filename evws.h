/*
 * Copyright (c) 2021, Bashi Tech. All rights reserved.
 */

#ifndef __EVWS_H__
#define __EVWS_H__

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event_struct.h>
#include <event2/thread.h>
#include <event2/dns.h>
#include <event2/http.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <inttypes.h>


struct evws;
typedef struct evws evws_t;

typedef enum{
    EVWS_FRAME_CONTINUE = 0,
    EVWS_FRAME_TEXT = 1,
    EVWS_FRAME_BINARY = 2,
    EVWS_FRAME_CLOSE = 8,
    EVWS_FRAME_PING = 9,
    EVWS_FRAME_PONG = 10,
}evws_frame_e;

typedef void (*evws_on_connect)(evws_t *evws, int rc, void *args);
typedef void (*evws_on_frame)(evws_t *evws, void *args, evws_frame_e type, int len, const void *payload);
typedef void (*evws_on_close)(evws_t *evws, int rc);

evws_t *evws_new();

void evws_setcbs(evws_t *ws, evws_on_connect onconnect, evws_on_frame onframe, evws_on_close onclose, void *args);
void evws_setbase(evws_t *ws, struct event_base *base, struct evdns_base *dnsbase);
int evws_setssl(evws_t *ws, const char *crtfile, const char *keyfile);

int evws_connect(evws_t *ws, const char *uri);

int evws_send_frame(evws_t *ws, evws_frame_e type, uint8_t *data, size_t len);

int evws_free(evws_t *ws);

#endif  // __EVWS_H__
