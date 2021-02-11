/*
 * Copyright (c) 2021, Bashi Tech. All rights reserved.
 */
#include "evws.h"

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

#include <unistd.h>
#include <sys/reboot.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <stdarg.h>


#define log_info    printf
#define log_warn    printf
#undef  TRACE
#define TRACE       printf

#define SERVER_CERT_FILE        "./ssl.crt"
#define SERVER_KEY_FILE         "./ssl.key"

const char *wx = "wss://openhw.work.weixin.qq.com";
//const char *wx = "ws://127.0.0.1:8888/ws";
static char data_puts[128] = "{\"cmd\":\"get_secret_no\",\"headers\":{\"req_id\":\"2\"},\"body\":{}}";

static void onconnect(evws_t *ws, int rc, void *args){
    log_info("onconnect -> %d\n", rc);
    
    if(rc == 0){
        evws_send_frame(ws, EVWS_FRAME_PING, NULL, 0);

        log_info("onconnect -> %d\n", strlen(data_puts));
        evws_send_frame(ws, 0x80|EVWS_FRAME_TEXT, data_puts, strlen(data_puts));
    }
}

static void onframe(evws_t *ws, void *args, evws_frame_e type, int len, const void *payload){
    log_info("onframe -> %d\n", type);

    switch(type){
    case EVWS_FRAME_PING:
        evws_send_frame(ws, EVWS_FRAME_PONG, NULL, 0);
        break;
    case EVWS_FRAME_TEXT:
        log_info("onframe -> %s\n", (char*)payload);
        break;
    
    default:
        break;
    }
}

static void onclose(evws_t *ws, int rc){
    log_info("onclose -> %d\n", rc);
}


int main(){
    struct event_base *base;
    struct evdns_base *dnsbase;
    evws_t  *ws;

    log_info("main => thread init ...\n");

    evthread_use_pthreads();

    base = event_base_new();
    if (base == NULL){
        log_warn("main => create event_base failed!\n");
        return -1;
    }

    dnsbase = evdns_base_new(base, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    if(dnsbase == NULL){
        log_warn("main => create evdns_base_new failed!\n");
        event_base_free(base);
        return -1;
    }

    ws = evws_new();

    evws_setcbs(ws, onconnect, onframe, onclose, ws);
    evws_setssl(ws, SERVER_CERT_FILE, SERVER_KEY_FILE);
    evws_setbase(ws, base, dnsbase);

    evws_connect(ws, wx);

    log_info("main => loop ...\n");
	event_base_dispatch(base);
    //event_base_loop(base, EVLOOP_NO_EXIT_ON_EMPTY);
    
    evws_free(ws);
    event_base_free(base);
    
    return 0;
}

