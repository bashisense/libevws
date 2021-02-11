/*
 * Copyright (c) 2021, Bashi Tech. All rights reserved.
 */

#include "evws.h"

#include <stdlib.h>
#include <string.h>

#define log_warn    printf
#define log_info    printf

#if __BIG_ENDIAN__
    #define htonll(x)   (x)
    #define ntohll(x)   (x)
#else
    #define htonll(x)   ((((uint64_t)htonl(x&0xFFFFFFFF)) << 32) + htonl(x >> 32))
    #define ntohll(x)   ((((uint64_t)ntohl(x&0xFFFFFFFF)) << 32) + ntohl(x >> 32))
#endif

static const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";  // not used
static const char *secWebSocketKey = "w4v7O6xFTi36lq3RNcgctw==";
static const char *secWebSocketAccept = "Oy4NRAQ13jhfONC7bP8dTKb4PTU=";

struct evws{
    struct bufferevent          *bev;
    struct evhttp_connection    *conn;
    struct evhttp_request       *req;
    struct event_base           *base;
    struct evdns_base           *dnsbase;

    evws_on_connect onconnect;
    evws_on_frame   onframe;
    evws_on_close   onclose;
    void *args;
    
    SSL_CTX     *ctx;
    SSL         *ssl;
};

typedef struct wspack{
    uint8_t fopc;   // fin & opcode
    uint8_t mlen;   // mask & len < 126
    union{
        uint16_t slen;  // len < (1 << 16)
        uint64_t olen;  // len >= (1 << 16)
        uint8_t  mask[4];

        struct{
            uint16_t smlen;
            uint8_t  smask[4];
        };

        struct{
            uint64_t omlen;  // len >= (1 << 16)
            uint8_t  omask[4];
        };
    };
}__attribute__((packed))wspack_t;

evws_t *evws_new(){
    evws_t *ws;

    ws = (evws_t *)malloc(sizeof(*ws));
    if(ws == NULL){
        log_warn("evws_new -> no more memory!\n");
        return NULL;
    }
    memset(ws, 0, sizeof(*ws));

    return ws;
}

void evws_setcbs(evws_t *ws, evws_on_connect onconnect, evws_on_frame onframe, evws_on_close onclose, void *args){
    log_info("evws_setcbs ->  \n");

    ws->args = args;
    ws->onconnect = onconnect;
    ws->onframe = onframe;
    ws->onclose = onclose;
}

void evws_setbase(evws_t *ws, struct event_base *base, struct evdns_base *dnsbase){
    log_info("evws_setbase ->  \n");
    ws->base = base;
    ws->dnsbase = dnsbase;
}

int evws_setssl(evws_t *ws, const char *crtfile, const char *keyfile){

    log_info("evws_setssl -> %s, %s \n", crtfile, keyfile);

    ws->ctx = SSL_CTX_new(SSLv23_client_method()); // SSLv23_method
    if(ws->ctx == NULL){
        log_warn("evws_setssl -> create ssl ctx fail!\n");
        ERR_print_errors_fp(stdout);
        return -1;
    }

#if 0
    // 加载CA的证书  
    if(!SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)){
        log_warn("SSL_CTX_load_verify_locations error!\n");
        SSL_CTX_free(ws->ctx);
        return -1;
    }
#endif
    
    if(SSL_CTX_use_certificate_file(ws->ctx, crtfile, SSL_FILETYPE_PEM) <= 0){
        log_warn("SSL_CTX_use_certificate_file error!\n");
        SSL_CTX_free(ws->ctx);
        return -1;
    }

    if(SSL_CTX_use_PrivateKey_file(ws->ctx, keyfile, SSL_FILETYPE_PEM) <= 0){
        log_warn("SSL_CTX_use_PrivateKey_file error!\n");
        SSL_CTX_free(ws->ctx);
        return -1;
    }

    if(!SSL_CTX_check_private_key(ws->ctx)){
        log_warn("SSL_CTX_check_private_key error!\n");
        SSL_CTX_free(ws->ctx);
        return -1;
    }

    // 不要求校验对方证书 
    SSL_CTX_set_verify(ws->ctx, SSL_VERIFY_NONE, NULL); 

    ws->ssl = SSL_new(ws->ctx);
    if(ws->ssl == NULL){
        log_warn("SSL_new error!\n");
        SSL_CTX_free(ws->ctx);
        return -1;
    }

    return 0;
}

static void evms_mask(uint8_t *data,  size_t len, uint8_t *mask){
    log_info("evms_mask -> %d\n", len);

    for(size_t i = 0; i < len; i++){
		data[i] = (data[i]) ^ (mask[i%4]);;
	}
}

static void evms_unmask(uint8_t *data,  size_t len, uint8_t *mask){
	for(size_t i = 0; i < len; i++)
		data[i] ^= mask[i%4];
}

static int evws_read_frame(evws_t *ws, struct bufferevent *bev){
    struct evbuffer* buf = bufferevent_get_input(bev);
    unsigned char *data;
    size_t header_len = 0;
    wspack_t wsp;
    uint8_t fin;
    uint8_t mask;
    uint8_t *mbuf = NULL;
    uint8_t opcode;
    uint8_t len;
    uint32_t len16 = 0;
    uint64_t len64 = 0;
    
    log_info("evws_read_frame \n");

	size_t data_len = evbuffer_get_length(buf);
	if(data_len < 2){
        log_warn("evws_read_frame -> no more data in buffer\n");
		return -1;
    }
    log_info("evws_read_frame -> data len %lu\n", data_len);

    evbuffer_copyout(buf, &wsp, 2);
    header_len += 2;

	fin = wsp.fopc & 0x80;
	opcode = wsp.fopc & 0x0F;
	mask = wsp.mlen & 0x80;
    len = wsp.mlen & 0x7F;
    if(mask){
        header_len += 4;    // add mask buffer
    }

    log_info("evws_read_frame -> opcode %d\n", opcode);

    if(len == 126){
        header_len += 2;
        if(header_len > data_len){
            log_warn("evws_read_frame -> no more data in buffer for len16\n");
            return -1;
        }
        evbuffer_copyout(buf, &wsp, header_len);
        len16 = ntohs(wsp.slen);

        mbuf = wsp.smask;
        len64 = len16;
    }else if(len == 127){
        header_len += 8;
        if(header_len > data_len){
            log_warn("evws_read_frame -> no more data in buffer for len64\n");
            return -1;
        }
        evbuffer_copyout(buf, &wsp, header_len);
        len64 = ntohll(wsp.olen);
        mbuf = wsp.omask;
    }else{
        if(mask){
            evbuffer_copyout(buf, &wsp, header_len);
            mbuf = wsp.mask;
        }

        len64 = len;
    }

    if(data_len < (len64 + header_len)){
        log_warn("evws_read_frame -> no more data in buffer for payload\n");
        return -1;
    }
	data = evbuffer_pullup(buf, len64 + header_len);

    if(mask){
        evms_unmask(data + header_len, (size_t)len64, mbuf);
    }

    if(ws->onframe){
        ws->onframe(ws, ws->args, (evws_frame_e)opcode, (int)len64, data + header_len);
    }

	evbuffer_drain(buf, header_len + len64);
    return 0;
}

static void evws_readcb(struct bufferevent *bev, void *ctx){
    evws_t *ws = (evws_t *)ctx;
    log_info("evws_readcb \n");

    while(evws_read_frame(ws, bev) == 0){
        log_info("evws_readcb -> read next frame\n");
    }
}

static void evws_writecb(struct bufferevent *bev, void *ctx){
    evws_t *ws = (evws_t *)ctx;

    log_info("evws_writecb \n");
}

static void evws_build_frame(struct evbuffer* buf, uint8_t opcode, uint8_t *data, size_t sz){
	uint8_t a = opcode;
	uint8_t b = 0;
    if(sz > 0){
	    b |= 1 << 7; //mask
	}

    log_info("evws_build_frame -> 0x%02x\n", opcode);

	uint16_t c = 0;
	uint64_t d = 0;
    if(sz < 126){
		b |= sz; 
	}else if(sz < (1 << 16)){
		b |= 126;
		c = htons(sz);
	}else{
		b |= 127;
		d = htonll(sz);
	}

	evbuffer_add(buf, &a, 1);
	evbuffer_add(buf, &b, 1);
	
    if(c){
        evbuffer_add(buf, &c, sizeof(c));
	}else if(d){
        evbuffer_add(buf, &d, sizeof(d));
    }

    log_info("evws_build_frame -> %d\n", sz);
    if(sz > 0){
	    uint8_t mask_key[4];
        int r = random();
        *((int *)mask_key) = r;

        log_info("evws_build_frame 1-> %d\n", sz);
	    evbuffer_add(buf, &mask_key, 4);
        log_info("evws_build_frame 2-> %d\n", sz);
        evms_mask(data, sz, mask_key);
        
        log_info("evws_build_frame 3-> %d\n", sz);
        evbuffer_add(buf, data, sz);
    }	
}

int evws_send_frame(evws_t *ws, evws_frame_e type, uint8_t *data, size_t len){
    struct evbuffer *evb = evbuffer_new();
    
    if(evb == NULL){
        log_warn("evws_send_frame -> new evbuffer fail\n");
        return -1;
    }
    
    evws_build_frame(evb, type, data, len);
    bufferevent_write_buffer(ws->bev, evb);
    evbuffer_free(evb);
    
    return 0;
}

static void evws_eventcb(struct bufferevent *bev, short what, void *ctx){
    evws_t *ws = (evws_t *)ctx;

    log_info("evws_eventcb -> 0x%02x\n", what);
    if(what&(BEV_EVENT_EOF|BEV_EVENT_ERROR)){
        if(ws->onclose){
            ws->onclose(ws, -1);
        }
    }

    if(what&BEV_EVENT_TIMEOUT){
        evws_send_frame(ws, EVWS_FRAME_PING, NULL, 0);
    }
}

static void evws_request_done(struct evhttp_request *req, void *ctx){
    evws_t *ws = (evws_t *)ctx;
    char buffer[256] = {};
	int nread;
    log_info("evws_request_done -> \n");

	if (!req || !evhttp_request_get_response_code(req)) {
		/* If req is NULL, it means an error occurred, but
		 * sadly we are mostly left guessing what the error
		 * might have been.  We'll do our best... */
		unsigned long oslerr;
		int printed_err = 0;
		int errcode = EVUTIL_SOCKET_ERROR();
        log_warn("evws_request_done -> request fail, but we don't kown why\n");
		/* Print out the OpenSSL error queue that libevent
		 * squirreled away for us, if any. */
		while ((oslerr = bufferevent_get_openssl_error(ws->bev))) {
			ERR_error_string_n(oslerr, buffer, sizeof(buffer));
            log_warn("evws_request_done -> request ssl fail:%s\n", buffer);
			printed_err = 1;
		}

		/* If the OpenSSL error queue was empty, maybe it was a
		 * socket error; let's try printing that. */
		if (!printed_err){
			log_warn("evws_request_done -> socket error = %s (%d)\n", evutil_socket_error_to_string(errcode), errcode);
        }

        if(ws->onconnect){
            ws->onconnect(ws, -1, ws->args);
        }

		return;
	}

    const char *secAcp = evhttp_find_header(evhttp_request_get_input_headers(req), "Sec-WebSocket-Accept");
    if(strcmp(secAcp, secWebSocketAccept) != 0){
	    log_warn("evws_request_done -> secWebSocketAccept wrong\n");
        if(ws->onconnect){
            ws->onconnect(ws, -1, ws->args);
        }

        return ;
    }

	log_info("evws_request_done -> response line: %d %s\n", evhttp_request_get_response_code(req), evhttp_request_get_response_code_line(req));

	while ((nread = evbuffer_remove(evhttp_request_get_input_buffer(req),buffer, sizeof(buffer))) > 0){
		/* These are just arbitrary chunks of 256 bytes.
		 * They are not lines, so we can't treat them as such. */
		fwrite(buffer, nread, 1, stdout);
	}
    
    log_info("evws_request_done -> upgrade to websocket ...\n");
    bufferevent_setcb(ws->bev, evws_readcb, evws_writecb, evws_eventcb, ws);
	bufferevent_enable(ws->bev, EV_READ|EV_WRITE|EV_PERSIST|EV_TIMEOUT|EV_CLOSED);

    if(ws->onconnect){
        ws->onconnect(ws, 0, ws->args);
    }
}

int evws_connect(evws_t *ws, const char *uri){
    struct evhttp_uri *evuri;
    const char *scheme;
    const char *host;
    ev_uint16_t port;
    const char *path;
    int rc;

    log_info("evws_connect -> %s\n", uri);
    
    evuri = evhttp_uri_parse(uri);
    if(evuri == NULL){
        return -1;
    }

    scheme = evhttp_uri_get_scheme(evuri);
    host = evhttp_uri_get_host(evuri);
    
	path = evhttp_uri_get_path(evuri);
	if (strlen(path) == 0) {
		path = "/";
	}

    port = evhttp_uri_get_port(evuri);

    log_info("evws_connect -> scheme %s, port %d\n", scheme, port);
    if(strcasecmp(scheme, "wss") == 0){
        if(port == (ev_uint16_t)-1){
            port = 443;
        }

        ws->bev = bufferevent_openssl_socket_new(ws->base, -1, ws->ssl, BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE);
	    bufferevent_openssl_set_allow_dirty_shutdown(ws->bev, 1);
    }else if(strcasecmp(scheme, "ws") == 0){
        if(port == (ev_uint16_t)-1){
            port = 80;
        }

        ws->bev = bufferevent_socket_new(ws->base, -1, BEV_OPT_CLOSE_ON_FREE);
    }else{
        log_warn("evws_connect -> scheme is unkown:%s\n", scheme);
        evhttp_uri_free(evuri);
        return -1;
    }

    ws->conn = evhttp_connection_base_bufferevent_new(ws->base, ws->dnsbase, ws->bev, host, port);
    if(ws->conn == NULL){
        log_warn("evws_connect => evhttp_connection_base_bufferevent_new failed!\n");
        evhttp_uri_free(evuri);
        return -1;
    }

	evhttp_connection_set_family(ws->conn, AF_INET);
	evhttp_connection_set_retries(ws->conn, 5);
	evhttp_connection_set_timeout(ws->conn, 40);

    ws->req = evhttp_request_new(evws_request_done, ws);
    if(ws->req == NULL){
        log_warn("evws_connect => evhttp_request_new failed!\n");
        evhttp_connection_free(ws->conn);
        evhttp_uri_free(evuri);
        ws->conn = NULL;
        return -1;
    }

    log_info("evws_connect => request host %s ...\n", host);
	struct evkeyvalq *output_headers = evhttp_request_get_output_headers(ws->req);
	evhttp_add_header(output_headers, "Host", host);
	evhttp_add_header(output_headers, "Connection", "upgrade");
	evhttp_add_header(output_headers, "Upgrade", "websocket");
	evhttp_add_header(output_headers, "Sec-WebSocket-Key", secWebSocketKey);
	evhttp_add_header(output_headers, "Sec-WebSocket-Version", "13");
	evhttp_add_header(output_headers, "Origin:", uri);

    log_info("evws_connect => request %s ...\n", path);
    rc = evhttp_make_request(ws->conn, ws->req, EVHTTP_REQ_GET, path);
    if(rc != 0){
        log_warn("evws_connect => evhttp_make_request failed!\n");
        evhttp_connection_free(ws->conn);
        evhttp_request_free(ws->req);
        evhttp_uri_free(evuri);
        ws->conn = NULL;
        ws->req = NULL;
        return -1;
    }

    evhttp_uri_free(evuri);
    return 0;
}

int evws_free(evws_t *ws){
    bufferevent_free(ws->bev);
    evhttp_connection_free(ws->conn);
    evhttp_request_free(ws->req);

    SSL_free(ws->ssl);
    SSL_CTX_free(ws->ctx);
    memset(ws, 0, sizeof(*ws));

    return 0;
}
