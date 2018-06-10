#include "coap_config.h"
#include <stdio.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>
#include "libcoap.h"
#include "debug.h"
#include "mem.h"
#include "net.h"
#include "coap_io.h"
#include "pdu.h"
#include "utlist.h"
#include "resource.h"

#define OPTVAL_T(t)         (t)
#define OPTVAL_GT(t)        (t)
#define SIN6(A) ((struct sockaddr_in6 *)(A))

struct in6_pktinfo {
    struct in6_addr ipi6_addr;	/* src/dst IPv6 address */
    unsigned int ipi6_ifindex;	/* send/recv interface index */
};

struct in_pktinfo {
    int ipi_ifindex;
    struct in_addr ipi_spec_dst;
    struct in_addr ipi_addr;
};

/*******************************************************/
/************** Functions to be implemented ************/
/*******************************************************/
int coap_socket_connect_udp(coap_socket_t *sock, const coap_address_t *local_if,
        const coap_address_t *server, int default_port,
        coap_address_t *local_addr, coap_address_t *remote_addr) {
    coap_address_t connect_addr;

    // (0) Set the address of the server
    coap_address_copy(&connect_addr, server);

    // (1) Initialize the socket
    sock->flags &= ~(COAP_SOCKET_CONNECTED | COAP_SOCKET_MULTICAST);
    sock->fd = socket(connect_addr.addr.sa.sa_family, SOCK_DGRAM, 0);
    if (sock->fd == COAP_INVALID_SOCKET) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: socket: %s\n", coap_socket_strerror());
        goto error;
    }

    // XXX Ignore non blocking socket
    // (2) Set the port
    switch (connect_addr.addr.sa.sa_family) {
        case AF_INET6:
            if (connect_addr.addr.sin6.sin6_port == 0)
                connect_addr.addr.sin6.sin6_port = htons(default_port);
            break;
        case AF_INET:
            /* ignore ipv4 */
        default:
            coap_log(LOG_ALERT, "coap_socket_connect_udp: unsupported sa_family\n");
            break;
    }

    // Ignore local interface and address
    // (3) Connect the socket
    if (connect(sock->fd, &connect_addr.addr, connect_addr.size) == COAP_SOCKET_ERROR) {
        coap_log(LOG_WARNING, "coap_socket_connect_udp: connect: %s\n", coap_socket_strerror());
        goto error;
    }

    // (2) Set the timeout
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 5000;

    if (setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0) {
        printf("setsockopt failed\n");
    }

    sock->flags |= COAP_SOCKET_CONNECTED;
    return 1;
error:
    coap_socket_close(sock);
    return 0;
}

ssize_t coap_network_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen) {
    ssize_t bytes_written = 0;
    bytes_written = sendto(sock->fd, data, datalen, 0, &session->remote_addr.addr, session->remote_addr.size);

    if (bytes_written < 0) {
        coap_log(LOG_CRIT, "coap_network_send: %s\n", coap_socket_strerror());
    }

    return bytes_written;
}


ssize_t coap_network_read(coap_socket_t *sock, coap_packet_t *packet) {

    assert(sock);
    assert(packet);

    ssize_t len = -1;
    if ((sock->flags & COAP_SOCKET_CAN_READ) == 0) {
        return -1;
    } else {
        /* clear has-data flag */
        sock->flags &= ~COAP_SOCKET_CAN_READ;
    }

    struct sockaddr srcaddr;
    socklen_t socklen = sizeof(struct sockaddr_in6);

    if (sock->flags & COAP_SOCKET_CONNECTED) {
        len = recvfrom(sock->fd, packet->payload, COAP_RXBUFFER_SIZE, 0, NULL, NULL);
        if (len < 0) {
            if (errno == ECONNREFUSED) {
                /* client-side ICMP destination unreachable, ignore it */
                coap_log(LOG_WARNING, "coap_network_read: unreachable\n");
                return -2;
            }
            coap_log(LOG_WARNING, "coap_network_read: %s\n", coap_socket_strerror());
            goto error;
        } else if (len > 0) {
            packet->length = (size_t)len;
        }
    }
    if (len >= 0)
        return len;
error:
    return -1;
}

unsigned int coap_write(coap_context_t *ctx,
        coap_socket_t *sockets[], unsigned int max_sockets,
        unsigned int *num_sockets, coap_tick_t now) {
    coap_queue_t *nextpdu;
    coap_endpoint_t *ep;
    coap_session_t *s;
    coap_tick_t session_timeout;
    coap_tick_t timeout = 0;

    *num_sockets = 0;

    /* Check to see if we need to send off any Observe requests */
    coap_check_notify(ctx);

    if (ctx->session_timeout > 0)
        session_timeout = ctx->session_timeout * COAP_TICKS_PER_SECOND;
    else
        session_timeout = COAP_DEFAULT_SESSION_TIMEOUT * COAP_TICKS_PER_SECOND;
    LL_FOREACH(ctx->endpoint, ep) {
        coap_session_t *tmp;
        if (ep->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_ACCEPT)) {
            if (*num_sockets < max_sockets)
                sockets[(*num_sockets)++] = &ep->sock;
        }
        LL_FOREACH_SAFE(ep->sessions, s, tmp) {
            if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 && s->sendqueue == NULL && (s->last_rx_tx +              session_timeout <= now || s->state == COAP_SESSION_STATE_NONE)) {
                coap_session_free(s);
            } else {
                if (s->type == COAP_SESSION_TYPE_SERVER && s->ref == 0 && s->sendqueue == NULL) {
                    coap_tick_t s_timeout = (s->last_rx_tx + session_timeout) - now;
                    if (timeout == 0 || s_timeout < timeout)
                        timeout = s_timeout;
                }
                if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE)) {
                    if (*num_sockets < max_sockets)
                        sockets[(*num_sockets)++] = &s->sock;
                }
            }
        }
    }
    LL_FOREACH(ctx->sessions, s) {
        if (s->sock.flags & (COAP_SOCKET_WANT_READ | COAP_SOCKET_WANT_WRITE | COAP_SOCKET_WANT_CONNECT)) {
            if (*num_sockets < max_sockets)
                sockets[(*num_sockets)++] = &s->sock;
        }
    }

    nextpdu = coap_peek_next(ctx);

    while (nextpdu && now >= ctx->sendqueue_basetime && nextpdu->t <= now - ctx->sendqueue_basetime) {
        nextpdu->t = 0;
        coap_retransmit(ctx, coap_pop_next(ctx));
        nextpdu = coap_peek_next(ctx);
    }

    if (nextpdu && (timeout == 0 || nextpdu->t - ( now - ctx->sendqueue_basetime ) < timeout))
        timeout = nextpdu->t - (now - ctx->sendqueue_basetime);
    if (ctx->dtls_context) {
     if (coap_dtls_is_context_timeout()) {
       coap_tick_t tls_timeout = coap_dtls_get_context_timeout(ctx->dtls_context);
       if (tls_timeout > 0) {
         if (tls_timeout < now + COAP_TICKS_PER_SECOND / 10)
             tls_timeout = now + COAP_TICKS_PER_SECOND / 10;
         debug("** DTLS global timeout set to %dms\n", (int)((tls_timeout - now) * 1000 / COAP_TICKS_PER_SECOND));
         if (timeout == 0 || tls_timeout - now < timeout)
             timeout = tls_timeout - now;
       }
     } else {
         LL_FOREACH(ctx->endpoint, ep) {
             if (ep->proto == COAP_PROTO_DTLS) {
                 LL_FOREACH(ep->sessions, s) {
                     if (s->proto == COAP_PROTO_DTLS && s->tls) {
                         coap_tick_t tls_timeout = coap_dtls_get_timeout(s);
                         while (tls_timeout > 0 && tls_timeout <= now) {
                             coap_log(LOG_DEBUG, "**  %s: DTLS retransmit timeout\n", coap_session_str(s));
                             coap_dtls_handle_timeout(s);
                             if (s->tls)
                                 tls_timeout = coap_dtls_get_timeout(s);
                             else {
                                 tls_timeout = 0;
                                 timeout = 1;
                             }
                         }
                         if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
                             timeout = tls_timeout - now;
                     }
                 }
             }
         }
         LL_FOREACH(ctx->sessions, s) {
             if (s->proto == COAP_PROTO_DTLS && s->tls) {
                 coap_tick_t tls_timeout = coap_dtls_get_timeout(s);
                 while (tls_timeout > 0 && tls_timeout <= now) {
                     coap_log(LOG_DEBUG, "**  %s: DTLS retransmit timeout\n", coap_session_str(s));
                     coap_dtls_handle_timeout(s);
                     if (s->tls)
                         tls_timeout = coap_dtls_get_timeout(s);
                     else {
                         tls_timeout = 0;
                         timeout = 1;
                     }
                 }
                 if (tls_timeout > 0 && (timeout == 0 || tls_timeout - now < timeout))
                     timeout = tls_timeout - now;
             }
         }
     }
    }

    return (unsigned int)((timeout * 1000 + COAP_TICKS_PER_SECOND - 1) / COAP_TICKS_PER_SECOND);
}

int coap_run_once(coap_context_t *ctx, unsigned timeout_ms) {
    unsigned int timeout, i, num_sockets = 0;
    coap_tick_t before, now;
    coap_socket_t *sockets[10]; /// MAX 10 sockets

    coap_ticks(&before);
    timeout = coap_write(ctx, sockets, (unsigned int)(sizeof(sockets) / sizeof(sockets[0])), &num_sockets, before);
    if (timeout == 0 || timeout_ms < timeout)
        timeout = timeout_ms;

    for (i=0; i<num_sockets; i++) {
        sockets[i]->flags |= COAP_SOCKET_CAN_READ;
    }
    coap_ticks(&now);

    coap_read(ctx, now);

    return (int)(((now - before) * 1000) / COAP_TICKS_PER_SECOND);
}

/*******************************************************/
/************* Functions already implemented ************/
/*******************************************************/

ssize_t coap_socket_write(coap_socket_t *sock, const uint8_t *data, size_t data_len) {
    ssize_t r;

    sock->flags &= ~(COAP_SOCKET_WANT_WRITE | COAP_SOCKET_CAN_WRITE);
    r = send(sock->fd, data, data_len, 0);
    if (r == COAP_SOCKET_ERROR) {
        if (errno==EAGAIN || errno == EINTR) {
            sock->flags |= COAP_SOCKET_WANT_WRITE;
            return 0;
        }
        coap_log(LOG_WARNING, "coap_socket_write: send: %s\n", coap_socket_strerror());
        return -1;
    }
    if (r < (ssize_t)data_len)
        sock->flags |= COAP_SOCKET_WANT_WRITE;
    return r;
}

ssize_t coap_socket_read(coap_socket_t *sock, uint8_t *data, size_t data_len) {
    ssize_t r;

    r = recv(sock->fd, data, data_len, 0);
    if (r == 0) {
        /* graceful shutdown */
        sock->flags &= ~COAP_SOCKET_CAN_READ;
        return -1;
    } else if (r == COAP_SOCKET_ERROR) {
        sock->flags &= ~COAP_SOCKET_CAN_READ;
        if (errno==EAGAIN || errno == EINTR) {
            return 0;
        }
        if (errno != ECONNRESET)
            coap_log(LOG_WARNING, "coap_socket_read: recv: %s\n", coap_socket_strerror());
        return -1;
    }
    if (r < (ssize_t)data_len)
        sock->flags &= ~COAP_SOCKET_CAN_READ;
    return r;
}

ssize_t
coap_socket_send(coap_socket_t *sock, coap_session_t *session,
        const uint8_t *data, size_t data_len) {
    return session->context->network_send(sock, session, data, data_len);
}

static const char *coap_socket_format_errno(int error) {
    return strerror(error);
}

const char *coap_socket_strerror(void) {
    return strerror(errno);
}


struct coap_endpoint_t *
coap_malloc_endpoint(void) {
    return (struct coap_endpoint_t *)coap_malloc_type(COAP_ENDPOINT, sizeof(struct coap_endpoint_t));
}

void
coap_mfree_endpoint(struct coap_endpoint_t *ep) {
    coap_free_type(COAP_ENDPOINT, ep);
}

void coap_socket_close(coap_socket_t *sock) {
    if (sock->fd != COAP_INVALID_SOCKET) {
        coap_closesocket(sock->fd);
        sock->fd = COAP_INVALID_SOCKET;
    }
    sock->flags = 0;
}

void coap_packet_get_memmapped(coap_packet_t *packet, unsigned char **address, size_t *length) {
    *address = packet->payload;
    *length = packet->length;
}

void coap_packet_set_addr(coap_packet_t *packet, const coap_address_t *src, const coap_address_t *dst) {
    coap_address_copy(&packet->src, src);
    coap_address_copy(&packet->dst, dst);
}

/*******************************************************/
/********** Functions not to be implemented ************/
/*******************************************************/
int
coap_socket_connect_tcp1(coap_socket_t *sock,
        const coap_address_t *local_if,
        const coap_address_t *server,
        int default_port,
        coap_address_t *local_addr,
        coap_address_t *remote_addr) {
    return -1;
}

int
coap_socket_connect_tcp2(coap_socket_t *sock,
        coap_address_t *local_addr,
        coap_address_t *remote_addr) {
    return -1;
}

int
coap_socket_bind_tcp(coap_socket_t *sock,
        const coap_address_t *listen_addr,
        coap_address_t *bound_addr) {
    return -1;
}

int
coap_socket_accept_tcp(coap_socket_t *server,
        coap_socket_t *new_client,
        coap_address_t *local_addr,
        coap_address_t *remote_addr) {
    return -1;
}

int coap_socket_bind_udp(coap_socket_t *sock,
        const coap_address_t *listen_addr,
        coap_address_t *bound_addr) {
    /* I do not want to implement a server now */
    return -1;
}
