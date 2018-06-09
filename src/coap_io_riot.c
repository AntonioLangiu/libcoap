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
}



ssize_t coap_network_send(coap_socket_t *sock, const coap_session_t *session, const uint8_t *data, size_t datalen) {
    ssize_t bytes_written = 0;
    /// XXX To be implemented
    return 0;
}


ssize_t coap_network_read(coap_socket_t *sock, coap_packet_t *packet) {
    /* XXX to implement */
    return -1;
}

unsigned int coap_write(coap_context_t *ctx,
        coap_socket_t *sockets[], unsigned int max_sockets,
        unsigned int *num_sockets, coap_tick_t now)
{
    /* XXX to implement */
    return 0;
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
    /* I do not want to implement a server right now */
    return -1;
}

int coap_run_once(coap_context_t *ctx, unsigned timeout_ms) {
    /* This function uses select that is not available on riot */
    return -1;
}
