#define _POSIX_C_SOURCE 200112L

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET socket_t;
#define INVALID_FD INVALID_SOCKET
#define close_socket closesocket
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_FD (-1)
#define close_socket close
#endif

#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#ifndef HANDSHAKE_TIMEOUT_SECONDS
#define HANDSHAKE_TIMEOUT_SECONDS 15
#endif
#ifndef CONNECT_TIMEOUT_SECONDS
#define CONNECT_TIMEOUT_SECONDS 10
#endif
#define UDP_BUFFER_SIZE 65536
#define UDP_DESTINATION_LIMIT 64
#define UDP_DESTINATION_TTL_SECONDS 60
#define UDP_DNS_CACHE_LIMIT 8
#define UDP_DNS_CACHE_TTL_SECONDS 60
#define CONNECT_FALLBACK_DELAY_MS 250
#define CONNECT_PENDING_LIMIT 8

#ifndef MAX_CLIENTS
#define MAX_CLIENTS 64
#endif
#ifndef IDLE_TIMEOUT_SECONDS
#define IDLE_TIMEOUT_SECONDS 300
#endif

_Static_assert(MAX_CLIENTS > 0, "MAX_CLIENTS must be positive");
_Static_assert(HANDSHAKE_TIMEOUT_SECONDS > 0 && HANDSHAKE_TIMEOUT_SECONDS <= INT_MAX / 1000,
               "HANDSHAKE_TIMEOUT_SECONDS is out of range");
_Static_assert(CONNECT_TIMEOUT_SECONDS > 0 && CONNECT_TIMEOUT_SECONDS <= INT_MAX / 1000,
               "CONNECT_TIMEOUT_SECONDS is out of range");
_Static_assert(IDLE_TIMEOUT_SECONDS > 0 && IDLE_TIMEOUT_SECONDS <= INT_MAX / 1000,
               "IDLE_TIMEOUT_SECONDS is out of range");

#ifdef _WIN32
typedef WSAPOLLFD pollfd_t;
#else
typedef struct pollfd pollfd_t;
#endif

static atomic_uint active_clients = ATOMIC_VAR_INIT(0);

static int reserve_client(void) {
    unsigned int count = atomic_load_explicit(&active_clients, memory_order_relaxed);
    while (count < MAX_CLIENTS) {
        if (atomic_compare_exchange_weak_explicit(&active_clients, &count, count + 1,
                                                  memory_order_relaxed, memory_order_relaxed))
            return 1;
    }
    return 0;
}

static int poll_sockets(pollfd_t *fds, unsigned int count, int timeout_ms) {
#ifdef _WIN32
    return WSAPoll(fds, (ULONG)count, timeout_ms);
#else
    return poll(fds, (nfds_t)count, timeout_ms);
#endif
}

static uint64_t monotonic_milliseconds(void) {
#ifdef _WIN32
    return (uint64_t)GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0)
        return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
    return (uint64_t)time(NULL) * 1000;
#endif
}

static int socket_error(void) {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}

static int interrupted(int error) {
#ifdef _WIN32
    return error == WSAEINTR;
#else
    return error == EINTR;
#endif
}

static int would_block(int error) {
#ifdef _WIN32
    return error == WSAEWOULDBLOCK;
#else
    return error == EAGAIN || error == EWOULDBLOCK;
#endif
}

/* Errors for a pending client must not stop the listening socket. */
static int accept_retry_delay(int error) {
    if (interrupted(error) || would_block(error)) return 0;
#ifdef _WIN32
    if (error == WSAECONNRESET || error == WSAECONNABORTED) return 0;
    if (error == WSAEMFILE || error == WSAENOBUFS || error == WSAENETDOWN) return 100;
#else
    if (error == ECONNABORTED) return 0;
#ifdef __linux__
    if (error == EPROTO || error == ENOPROTOOPT || error == EHOSTDOWN ||
        error == ENONET || error == EHOSTUNREACH || error == EOPNOTSUPP ||
        error == ENETUNREACH) return 0;
#endif
    if (error == EMFILE || error == ENFILE || error == ENOBUFS ||
        error == ENOMEM || error == ENETDOWN) return 100;
#endif
    return -1;
}

static void retry_pause(int milliseconds) {
    if (!milliseconds) return;
#ifdef _WIN32
    Sleep((DWORD)milliseconds);
#else
    struct timespec delay = {milliseconds / 1000, (milliseconds % 1000) * 1000000L};
    while (nanosleep(&delay, &delay) != 0 && errno == EINTR) {}
#endif
}

static int remaining_milliseconds(uint64_t deadline_ms) {
    uint64_t now = monotonic_milliseconds();
    if (now >= deadline_ms) return 0;
    uint64_t remaining = deadline_ms - now;
    return remaining > INT_MAX ? INT_MAX : (int)remaining;
}

static int set_nonblocking(socket_t fd, int enabled) {
#ifdef _WIN32
    u_long mode = enabled ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL,
                               enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0;
#endif
}

static int wait_for_connect(pollfd_t *fds, unsigned int count, int timeout_ms) {
#ifdef _WIN32
    /* select reports failed connections in the exception set on older Winsock too. */
    fd_set writable, failed;
    FD_ZERO(&writable);
    FD_ZERO(&failed);
    for (unsigned int i = 0; i < count; ++i) {
        FD_SET(fds[i].fd, &writable);
        FD_SET(fds[i].fd, &failed);
        fds[i].revents = 0;
    }
    struct timeval timeout = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int ready = select(0, NULL, &writable, &failed, &timeout);
    if (ready > 0)
        for (unsigned int i = 0; i < count; ++i)
            if (FD_ISSET(fds[i].fd, &writable) || FD_ISSET(fds[i].fd, &failed))
                fds[i].revents = POLLOUT;
    return ready;
#else
    return poll_sockets(fds, count, timeout_ms);
#endif
}

static int wait_for_io(socket_t fd, short events, uint64_t deadline_ms) {
    for (;;) {
        int timeout_ms = remaining_milliseconds(deadline_ms);
        if (!timeout_ms) return 0;
        pollfd_t pending = {fd, events, 0};
        int ready = poll_sockets(&pending, 1, timeout_ms);
        if (ready > 0) return (pending.revents & (events | POLLERR | POLLHUP)) != 0;
        if (ready == 0 || !interrupted(socket_error())) return 0;
    }
}

static int send_all(socket_t fd, const unsigned char *data, size_t length,
                    uint64_t deadline_ms) {
    while (length != 0) {
        if (!remaining_milliseconds(deadline_ms)) return 0;
        int n = send(fd, (const char *)data, (int)length, 0);
        if (n <= 0) {
            if (n < 0) {
                int error = socket_error();
                if (interrupted(error)) continue;
                if (would_block(error) && wait_for_io(fd, POLLOUT, deadline_ms)) continue;
            }
            return 0;
        }
        data += n;
        length -= (size_t)n;
    }
    return 1;
}

static int recv_all(socket_t fd, unsigned char *data, size_t length,
                    uint64_t deadline_ms) {
    while (length != 0) {
        if (!remaining_milliseconds(deadline_ms)) return 0;
        int n = recv(fd, (char *)data, (int)length, 0);
        if (n <= 0) {
            if (n < 0) {
                int error = socket_error();
                if (interrupted(error)) continue;
                if (would_block(error) && wait_for_io(fd, POLLIN, deadline_ms)) continue;
            }
            return 0;
        }
        data += n;
        length -= (size_t)n;
    }
    return 1;
}

static int send_reply(socket_t client, unsigned char status, socket_t outbound) {
    unsigned char reply[4 + 16 + 2] = {5, status, 0, 1};
    size_t length = 10;
    if (status == 0) {
        struct sockaddr_storage local;
        socklen_t local_length = (socklen_t)sizeof(local);
        if (getsockname(outbound, (struct sockaddr *)&local, &local_length) == 0) {
            if (local.ss_family == AF_INET) {
                const struct sockaddr_in *addr = (const struct sockaddr_in *)&local;
                memcpy(reply + 4, &addr->sin_addr, 4);
                memcpy(reply + 8, &addr->sin_port, 2);
            } else if (local.ss_family == AF_INET6) {
                const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)&local;
                reply[3] = 4;
                memcpy(reply + 4, &addr->sin6_addr, 16);
                memcpy(reply + 20, &addr->sin6_port, 2);
                length = 22;
            }
        }
    }
    /* Resolution and connection precede a separate reply deadline. */
    uint64_t deadline_ms = monotonic_milliseconds() + HANDSHAKE_TIMEOUT_SECONDS * 1000;
    return send_all(client, reply, length, deadline_ms);
}

static void normalize_ipv4_mapped(struct sockaddr_storage *address);
static socklen_t address_length(const struct sockaddr_storage *address);
static void set_address_port(struct sockaddr_storage *address, unsigned short port);

static unsigned char connect_error_status(int error) {
#ifdef _WIN32
    if (error == WSAEACCES) return 2;
    if (error == WSAENETUNREACH) return 3;
    if (error == WSAEHOSTUNREACH || error == WSAETIMEDOUT) return 4;
    if (error == WSAECONNREFUSED) return 5;
#else
    if (error == EACCES || error == EPERM) return 2;
    if (error == ENETUNREACH) return 3;
    if (error == EHOSTUNREACH || error == ETIMEDOUT) return 4;
    if (error == ECONNREFUSED) return 5;
#endif
    return 1;
}

/* Scan each family once, retaining the resolver's order within that family. */
static struct addrinfo *next_connect_address(struct addrinfo **cursor, int family) {
    while (*cursor) {
        struct addrinfo *address = *cursor;
        *cursor = address->ai_next;
        if (!address->ai_addr || (size_t)address->ai_addrlen > sizeof(struct sockaddr_storage))
            continue;
        struct sockaddr_storage endpoint = {0};
        memcpy(&endpoint, address->ai_addr, address->ai_addrlen);
        normalize_ipv4_mapped(&endpoint);
        if (endpoint.ss_family == family) return address;
    }
    return NULL;
}

static socket_t connect_target(const char *host, const char *port,
                               const struct sockaddr_storage *numeric,
                               unsigned char *status) {
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo numeric_address = {0};
    struct sockaddr_storage numeric_endpoint;
    socket_t result = INVALID_FD;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICSERV;
    if (numeric) {
        /* The SOCKS request already contains the binary address and port. */
        numeric_endpoint = *numeric;
        numeric_address.ai_addr = (struct sockaddr *)&numeric_endpoint;
        numeric_address.ai_addrlen = address_length(&numeric_endpoint);
        addresses = &numeric_address;
    } else if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        *status = 4; /* Host unreachable. */
        return INVALID_FD;
    }

    *status = 1; /* General failure. */
    /* Stagger candidates within one budget, bounding sockets for small devices. */
    uint64_t deadline_ms = monotonic_milliseconds() + CONNECT_TIMEOUT_SECONDS * 1000;
    uint64_t next_start_ms = monotonic_milliseconds();
    struct addrinfo *cursors[2] = {addresses, addresses};
    int family_index = 0;
    struct addrinfo *first = next_connect_address(&cursors[0], AF_INET);
    struct addrinfo *first_ipv6 = next_connect_address(&cursors[1], AF_INET6);
    /* Keep the first usable resolver result as the preferred family. */
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        if (address == first || address == first_ipv6) {
            family_index = address == first_ipv6;
            break;
        }
    }
    cursors[0] = first;
    cursors[1] = first_ipv6;
    pollfd_t pending[CONNECT_PENDING_LIMIT];
    unsigned int count = 0;
    while (cursors[0] || cursors[1] || count) {
        if (!remaining_milliseconds(deadline_ms)) {
            *status = 4;
            break;
        }
        if (count < CONNECT_PENDING_LIMIT && (cursors[0] || cursors[1]) &&
            (!count || monotonic_milliseconds() >= next_start_ms)) {
            struct addrinfo *address = next_connect_address(&cursors[family_index],
                                                            family_index ? AF_INET6 : AF_INET);
            if (!address) {
                family_index = 1 - family_index;
                address = next_connect_address(&cursors[family_index],
                                                family_index ? AF_INET6 : AF_INET);
            }
            if (!address) continue;
            family_index = 1 - family_index;
            struct sockaddr_storage endpoint = {0};
            memcpy(&endpoint, address->ai_addr, address->ai_addrlen);
            normalize_ipv4_mapped(&endpoint);
            socket_t fd = socket(endpoint.ss_family, SOCK_STREAM, IPPROTO_TCP);
            if (fd == INVALID_FD) {
                *status = connect_error_status(socket_error());
                next_start_ms = monotonic_milliseconds();
                continue;
            }
            if (!set_nonblocking(fd, 1)) {
                *status = connect_error_status(socket_error());
                close_socket(fd);
                next_start_ms = monotonic_milliseconds();
                continue;
            }
            if (connect(fd, (struct sockaddr *)&endpoint, address_length(&endpoint)) == 0) {
                result = fd;
                break;
            }
            int error = socket_error();
#ifdef _WIN32
            int in_progress = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
            int in_progress = error == EINPROGRESS || error == EINTR;
#endif
            if (in_progress) {
                pending[count++] = (pollfd_t){fd, POLLOUT, 0};
                next_start_ms = monotonic_milliseconds() + CONNECT_FALLBACK_DELAY_MS;
            } else {
                *status = connect_error_status(error);
                close_socket(fd);
                next_start_ms = monotonic_milliseconds();
            }
            continue;
        }
        if (!count) continue;
        int timeout_ms = remaining_milliseconds(deadline_ms);
        if (count < CONNECT_PENDING_LIMIT && (cursors[0] || cursors[1])) {
            int delay_ms = remaining_milliseconds(next_start_ms);
            if (delay_ms < timeout_ms) timeout_ms = delay_ms;
        }
        int ready = wait_for_connect(pending, count, timeout_ms);
        if (ready < 0) {
            int error = socket_error();
            if (interrupted(error)) continue;
            *status = connect_error_status(error);
            break;
        }
        for (unsigned int i = 0; i < count && ready > 0;) {
            if (!pending[i].revents) {
                ++i;
                continue;
            }
            int error = 0;
            socklen_t error_length = (socklen_t)sizeof(error);
            if (getsockopt(pending[i].fd, SOL_SOCKET, SO_ERROR, (char *)&error,
                           &error_length) != 0) error = socket_error();
            if (!error && !(pending[i].revents & POLLNVAL)) {
                result = pending[i].fd;
                pending[i] = pending[--count];
                goto connected;
            }
            *status = connect_error_status(error);
            close_socket(pending[i].fd);
            pending[i] = pending[--count];
            next_start_ms = monotonic_milliseconds();
        }
    }
connected:
    for (unsigned int i = 0; i < count; ++i) close_socket(pending[i].fd);
    if (result != INVALID_FD) *status = 0;
    if (!numeric) freeaddrinfo(addresses);
    return result;
}

struct relay_buffer {
    unsigned char data[16384];
    size_t offset, length;
    int read_open, write_shutdown;
};

static void relay(socket_t client, socket_t target) {
    socket_t sockets[2] = {client, target};
    struct relay_buffer buffers[2] = {
        {.read_open = 1}, {.read_open = 1}
    };
    uint64_t deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
    for (;;) {
        pollfd_t fds[2];
        int indices[2] = {-1, -1};
        unsigned int count = 0;
        for (int i = 0; i < 2; ++i) {
            struct relay_buffer *buffer = &buffers[i];
            if (!buffer->read_open && !buffer->length && !buffer->write_shutdown) {
#ifdef _WIN32
                shutdown(sockets[1 - i], SD_SEND);
#else
                shutdown(sockets[1 - i], SHUT_WR);
#endif
                buffer->write_shutdown = 1;
            }
            short events = 0;
            if (buffer->read_open && buffer->length < sizeof(buffer->data)) events |= POLLIN;
            if (buffers[1 - i].length) events |= POLLOUT;
            if (events) {
                indices[i] = (int)count;
                fds[count++] = (pollfd_t){sockets[i], events, 0};
            }
        }
        int timeout_ms = remaining_milliseconds(deadline_ms);
        if (!count || !timeout_ms) return;
        int ready = poll_sockets(fds, count, timeout_ms);
        if (ready < 0 && interrupted(socket_error())) continue;
        if (ready <= 0) return;

        for (int i = 0; i < 2; ++i) {
            if (indices[i] < 0) continue;
            short events = fds[indices[i]].revents;
            if (events & POLLNVAL) return;
            struct relay_buffer *out = &buffers[1 - i];
            if (out->length && (events & (POLLOUT | POLLERR | POLLHUP))) {
                size_t contiguous = sizeof(out->data) - out->offset;
                if (contiguous > out->length) contiguous = out->length;
                int n = send(sockets[i], (const char *)out->data + out->offset,
                             (int)contiguous, 0);
                if (n > 0) {
                    out->offset = (out->offset + (size_t)n) % sizeof(out->data);
                    out->length -= (size_t)n;
                    if (!out->length) out->offset = 0;
                    deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
                } else if (n == 0 || (!interrupted(socket_error()) && !would_block(socket_error()))) {
                    return;
                }
            }
            struct relay_buffer *in = &buffers[i];
            if (in->read_open && in->length < sizeof(in->data) &&
                (events & (POLLIN | POLLERR | POLLHUP))) {
                /* A ring keeps unsent bytes in place under backpressure. */
                size_t tail = (in->offset + in->length) % sizeof(in->data);
                size_t contiguous = sizeof(in->data) - tail;
                if (contiguous > sizeof(in->data) - in->length)
                    contiguous = sizeof(in->data) - in->length;
                int n = recv(sockets[i], (char *)in->data + tail, (int)contiguous, 0);
                if (n > 0) {
                    in->length += (size_t)n;
                    deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
                } else if (n == 0) {
                    in->read_open = 0;
                } else if (!interrupted(socket_error()) && !would_block(socket_error())) {
                    return;
                }
            }
        }
    }
}

static void normalize_ipv4_mapped(struct sockaddr_storage *address) {
    static const unsigned char prefix[12] =
        {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (address->ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        if (memcmp(&ipv6->sin6_addr, prefix, sizeof(prefix)) == 0) {
            struct sockaddr_in ipv4;
            memset(&ipv4, 0, sizeof(ipv4));
            ipv4.sin_family = AF_INET;
            ipv4.sin_port = ipv6->sin6_port;
            memcpy(&ipv4.sin_addr, (const unsigned char *)&ipv6->sin6_addr + 12, 4);
            memset(address, 0, sizeof(*address));
            memcpy(address, &ipv4, sizeof(ipv4));
        }
    }
}

static socklen_t address_length(const struct sockaddr_storage *address) {
    return (socklen_t)(address->ss_family == AF_INET ? sizeof(struct sockaddr_in) :
                       sizeof(struct sockaddr_in6));
}

static int same_ip(const struct sockaddr_storage *a,
                   const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        return ((const struct sockaddr_in *)a)->sin_addr.s_addr ==
               ((const struct sockaddr_in *)b)->sin_addr.s_addr;
    }
    if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *y = (const struct sockaddr_in6 *)b;
        return memcmp(&x->sin6_addr, &y->sin6_addr, 16) == 0 &&
               x->sin6_scope_id == y->sin6_scope_id;
    }
    return 0;
}

static unsigned short address_port(const struct sockaddr_storage *address) {
    if (address->ss_family == AF_INET)
        return ntohs(((const struct sockaddr_in *)address)->sin_port);
    return ntohs(((const struct sockaddr_in6 *)address)->sin6_port);
}

static void set_address_port(struct sockaddr_storage *address, unsigned short port) {
    if (address->ss_family == AF_INET)
        ((struct sockaddr_in *)address)->sin_port = htons(port);
    else
        ((struct sockaddr_in6 *)address)->sin6_port = htons(port);
}

struct udp_destination {
    struct sockaddr_storage address;
    uint64_t expires_at_ms;
};

struct udp_dns_entry {
    char host[256];
    struct sockaddr_storage address;
    uint64_t expires_at_ms;
};

static void remember_udp_destination(struct udp_destination *destinations,
                                     const struct sockaddr *address, socklen_t length) {
    struct sockaddr_storage endpoint;
    memset(&endpoint, 0, sizeof(endpoint));
    if ((size_t)length > sizeof(endpoint)) return;
    memcpy(&endpoint, address, length);
    normalize_ipv4_mapped(&endpoint);

    uint64_t now = monotonic_milliseconds();
    unsigned int slot = 0;
    for (unsigned int i = 0; i < UDP_DESTINATION_LIMIT; ++i) {
        if (destinations[i].expires_at_ms > now &&
            same_ip(&destinations[i].address, &endpoint) &&
            address_port(&destinations[i].address) == address_port(&endpoint)) {
            slot = i;
            break;
        }
        if (destinations[i].expires_at_ms < destinations[slot].expires_at_ms) slot = i;
    }
    destinations[slot].address = endpoint;
    destinations[slot].expires_at_ms = now + UDP_DESTINATION_TTL_SECONDS * 1000;
}

static int known_udp_destination(const struct udp_destination *destinations,
                                 const struct sockaddr_storage *source) {
    uint64_t now = monotonic_milliseconds();
    for (unsigned int i = 0; i < UDP_DESTINATION_LIMIT; ++i) {
        if (destinations[i].expires_at_ms > now &&
            same_ip(&destinations[i].address, source) &&
            address_port(&destinations[i].address) == address_port(source))
            return 1;
    }
    return 0;
}

static int send_udp_request(const unsigned char *payload, size_t length,
                            struct sockaddr_storage *destination,
                            socket_t *ipv4, socket_t *ipv6,
                            struct udp_destination *destinations) {
    /* Winsock IPv6 sockets may reject mapped IPv4 destinations by default. */
    normalize_ipv4_mapped(destination);
    socket_t *outbound = destination->ss_family == AF_INET ? ipv4 : ipv6;
    if (*outbound == INVALID_FD) {
        *outbound = socket(destination->ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (*outbound != INVALID_FD && !set_nonblocking(*outbound, 1)) {
            close_socket(*outbound);
            *outbound = INVALID_FD;
        }
    }
    socklen_t destination_length = address_length(destination);
    if (*outbound == INVALID_FD ||
        sendto(*outbound, (const char *)payload, (int)length, 0,
               (const struct sockaddr *)destination, destination_length) != (int)length)
        return 0;
    remember_udp_destination(destinations, (const struct sockaddr *)destination,
                             destination_length);
    return 1;
}

static int forward_udp_request(const unsigned char *packet, size_t length,
                                socket_t *ipv4, socket_t *ipv6,
                                struct udp_destination *destinations,
                                struct udp_dns_entry *dns_cache) {
    char host[256], port[6];
    struct sockaddr_storage destination;
    memset(&destination, 0, sizeof(destination));
    size_t offset = 4, address_size;
    if (length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0)
        return 0; /* Fragmented UDP datagrams are not supported. */
    if (packet[3] == 1 || packet[3] == 4) {
        int family = packet[3] == 1 ? AF_INET : AF_INET6;
        address_size = family == AF_INET ? 4 : 16;
        if (length < offset + address_size + 2) return 0;
        destination.ss_family = (unsigned short)family;
        if (family == AF_INET)
            memcpy(&((struct sockaddr_in *)&destination)->sin_addr, packet + offset, 4);
        else
            memcpy(&((struct sockaddr_in6 *)&destination)->sin6_addr, packet + offset, 16);
        offset += address_size;
    } else if (packet[3] == 3) {
        if (length < offset + 1 || packet[offset] == 0) return 0;
        address_size = packet[offset++];
        if (length < offset + address_size + 2 ||
            memchr(packet + offset, '\0', address_size) != NULL) return 0;
        memcpy(host, packet + offset, address_size);
        host[address_size] = '\0';
        offset += address_size;
    } else {
        return 0;
    }
    unsigned short target_port = (unsigned short)(packet[offset] << 8 | packet[offset + 1]);
    offset += 2;
    if (packet[3] != 3) {
        /* Numeric addresses already contain everything needed by sendto. */
        set_address_port(&destination, target_port);
        return send_udp_request(packet + offset, length - offset, &destination,
                                ipv4, ipv6, destinations);
    }
    snprintf(port, sizeof(port), "%u", (unsigned)target_port);

    uint64_t now = monotonic_milliseconds();
    unsigned int slot = 0;
    for (unsigned int i = 0; i < UDP_DNS_CACHE_LIMIT; ++i) {
        if (dns_cache[i].expires_at_ms > now && !strcmp(dns_cache[i].host, host)) {
            destination = dns_cache[i].address;
            set_address_port(&destination, target_port);
            if (send_udp_request(packet + offset, length - offset, &destination,
                                 ipv4, ipv6, destinations)) return 1;
            /* Retry resolution and other candidates after a cached send fails. */
            dns_cache[i].expires_at_ms = 0;
        }
        if (dns_cache[i].expires_at_ms < dns_cache[slot].expires_at_ms) slot = i;
    }

    struct addrinfo hints, *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    hints.ai_flags = AI_NUMERICSERV;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) return 0;
    int forwarded = 0;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        if (address->ai_family != AF_INET && address->ai_family != AF_INET6) continue;
        if ((size_t)address->ai_addrlen > sizeof(destination)) continue;
        memset(&destination, 0, sizeof(destination));
        memcpy(&destination, address->ai_addr, address->ai_addrlen);
        if (send_udp_request(packet + offset, length - offset, &destination,
                             ipv4, ipv6, destinations)) {
            strcpy(dns_cache[slot].host, host);
            dns_cache[slot].address = destination;
            dns_cache[slot].expires_at_ms = monotonic_milliseconds() +
                                          UDP_DNS_CACHE_TTL_SECONDS * 1000;
            forwarded = 1;
            break;
        }
    }
    freeaddrinfo(addresses);
    return forwarded;
}

static int forward_udp_reply(socket_t outbound, socket_t association,
                              const struct sockaddr_storage *client_address,
                              unsigned char *packet,
                              const struct udp_destination *destinations) {
    struct sockaddr_storage source;
    socklen_t source_length = (socklen_t)sizeof(source);
    int count = recvfrom(outbound, (char *)packet + 22, UDP_BUFFER_SIZE - 22, 0,
                         (struct sockaddr *)&source, &source_length);
    if (count < 0) return 0;
    normalize_ipv4_mapped(&source);
    if (!known_udp_destination(destinations, &source)) return 0;
    size_t header_length;
    unsigned char *reply;
    if (source.ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)&source;
        header_length = 10;
        reply = packet + 12;
        reply[3] = 1;
        memcpy(reply + 4, &ipv4->sin_addr, 4);
        memcpy(reply + 8, &ipv4->sin_port, 2);
    } else if (source.ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)&source;
        header_length = 22;
        reply = packet;
        reply[3] = 4;
        memcpy(reply + 4, &ipv6->sin6_addr, 16);
        memcpy(reply + 20, &ipv6->sin6_port, 2);
    } else {
        return 0;
    }
    reply[0] = 0;
    reply[1] = 0;
    reply[2] = 0;
    int reply_length = count + (int)header_length;
    return sendto(association, (const char *)reply, reply_length, 0,
                  (const struct sockaddr *)client_address,
                  address_length(client_address)) == reply_length;
}

static void udp_associate(socket_t client, unsigned short requested_port) {
    struct sockaddr_storage local, peer, udp_client;
    struct udp_destination destinations[UDP_DESTINATION_LIMIT] = {{0}};
    struct udp_dns_entry dns_cache[UDP_DNS_CACHE_LIMIT] = {{0}};
    socklen_t length = (socklen_t)sizeof(local);
    socket_t association = INVALID_FD, ipv4 = INVALID_FD, ipv6 = INVALID_FD;
    if (getsockname(client, (struct sockaddr *)&local, &length) != 0) goto failed;
    length = (socklen_t)sizeof(peer);
    if (getpeername(client, (struct sockaddr *)&peer, &length) != 0) goto failed;
    normalize_ipv4_mapped(&local);
    normalize_ipv4_mapped(&peer);
    if (local.ss_family != AF_INET && local.ss_family != AF_INET6) goto failed;
    set_address_port(&local, 0);
    association = socket(local.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    if (association == INVALID_FD ||
        bind(association, (struct sockaddr *)&local, address_length(&local)) != 0 ||
        !set_nonblocking(association, 1))
        goto failed;
    if (!send_reply(client, 0, association)) goto done;

    unsigned char packet[UDP_BUFFER_SIZE];
    int client_known = 0;
    uint64_t deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
    for (;;) {
        pollfd_t readable[4] = {
            {client, POLLIN, 0},
            {association, POLLIN, 0}
        };
        unsigned int count = 2;
        int ipv4_index = -1, ipv6_index = -1;
        if (ipv4 != INVALID_FD) {
            ipv4_index = (int)count;
            readable[count++] = (pollfd_t){ipv4, POLLIN, 0};
        }
        if (ipv6 != INVALID_FD) {
            ipv6_index = (int)count;
            readable[count++] = (pollfd_t){ipv6, POLLIN, 0};
        }
        int timeout_ms = remaining_milliseconds(deadline_ms);
        if (!timeout_ms) break;
        int ready = poll_sockets(readable, count, timeout_ms);
        if (ready < 0) {
            if (interrupted(socket_error())) continue;
            break;
        }
        if (ready == 0) break;
        if (readable[0].revents) {
            /* The TCP control connection defines the association lifetime. */
            int count = recv(client, (char *)packet, sizeof(packet), 0);
            if (count == 0 || (count < 0 && !interrupted(socket_error()) &&
                              !would_block(socket_error()))) break;
        }
        if (readable[1].revents) {
            struct sockaddr_storage source;
            socklen_t source_length = (socklen_t)sizeof(source);
            int count = recvfrom(association, (char *)packet, sizeof(packet), 0,
                                 (struct sockaddr *)&source, &source_length);
            if (count >= 0) {
                normalize_ipv4_mapped(&source);
                if (same_ip(&peer, &source) &&
                    (!requested_port || address_port(&source) == requested_port) &&
                    (!client_known || address_port(&source) == address_port(&udp_client))) {
                    if (forward_udp_request(packet, (size_t)count, &ipv4, &ipv6,
                                            destinations, dns_cache)) {
                        udp_client = source;
                        client_known = 1;
                        deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
                    }
                }
            }
        }
        if (client_known && ipv4_index >= 0 && readable[ipv4_index].revents)
            if (forward_udp_reply(ipv4, association, &udp_client, packet, destinations))
                deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
        if (client_known && ipv6_index >= 0 && readable[ipv6_index].revents)
            if (forward_udp_reply(ipv6, association, &udp_client, packet, destinations))
                deadline_ms = monotonic_milliseconds() + IDLE_TIMEOUT_SECONDS * 1000;
    }
    goto done;
failed:
    send_reply(client, 1, INVALID_FD);
done:
    if (association != INVALID_FD) close_socket(association);
    if (ipv4 != INVALID_FD) close_socket(ipv4);
    if (ipv6 != INVALID_FD) close_socket(ipv6);
}

static void handle_client(socket_t client) {
    unsigned char header[4], methods[255], port_bytes[2];
    char host[256], port[6];
    struct sockaddr_storage address;
    memset(&address, 0, sizeof(address));
    socket_t target = INVALID_FD;
    uint64_t deadline_ms = monotonic_milliseconds() + HANDSHAKE_TIMEOUT_SECONDS * 1000;
    if (!set_nonblocking(client, 1)) goto done;

    if (!recv_all(client, header, 2, deadline_ms) || header[0] != 5 || header[1] == 0) goto done;
    if (!recv_all(client, methods, header[1], deadline_ms)) goto done;
    int no_auth = 0;
    for (unsigned int i = 0; i < header[1]; ++i) {
        if (methods[i] == 0) no_auth = 1;
    }
    unsigned char selection[2] = {5, no_auth ? 0 : 255};
    if (!send_all(client, selection, sizeof(selection), deadline_ms) || !no_auth) goto done;

    if (!recv_all(client, header, 4, deadline_ms) || header[0] != 5 || header[2] != 0) goto done;
    if (header[1] != 1 && header[1] != 3) {
        send_reply(client, 7, INVALID_FD); /* Command not supported. */
        goto done;
    }
    if (header[3] == 1 || header[3] == 4) {
        int family = header[3] == 1 ? AF_INET : AF_INET6;
        address.ss_family = (unsigned short)family;
        size_t length = family == AF_INET ? 4 : 16;
        unsigned char *bytes = family == AF_INET ?
            (unsigned char *)&((struct sockaddr_in *)&address)->sin_addr :
            (unsigned char *)&((struct sockaddr_in6 *)&address)->sin6_addr;
        if (!recv_all(client, bytes, length, deadline_ms)) goto done;
    } else if (header[3] == 3) {
        unsigned char length;
        if (!recv_all(client, &length, 1, deadline_ms) || length == 0) goto done;
        if (!recv_all(client, (unsigned char *)host, length, deadline_ms)) goto done;
        if (memchr(host, '\0', length) != NULL) goto done;
        host[length] = '\0';
    } else {
        send_reply(client, 8, INVALID_FD); /* Address type not supported. */
        goto done;
    }
    if (!recv_all(client, port_bytes, 2, deadline_ms)) goto done;
    unsigned short target_port = (unsigned short)(port_bytes[0] << 8 | port_bytes[1]);

    if (header[1] == 3) {
        udp_associate(client, target_port);
        goto done;
    }

    unsigned char status;
    if (header[3] == 3) {
        snprintf(port, sizeof(port), "%u", (unsigned)target_port);
        target = connect_target(host, port, NULL, &status);
    } else {
        set_address_port(&address, target_port);
        target = connect_target(NULL, NULL, &address, &status);
    }
    if (!send_reply(client, status, target)) goto done;
    if (target == INVALID_FD) goto done;
    relay(client, target);

done:
    if (target != INVALID_FD) close_socket(target);
    close_socket(client);
}

#ifdef _WIN32
static DWORD WINAPI client_thread(LPVOID argument) {
    socket_t client = *(socket_t *)argument;
    free(argument);
    handle_client(client);
    atomic_fetch_sub_explicit(&active_clients, 1, memory_order_relaxed);
    return 0;
}
#else
static void *client_thread(void *argument) {
    socket_t client = *(socket_t *)argument;
    free(argument);
    handle_client(client);
    atomic_fetch_sub_explicit(&active_clients, 1, memory_order_relaxed);
    return NULL;
}
#endif

static int valid_listen_port(const char *text) {
    if (!*text) return 0;
    unsigned int value = 0;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return 0;
        value = value * 10 + (unsigned int)(*text - '0');
        if (value > 65535) return 0;
    }
    return 1;
}

static void print_usage(FILE *stream, const char *program) {
    fprintf(stream, "Usage: %s [listen-address [port]]\n"
                    "Default: 0.0.0.0:1080; port 0 selects an available port.\n", program);
}

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "0.0.0.0";
    const char *port = argc > 2 ? argv[2] : "1080";
    if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
        print_usage(stdout, argv[0]);
        return 0;
    }
    if (argc > 3) {
        print_usage(stderr, argv[0]);
        return 1;
    }
    if (!valid_listen_port(port)) {
        fprintf(stderr, "Invalid port: expected a decimal number from 0 to 65535\n");
        return 1;
    }
    if (!*host) {
        fprintf(stderr, "Invalid listen address\n");
        return 1;
    }
#ifdef _WIN32
    WSADATA winsock;
    if (WSAStartup(MAKEWORD(2, 2), &winsock) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_t listener = INVALID_FD;
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        fprintf(stderr, "Invalid listen address or port\n");
        goto done;
    }
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        socket_t fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd == INVALID_FD) continue;
#ifndef _WIN32
        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#endif
        if (bind(fd, address->ai_addr, (socklen_t)address->ai_addrlen) == 0 &&
            listen(fd, SOMAXCONN) == 0) {
            listener = fd;
            break;
        }
        close_socket(fd);
    }
    freeaddrinfo(addresses);
    if (listener == INVALID_FD) {
        fprintf(stderr, "Could not listen on %s:%s\n", host, port);
        goto done;
    }
    struct sockaddr_storage bound;
    socklen_t bound_length = (socklen_t)sizeof(bound);
    char bound_host[256], bound_port[6];
    if (getsockname(listener, (struct sockaddr *)&bound, &bound_length) != 0 ||
        getnameinfo((struct sockaddr *)&bound, bound_length,
                    bound_host, sizeof(bound_host), bound_port, sizeof(bound_port),
                    NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        fprintf(stderr, "Could not determine listen endpoint\n");
        goto done;
    }
    int ipv6 = bound.ss_family == AF_INET6;
    fprintf(stderr, "SOCKS5 listening on %s%s%s:%s\n",
            ipv6 ? "[" : "", bound_host, ipv6 ? "]" : "", bound_port);

    for (;;) {
        socket_t client = accept(listener, NULL, NULL);
        if (client == INVALID_FD) {
            int error = socket_error();
            int delay = accept_retry_delay(error);
            if (delay >= 0) {
                retry_pause(delay);
                continue;
            }
            fprintf(stderr, "accept failed: %d\n", error);
            break;
        }
        if (!reserve_client()) {
            close_socket(client);
            continue;
        }
        socket_t *argument = malloc(sizeof(*argument));
        if (!argument) {
            close_socket(client);
            atomic_fetch_sub_explicit(&active_clients, 1, memory_order_relaxed);
            continue;
        }
        *argument = client;
#ifdef _WIN32
        HANDLE thread = CreateThread(NULL, 0, client_thread, argument, 0, NULL);
        if (thread) CloseHandle(thread);
        else {
            free(argument);
            close_socket(client);
            atomic_fetch_sub_explicit(&active_clients, 1, memory_order_relaxed);
        }
#else
        pthread_t thread;
        if (pthread_create(&thread, NULL, client_thread, argument) == 0) {
            pthread_detach(thread);
        } else {
            free(argument);
            close_socket(client);
            atomic_fetch_sub_explicit(&active_clients, 1, memory_order_relaxed);
        }
#endif
    }
done:
    if (listener != INVALID_FD) close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
}
