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
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>

#ifndef HANDSHAKE_TIMEOUT_SECONDS
#define HANDSHAKE_TIMEOUT_SECONDS 15
#endif
#define CONNECT_TIMEOUT_SECONDS 10
#define UDP_BUFFER_SIZE 65536
#define UDP_DESTINATION_LIMIT 64
#define UDP_DESTINATION_TTL_SECONDS 60

#ifndef MAX_CLIENTS
#define MAX_CLIENTS 64
#endif
#ifndef IDLE_TIMEOUT_SECONDS
#define IDLE_TIMEOUT_SECONDS 300
#endif

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

static int set_nonblocking(socket_t fd, int enabled) {
#ifdef _WIN32
    u_long mode = enabled ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    /* Only used while establishing a new outbound connection. */
    int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL,
                               enabled ? flags | O_NONBLOCK : flags & ~O_NONBLOCK) == 0;
#endif
}

static int send_all(socket_t fd, const unsigned char *data, size_t length) {
    while (length != 0) {
        int n = send(fd, (const char *)data, (int)length, 0);
        if (n <= 0) {
            if (n < 0 && interrupted(socket_error())) continue;
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
        uint64_t now = monotonic_milliseconds();
        if (now >= deadline_ms) return 0;
        pollfd_t readable = {fd, POLLIN, 0};
        int ready = poll_sockets(&readable, 1, (int)(deadline_ms - now));
        if (ready == 0) return 0;
        if (ready < 0) {
            if (interrupted(socket_error())) continue;
            return 0;
        }
        int n = recv(fd, (char *)data, (int)length, 0);
        if (n <= 0) {
            if (n < 0 && interrupted(socket_error())) continue;
            return 0;
        }
        data += n;
        length -= (size_t)n;
    }
    return 1;
}

static void set_socket_timeout(socket_t fd, int seconds) {
#ifdef _WIN32
    DWORD ms = (DWORD)seconds * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&ms, sizeof(ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
#else
    struct timeval timeout = {seconds, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
#endif
}

static void send_reply(socket_t client, unsigned char status, socket_t outbound) {
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
    (void)send_all(client, reply, length);
}

static socket_t connect_target(const char *host, const char *port, unsigned char *status) {
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    socket_t result = INVALID_FD;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        *status = 4; /* Host unreachable. */
        return INVALID_FD;
    }

    *status = 1; /* General failure. */
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        socket_t fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd == INVALID_FD) continue;
        if (!set_nonblocking(fd, 1)) {
            close_socket(fd);
            continue;
        }

        int connected = connect(fd, address->ai_addr, (socklen_t)address->ai_addrlen) == 0;
        if (!connected) {
            int error = socket_error();
#ifdef _WIN32
            int pending = error == WSAEWOULDBLOCK || error == WSAEINPROGRESS;
#else
            int pending = error == EINPROGRESS;
#endif
            if (pending) {
                pollfd_t writable = {fd, POLLOUT, 0};
                int ready = poll_sockets(&writable, 1, CONNECT_TIMEOUT_SECONDS * 1000);
                if (ready > 0) {
                    int so_error = 0;
                    socklen_t error_length = (socklen_t)sizeof(so_error);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, (char *)&so_error,
                                   &error_length) == 0) {
                        error = so_error;
                        connected = error == 0;
                    }
                }
            }
            if (!connected) {
#ifdef _WIN32
                if (error == WSAECONNREFUSED) *status = 5;
                else if (error == WSAENETUNREACH) *status = 3;
                else if (error == WSAEHOSTUNREACH) *status = 4;
#else
                if (error == ECONNREFUSED) *status = 5;
                else if (error == ENETUNREACH) *status = 3;
                else if (error == EHOSTUNREACH) *status = 4;
#endif
            }
        }
        if (connected && set_nonblocking(fd, 0)) {
            result = fd;
            *status = 0;
            break;
        }
        close_socket(fd);
    }
    freeaddrinfo(addresses);
    return result;
}

static void relay(socket_t client, socket_t target) {
    unsigned char buffer[16384];
    int client_open = 1, target_open = 1;
    while (client_open || target_open) {
        pollfd_t readable[2];
        unsigned int count = 0;
        int client_index = -1, target_index = -1;
        if (client_open) {
            client_index = (int)count;
            readable[count++] = (pollfd_t){client, POLLIN, 0};
        }
        if (target_open) {
            target_index = (int)count;
            readable[count++] = (pollfd_t){target, POLLIN, 0};
        }
        int ready = poll_sockets(readable, count, IDLE_TIMEOUT_SECONDS * 1000);
        if (ready < 0) {
            if (interrupted(socket_error())) continue;
            break;
        }
        if (ready == 0) break;
        if (client_open && readable[client_index].revents) {
            int n = recv(client, (char *)buffer, sizeof(buffer), 0);
            if (n > 0) {
                if (!send_all(target, buffer, (size_t)n)) break;
            } else if (n < 0 && interrupted(socket_error())) {
                continue;
            } else {
                client_open = 0;
#ifdef _WIN32
                shutdown(target, SD_SEND);
#else
                shutdown(target, SHUT_WR);
#endif
            }
        }
        if (target_open && readable[target_index].revents) {
            int n = recv(target, (char *)buffer, sizeof(buffer), 0);
            if (n > 0) {
                if (!send_all(client, buffer, (size_t)n)) break;
            } else if (n < 0 && interrupted(socket_error())) {
                continue;
            } else {
                target_open = 0;
#ifdef _WIN32
                shutdown(client, SD_SEND);
#else
                shutdown(client, SHUT_WR);
#endif
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

static void forward_udp_request(const unsigned char *packet, size_t length,
                                socket_t *ipv4, socket_t *ipv6,
                                struct udp_destination *destinations) {
    char host[256], port[6];
    size_t offset = 4, address_size;
    int family;
    if (length < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0)
        return; /* Fragmented UDP datagrams are not supported. */
    if (packet[3] == 1 || packet[3] == 4) {
        family = packet[3] == 1 ? AF_INET : AF_INET6;
        address_size = family == AF_INET ? 4 : 16;
        if (length < offset + address_size + 2 ||
            !inet_ntop(family, packet + offset, host, sizeof(host))) return;
        offset += address_size;
    } else if (packet[3] == 3) {
        if (length < offset + 1 || packet[offset] == 0) return;
        address_size = packet[offset++];
        if (length < offset + address_size + 2 ||
            memchr(packet + offset, '\0', address_size) != NULL) return;
        memcpy(host, packet + offset, address_size);
        host[address_size] = '\0';
        offset += address_size;
        family = AF_UNSPEC;
    } else {
        return;
    }
    snprintf(port, sizeof(port), "%u", (unsigned)(packet[offset] << 8 | packet[offset + 1]));
    offset += 2;

    struct addrinfo hints, *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) return;
    for (struct addrinfo *address = addresses; address; address = address->ai_next) {
        socket_t *outbound = address->ai_family == AF_INET ? ipv4 : ipv6;
        if (address->ai_family != AF_INET && address->ai_family != AF_INET6) continue;
        if (*outbound == INVALID_FD) {
            *outbound = socket(address->ai_family, SOCK_DGRAM, IPPROTO_UDP);
            if (*outbound != INVALID_FD)
                set_socket_timeout(*outbound, IDLE_TIMEOUT_SECONDS);
        }
        if (*outbound != INVALID_FD &&
            sendto(*outbound, (const char *)packet + offset, (int)(length - offset), 0,
                   address->ai_addr, (socklen_t)address->ai_addrlen) >= 0) {
            remember_udp_destination(destinations, address->ai_addr,
                                     (socklen_t)address->ai_addrlen);
            break;
        }
    }
    freeaddrinfo(addresses);
}

static void forward_udp_reply(socket_t outbound, socket_t association,
                              const struct sockaddr_storage *client_address,
                              unsigned char *packet,
                              const struct udp_destination *destinations) {
    struct sockaddr_storage source;
    socklen_t source_length = (socklen_t)sizeof(source);
    int count = recvfrom(outbound, (char *)packet + 22, UDP_BUFFER_SIZE - 22, 0,
                         (struct sockaddr *)&source, &source_length);
    if (count < 0) return;
    normalize_ipv4_mapped(&source);
    if (!known_udp_destination(destinations, &source)) return;
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
        return;
    }
    reply[0] = 0;
    reply[1] = 0;
    reply[2] = 0;
    (void)sendto(association, (const char *)reply, count + (int)header_length, 0,
                 (const struct sockaddr *)client_address, address_length(client_address));
}

static void udp_associate(socket_t client, unsigned short requested_port) {
    struct sockaddr_storage local, peer, udp_client;
    struct udp_destination destinations[UDP_DESTINATION_LIMIT] = {{0}};
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
        bind(association, (struct sockaddr *)&local, address_length(&local)) != 0)
        goto failed;
    send_reply(client, 0, association);
    set_socket_timeout(client, IDLE_TIMEOUT_SECONDS);
    set_socket_timeout(association, IDLE_TIMEOUT_SECONDS);

    unsigned char packet[UDP_BUFFER_SIZE];
    int client_known = 0;
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
        int ready = poll_sockets(readable, count, IDLE_TIMEOUT_SECONDS * 1000);
        if (ready < 0) {
            if (interrupted(socket_error())) continue;
            break;
        }
        if (ready == 0) break;
        if (readable[0].revents) {
            /* The TCP control connection defines the association lifetime. */
            int count = recv(client, (char *)packet, sizeof(packet), 0);
            if (count <= 0 && !(count < 0 && interrupted(socket_error()))) break;
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
                    udp_client = source;
                    client_known = 1;
                    forward_udp_request(packet, (size_t)count, &ipv4, &ipv6,
                                        destinations);
                }
            }
        }
        if (client_known && ipv4_index >= 0 && readable[ipv4_index].revents)
            forward_udp_reply(ipv4, association, &udp_client, packet, destinations);
        if (client_known && ipv6_index >= 0 && readable[ipv6_index].revents)
            forward_udp_reply(ipv6, association, &udp_client, packet, destinations);
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
    unsigned char header[4], methods[255], address[16], port_bytes[2];
    char host[256], port[6];
    socket_t target = INVALID_FD;
    uint64_t deadline_ms = monotonic_milliseconds() + HANDSHAKE_TIMEOUT_SECONDS * 1000;
    set_socket_timeout(client, HANDSHAKE_TIMEOUT_SECONDS);

    if (!recv_all(client, header, 2, deadline_ms) || header[0] != 5 || header[1] == 0) goto done;
    if (!recv_all(client, methods, header[1], deadline_ms)) goto done;
    int no_auth = 0;
    for (unsigned int i = 0; i < header[1]; ++i) {
        if (methods[i] == 0) no_auth = 1;
    }
    unsigned char selection[2] = {5, no_auth ? 0 : 255};
    if (!send_all(client, selection, sizeof(selection)) || !no_auth) goto done;

    if (!recv_all(client, header, 4, deadline_ms) || header[0] != 5 || header[2] != 0) goto done;
    if (header[1] != 1 && header[1] != 3) {
        send_reply(client, 7, INVALID_FD); /* Command not supported. */
        goto done;
    }
    if (header[3] == 1 || header[3] == 4) {
        int family = header[3] == 1 ? AF_INET : AF_INET6;
        size_t length = family == AF_INET ? 4 : 16;
        if (!recv_all(client, address, length, deadline_ms)) goto done;
        if (!inet_ntop(family, address, host, sizeof(host))) goto done;
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
    snprintf(port, sizeof(port), "%u", (unsigned)(port_bytes[0] << 8 | port_bytes[1]));

    if (header[1] == 3) {
        udp_associate(client, (unsigned short)(port_bytes[0] << 8 | port_bytes[1]));
        goto done;
    }

    unsigned char status;
    target = connect_target(host, port, &status);
    send_reply(client, status, target);
    if (target == INVALID_FD) goto done;
    set_socket_timeout(client, IDLE_TIMEOUT_SECONDS);
    set_socket_timeout(target, IDLE_TIMEOUT_SECONDS);
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

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "0.0.0.0";
    const char *port = argc > 2 ? argv[2] : "1080";
    if (argc > 3) {
        fprintf(stderr, "Usage: %s [listen-address [port]]\n", argv[0]);
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

    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    if (getaddrinfo(host, port, &hints, &addresses) != 0) {
        fprintf(stderr, "Invalid listen address or port\n");
        return 1;
    }
    socket_t listener = INVALID_FD;
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
        return 1;
    }
    fprintf(stderr, "SOCKS5 listening on %s:%s\n", host, port);

    for (;;) {
        socket_t client = accept(listener, NULL, NULL);
        if (client == INVALID_FD) {
            if (interrupted(socket_error())) continue;
            fprintf(stderr, "accept failed: %d\n", socket_error());
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
    close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
    return 1;
}
