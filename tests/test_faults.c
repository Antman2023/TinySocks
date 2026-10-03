/* Deterministic resolver, connection and accept failures without external services. */
#define _POSIX_C_SOURCE 200112L
#define CONNECT_TIMEOUT_SECONDS 1
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
/* Zig's optimized builds define NDEBUG; checks must still execute. */
#undef NDEBUG
#include <assert.h>

static int injected_getaddrinfo(const char *, const char *, const struct addrinfo *,
                                struct addrinfo **);
static void injected_freeaddrinfo(struct addrinfo *);
#ifdef _WIN32
static SOCKET injected_accept(SOCKET, struct sockaddr *, int *);
static int injected_connect(SOCKET, const struct sockaddr *, int);
static int injected_close(SOCKET);
static int injected_getsockopt(SOCKET, int, int, char *, int *);
static int injected_select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
#else
static int injected_accept(int, struct sockaddr *, socklen_t *);
static int injected_connect(int, const struct sockaddr *, socklen_t);
static int injected_close(int);
static int injected_getsockopt(int, int, int, void *, socklen_t *);
static int injected_poll(struct pollfd *, nfds_t, int);
#endif

#define getaddrinfo injected_getaddrinfo
#define freeaddrinfo injected_freeaddrinfo
#define accept injected_accept
#define connect injected_connect
#define getsockopt injected_getsockopt
#ifdef _WIN32
#define closesocket injected_close
#define select injected_select
#else
#define close injected_close
#define poll injected_poll
#endif
#define main tinysocks_main
#include "../tinysocks.c"
#undef main
#undef accept
#undef getaddrinfo
#undef freeaddrinfo
#undef connect
#undef getsockopt
#ifdef _WIN32
#undef closesocket
#undef select
#else
#undef close
#undef poll
#endif

static int fake_dns;
static unsigned int resolutions;
#define TEST_LOOPBACK_IP UINT32_C(0x7f000001)
/* 1: slow IPv6; 2: all slow; 3: asynchronous refusal; 4: access denied. */
static int fake_connect;
static struct addrinfo connect_addresses[3];
static struct sockaddr_storage connect_endpoints[3];
static socket_t slow_sockets[CONNECT_PENDING_LIMIT];
static unsigned int slow_count, slow_closed, connect_calls, connect_waits;
static int connect_families[CONNECT_PENDING_LIMIT];

static void set_test_error(int error) {
#ifdef _WIN32
    WSASetLastError(error);
#else
    errno = error;
#endif
}

static int slow_socket(socket_t fd) {
    for (unsigned int i = 0; i < slow_count; ++i)
        if (slow_sockets[i] == fd) return 1;
    return 0;
}

static void injected_freeaddrinfo(struct addrinfo *addresses) {
    if (addresses != connect_addresses) freeaddrinfo(addresses);
}

static int injected_getaddrinfo(const char *host, const char *port,
                                const struct addrinfo *hints, struct addrinfo **result) {
    if (fake_connect && !strcmp(host, "fallback.test")) {
        *result = connect_addresses;
        return 0;
    }
    if (!fake_dns) return getaddrinfo(host, port, hints, result);
    ++resolutions;
    if (!strcmp(host, "missing.test")) return EAI_NONAME;
    return getaddrinfo(!strcmp(host, "broadcast.test") ? "255.255.255.255" : "127.0.0.1",
                       port, hints, result);
}

#ifdef _WIN32
static int injected_connect(SOCKET fd, const struct sockaddr *address, int length) {
#else
static int injected_connect(int fd, const struct sockaddr *address, socklen_t length) {
#endif
    if (!fake_connect) return connect(fd, address, length);
    assert(connect_calls < CONNECT_PENDING_LIMIT);
    connect_families[connect_calls++] = address->sa_family;
    if (fake_connect == 4) {
#ifdef _WIN32
        set_test_error(WSAEACCES);
#else
        set_test_error(EACCES);
#endif
        return -1;
    }
    if (fake_connect != 1 || address->sa_family == AF_INET6 ||
        ((const struct sockaddr_in *)address)->sin_addr.s_addr != htonl(TEST_LOOPBACK_IP)) {
        slow_sockets[slow_count++] = fd;
#ifdef _WIN32
        set_test_error(WSAEWOULDBLOCK);
#else
        set_test_error(EINPROGRESS);
#endif
        return -1;
    }
    return connect(fd, address, length);
}

#ifdef _WIN32
static int injected_close(SOCKET fd) {
#else
static int injected_close(int fd) {
#endif
    if (fake_connect && slow_socket(fd)) {
        ++slow_closed;
        for (unsigned int i = 0; i < slow_count; ++i)
            if (slow_sockets[i] == fd) slow_sockets[i] = INVALID_FD;
    }
    return close_socket(fd);
}

#ifdef _WIN32
static int injected_getsockopt(SOCKET fd, int level, int option, char *value, int *length) {
#else
static int injected_getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
#endif
    if (fake_connect == 3 && slow_socket(fd) && level == SOL_SOCKET && option == SO_ERROR) {
#ifdef _WIN32
        *(int *)value = WSAECONNREFUSED;
#else
        *(int *)value = ECONNREFUSED;
#endif
        *length = sizeof(int);
        return 0;
    }
    return getsockopt(fd, level, option, value, length);
}

#ifdef _WIN32
static int injected_select(int ignored, fd_set *readable, fd_set *writable,
                            fd_set *failed, const struct timeval *timeout) {
    if (!fake_connect) return select(ignored, readable, writable, failed, timeout);
    ++connect_waits;
    if (fake_connect == 3) {
        FD_ZERO(failed);
        return (int)writable->fd_count;
    }
    for (unsigned int i = 0; i < slow_count; ++i) {
        FD_CLR(slow_sockets[i], writable);
        FD_CLR(slow_sockets[i], failed);
    }
    if (writable->fd_count || failed->fd_count)
        return select(ignored, readable, writable, failed, timeout);
    retry_pause((int)(timeout->tv_sec * 1000 + timeout->tv_usec / 1000));
    return 0;
}
#else
static int injected_poll(struct pollfd *fds, nfds_t count, int timeout) {
    if (!fake_connect) return poll(fds, count, timeout);
    ++connect_waits;
    if (fake_connect == 3) {
        for (nfds_t i = 0; i < count; ++i) fds[i].revents = POLLOUT;
        return (int)count;
    }
    struct pollfd visible[CONNECT_PENDING_LIMIT];
    assert(count <= CONNECT_PENDING_LIMIT);
    for (nfds_t i = 0; i < count; ++i) {
        visible[i] = fds[i];
        if (slow_socket(visible[i].fd)) visible[i].fd = -1;
    }
    int ready = poll(visible, count, timeout);
    for (nfds_t i = 0; i < count; ++i) fds[i].revents = visible[i].revents;
    return ready;
}
#endif

/* Exercise the real accept loop, including its resource-pressure pause. */
#ifdef _WIN32
static SOCKET injected_accept(SOCKET listener, struct sockaddr *address, int *length) {
    static const int errors[] = {WSAECONNABORTED, WSAECONNRESET, WSAENOBUFS};
#else
static int injected_accept(int listener, struct sockaddr *address, socklen_t *length) {
    static const int errors[] = {ECONNABORTED, ENOBUFS, EMFILE,
#ifdef __linux__
                                 EPROTO, EHOSTUNREACH,
#endif
    };
#endif
    static unsigned int calls;
    if (calls < sizeof(errors) / sizeof(errors[0])) {
        int error = errors[calls++];
#ifdef _WIN32
        WSASetLastError(error);
#else
        errno = error;
#endif
        return INVALID_FD;
    }
    return accept(listener, address, length);
}

static int domain_request(const char *host, unsigned short port, socket_t *ipv4,
                           socket_t *ipv6, struct udp_destination *destinations,
                           struct udp_dns_entry *cache) {
    unsigned char packet[262] = {0, 0, 0, 3};
    size_t length = strlen(host);
    assert(length > 0 && length <= 255);
    packet[4] = (unsigned char)length;
    memcpy(packet + 5, host, length);
    packet[5 + length] = (unsigned char)(port >> 8);
    packet[6 + length] = (unsigned char)port;
    return forward_udp_request(packet, length + 7, ipv4, ipv6, destinations, cache);
}

static struct udp_dns_entry *cached_entry(struct udp_dns_entry *cache, const char *host) {
    for (unsigned int i = 0; i < UDP_DNS_CACHE_LIMIT; ++i)
        if (cache[i].expires_at_ms > monotonic_milliseconds() &&
            !strcmp(cache[i].host, host)) return &cache[i];
    assert(0 && "expected a live cache entry");
    return NULL;
}

static void test_dns_cache(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    socket_t target = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(target != INVALID_FD);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    assert(inet_pton(AF_INET, "127.0.0.1", &local.sin_addr) == 1);
    assert(bind(target, (struct sockaddr *)&local, sizeof(local)) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(target, (struct sockaddr *)&local, &length) == 0);
    unsigned short port = ntohs(local.sin_port);
    socket_t second = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(second != INVALID_FD);
    struct sockaddr_in other = local;
    other.sin_port = 0;
    assert(bind(second, (struct sockaddr *)&other, sizeof(other)) == 0);
    assert(getsockname(second, (struct sockaddr *)&other, &length) == 0);
    unsigned short other_port = ntohs(other.sin_port);
    socket_t ipv4 = INVALID_FD, ipv6 = INVALID_FD;
    struct udp_destination destinations[UDP_DESTINATION_LIMIT] = {{0}};
    struct udp_dns_entry cache[UDP_DNS_CACHE_LIMIT] = {{0}};
    fake_dns = 1;

    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    uint64_t expiry = cached_entry(cache, "cached.test")->expires_at_ms;
    for (int i = 1; i < 100; ++i)
        assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 1);
    assert(cached_entry(cache, "cached.test")->expires_at_ms == expiry);
    /* Ports are applied to cached IPs, not retained from the first request. */
    assert(domain_request("cached.test", other_port,
                          &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 1);
    assert(address_port(&cache[0].address) == port);
    assert(address_port(&destinations[1].address) == other_port);

    /* Expiry is absolute: repeated packets do not extend cached DNS lifetime. */
    cached_entry(cache, "cached.test")->expires_at_ms = monotonic_milliseconds() - 1;
    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 2);

    /* A failed cached send re-resolves instead of pinning an unusable IP. */
    ((struct sockaddr_in *)&cached_entry(cache, "cached.test")->address)->sin_addr.s_addr =
        htonl(INADDR_BROADCAST);
    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 3);
    assert(((struct sockaddr_in *)&cached_entry(cache, "cached.test")->address)->sin_addr.s_addr ==
           local.sin_addr.s_addr);

    for (int i = 0; i < 2; ++i)
        assert(!domain_request("missing.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 5); /* Failed lookups are not cached. */
    for (int i = 0; i < 2; ++i)
        assert(!domain_request("broadcast.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 7); /* Failed sends are not cached either. */

    cached_entry(cache, "cached.test")->expires_at_ms = monotonic_milliseconds() + 9000;
    for (unsigned int i = 0; i < UDP_DNS_CACHE_LIMIT; ++i) {
        char host[32];
        snprintf(host, sizeof(host), "host-%u.test", i);
        assert(domain_request(host, port, &ipv4, &ipv6, destinations, cache));
        /* Make replacement order independent of timer resolution. */
        for (unsigned int j = 0; j < UDP_DNS_CACHE_LIMIT; ++j)
            if (!strcmp(cache[j].host, host))
                cache[j].expires_at_ms = monotonic_milliseconds() + 10000 + i;
    }
    unsigned int before = resolutions;
    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == before + 1); /* The bounded cache evicted this host. */

    close_socket(target);
    close_socket(second);
    close_socket(ipv4);
    if (ipv6 != INVALID_FD) close_socket(ipv6);
#ifdef _WIN32
    WSACleanup();
#endif
}

static void reset_connect_test(int mode) {
    fake_connect = mode;
    slow_count = slow_closed = connect_calls = connect_waits = 0;
}

static void test_connection_fallback(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    socket_t listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(listener != INVALID_FD);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(TEST_LOOPBACK_IP);
    assert(bind(listener, (struct sockaddr *)&local, sizeof(local)) == 0);
    assert(listen(listener, 8) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(listener, (struct sockaddr *)&local, &length) == 0);
    socket_t ipv6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    int have_ipv6 = ipv6 != INVALID_FD;
    if (have_ipv6) close_socket(ipv6);
    memset(connect_addresses, 0, sizeof(connect_addresses));
    memset(connect_endpoints, 0, sizeof(connect_endpoints));
    for (unsigned int i = 0; i < 3; ++i) {
        if (i < 2 && have_ipv6) {
            struct sockaddr_in6 *endpoint = (struct sockaddr_in6 *)&connect_endpoints[i];
            endpoint->sin6_family = AF_INET6;
            assert(inet_pton(AF_INET6, "::1", &endpoint->sin6_addr) == 1);
            endpoint->sin6_port = local.sin_port;
        } else {
            memcpy(&connect_endpoints[i], &local, sizeof(local));
            if (i < 2)
                ((struct sockaddr_in *)&connect_endpoints[i])->sin_addr.s_addr =
                    htonl(TEST_LOOPBACK_IP + i + 1);
        }
        connect_addresses[i].ai_family = connect_endpoints[i].ss_family;
        connect_addresses[i].ai_addr = (struct sockaddr *)&connect_endpoints[i];
        connect_addresses[i].ai_addrlen = address_length(&connect_endpoints[i]);
        if (i < 2) connect_addresses[i].ai_next = &connect_addresses[i + 1];
    }
    char port[6];
    snprintf(port, sizeof(port), "%u", (unsigned int)ntohs(local.sin_port));
    unsigned char status;
    reset_connect_test(1);
    uint64_t start = monotonic_milliseconds();
    socket_t target = connect_target("fallback.test", port, NULL, &status);
    uint64_t elapsed = monotonic_milliseconds() - start;
    assert(target != INVALID_FD && status == 0);
    assert(elapsed >= 200 && elapsed < CONNECT_TIMEOUT_SECONDS * 1000);
    assert(connect_calls == (have_ipv6 ? 2u : 3u));
    assert(connect_families[0] == (have_ipv6 ? AF_INET6 : AF_INET));
    assert(connect_families[have_ipv6 ? 1 : 2] == AF_INET);
    assert(slow_closed == slow_count && slow_count > 0);
    /* The returned socket must actually carry data, not just have SO_ERROR == 0. */
    socket_t accepted = accept(listener, NULL, NULL);
    assert(accepted != INVALID_FD);
    assert(set_nonblocking(accepted, 1));
    assert(send(target, "ok", 2, 0) == 2);
    unsigned char payload[2];
    assert(recv_all(accepted, payload, 2, monotonic_milliseconds() + 1000));
    assert(memcmp(payload, "ok", 2) == 0);
    close_socket(accepted);
    close_socket(target);

    reset_connect_test(2);
    start = monotonic_milliseconds();
    assert(connect_target("fallback.test", port, NULL, &status) == INVALID_FD);
    elapsed = monotonic_milliseconds() - start;
    assert(status == 4 && connect_calls == 3);
    assert(elapsed >= 900 && elapsed < 2000); /* One budget, not one per address. */
    assert(slow_closed == slow_count && slow_count == 3);
    assert(connect_waits < 20); /* Sleeping candidates must not cause a busy loop. */

    reset_connect_test(3);
    assert(connect_target("fallback.test", port, NULL, &status) == INVALID_FD);
    assert(status == 5 && connect_calls == 3 && slow_closed == 3);

    reset_connect_test(4);
    struct sockaddr_storage numeric = {0};
    memcpy(&numeric, &local, sizeof(local));
    unsigned int before = resolutions;
    assert(connect_target(NULL, NULL, &numeric, &status) == INVALID_FD);
    assert(status == 2 && connect_calls == 1 && resolutions == before);
    fake_connect = 0;
    close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
    puts("TCP fallback checks passed (slow candidates, shared deadline, cleanup, errors).");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--test-internals")) {
        test_dns_cache();
        puts("UDP DNS cache checks passed (100 packets, one resolution).");
        test_connection_fallback();
        return 0;
    }
    return tinysocks_main(argc, argv);
}
