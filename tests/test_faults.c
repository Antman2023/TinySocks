/* Deterministic resolver and accept failures without external services. */
#define _POSIX_C_SOURCE 200112L
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netdb.h>
#include <sys/socket.h>
#endif
/* Zig's optimized builds define NDEBUG; checks must still execute. */
#undef NDEBUG
#include <assert.h>

static int injected_getaddrinfo(const char *, const char *, const struct addrinfo *,
                                struct addrinfo **);
#ifdef _WIN32
static SOCKET injected_accept(SOCKET, struct sockaddr *, int *);
#else
static int injected_accept(int, struct sockaddr *, socklen_t *);
#endif

#define getaddrinfo injected_getaddrinfo
#define accept injected_accept
#define main tinysocks_main
#include "../tinysocks.c"
#undef main
#undef accept
#undef getaddrinfo

static int fake_dns;
static unsigned int resolutions;

static int injected_getaddrinfo(const char *host, const char *port,
                                const struct addrinfo *hints, struct addrinfo **result) {
    if (!fake_dns) return getaddrinfo(host, port, hints, result);
    ++resolutions;
    if (!strcmp(host, "missing.test")) return EAI_NONAME;
    return getaddrinfo(!strcmp(host, "broadcast.test") ? "255.255.255.255" : "127.0.0.1",
                       port, hints, result);
}

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

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--test-internals")) {
        test_dns_cache();
        puts("UDP DNS cache checks passed (100 packets, one resolution).");
        return 0;
    }
    return tinysocks_main(argc, argv);
}
