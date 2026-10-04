/* Deterministic resolver, connection and accept failures without external services. */
#define _POSIX_C_SOURCE 200112L
#define CONNECT_TIMEOUT_SECONDS 1
#define MAX_RESOLVERS 2
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
/* Zig's optimized builds define NDEBUG; checks must still execute. */
#undef NDEBUG
#include <assert.h>
#include <stdlib.h>

static int injected_getaddrinfo(const char *, const char *, const struct addrinfo *,
                                struct addrinfo **);
static void injected_freeaddrinfo(struct addrinfo *);
static void *injected_calloc(size_t, size_t);
#ifdef _WIN32
static SOCKET injected_accept(SOCKET, struct sockaddr *, int *);
static int injected_connect(SOCKET, const struct sockaddr *, int);
static int injected_close(SOCKET);
static int injected_getsockopt(SOCKET, int, int, char *, int *);
static int injected_recv(SOCKET, char *, int, int);
static int injected_ioctlsocket(SOCKET, long, u_long *);
static int injected_wsa_poll(WSAPOLLFD *, ULONG, INT);
static int injected_select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
static HANDLE injected_create_event(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
static HANDLE injected_create_thread(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE,
                                      LPVOID, DWORD, LPDWORD);
static WSAEVENT injected_wsa_create_event(void);
static int injected_wsa_event_select(SOCKET, WSAEVENT, long);
#else
static int injected_accept(int, struct sockaddr *, socklen_t *);
static int injected_connect(int, const struct sockaddr *, socklen_t);
static int injected_close(int);
static int injected_getsockopt(int, int, int, void *, socklen_t *);
static ssize_t injected_recv(int, void *, size_t, int);
static int injected_ioctl(int, unsigned long, int *);
static int injected_poll(struct pollfd *, nfds_t, int);
static int injected_pipe(int *);
static int injected_pthread_create(pthread_t *, const pthread_attr_t *,
                                    void *(*)(void *), void *);
#endif

#define getaddrinfo injected_getaddrinfo
#define freeaddrinfo injected_freeaddrinfo
#define accept injected_accept
#define connect injected_connect
#define getsockopt injected_getsockopt
#define calloc injected_calloc
#define recv injected_recv
#ifdef _WIN32
#define ioctlsocket injected_ioctlsocket
#define WSAPoll injected_wsa_poll
#undef CreateEvent
#define CreateEvent injected_create_event
#define CreateThread injected_create_thread
#define closesocket injected_close
#define select injected_select
#define WSACreateEvent injected_wsa_create_event
#define WSAEventSelect injected_wsa_event_select
#else
#define close injected_close
#define ioctl injected_ioctl
#define poll injected_poll
#define pipe injected_pipe
#define pthread_create injected_pthread_create
#endif
#define main tinysocks_main
#include "../tinysocks.c"
#undef main
#undef accept
#undef getaddrinfo
#undef freeaddrinfo
#undef connect
#undef getsockopt
#undef calloc
#undef recv
#ifdef _WIN32
#undef ioctlsocket
#undef WSAPoll
#undef CreateEvent
#undef CreateThread
#undef closesocket
#undef select
#undef WSACreateEvent
#undef WSAEventSelect
#else
#undef close
#undef ioctl
#undef poll
#undef pipe
#undef pthread_create
#endif

static int fake_dns;
static unsigned int resolutions;
static char last_dns_host[256];
#define TEST_LOOPBACK_IP UINT32_C(0x7f000001)
/* 1: slow IPv6; 2: all slow; 3: asynchronous refusal; 4: access denied. */
static int fake_connect;
static struct addrinfo connect_addresses[3];
static struct sockaddr_storage connect_endpoints[3];
static socket_t slow_sockets[CONNECT_PENDING_LIMIT];
static unsigned int slow_count, slow_closed, connect_calls, connect_waits;
static atomic_uint connect_started = ATOMIC_VAR_INIT(0);
static int connect_families[CONNECT_PENDING_LIMIT];
static atomic_int release_held_dns = ATOMIC_VAR_INIT(0);
static atomic_uint held_dns_calls = ATOMIC_VAR_INIT(0);
static atomic_uint held_dns_freed = ATOMIC_VAR_INIT(0);
static _Atomic(struct addrinfo *) held_results[MAX_RESOLVERS];
static int resolver_setup_failure;
/* Only the chosen control socket has a continuously replenished receive queue. */
static socket_t continuous_control = INVALID_FD;
static unsigned int continuous_reads;
static int control_query_failure;
static socket_t udp_fixture_control = INVALID_FD;
static atomic_int udp_fixture_phase = ATOMIC_VAR_INIT(0);
#ifdef _WIN32
static HANDLE failed_resolver_event;
static WSAEVENT failed_control_event;
#else
static int failed_resolver_pipe[2];
#endif

static void *injected_calloc(size_t count, size_t size) {
    if (resolver_setup_failure == 1) return NULL;
    return calloc(count, size);
}

#ifdef _WIN32
static HANDLE injected_create_event(LPSECURITY_ATTRIBUTES attributes, BOOL manual_reset,
                                     BOOL initial_state, LPCSTR name) {
    if (resolver_setup_failure == 2) return NULL;
    HANDLE event = CreateEventA(attributes, manual_reset, initial_state, name);
    if (resolver_setup_failure == 3) failed_resolver_event = event;
    return event;
}

static HANDLE injected_create_thread(LPSECURITY_ATTRIBUTES attributes, SIZE_T stack_size,
                                      LPTHREAD_START_ROUTINE start, LPVOID argument,
                                      DWORD flags, LPDWORD thread_id) {
    if (resolver_setup_failure == 3 && start == resolver_thread) return NULL;
    return CreateThread(attributes, stack_size, start, argument, flags, thread_id);
}

static WSAEVENT injected_wsa_create_event(void) {
    if (resolver_setup_failure == 4) return WSA_INVALID_EVENT;
    WSAEVENT event = WSACreateEvent();
    if (resolver_setup_failure == 5) failed_control_event = event;
    return event;
}

static int injected_wsa_event_select(SOCKET client, WSAEVENT event, long events) {
    if (resolver_setup_failure == 5 && events) {
        WSASetLastError(WSAENOBUFS);
        return SOCKET_ERROR;
    }
    return WSAEventSelect(client, event, events);
}
#else
static int injected_pipe(int *fds) {
    if (resolver_setup_failure == 2) {
        errno = EMFILE;
        return -1;
    }
    int result = pipe(fds);
    if (!result && resolver_setup_failure == 3) {
        failed_resolver_pipe[0] = fds[0];
        failed_resolver_pipe[1] = fds[1];
    }
    return result;
}

static int injected_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                                    void *(*start)(void *), void *argument) {
    if (resolver_setup_failure == 3 && start == resolver_thread) return EAGAIN;
    return pthread_create(thread, attributes, start, argument);
}
#endif

static void set_test_error(int error) {
#ifdef _WIN32
    WSASetLastError(error);
#else
    errno = error;
#endif
}

#ifdef _WIN32
static int injected_recv(SOCKET fd, char *buffer, int length, int flags) {
#else
static ssize_t injected_recv(int fd, void *buffer, size_t length, int flags) {
#endif
    if (fd != continuous_control) return recv(fd, buffer, length, flags);
    if (!(flags & MSG_PEEK)) {
        ++continuous_reads;
        retry_pause(1);
    }
    memset(buffer, 'c', (size_t)length);
    return length;
}

#ifdef _WIN32
static int injected_ioctlsocket(SOCKET fd, long request, u_long *pending) {
#else
static int injected_ioctl(int fd, unsigned long request, int *pending) {
#endif
    if (fd == continuous_control && request == FIONREAD) {
        if (control_query_failure) {
            int interrupted_query = control_query_failure == 2;
            if (interrupted_query) control_query_failure = 0;
#ifdef _WIN32
            set_test_error(interrupted_query ? WSAEINTR : WSAEINVAL);
#else
            set_test_error(interrupted_query ? EINTR : EIO);
#endif
            return -1;
        }
        *pending = 4096;
        return 0;
    }
#ifdef _WIN32
    return ioctlsocket(fd, request, pending);
#else
    return ioctl(fd, request, pending);
#endif
}

static int slow_socket(socket_t fd) {
    for (unsigned int i = 0; i < slow_count; ++i)
        if (slow_sockets[i] == fd) return 1;
    return 0;
}

static void injected_freeaddrinfo(struct addrinfo *addresses) {
    for (unsigned int i = 0; i < MAX_RESOLVERS; ++i)
        if (atomic_load_explicit(&held_results[i], memory_order_acquire) == addresses) {
            atomic_fetch_add_explicit(&held_dns_freed, 1, memory_order_relaxed);
            atomic_store_explicit(&held_results[i], NULL, memory_order_relaxed);
        }
    if (addresses != connect_addresses) freeaddrinfo(addresses);
}

static int injected_getaddrinfo(const char *host, const char *port,
                                const struct addrinfo *hints, struct addrinfo **result) {
    if (!strcmp(host, "held.test") || !strcmp(host, "reset.test")) {
        unsigned int slot = atomic_fetch_add_explicit(&held_dns_calls, 1, memory_order_relaxed);
        assert(slot < MAX_RESOLVERS);
        if (!strcmp(host, "reset.test")) {
            fprintf(stderr, "Fault DNS held: %u\n", slot);
            fflush(stderr);
        }
        while (!atomic_load_explicit(&release_held_dns, memory_order_acquire)) retry_pause(1);
        int error = getaddrinfo("127.0.0.1", port, hints, result);
        assert(error == 0);
        atomic_store_explicit(&held_results[slot], *result, memory_order_release);
        return error;
    }
    if (!strcmp(host, "slow.test")) {
        retry_pause(2000);
        return getaddrinfo("127.0.0.1", port, hints, result);
    }
    if (!strcmp(host, "delayed.test")) {
        retry_pause(600);
        return getaddrinfo("127.0.0.1", port, hints, result);
    }
    if (fake_connect && !strcmp(host, "fallback.test")) {
        *result = connect_addresses;
        return 0;
    }
    if (fake_connect && !strcmp(host, "slow-fallback.test")) {
        retry_pause(600);
        *result = connect_addresses;
        return 0;
    }
    if (!strcmp(host, "CacheCase.Test") || !strcmp(host, "cachecase.test") ||
        !strcmp(host, "CACHECASE.TEST"))
        return getaddrinfo("127.0.0.1", port, hints, result);
    if (!fake_dns) return getaddrinfo(host, port, hints, result);
    ++resolutions;
    strcpy(last_dns_host, host);
    if (!strcmp(host, "missing.test") || !strcmp(host, "MISSING.TEST")) return EAI_NONAME;
    return getaddrinfo((!strcmp(host, "broadcast.test") || !strcmp(host, "BROADCAST.TEST"))
                       ? "255.255.255.255" : "127.0.0.1",
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
    atomic_store_explicit(&connect_started, connect_calls, memory_order_release);
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
#ifndef _WIN32
    /* Resolver workers close pipes without touching the main test's socket state. */
    int type;
    socklen_t length = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) != 0) return close(fd);
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

/* Hold the association's first poll until real TCP and UDP input are both queued. */
static void synchronize_udp_input(pollfd_t *fds, size_t count) {
    if (count < 2 || fds[0].fd != udp_fixture_control ||
        atomic_load_explicit(&udp_fixture_phase, memory_order_acquire) == 2) return;
    uint64_t deadline_ms = monotonic_milliseconds() + 2000;
    while (!atomic_load_explicit(&udp_fixture_phase, memory_order_acquire)) {
        assert(remaining_milliseconds(deadline_ms));
        retry_pause(1);
    }
    assert(wait_for_io(fds[1].fd, POLLIN, deadline_ms));
    atomic_store_explicit(&udp_fixture_phase, 2, memory_order_release);
}

#ifdef _WIN32
static int injected_wsa_poll(WSAPOLLFD *fds, ULONG count, INT timeout) {
    synchronize_udp_input(fds, count);
    return WSAPoll(fds, count, timeout);
}

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
    synchronize_udp_input(fds, count);
    if (!fake_connect) return poll(fds, count, timeout);
    ++connect_waits;
    struct pollfd visible[CONNECT_PENDING_LIMIT];
    assert(count <= CONNECT_PENDING_LIMIT);
    int forced = 0;
    for (nfds_t i = 0; i < count; ++i) {
        visible[i] = fds[i];
        if (slow_socket(visible[i].fd)) {
            visible[i].fd = -1;
            if (fake_connect == 3) ++forced;
        }
    }
    /* Real read descriptors, including resolver pipes, keep their actual readiness. */
    int ready = poll(visible, count, forced ? 0 : timeout);
    if (ready < 0) return ready;
    for (nfds_t i = 0; i < count; ++i)
        fds[i].revents = fake_connect == 3 && slow_socket(fds[i].fd) ?
                          POLLOUT : visible[i].revents;
    return ready + forced;
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
    return forward_udp_request(packet, length + 7, ipv4, ipv6, destinations, cache,
                                monotonic_milliseconds() + CONNECT_TIMEOUT_SECONDS * 1000,
                                INVALID_FD);
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

    const char *fallback_hosts[] = {
        "127.1", "2130706433", "0177.0.0.1", "0x7f.0.0.1", "127.000.000.001",
        "::ffff:127.0.0.01", "::ffff:127.1", "::ffff:2130706433", "[::1]",
        "fe80::1%1", "localhost", "", "127.0.0.256", "127.0.0.1.", "127.0.0.1 "
    };
    struct sockaddr_storage untouched, parsed;
    memset(&untouched, 0xa5, sizeof(untouched));
    for (unsigned int i = 0; i < sizeof(fallback_hosts) / sizeof(fallback_hosts[0]); ++i) {
        parsed = untouched;
        int numeric = parse_numeric_host(fallback_hosts[i], &parsed);
        if (numeric) fprintf(stderr, "Unexpected literal conversion: %s\n", fallback_hosts[i]);
        assert(!numeric);
        assert(memcmp(&parsed, &untouched, sizeof(parsed)) == 0);
    }
    assert(parse_numeric_host("0000:0000:0000:0000:0000:0000:0000:0001", &parsed));
    const unsigned char loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    assert(parsed.ss_family == AF_INET6);
    assert(memcmp(&((struct sockaddr_in6 *)&parsed)->sin6_addr, loopback, 16) == 0);
    assert(((struct sockaddr_in6 *)&parsed)->sin6_port == 0);
    assert(((struct sockaddr_in6 *)&parsed)->sin6_scope_id == 0);
    const char *literals[] = {"127.0.0.1", "::ffff:127.0.0.1", "::FFFF:127.0.0.1"};
    for (unsigned int i = 0; i < 100; ++i)
        assert(domain_request(literals[i % 3], port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 0);
    for (unsigned int i = 0; i < UDP_DNS_CACHE_LIMIT; ++i)
        assert(cache[i].expires_at_ms == 0);

    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    uint64_t expiry = cached_entry(cache, "cached.test")->expires_at_ms;
    for (unsigned int i = 1; i < 100; ++i) {
        char variant[] = "cached.test";
        for (unsigned int bit = 0; bit < 4; ++bit)
            if (i & (1u << bit)) variant[bit] = (char)(variant[bit] - ('a' - 'A'));
        assert(domain_request(variant, port, &ipv4, &ipv6, destinations, cache));
    }
    assert(resolutions == 1);
    assert(!strcmp(last_dns_host, "cached.test"));
    assert(cached_entry(cache, "cached.test")->expires_at_ms == expiry);
    unsigned int live_entries = 0;
    for (unsigned int i = 0; i < UDP_DNS_CACHE_LIMIT; ++i)
        if (cache[i].expires_at_ms) ++live_entries;
    assert(live_entries == 1);
    /* Ports are applied to cached IPs, not retained from the first request. */
    assert(domain_request("CACHED.TEST", other_port,
                          &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 1);
    assert(address_port(&cache[0].address) == port);
    assert(address_port(&destinations[1].address) == other_port);

    /* Expiry is absolute: repeated packets do not extend cached DNS lifetime. */
    cached_entry(cache, "cached.test")->expires_at_ms = monotonic_milliseconds() - 1;
    assert(domain_request("CACHED.TEST", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 2);
    assert(!strcmp(last_dns_host, "CACHED.TEST"));

    /* A failed cached send re-resolves instead of pinning an unusable IP. */
    ((struct sockaddr_in *)&cached_entry(cache, "CACHED.TEST")->address)->sin_addr.s_addr =
        htonl(INADDR_BROADCAST);
    assert(domain_request("cached.test", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 3);
    assert(((struct sockaddr_in *)&cached_entry(cache, "cached.test")->address)->sin_addr.s_addr ==
           local.sin_addr.s_addr);

    const char *missing[] = {"missing.test", "MISSING.TEST"};
    for (int i = 0; i < 2; ++i)
        assert(!domain_request(missing[i], port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == 5); /* Failed lookups are not cached. */
    const char *broadcast[] = {"broadcast.test", "BROADCAST.TEST"};
    for (int i = 0; i < 2; ++i)
        assert(!domain_request(broadcast[i], port, &ipv4, &ipv6, destinations, cache));
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
    before = resolutions;
    assert(domain_request("127.1", port, &ipv4, &ipv6, destinations, cache));
    assert(resolutions == before + 1); /* Legacy forms still use the system resolver. */

    /* Only ordinary DNS spellings share case variants. Keep resolver-specific
       syntax, non-ASCII bytes and relative/absolute names distinct. */
    const struct {
        const char *first, *second;
        unsigned int expected_resolutions;
    } names[] = {
        {"XN--Cache.Test", "xn--cache.test", 1},
        {"_Cache._UDP.Test", "_cache._udp.test", 1},
        {"Case.Test.", "case.test.", 1},
        {"LocalHost", "localhost", 1},
        {"Case.Test.", "case.test", 2},
        {"fe80::1%eth0", "fe80::1%ETH0", 2},
        {"\\Case.Test", "\\case.test", 2},
        {"Case-\xc4.Test", "case-\xc4.test", 2},
        {"\xc4.Test", "\xe4.test", 2},
        {"Case Test", "case test", 2},
        {"[Case]", "[case]", 2}
    };
    for (unsigned int i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        memset(cache, 0, sizeof(cache));
        before = resolutions;
        assert(domain_request(names[i].first, port, &ipv4, &ipv6, destinations, cache));
        assert(!strcmp(last_dns_host, names[i].first)); /* Never rewrite resolver input. */
        expiry = cached_entry(cache, names[i].first)->expires_at_ms;
        assert(domain_request(names[i].second, other_port,
                              &ipv4, &ipv6, destinations, cache));
        assert(resolutions == before + names[i].expected_resolutions);
        assert(cached_entry(cache, names[i].first)->expires_at_ms == expiry);
        if (names[i].expected_resolutions == 2)
            assert(!strcmp(last_dns_host, names[i].second));
        assert(domain_request(names[i].second, port, &ipv4, &ipv6, destinations, cache));
        assert(resolutions == before + names[i].expected_resolutions);
    }

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
    atomic_store_explicit(&connect_started, 0, memory_order_relaxed);
}

static void wait_for_resolvers(void) {
    uint64_t deadline_ms = monotonic_milliseconds() + 1000;
    while (atomic_load_explicit(&active_resolvers, memory_order_acquire)) {
        assert(remaining_milliseconds(deadline_ms));
        retry_pause(1);
    }
}

static void reset_held_dns(void) {
    wait_for_resolvers();
    atomic_store_explicit(&held_dns_calls, 0, memory_order_relaxed);
    atomic_store_explicit(&held_dns_freed, 0, memory_order_relaxed);
    atomic_store_explicit(&release_held_dns, 0, memory_order_relaxed);
    for (unsigned int i = 0; i < MAX_RESOLVERS; ++i)
        assert(atomic_load_explicit(&held_results[i], memory_order_relaxed) == NULL);
}

static void control_pair(socket_t pair[2]) {
    socket_t listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(listener != INVALID_FD);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(TEST_LOOPBACK_IP);
    assert(bind(listener, (struct sockaddr *)&local, sizeof(local)) == 0);
    assert(listen(listener, 1) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(listener, (struct sockaddr *)&local, &length) == 0);
    pair[1] = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    assert(pair[1] != INVALID_FD);
    assert(connect(pair[1], (struct sockaddr *)&local, sizeof(local)) == 0);
    pair[0] = accept(listener, NULL, NULL);
    assert(pair[0] != INVALID_FD && set_nonblocking(pair[0], 1));
    close_socket(listener);
}

#ifdef _WIN32
static DWORD WINAPI associate_fixture_thread(LPVOID argument) {
#else
static void *associate_fixture_thread(void *argument) {
#endif
    socket_t client = *(socket_t *)argument;
    udp_associate(client, 0);
    close_socket(client);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void test_udp_control_backlog(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    for (int closed = 0; closed <= 1; ++closed) {
        socket_t control[2];
        control_pair(control);
        int receive_size = 512 * 1024;
        assert(setsockopt(control[0], SOL_SOCKET, SO_RCVBUF,
                         (const char *)&receive_size, sizeof(receive_size)) == 0);
        assert(set_nonblocking(control[1], 1));
        const size_t backlog_size = 200 * 1024;
        unsigned char *backlog = malloc(backlog_size);
        assert(backlog != NULL);
        memset(backlog, 'b', backlog_size);
        uint64_t deadline_ms = monotonic_milliseconds() + 2000;
        assert(send_all(control[1], backlog, backlog_size, deadline_ms));
        free(backlog);
        if (closed) {
#ifdef _WIN32
            assert(shutdown(control[1], SD_SEND) == 0);
#else
            assert(shutdown(control[1], SHUT_WR) == 0);
#endif
        }
        /* The entire backlog must be in the receiver, not the sender's queue. */
        for (;;) {
#ifdef _WIN32
            u_long queued;
            assert(ioctlsocket(control[0], FIONREAD, &queued) == 0);
#else
            int queued;
            assert(ioctl(control[0], FIONREAD, &queued) == 0);
#endif
            if ((size_t)queued == backlog_size) break;
            assert(remaining_milliseconds(deadline_ms));
            retry_pause(1);
        }
        socket_t target = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        socket_t sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        assert(target != INVALID_FD && sender != INVALID_FD);
        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(TEST_LOOPBACK_IP);
        assert(bind(target, (struct sockaddr *)&local, sizeof(local)) == 0);
        socklen_t length = sizeof(local);
        assert(getsockname(target, (struct sockaddr *)&local, &length) == 0);
        unsigned short port = ntohs(local.sin_port);
        udp_fixture_control = control[0];
        atomic_store_explicit(&udp_fixture_phase, 0, memory_order_relaxed);
#ifdef _WIN32
        HANDLE thread = CreateThread(NULL, 0, associate_fixture_thread, &control[0], 0, NULL);
        assert(thread != NULL);
#else
        pthread_t thread;
        assert(pthread_create(&thread, NULL, associate_fixture_thread, &control[0]) == 0);
#endif
        unsigned char reply[10];
        assert(recv_all(control[1], reply, sizeof(reply), deadline_ms));
        assert(reply[0] == 5 && reply[1] == 0 && reply[3] == 1);
        struct sockaddr_in relay_address = {0};
        relay_address.sin_family = AF_INET;
        memcpy(&relay_address.sin_addr, reply + 4, 4);
        memcpy(&relay_address.sin_port, reply + 8, 2);
        const unsigned char packet[] = {0, 0, 0, 1, 127, 0, 0, 1,
                                        (unsigned char)(port >> 8), (unsigned char)port,
                                        'u', 'd', 'p'};
        assert(sendto(sender, (const char *)packet, sizeof(packet), 0,
                       (struct sockaddr *)&relay_address, sizeof(relay_address)) == sizeof(packet));
        atomic_store_explicit(&udp_fixture_phase, 1, memory_order_release);
        if (!closed) {
            assert(wait_for_io(target, POLLIN, deadline_ms));
            unsigned char received[4];
            assert(recvfrom(target, (char *)received, sizeof(received), 0, NULL, NULL) == 3);
            assert(memcmp(received, packet + 10, 3) == 0);
#ifdef _WIN32
            assert(shutdown(control[1], SD_SEND) == 0);
#else
            assert(shutdown(control[1], SHUT_WR) == 0);
#endif
        }
        assert(wait_for_io(control[1], POLLIN, monotonic_milliseconds() + 400));
        char eof;
        assert(recv(control[1], &eof, 1, 0) == 0);
#ifdef _WIN32
        assert(WaitForSingleObject(thread, 400) == WAIT_OBJECT_0);
        CloseHandle(thread);
#else
        assert(pthread_join(thread, NULL) == 0);
#endif
        if (closed)
            assert(!wait_for_io(target, POLLIN, monotonic_milliseconds() + 100));
        udp_fixture_control = INVALID_FD;
        close_socket(control[1]);
        close_socket(target);
        close_socket(sender);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    puts("UDP backlog checks passed (200 KiB queued, intact live request, EOF before numeric forwarding).");
}

static void test_udp_control_fairness(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    socket_t control[2];
    control_pair(control);
    struct resolver_job ready = {0};
#ifdef _WIN32
    ready.ready = CreateEventA(NULL, TRUE, TRUE, NULL);
    assert(ready.ready != NULL);
#else
    assert(pipe(ready.ready) == 0);
    assert(write(ready.ready[1], "r", 1) == 1);
#endif
    continuous_control = control[0];
    continuous_reads = 0;
    /* Ready DNS must be observed before the budget expires, despite new bytes. */
    uint64_t start = monotonic_milliseconds();
    assert(wait_for_resolver(&ready, control[0], RESOLVE_UDP, start + 400));
    assert(continuous_reads && monotonic_milliseconds() - start < 250);
    control_query_failure = 1;
    assert(!wait_for_resolver(&ready, control[0], RESOLVE_UDP,
                              monotonic_milliseconds() + 400));
    control_query_failure = 2;
    assert(wait_for_resolver(&ready, control[0], RESOLVE_UDP,
                             monotonic_milliseconds() + 400));
    assert(control_query_failure == 0);
    assert(!udp_control_open(control[0], monotonic_milliseconds()));

    socket_t target = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(target != INVALID_FD);
    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(TEST_LOOPBACK_IP);
    assert(bind(target, (struct sockaddr *)&local, sizeof(local)) == 0);
    socklen_t length = sizeof(local);
    assert(getsockname(target, (struct sockaddr *)&local, &length) == 0);
    unsigned short port = ntohs(local.sin_port);
    const char host[] = "fair.test";
    const char payload[] = "pending UDP payload stays intact";
    unsigned char packet[7 + sizeof(host) - 1 + sizeof(payload)] = {0, 0, 0, 3};
    packet[4] = sizeof(host) - 1;
    memcpy(packet + 5, host, sizeof(host) - 1);
    packet[5 + sizeof(host) - 1] = (unsigned char)(port >> 8);
    packet[6 + sizeof(host) - 1] = (unsigned char)port;
    memcpy(packet + 7 + sizeof(host) - 1, payload, sizeof(payload));
    socket_t ipv4 = INVALID_FD, ipv6 = INVALID_FD;
    struct udp_destination destinations[UDP_DESTINATION_LIMIT] = {{0}};
    struct udp_dns_entry cache[UDP_DNS_CACHE_LIMIT] = {{0}};
    fake_dns = 1;
    assert(forward_udp_request(packet, sizeof(packet), &ipv4, &ipv6, destinations,
                                cache, monotonic_milliseconds() + 2000, control[0]) == 1);
    assert(wait_for_io(target, POLLIN, monotonic_milliseconds() + 1000));
    char received[sizeof(payload) + 1];
    assert(recvfrom(target, received, sizeof(received), 0, NULL, NULL) == sizeof(payload));
    assert(memcmp(received, payload, sizeof(payload)) == 0);
    assert(cached_entry(cache, host)->address.ss_family == AF_INET);
    wait_for_resolvers();
    fake_dns = 0;
    continuous_control = INVALID_FD;
    if (ipv4 != INVALID_FD) close_socket(ipv4);
    if (ipv6 != INVALID_FD) close_socket(ipv6);
    close_socket(target);
    close_socket(control[0]);
    close_socket(control[1]);
#ifdef _WIN32
    CloseHandle(ready.ready);
    WSACleanup();
#else
    close(ready.ready[0]);
    close(ready.ready[1]);
#endif
    puts("UDP control fairness checks passed (continuous input, ready DNS, query errors, intact payload).");
}

struct control_closer {
    socket_t peer;
    unsigned int dns_calls;
    int abortive, wait_connect;
};

#ifdef _WIN32
static DWORD WINAPI close_control_thread(LPVOID argument) {
#else
static void *close_control_thread(void *argument) {
#endif
    struct control_closer *closer = argument;
    uint64_t deadline_ms = monotonic_milliseconds() + 1000;
    while (atomic_load_explicit(&held_dns_calls, memory_order_acquire) < closer->dns_calls) {
        assert(remaining_milliseconds(deadline_ms));
        retry_pause(1);
    }
    while (closer->wait_connect && !atomic_load_explicit(&connect_started, memory_order_acquire)) {
        assert(remaining_milliseconds(deadline_ms));
        retry_pause(1);
    }
    retry_pause(50);
    unsigned char ignored[4096] = {0};
    assert(send_all(closer->peer, ignored, sizeof(ignored), deadline_ms));
    if (closer->abortive) {
        struct linger reset = {1, 0};
        assert(setsockopt(closer->peer, SOL_SOCKET, SO_LINGER,
                         (const char *)&reset, sizeof(reset)) == 0);
        close_socket(closer->peer);
        closer->peer = INVALID_FD;
    } else {
#ifdef _WIN32
        assert(shutdown(closer->peer, SD_SEND) == 0);
#else
        assert(shutdown(closer->peer, SHUT_WR) == 0);
#endif
    }
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void test_resolver_control_close(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICSERV;
    socket_t control[2];
    reset_held_dns();
    control_pair(control);
    close_socket(control[1]);
    assert(wait_for_io(control[0], POLLIN, monotonic_milliseconds() + 1000));
    assert(resolve_target("held.test", "80", &hints, &addresses,
                          monotonic_milliseconds() + 1000, control[0], RESOLVE_UDP) == EAI_AGAIN);
    assert(addresses == NULL && atomic_load_explicit(&active_resolvers, memory_order_acquire) == 0);
    assert(atomic_load_explicit(&held_dns_calls, memory_order_relaxed) == 0);
    close_socket(control[0]);

    for (int queued = 0; queued <= 1; ++queued) {
        reset_held_dns();
        if (queued)
            for (unsigned int i = 0; i < MAX_RESOLVERS; ++i)
                assert(resolve_target("held.test", "80", &hints, &addresses,
                                      monotonic_milliseconds() + 20, INVALID_FD, RESOLVE_TCP) == EAI_AGAIN);
        unsigned int expected_jobs = queued ? MAX_RESOLVERS : 1;
        control_pair(control);
        struct control_closer closer = {.peer = control[1], .dns_calls = expected_jobs};
#ifdef _WIN32
        HANDLE thread = CreateThread(NULL, 0, close_control_thread, &closer, 0, NULL);
        assert(thread != NULL);
#else
        pthread_t thread;
        assert(pthread_create(&thread, NULL, close_control_thread, &closer) == 0);
#endif
        uint64_t start = monotonic_milliseconds();
        assert(resolve_target(queued ? "127.0.0.1" : "held.test", "80", &hints, &addresses,
                              start + 1000, control[0], RESOLVE_UDP) == EAI_AGAIN);
        assert(addresses == NULL && monotonic_milliseconds() - start < 500);
#ifdef _WIN32
        assert(WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0);
        CloseHandle(thread);
#else
        assert(pthread_join(thread, NULL) == 0);
#endif
        /* Cancelling a caller does not free the still-running resolver's slot. */
        assert(atomic_load_explicit(&active_resolvers, memory_order_acquire) == expected_jobs);
        assert(atomic_load_explicit(&held_dns_calls, memory_order_relaxed) == expected_jobs);
        assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == 0);
        atomic_store_explicit(&release_held_dns, 1, memory_order_release);
        wait_for_resolvers();
        assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == expected_jobs);
        close_socket(control[0]);
        close_socket(control[1]);
    }
#ifdef _WIN32
    for (int failure = 4; failure <= 5; ++failure) {
        reset_held_dns();
        control_pair(control);
        resolver_setup_failure = failure;
        assert(resolve_target("held.test", "80", &hints, &addresses,
                              monotonic_milliseconds() + 1000, control[0], RESOLVE_UDP) == EAI_AGAIN);
        assert(addresses == NULL);
        if (failure == 5) {
            assert(failed_control_event != WSA_INVALID_EVENT);
            assert(WaitForSingleObject(failed_control_event, 0) == WAIT_FAILED);
        }
        resolver_setup_failure = 0;
        atomic_store_explicit(&release_held_dns, 1, memory_order_release);
        wait_for_resolvers();
        assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == 1);
        assert(resolve_target("127.0.0.1", "80", &hints, &addresses,
                              monotonic_milliseconds() + 1000, control[0], RESOLVE_UDP) == 0);
        freeaddrinfo(addresses);
        wait_for_resolvers();
        close_socket(control[0]);
        close_socket(control[1]);
    }
    WSACleanup();
#endif
    puts("UDP control checks passed (closed, resolving, queued, late cleanup, recovery).");
}

static void test_resolver_tcp_reset(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    socket_t control[2];
    reset_held_dns();
    control_pair(control);
    struct linger reset = {1, 0};
    assert(setsockopt(control[1], SOL_SOCKET, SO_LINGER,
                     (const char *)&reset, sizeof(reset)) == 0);
    close_socket(control[1]);
    assert(wait_for_io(control[0], POLLIN, monotonic_milliseconds() + 1000));
    assert(resolve_target("held.test", "80", &hints, &addresses,
                          monotonic_milliseconds() + 1000, control[0], RESOLVE_TCP) == EAI_AGAIN);
    assert(addresses == NULL && atomic_load_explicit(&active_resolvers, memory_order_acquire) == 0);
    assert(atomic_load_explicit(&held_dns_calls, memory_order_relaxed) == 0);
    close_socket(control[0]);

    for (int queued = 0; queued <= 1; ++queued) {
        reset_held_dns();
        if (queued)
            for (unsigned int i = 0; i < MAX_RESOLVERS; ++i)
                assert(resolve_target("held.test", "80", &hints, &addresses,
                                      monotonic_milliseconds() + 20, INVALID_FD, RESOLVE_TCP) == EAI_AGAIN);
        unsigned int expected_jobs = queued ? MAX_RESOLVERS : 1;
        control_pair(control);
        struct control_closer closer = {.peer = control[1], .dns_calls = expected_jobs, .abortive = 1};
#ifdef _WIN32
        HANDLE thread = CreateThread(NULL, 0, close_control_thread, &closer, 0, NULL);
        assert(thread != NULL);
#else
        pthread_t thread;
        assert(pthread_create(&thread, NULL, close_control_thread, &closer) == 0);
#endif
        uint64_t start = monotonic_milliseconds();
        assert(resolve_target(queued ? "127.0.0.1" : "held.test", "80", &hints, &addresses,
                              start + 1000, control[0], RESOLVE_TCP) == EAI_AGAIN);
        assert(addresses == NULL && monotonic_milliseconds() - start < 500);
#ifdef _WIN32
        assert(WaitForSingleObject(thread, 1000) == WAIT_OBJECT_0);
        CloseHandle(thread);
#else
        assert(pthread_join(thread, NULL) == 0);
#endif
        assert(closer.peer == INVALID_FD);
        assert(atomic_load_explicit(&active_resolvers, memory_order_acquire) == expected_jobs);
        assert(atomic_load_explicit(&held_dns_calls, memory_order_relaxed) == expected_jobs);
        assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == 0);
        atomic_store_explicit(&release_held_dns, 1, memory_order_release);
        wait_for_resolvers();
        assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == expected_jobs);
        close_socket(control[0]);
    }
#ifdef _WIN32
    WSACleanup();
#endif
    puts("TCP DNS reset checks passed (before queuing, resolving, queued, retained worker slots, late cleanup).");
}

#ifdef _WIN32
static DWORD WINAPI release_dns_thread(LPVOID argument) {
#else
static void *release_dns_thread(void *argument) {
#endif
    (void)argument;
    retry_pause(50);
    atomic_store_explicit(&release_held_dns, 1, memory_order_release);
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

static void test_resolver_deadline_and_limit(void) {
#ifdef _WIN32
    WSADATA winsock;
    assert(WSAStartup(MAKEWORD(2, 2), &winsock) == 0);
#endif
    wait_for_resolvers();
    struct addrinfo hints = {0}, *addresses = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICSERV;
    for (unsigned int i = 0; i < MAX_RESOLVERS; ++i) {
        assert(resolve_target("held.test", "80", &hints, &addresses,
                              monotonic_milliseconds() + 50, INVALID_FD, RESOLVE_TCP) == EAI_AGAIN);
        assert(addresses == NULL);
    }
    assert(atomic_load_explicit(&active_resolvers, memory_order_acquire) == MAX_RESOLVERS);
    uint64_t start = monotonic_milliseconds();
    assert(resolve_target("held.test", "80", &hints, &addresses,
                          start + 50, INVALID_FD, RESOLVE_TCP) == EAI_AGAIN);
    assert(monotonic_milliseconds() - start >= 40 && monotonic_milliseconds() - start < 250);
#ifdef _WIN32
    HANDLE releaser = CreateThread(NULL, 0, release_dns_thread, NULL, 0, NULL);
    assert(releaser != NULL);
#else
    pthread_t releaser;
    assert(pthread_create(&releaser, NULL, release_dns_thread, NULL) == 0);
#endif
    /* A caller queued at capacity succeeds when earlier timed-out jobs finish. */
    start = monotonic_milliseconds();
    assert(resolve_target("127.0.0.1", "80", &hints, &addresses,
                          start + 1000, INVALID_FD, RESOLVE_TCP) == 0);
    assert(monotonic_milliseconds() - start >= 40);
    assert(addresses != NULL);
    freeaddrinfo(addresses);
    wait_for_resolvers();
    assert(atomic_load_explicit(&held_dns_calls, memory_order_relaxed) == MAX_RESOLVERS);
    assert(atomic_load_explicit(&held_dns_freed, memory_order_relaxed) == MAX_RESOLVERS);
    for (int failure = 1; failure <= 3; ++failure) {
        resolver_setup_failure = failure;
        int error = resolve_target("127.0.0.1", "80", &hints, &addresses,
                                    monotonic_milliseconds() + 1000, INVALID_FD, RESOLVE_TCP);
        assert(error == (failure == 1 ? EAI_MEMORY : EAI_AGAIN));
        assert(addresses == NULL);
        assert(atomic_load_explicit(&active_resolvers, memory_order_acquire) == 0);
        if (failure == 3) {
#ifdef _WIN32
            assert(failed_resolver_event != NULL);
            assert(WaitForSingleObject(failed_resolver_event, 0) == WAIT_FAILED);
#else
            for (int i = 0; i < 2; ++i) {
                assert(fcntl(failed_resolver_pipe[i], F_GETFD) == -1);
                assert(errno == EBADF);
            }
#endif
        }
        resolver_setup_failure = 0;
        assert(resolve_target("127.0.0.1", "80", &hints, &addresses,
                              monotonic_milliseconds() + 1000, INVALID_FD, RESOLVE_TCP) == 0);
        freeaddrinfo(addresses);
        wait_for_resolvers();
    }
#ifdef _WIN32
    assert(WaitForSingleObject(releaser, 1000) == WAIT_OBJECT_0);
    CloseHandle(releaser);
    WSACleanup();
#else
    assert(pthread_join(releaser, NULL) == 0);
#endif
    puts("Resolver checks passed (deadlines, job limit, queuing, cleanup, setup failures, recovery).");
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
    socket_t target = connect_target("fallback.test", port, NULL, &status, INVALID_FD);
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
    assert(connect_target("fallback.test", port, NULL, &status, INVALID_FD) == INVALID_FD);
    elapsed = monotonic_milliseconds() - start;
    assert(status == 4 && connect_calls == 3);
    assert(elapsed >= 900 && elapsed < 2000); /* One budget, not one per address. */
    assert(slow_closed == slow_count && slow_count == 3);
    assert(connect_waits < 20); /* Sleeping candidates must not cause a busy loop. */

    reset_connect_test(2);
    start = monotonic_milliseconds();
    assert(connect_target("slow-fallback.test", port, NULL, &status, INVALID_FD) == INVALID_FD);
    elapsed = monotonic_milliseconds() - start;
    assert(status == 4 && elapsed >= 900 && elapsed < 1500);
    assert(connect_calls > 0 && connect_calls < 3 && slow_closed == slow_count);

    reset_connect_test(3);
    assert(connect_target("fallback.test", port, NULL, &status, INVALID_FD) == INVALID_FD);
    assert(status == 5 && connect_calls == 3 && slow_closed == 3);

    reset_connect_test(4);
    struct sockaddr_storage numeric = {0};
    memcpy(&numeric, &local, sizeof(local));
    unsigned int before = resolutions;
    assert(connect_target(NULL, NULL, &numeric, &status, INVALID_FD) == INVALID_FD);
    assert(status == 2 && connect_calls == 1 && resolutions == before);
    fake_connect = 0;
    socket_t control[2];
    control_pair(control);
    reset_connect_test(2);
    struct control_closer closer = {.peer = control[1], .abortive = 1, .wait_connect = 1};
#ifdef _WIN32
    HANDLE resetter = CreateThread(NULL, 0, close_control_thread, &closer, 0, NULL);
    assert(resetter != NULL);
#else
    pthread_t resetter;
    assert(pthread_create(&resetter, NULL, close_control_thread, &closer) == 0);
#endif
    start = monotonic_milliseconds();
    assert(connect_target("fallback.test", port, NULL, &status, control[0]) == INVALID_FD);
    assert(status == 4 && monotonic_milliseconds() - start < 500);
    assert(connect_calls > 0 && slow_closed == slow_count);
#ifdef _WIN32
    assert(WaitForSingleObject(resetter, 1000) == WAIT_OBJECT_0);
    CloseHandle(resetter);
#else
    assert(pthread_join(resetter, NULL) == 0);
#endif
    assert(closer.peer == INVALID_FD);
    close_socket(control[0]);
    fake_connect = 0;
    close_socket(listener);
#ifdef _WIN32
    WSACleanup();
#endif
    puts("TCP fallback checks passed (slow candidates, shared deadline, cleanup, errors, client reset).");
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--test-internals")) {
        test_dns_cache();
        puts("UDP DNS checks passed (100 literals, zero resolutions; 100 case variants, one resolution; syntax, TTL, ports, failures).");
        test_udp_control_fairness();
        test_udp_control_backlog();
        test_connection_fallback();
        test_resolver_deadline_and_limit();
        test_resolver_control_close();
        test_resolver_tcp_reset();
        return 0;
    }
    return tinysocks_main(argc, argv);
}
