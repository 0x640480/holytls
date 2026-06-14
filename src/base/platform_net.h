// platform_net.h — the platform's IP/socket address declarations: inet_pton,
// htons/ntohs, struct sockaddr_in/sockaddr_in6, socklen_t, AF_INET*. On Windows
// these live in winsock2 / ws2tcpip, which MUST be included before any
// <windows.h>; everywhere else they are the POSIX headers. Include this instead
// of the raw <arpa/inet.h>/<netinet/in.h> so the unity TU cross-compiles.
#ifndef HOLYTLS_PLATFORM_NET_H
#define HOLYTLS_PLATFORM_NET_H

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN  // stop a later <windows.h> from pulling winsock1
#endif
#include <winsock2.h>
#include <ws2tcpip.h>  // inet_pton/inet_ntop, sockaddr_in6
#else
#include <arpa/inet.h>   // inet_pton, htons
#include <netdb.h>       // struct addrinfo
#include <netinet/in.h>  // sockaddr_in / sockaddr_in6, AF_INET*
#include <sys/socket.h>  // socklen_t, AF_*/SOCK_*
#endif

#endif  // HOLYTLS_PLATFORM_NET_H
