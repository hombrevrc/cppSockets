// From:
// http://bobah.net/d4d/source-code/networking/sss-client-socket
//
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
 
#include <cstdio>
#include <cstring>
 
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <assert.h>
 
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <string.h>
 
#include <iostream>
#include <iomanip>
 
 
namespace {
 
enum {
  FATAL = 0,
  ERROR,
  WARNING,
  INFO,
  DETAIL,
  DEBUG,
  TRACE
};
 
int _logLevel = DETAIL;
 
#define LOG(level,msg) do { if (level <= _logLevel) {std::cout << msg; } } while(0)
#define LOG_ERROR(msg) do { LOG(ERROR, "-E- " << __func__ << ' ' << msg << std::endl); } while(0)
#define LOG_DEBUG(msg) do { LOG(DEBUG, "-D- " << __func__ << ' ' << msg << '\n'); } while(0)
#define LOG_INFO(msg)  do { LOG(INFO,  "-I- " << __func__ << ' ' << msg << '\n'); } while(0)
 
#define PERROR_AND_RETURN(rc) do {                                           \
  LOG_ERROR(strerror(errno) << '(' << errno << ')'); \
  return rc;                                                                        \
} while (0)
 
 
struct addrinfo* get_addrinfo(const char* node, const char* service, bool tcp) {
  struct addrinfo  hints  = addrinfo();
  struct addrinfo* result = NULL;
 
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family    = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype  = tcp ? SOCK_STREAM : SOCK_DGRAM; /* Stream/Datagram socket */
  hints.ai_flags     = 0;
  hints.ai_protocol  = 0;          /* Any protocol */
 
  int rc = 0;
  if (getaddrinfo(node, service, &hints, &result) != 0) { LOG_ERROR(gai_strerror(rc)); return NULL; }
 
  return result;
}
 
/**
 * 
 */
int configure_socket(int fd, const struct addrinfo& ai, unsigned sndbuf, unsigned rcvbuf, bool blocking, bool nolinger, bool nodelay) {
  if (nolinger) {
    /* Set the socket for a non lingering, graceful close.
     * This will cause a final close of this socket not to wait until all
     * of the data sent on it has been received by the remote host.
     * The result is that the socket will be immediately released instead
     * of blocking in a TIME_WAIT state */
    linger linger = {1, 0};
    if (::setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == -1) { LOG_ERROR(strerror(errno)); return -1; }
  }
 
  if (nodelay) {
    int flag = 1;
    if (::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1) { LOG_ERROR(strerror(errno)); return -1; }
  }
 
  if (sndbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf)) == -1) { LOG_ERROR(strerror(errno)); return -1; }
  if (rcvbuf > 0 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) { LOG_ERROR(strerror(errno)); return -1; }
 
  // put socket to blocking/non-blocking mode
  int flags = -1;
  if ((flags = fcntl(fd, F_GETFL, 0)) == -1) { LOG_ERROR(strerror(errno)); return -1; }
  if (blocking) flags &= ~O_NONBLOCK;
  else          flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) == -1) { LOG_ERROR(strerror(errno)); return -1; }
 
  return 0;
}
 
 
/**
 * returns tcp-connected socket
 */
int get_tcp_connection(const char* node, const char* service) {
  struct addrinfo* ai = get_addrinfo(node, service, true /* tcp */);
  if (ai == NULL) return -1;
 
  const unsigned sndbuf = 1024*128;
  const unsigned rcvbuf = 1024*128;
 
  int fd = -1;
  for (struct addrinfo* rp = ai; rp != NULL; rp = rp->ai_next) {
    if ((fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) == -1) { LOG_ERROR(strerror(errno)); fd = -1; break; }
    if (configure_socket(fd, *rp, sndbuf, rcvbuf, true /* blocking */, true /* nolinger */, true /* nodelay */) != 0) { ::close(fd); fd = -1; break; }
 
    if (::connect(fd, rp->ai_addr, rp->ai_addrlen) != -1) break;
    ::close(fd); fd = -1;
  }
 
  ::freeaddrinfo(ai);
  return fd;
}
 
}
 
int main()
{
    int p;
 
    const char* request = "GET /\n\n";
    char r[1024];
 
    /* Set up the library */
    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
 
    /* Set up the SSL context */
 
    SSL_CTX* ctx = SSL_CTX_new(SSLv3_method());
    if (!ctx) {
      ERR_print_errors_fp(stderr);
      return 1;
    }
 
    /* Load the trust store */
 
    if(! SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs"))
    {
        fprintf(stderr, "Error loading trust store\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 0;
    }
 
    /* Setup the connection */
 
    int fd = get_tcp_connection("127.0.0.1", "12345");
//    int fd = my_connect("127.0.0.1", 80);
    if (fd == -1) {
      LOG_ERROR(strerror(errno));
      return 1;
    }
 
 
    SSL* ssl = SSL_new(ctx); assert(ssl);
    if (!SSL_set_fd(ssl, fd)) {
      LOG_ERROR("SSL_set_fd(ssl, fd)");
      return 1;
    }
 
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 
    int rc = SSL_get_error(ssl, SSL_connect(ssl));
    if (rc != SSL_ERROR_NONE) {
      LOG_ERROR(ERR_error_string(rc, NULL));
      while ((rc = ERR_get_error()) != 0) {
        LOG_ERROR(ERR_error_string(rc, NULL));
      }
      return 1;
    }
 
    /* Check the certificate */
 
    rc = SSL_get_verify_result(ssl);
    if(rc != X509_V_OK)
    {
        if (rc == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT || rc == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) {
          fprintf(stderr, "self signed certificate\n");
        }
        else {
          fprintf(stderr, "Certificate verification error: %ld\n", SSL_get_verify_result(ssl));
          SSL_CTX_free(ctx);
          return 0;
        }
    }
 
    /* Send the request */
    if (SSL_write(ssl, request, strlen(request)) == -1) {
      PERROR_AND_RETURN(1);
    }
    LOG_INFO("Data sent [" << request << "]");
 
    /* Read in the response */
 
    for(;;)
    {
        p = SSL_read(ssl, r, 1023);
        if(p <= 0) break;
        r[p] = 0;
        printf("%s", r);
    }
 
 
    rc = SSL_shutdown(ssl);
    if(!rc){
      /* If we called SSL_shutdown() first then
         we always get return value of '0'. In
         this case, try again, but first send a
         TCP FIN to trigger the other side's
         close_notify*/
      shutdown(fd,1);
      rc = SSL_shutdown(ssl);
    }
    switch(rc){
      case 1:
        break; /* Success */
      case 0:
      case -1:
      default:
        LOG_ERROR("Shutdown failed");
    }
 
    /* Close the connection and free the context */
 
    SSL_CTX_free(ctx);
//     if (write(fd, request, strlen(request)) == -1) {
//       PERROR_AND_RETURN("write(fd, request, strlen(request))", 1);
//     }
// 
//     /* Read in the response */
// 
//     for(;;)
//     {
//         p = read(fd, r, 1023);
//         if(p <= 0) break;
//         r[p] = 0;
//         printf("%s", r);
//     }
    return 0;
}
