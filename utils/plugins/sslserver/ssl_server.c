#include "ssl_server.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/epoll.h>

#define BUFFER_SIZE 4096

#define PORT 4433

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

SSL_CTX* create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        handle_errors();
    }

    return ctx;
}

int start_listening_socket(const char *ip, int port) {
    int server_fd;
    struct sockaddr_in address;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip);
    address.sin_port = htons(port);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 10) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }
    printf("Listening on %s:%d...\n", ip, port);
    return server_fd;
}
SSL* accept_new_connections(int server_fd, SSL_CTX *ctx) {
    int new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL *ssl;
    
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("accept failed");
        return NULL;
    }

    /* Set a receive timeout so blocking SSL_accept / SSL_read can't pin
     * a worker thread forever on a client that connects then idles. */
    struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
    if (setsockopt(new_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
        /* non-fatal: continue */
    }

    // Create SSL structure for the new connection
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        perror("SSL_new failed");
        close(new_socket);
        return NULL;
    }
    
    // Set the socket file descriptor for SSL
    SSL_set_fd(ssl, new_socket);
    
    // Perform the SSL handshake
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(new_socket);
        return NULL;
    }
    
    printf("SSL connection established with client\n");
    
    return ssl; // Return the SSL session to the manager instead of closing it here
}


void configure_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        handle_errors();
    }
}


typedef struct {
    SSL *ssl;
    int fd;
} connection_t;

void *connection_handler(void *arg) {
    connection_t *conn = (connection_t *)arg;
    SSL *ssl = conn->ssl;
    char buffer[BUFFER_SIZE];
    int n;

    while ((n = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[n] = '\0';
        printf("[Inspection] Analyzing decrypted data: %s\n", buffer);
        printf("Received: %s\n", buffer);
        SSL_write(ssl, buffer, n);
    }

    if (n < 0) {
        ERR_print_errors_fp(stderr);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(conn->fd);
    free(conn);
    return NULL;
}


int main(int argc, char *argv[]) {
    char *ip = "0.0.0.0";
    int port = 4433;

    if (argc >= 3) {
        ip = argv[1];
        port = atoi(argv[2]);
    }

    // Init SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create context
    SSL_CTX *ctx = create_context();
    // Configure context
    configure_context(ctx);
    // Create Socket
    int server_fd = start_listening_socket(ip, port);

    signal(SIGPIPE, SIG_IGN);

    while(1) {
        SSL *session = accept_new_connections(server_fd, ctx);
        if (session) {
            pthread_t tid;
            connection_t *conn = malloc(sizeof(connection_t));
            if (!conn) {
                perror("malloc failed");
                SSL_free(session);
                close(SSL_get_fd(session));
                continue;   /* keep serving; this one connection is dropped */
            }
            conn->ssl = session;
            conn->fd = SSL_get_fd(session);

            if (pthread_create(&tid, NULL, connection_handler, conn) != 0) {
                perror("pthread_create failed");
                SSL_free(session);
                close(conn->fd);
                free(conn);
            } else {
                pthread_detach(tid);
            }
        }
    }

    //Obligatory Cleanup
    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
}