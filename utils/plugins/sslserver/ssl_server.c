#include "ssl_server.h"
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

int start_listening_socket() {
    int server_fd, new_socket;
    struct sockaddr_in address;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
    }
    if (listen(server_fd, 3) < 0) {
        perror("listen error");
        exit(EXIT_FAILURE);
    }
    printf("Listening on port %d...\n", PORT);
    return server_fd;
    

}
void accept_new_connections(int server_fd, SSL_CTX *ctx) {
    int new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    SSL *ssl;
    
    new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
    if (new_socket < 0) {
        perror("accept failed");
        return;
    }
    
    // Create SSL structure for the new connection
    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        perror("SSL_new failed");
        close(new_socket);
        return;
    }
    
    // Set the socket file descriptor for SSL
    SSL_set_fd(ssl, new_socket);
    
    // Perform the SSL handshake //[ ]TODO: Pass the connection instead of closing it
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(new_socket);
        return;
    }
    
    printf("SSL connection established with client\n");
    
    //Now we pass the connection to the encryption function
    encrypt_data(ssl); //This is where we would pass the connection

    // Clean up 
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket); //AHA here's the problem
    return; // Return to main loop to accept more connections

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


void encrypt_data(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int n; // Rewrite to accept multiple client connections without freezing
    while ((n = SSL_read(ssl, buffer, BUFFER_SIZE - 1)) > 0) {
        buffer[n] = '\0';
        printf("Received: %s\n", buffer);
        SSL_write(ssl, buffer, n);
    }

    if (n < 0) {
        ERR_print_errors_fp(stderr);
    }
}


int main() {
    // Init SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // Init epoll

    // Create context
    SSL_CTX *ctx = create_context();
    // Configure context
    configure_context(ctx);
    // Create Socket
    int server_fd = start_listening_socket();
    struct sockaddr_in address;

    while(1) {
        //Accept + Encrypt in One Go :D //[ ]TODO add inspection engine to ssl connection lifecycle
        accept_new_connections(server_fd, ctx);
    }

    //Obligatory Cleanup
    SSL_CTX_free(ctx);
    close(server_fd);
    return 0;
    // (Technically unreachable but hey it makes me feel better)
}