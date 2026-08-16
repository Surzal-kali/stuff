#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include <openssl/ssl.h>

SSL_CTX* create_context();
void configure_context(SSL_CTX *ctx);
SSL* setup_client_connection(SSL_CTX *ctx);
void encrypt_data(SSL *ssl);

#endif // SSL_SERVER_H