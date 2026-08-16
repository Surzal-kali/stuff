#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

// we're making a .so for the brain to use, so we need to export the functions. The brain already makes the socket, so we just need to accept connections and read data from it. The brain will send us a string of data, which we will print to stdout.

// Reads exactly n bytes from fd into buf, looping over short reads. Returns 0 on success, -1 on error/EOF.
static int read_exact(int fd, char *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, buf + total, n - total);
        if (r <= 0) {
            return -1;
        }
        total += (size_t)r;
    }
    return 0;
}

// Parses a "<len>:" prefix off the socket, then reads exactly <len> bytes of payload into buffer.
// Returns the payload length on success, or -1 on error/EOF/malformed prefix.
static ssize_t read_framed_command(int client_fd, char *buffer, size_t buffer_size) {
    char len_digits[16];
    size_t len_digit_count = 0;

    // Read one byte at a time until we hit the ':' delimiter, collecting ASCII digits.
    while (1) {
        char c;
        ssize_t r = read(client_fd, &c, 1);
        if (r <= 0) {
            return -1; // connection closed or error before we got a full prefix
        }
        if (c == ':') {
            break;
        }
        if (!isdigit((unsigned char)c) || len_digit_count >= sizeof(len_digits) - 1) {
            return -1; // malformed prefix
        }
        len_digits[len_digit_count++] = c;
    }
    len_digits[len_digit_count] = '\0';

    if (len_digit_count == 0) {
        return -1;
    }

    long payload_len = strtol(len_digits, NULL, 10);
    if (payload_len < 0 || (size_t)payload_len >= buffer_size) {
        return -1; // command too big for our buffer
    }

    if (read_exact(client_fd, buffer, (size_t)payload_len) == -1) {
        return -1;
    }
    buffer[payload_len] = '\0';
    return (ssize_t)payload_len;
}

int main(int argc, char *argv[]) {
    int server_fd, client_fd;
    struct sockaddr_un address;
    char buffer[1024] = {0};

    // Create socket
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to a file path
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, "/tmp/brain_socket", sizeof(address.sun_path) - 1);
    unlink("/tmp/brain_socket"); // Remove any existing socket file

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("bind failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 5) == -1) {
        perror("listen failed");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Waiting for connections...\n");

    while (1) {
        // Accept a connection
        if ((client_fd = accept(server_fd, NULL, NULL)) == -1) {
            perror("accept failed");
            continue; // Continue to accept new connections
        }

        // Read a length-prefixed command from the client ("<len>:<payload>")
        ssize_t bytes_read = read_framed_command(client_fd, buffer, sizeof(buffer));
        if (bytes_read >= 0) {
            printf("Received: %s\n", buffer);
        } else {
            fprintf(stderr, "read_framed_command failed (malformed prefix or closed connection)\n");
        }

        close(client_fd); // Close the client connection
    }

    close(server_fd); // Close the server socket
    return 0;
}


void send_command(const char *command) {
    int sock;
    struct sockaddr_un address;

    // Create socket
    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket failed");
        return;
    }

    // Set up the address structure
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, "/tmp/brain_socket", sizeof(address.sun_path) - 1); //address sun_path is the path to the socket file

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&address, sizeof(address)) == -1) {
        perror("connect failed");
        close(sock);
        return;
    }

    // Frame the command as "<len>:<payload>" so the reader knows exactly how many bytes to expect
    char framed[1040];
    int framed_len = snprintf(framed, sizeof(framed), "%zu:%s", strlen(command), command);
    if (framed_len < 0 || (size_t)framed_len >= sizeof(framed)) {
        fprintf(stderr, "command too long to frame\n");
        close(sock);
        return;
    }

    // Send the framed command
    if (write(sock, framed, (size_t)framed_len) == -1) {
        perror("write failed");
    }

    close(sock); // Close the socket
}