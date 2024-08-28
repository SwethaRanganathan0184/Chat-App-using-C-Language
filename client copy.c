#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080

int main(int argc, char const *argv[])
{
    int sock = 0, valread;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    char message[1024];

    SSL_CTX *ctx;
    SSL *ssl;

    // Initialize OpenSSL
    SSL_library_init();
    ctx = SSL_CTX_new(TLS_client_method());

    if (ctx == NULL)
    {
        printf("SSL_CTX_new() failed\n");
        return -1;
    }

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("\n Socket creation error \n");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "192.168.43.9", &serv_addr.sin_addr) <= 0)
    {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }

    // Connect to server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        return -1;
    }

    // Set up SSL connection
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0)
    {
        printf("SSL_connect() failed\n");
        return -1;
    }

    while (1)
    {
        printf("Client: ");
        fgets(message, sizeof(message), stdin); // Read input from user
        SSL_write(ssl, message, strlen(message));

        if (strcmp(message, "exit\n") == 0)
        {
            printf("Exiting...\n");
            break;
        }

        valread = SSL_read(ssl, buffer, 1024);
        printf("Server: %s\n", buffer);
        memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    }

    // Close SSL connection and socket
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
