#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 8080
#define MAX_CLIENTS 5

// Client structure to hold client information
typedef struct
{
    int socket;
    struct sockaddr_in address;
    SSL *ssl;
} Client;

Client clients[MAX_CLIENTS];
int num_clients = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to handle client connections
void *handle_client(void *arg)
{
    int client_index = *((int *)arg);
    int client_socket = clients[client_index].socket;
    SSL *ssl = clients[client_index].ssl;
    char buffer[1024] = {0};
    int valread;

    while (1)
    {
        valread = SSL_read(ssl, buffer, sizeof(buffer));
        if (valread <= 0)
        {
            printf("Client %d disconnected\n", client_index);
            pthread_mutex_lock(&clients_mutex);
            close(client_socket);
            SSL_free(ssl);
            for (int i = client_index; i < num_clients - 1; i++)
            {
                clients[i] = clients[i + 1];
            }
            num_clients--;
            pthread_mutex_unlock(&clients_mutex);
            pthread_exit(NULL);
        }
        printf("Client %d: %s\n", client_index, buffer);

        // Forward message to other clients
        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < num_clients; i++)
        {
            if (i != client_index)
            {
                SSL_write(clients[i].ssl, buffer, strlen(buffer));
            }
        }
        pthread_mutex_unlock(&clients_mutex);

        memset(buffer, 0, sizeof(buffer)); // Clear the buffer
    }

    close(client_socket);
    SSL_free(ssl);
    free(arg);
    pthread_exit(NULL);
}

int main()
{
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    pthread_t thread_id;

    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());

    if (ctx == NULL)
    {
        printf("SSL_CTX_new() failed\n");
        return -1;
    }

    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "/Users/Swetha/Desktop/CN_2/server.crt", SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_certificate_file() failed\n");
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/Users/Swetha/Desktop/CN_2/server.key", SSL_FILETYPE_PEM) <= 0)
    {
        printf("SSL_CTX_use_PrivateKey_file() failed\n");
        return -1;
    }

    // Create socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, MAX_CLIENTS) < 0)
    {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Accept incoming connections and handle them in separate threads
    while (1)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t *)&addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Set up SSL connection
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, new_socket);
        if (SSL_accept(ssl) <= 0)
        {
            printf("SSL_accept() failed\n");
            close(new_socket);
            continue;
        }

        pthread_mutex_lock(&clients_mutex);
        clients[num_clients].socket = new_socket;
        clients[num_clients].address = address;
        clients[num_clients].ssl = ssl;
        int *client_index = malloc(sizeof(int));
        *client_index = num_clients;
        num_clients++;
        pthread_mutex_unlock(&clients_mutex);

        if (pthread_create(&thread_id, NULL, handle_client, (void *)client_index) < 0)
        {
            perror("could not create thread");
            exit(EXIT_FAILURE);
        }
        printf("New client connected\n");
    }

    return 0;
}
