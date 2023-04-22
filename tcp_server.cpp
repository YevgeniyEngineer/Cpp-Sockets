
#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <string>
#include <vector>

extern "C"
{
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
}

constexpr int PORT = 12345;
constexpr int BUFFER_SIZE = 1024;

// Define SignalHandler as a function taking an integer as an argument.
using SignalHandler = std::function<void(int)>;

// Signal handling wrapper function to set the correct handler function.
void signal_handler_wrapper(int signal_number, siginfo_t *info, void *context)
{
    static SignalHandler handler;
    if (info)
    {
        handler(signal_number);
    }
    else
    {
        handler = *reinterpret_cast<SignalHandler *>(context);
    }
}

// Function to install the custom signal handler.
void install_signal_handler(int signal_number, SignalHandler handler)
{
    struct sigaction action;
    action.sa_sigaction = signal_handler_wrapper;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, nullptr);

    signal_handler_wrapper(0, nullptr, &handler);
}

// Handle a new client connection.
void handle_client(int client_sock, sockaddr_in client_addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    int client_port = ntohs(client_addr.sin_port);

    char buffer[BUFFER_SIZE];
    ssize_t received_bytes;
    while ((received_bytes = recv(client_sock, buffer, BUFFER_SIZE, 0)) > 0)
    {
        std::string message(buffer, received_bytes);
        std::cout << "Received from " << client_ip << ":" << client_port << " - " << message << std::endl;
    }

    close(client_sock);
}

int main(int argc, const char **argv)
{
    // Create a TCP socket.
    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0)
    {
        std::cerr << "Socket creation failed." << std::endl;
        return EXIT_FAILURE;
    }

    // Install signal handler for SIGINT to close the socket and exit the application.
    install_signal_handler(SIGINT, [&server_sock](int signal_number) {
        std::cout << "Received signal " << signal_number << ", terminating..." << std::endl;
        close(server_sock);
        exit(signal_number);
    });

    // Set up the server address.
    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket to the server address.
    if (bind(server_sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Binding failed." << std::endl;
        close(server_sock);
        return EXIT_FAILURE;
    }

    // Prepare to accept connections.
    if (listen(server_sock, SOMAXCONN) < 0)
    {
        std::cerr << "Listening failed." << std::endl;
        close(server_sock);
        return EXIT_FAILURE;
    }

    // List of futures to handle connections concurrently.
    std::vector<std::future<void>> futures;

    while (true)
    {
        // Await a connection from a new client.
        sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        int client_sock = accept(server_sock, (sockaddr *)&client_addr, &client_addr_size);

        // Handle the new client in a separate thread.
        if (client_sock >= 0)
        {
            std::future<void> future = std::async(std::launch::async, handle_client, client_sock, client_addr);
            futures.push_back(std::move(future));
        }
    }

    // Wait for all client handling tasks to complete before exiting
    for (auto &future : futures)
    {
        future.wait();
    }

    // Close the socket and exit the application.
    close(server_sock);
    return EXIT_SUCCESS;
}
