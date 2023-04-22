#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>

extern "C"
{
#include <arpa/inet.h>
#include <sys/select.h>
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

int main(int argc, const char **argv)
{
    // Create a UDP socket.
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        std::cerr << "Socket creation failed." << std::endl;
        return EXIT_FAILURE;
    }

    // Install signal handler for SIGINT to close the socket and exit the application.
    install_signal_handler(SIGINT, [&sock](int signal_number) {
        std::cout << "Received signal " << signal_number << ", terminating..." << std::endl;
        close(sock);
        exit(signal_number);
    });

    // Set up the server address.
    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Bind the socket to the server address.
    if (bind(sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Binding failed." << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    // Buffer to store received messages.
    char buffer[BUFFER_SIZE];

    // Set up the file descriptor set and timeval for select().
    fd_set read_fds;
    struct timeval tv;

    while (true)
    {
        // Initialize the file descriptor set and timeval.
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Call select() to monitor the socket for incoming data.
        int ret = select(sock + 1, &read_fds, nullptr, nullptr, &tv);

        if (ret < 0)
        {
            std::cerr << "Error in select()." << std::endl;
            break;
        }
        else if (ret == 0)
        {
            // Timeout, do something else if needed
            std::cout << "Stamp: " << std::chrono::steady_clock::now().time_since_epoch().count() << ". Timeout ..."
                      << std::endl;
        }
        else
        {
            // Check if the socket has data available to read.
            if (FD_ISSET(sock, &read_fds))
            {
                sockaddr_in client_addr;
                socklen_t client_addr_size = sizeof(client_addr);

                // Receive data from the client and store it in the buffer.
                int received_bytes =
                    recvfrom(sock, buffer, BUFFER_SIZE, 0, (sockaddr *)&client_addr, &client_addr_size);

                if (received_bytes > 0)
                {
                    // Convert the client's IP address and port number to a human-readable format.
                    char client_ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
                    int client_port = ntohs(client_addr.sin_port);

                    // Create a string from the received bytes and print the message along with the client's
                    // information.
                    std::string message(buffer, received_bytes);
                    std::cout << "Received from " << client_ip << ":" << client_port << " - " << message << std::endl;
                }
            }
        }
    }

    // Close the socket and exit the application.
    close(sock);
    return EXIT_SUCCESS;
}
