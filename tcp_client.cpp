#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <iostream>
#include <string>
#include <thread>

extern "C"
{
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
}

constexpr const char *SERVER_IP = "127.0.0.1";
constexpr int PORT = 12345;
constexpr int MAX_RETRIES = 10;   // Maximum number of retries until giving up
constexpr int RETRY_INTERVAL = 3; // Retry interval in seconds

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
    // Create a TCP socket.
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Attempt to connect to the server.
    int retries = 0;
    while (retries < MAX_RETRIES)
    {
        if (connect(sock, (sockaddr *)&server_addr, sizeof(server_addr)) == 0)
        {
            break;
        }

        ++retries;
        std::cout << "Connection failed, retrying (" << retries << " of " << MAX_RETRIES << ")..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(RETRY_INTERVAL));
    }

    // If could not connect, close the socket.
    if (retries == MAX_RETRIES)
    {
        std::cerr << "Failed to connect after " << MAX_RETRIES << " retries. Giving up." << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    // Read messages from standard input and send them to the server.
    std::string message;
    while (std::getline(std::cin, message))
    {
        send(sock, message.c_str(), message.length(), 0);
    }

    // Close the socket and exit the application.
    close(sock);
    return EXIT_SUCCESS;
}
