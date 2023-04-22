#include <arpa/inet.h>
#include <chrono>
#include <csignal>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

constexpr int PORT = 12345;
constexpr int BUFFER_SIZE = 1024;

using SignalHandler = std::function<void(int)>;

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

void install_signal_handler(int signal_number, SignalHandler handler)
{
    struct sigaction action;
    action.sa_sigaction = signal_handler_wrapper;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    sigaction(signal_number, &action, nullptr);

    signal_handler_wrapper(0, nullptr, &handler);
}

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
    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_sock < 0)
    {
        std::cerr << "Socket creation failed." << std::endl;
        return EXIT_FAILURE;
    }

    install_signal_handler(SIGINT, [&server_sock](int signal_number) {
        std::cout << "Received signal " << signal_number << ", terminating..." << std::endl;
        close(server_sock);
        exit(signal_number);
    });

    sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(server_sock, (sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        std::cerr << "Binding failed." << std::endl;
        close(server_sock);
        return EXIT_FAILURE;
    }

    if (listen(server_sock, SOMAXCONN) < 0)
    {
        std::cerr << "Listening failed." << std::endl;
        close(server_sock);
        return EXIT_FAILURE;
    }

    std::vector<std::future<void>> futures;

    while (true)
    {
        sockaddr_in client_addr;
        socklen_t client_addr_size = sizeof(client_addr);
        int client_sock = accept(server_sock, (sockaddr *)&client_addr, &client_addr_size);

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

    close(server_sock);
    return EXIT_SUCCESS;
}
