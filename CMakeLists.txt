cmake_minimum_required(VERSION 3.18 FATAL_ERROR)

project(networking_protocols)

set(CMAKE_CXX_STANDARD 17)

add_executable(udp_client udp_client.cpp)

add_executable(udp_server udp_server.cpp)

add_executable(tcp_client tcp_client.cpp)

add_executable(tcp_server tcp_server.cpp)