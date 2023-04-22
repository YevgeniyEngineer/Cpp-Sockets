cmake_minimum_required(VERSION 3.18 FATAL_ERROR)

project(networking_protocols)

add_executable(udp_client udp_client.cpp)

add_executable(udp_server udp_server.cpp)