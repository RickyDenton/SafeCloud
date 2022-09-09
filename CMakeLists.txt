cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)

add_executable(client
        Client/client_main.cpp)

add_executable(server
        Server/server_main.cpp)
