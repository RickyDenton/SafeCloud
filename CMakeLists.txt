cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)


include_directories(src/common)

add_executable(client src/client/client_main.cpp)
add_executable(server src/server/server_main.cpp)


set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )