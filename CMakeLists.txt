cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)


include_directories(src/common)

add_executable(client src/client/client_init.cpp src/common/scode.h src/common/STSM.cpp src/common/STSM.h src/common/colors.h src/client/client_loop.cpp src/client/client_utils.cpp src/common/errlog.h src/common/utils.cpp src/common/utils.h)
add_executable(server src/server/server_init.cpp src/server/client.h src/common/scode.h src/common/STSM.cpp src/common/STSM.h src/common/colors.h src/server/client.cpp src/common/utils.cpp src/common/utils.h src/server/server_loop.cpp)


set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )