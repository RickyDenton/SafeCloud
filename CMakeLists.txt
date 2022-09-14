cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)


include_directories(src/common)

add_executable(client src/client/client_main.cpp src/common/safecloud/scode.h src/common/crypto/STSM.cpp src/common/crypto/STSM.h src/common/safecloud/scolors.h src/common/safecloud/sutils.cpp src/common/safecloud/sutils.h)
add_executable(server src/server/server_main.cpp src/server/clients/client.h src/common/safecloud/scode.h src/server/clients/guest.cpp src/server/clients/guest.h src/common/crypto/STSM.cpp src/common/crypto/STSM.h src/server/clients/user.cpp src/server/clients/user.h src/common/safecloud/scolors.h)


set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )