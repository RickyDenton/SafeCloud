cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)


include_directories(src/common)

add_executable(client src/client/client_init.cpp src/common/scode.h src/common/STSM/STSMData.cpp src/common/STSM/STSMData.h src/common/colors.h src/client/client_loop.cpp src/client/client_utils.cpp src/common/errlog.h src/common/utils.cpp src/common/utils.h src/common/sClient/sClient.cpp src/common/sClient/sClient.h src/common/OpenSSL/dh.cpp src/common/OpenSSL/dh.h src/common/STSM/STSMClientData.cpp src/common/STSM/STSMClientData.h src/common/STSM/STSMCliData.cpp src/common/STSM/STSMCliData.h)
add_executable(server src/server/server_init.cpp src/server/client.h src/common/scode.h src/common/STSM/STSMData.cpp src/common/STSM/STSMData.h src/common/colors.h src/server/client.cpp src/common/utils.cpp src/common/utils.h src/server/server_loop.cpp src/common/sClient/sClient.cpp src/common/sClient/sClient.h src/common/OpenSSL/dh.cpp src/common/OpenSSL/dh.h src/common/STSM/STSMSrvData.cpp src/common/STSM/STSMSrvData.h)


set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )