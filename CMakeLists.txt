cmake_minimum_required(VERSION 3.23)
project(SafeCloud)

set(CMAKE_CXX_STANDARD 14)


include_directories(src/common)

add_executable(client src/client/client_init.cpp src/common/scode.h src/common/STSMMgr.cpp src/common/STSMMgr.h src/common/colors.h src/client/client_loop.cpp src/client/client_utils.cpp src/common/errlog.h src/common/utils.cpp src/common/utils.h src/common/sClient_old/sClient.cpp src/common/sClient_old/sClient.h src/common/crypto_algs/dh.cpp src/common/crypto_algs/dh.h src/client/CliSTSMMgr.cpp src/client/CliSTSMMgr.h src/client/Client.cpp src/client/Client.h src/common/ConnMgr.cpp src/common/ConnMgr.h src/common/SessMgr.cpp src/common/SessMgr.h src/client/CliSessMgr.cpp src/client/CliSessMgr.h src/client/CliConnMgr.cpp src/client/CliConnMgr.h)
add_executable(server src/server/server_init.cpp src/server/client_old.h src/common/scode.h src/common/STSMMgr.cpp src/common/STSMMgr.h src/common/colors.h src/server/client.old.cpp src/common/utils.cpp src/common/utils.h src/server/server_loop.cpp src/common/sClient_old/sClient.cpp src/common/sClient_old/sClient.h src/common/crypto_algs/dh.cpp src/common/crypto_algs/dh.h src/server/SrvSTSMMgr.cpp src/server/SrvSTSMMgr.h src/common/ConnMgr.cpp src/common/ConnMgr.h src/common/SessMgr.cpp src/common/SessMgr.h src/server/SrvSessMgr.cpp src/server/SrvSessMgr.h)


set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )