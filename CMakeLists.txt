cmake_minimum_required(VERSION 3.23)  # Minimum CMake version
project(SafeCloud)                    # Project name
set(CMAKE_CXX_STANDARD 14)            # C++ standard

# Includes
include_directories(src/common)

# Linked Libraries
link_libraries(crypto)

# Debug mode
if (DEBUG_MODE)
    add_definitions(-DDEBUG_MODE=1)
endif (DEBUG_MODE)

# Executable targets (client and server)
add_executable(client src/client/client_main.cpp src/common/scode.h src/common/ConnMgr/STSMMgr/STSMMgr.cpp src/common/ConnMgr/STSMMgr/STSMMgr.h src/common/ansi_colors.h src/client/client_loop.cpp src/client/client_utils.cpp src/common/errlog.h src/common/utils.cpp src/common/utils.h src/common/sClient_old/sClient.cpp src/common/sClient_old/sClient.h src/common/crypto_algs/dh.cpp src/common/crypto_algs/dh.h src/client/Client/CliConnMgr/CliSTSMMgr/CliSTSMMgr.cpp src/client/Client/CliConnMgr/CliSTSMMgr/CliSTSMMgr.h src/client/Client/Client.cpp src/client/Client/Client.h src/common/ConnMgr/ConnMgr.cpp src/common/ConnMgr/ConnMgr.h src/common/ConnMgr/SessMgr/SessMgr.cpp src/common/ConnMgr/SessMgr/SessMgr.h src/client/Client/CliConnMgr/CliSessMgr/CliSessMgr.cpp src/client/Client/CliConnMgr/CliSessMgr/CliSessMgr.h src/client/Client/CliConnMgr/CliConnMgr.cpp src/client/Client/CliConnMgr/CliConnMgr.h src/common/errlog.cpp src/client/client_utils.h)
add_executable(server src/server/server_main.cpp src/server/client_old.h src/common/scode.h src/common/ConnMgr/STSMMgr/STSMMgr.cpp src/common/ConnMgr/STSMMgr/STSMMgr.h src/common/ansi_colors.h src/server/client.old.cpp src/common/utils.cpp src/common/utils.h src/server/server_loop.cpp src/common/sClient_old/sClient.cpp src/common/sClient_old/sClient.h src/common/crypto_algs/dh.cpp src/common/crypto_algs/dh.h src/server/Server/SrvConnMgr/SrvSTSMMgr/SrvSTSMMgr.cpp src/server/Server/SrvConnMgr/SrvSTSMMgr/SrvSTSMMgr.h src/common/ConnMgr/ConnMgr.cpp src/common/ConnMgr/ConnMgr.h src/common/ConnMgr/SessMgr/SessMgr.cpp src/common/ConnMgr/SessMgr/SessMgr.h src/server/Server/SrvConnMgr/SrvSessMgr/SrvSessMgr.cpp src/server/Server/SrvConnMgr/SrvSessMgr/SrvSessMgr.h src/server/Server/SrvConnMgr/SrvConnMgr.cpp src/server/Server/SrvConnMgr/SrvConnMgr.h src/server/Server/Server.cpp src/server/Server/Server.h src/common/errlog.cpp)

# Client Target Properties
set_target_properties(client
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/client"
        )

# Server Target Properties
set_target_properties(server
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "../release/server"
        )