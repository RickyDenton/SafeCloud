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
add_executable(client src/client/client_main.cpp src/common/errCodes/execErrCodes/execErrCodes.h src/common/ConnMgr/STSMMgr/STSMMgr.cpp src/common/ConnMgr/STSMMgr/STSMMgr.h src/common/errCodes/ansi_colors.h src/client/client_utils.cpp src/common/utils.cpp src/common/utils.h src/client/Client/CliConnMgr/CliSTSMMgr/CliSTSMMgr.cpp src/client/Client/CliConnMgr/CliSTSMMgr/CliSTSMMgr.h src/client/Client/Client.cpp src/client/Client/Client.h src/common/ConnMgr/ConnMgr.cpp src/common/ConnMgr/ConnMgr.h src/common/ConnMgr/SessMgr/SessMgr.cpp src/common/ConnMgr/SessMgr/SessMgr.h src/client/Client/CliConnMgr/CliSessMgr/CliSessMgr.cpp src/client/Client/CliConnMgr/CliSessMgr/CliSessMgr.h src/client/Client/CliConnMgr/CliConnMgr.cpp src/client/Client/CliConnMgr/CliConnMgr.h src/client/client_utils.h src/common/ConnMgr/STSMMgr/STSMMsg.h src/common/ConnMgr/IV/IV.cpp src/common/ConnMgr/IV/IV.h src/common/ossl_crypto/DigSig.cpp src/common/ossl_crypto/DigSig.h src/common/ossl_crypto/AES_128_CBC.cpp src/common/ossl_crypto/AES_128_CBC.h src/common/errCodes/sessErrCodes/sessErrCodes.h src/common/errCodes/errCodes.h src/common/errCodes/errCodes.cpp src/common/errCodes/execErrCodes/execErrCodes.cpp src/common/errCodes/sessErrCodes/sessErrCodes.cpp src/common/DirInfo/DirInfo.cpp src/common/DirInfo/DirInfo.h src/common/DirInfo/FileInfo/FileInfo.cpp src/common/DirInfo/FileInfo/FileInfo.h src/common/ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.cpp src/common/ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h src/common/ConnMgr/SessMgr/ProgressBar/ProgressBar.cpp src/common/ConnMgr/SessMgr/ProgressBar/ProgressBar.h)
add_executable(server src/server/server_main.cpp src/common/errCodes/execErrCodes/execErrCodes.h src/common/ConnMgr/STSMMgr/STSMMgr.cpp src/common/ConnMgr/STSMMgr/STSMMgr.h src/common/errCodes/ansi_colors.h src/common/utils.cpp src/common/utils.h src/server/Server/SrvConnMgr/SrvSTSMMgr/SrvSTSMMgr.cpp src/server/Server/SrvConnMgr/SrvSTSMMgr/SrvSTSMMgr.h src/common/ConnMgr/ConnMgr.cpp src/common/ConnMgr/ConnMgr.h src/common/ConnMgr/SessMgr/SessMgr.cpp src/common/ConnMgr/SessMgr/SessMgr.h src/server/Server/SrvConnMgr/SrvSessMgr/SrvSessMgr.cpp src/server/Server/SrvConnMgr/SrvSessMgr/SrvSessMgr.h src/server/Server/SrvConnMgr/SrvConnMgr.cpp src/server/Server/SrvConnMgr/SrvConnMgr.h src/server/Server/Server.cpp src/server/Server/Server.h src/common/ConnMgr/STSMMgr/STSMMsg.h src/common/ConnMgr/IV/IV.cpp src/common/ConnMgr/IV/IV.h src/common/ossl_crypto/DigSig.cpp src/common/ossl_crypto/DigSig.h src/common/ossl_crypto/AES_128_CBC.cpp src/common/ossl_crypto/AES_128_CBC.h src/common/errCodes/sessErrCodes/sessErrCodes.h src/common/errCodes/errCodes.h src/common/errCodes/errCodes.cpp src/common/errCodes/execErrCodes/execErrCodes.cpp src/common/errCodes/sessErrCodes/sessErrCodes.cpp src/common/DirInfo/DirInfo.cpp src/common/DirInfo/DirInfo.h src/common/DirInfo/FileInfo/FileInfo.cpp src/common/DirInfo/FileInfo/FileInfo.h src/common/ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.cpp src/common/ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h src/common/ConnMgr/SessMgr/ProgressBar/ProgressBar.cpp src/common/ConnMgr/SessMgr/ProgressBar/ProgressBar.h)

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