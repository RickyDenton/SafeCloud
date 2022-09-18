/* SafeCloud Client Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "CliConnMgr.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief       Connection Manager object constructor
 * @param csk   The connection socket's file descriptor
 * @param ip    The connection endpoint's IP address
 * @param port  The connection endpoint's port
 */
CliConnMgr::CliConnMgr(int csk, char* ip, int port, char* name, char* tmpDir, X509_STORE* cliStore, char* downDir)
                       : ConnMgr(csk,ip,port,name,tmpDir), _cliStore(cliStore), _downDir(downDir)
 {}