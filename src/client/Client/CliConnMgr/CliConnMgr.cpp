/* SafeCloud Client Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "CliConnMgr.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief          CliConnMgr object constructor
 * @param csk      The connection socket's file descriptor
 * @param ip       The connection endpoint's IP address
 * @param port     The connection endpoint's port
 * @param name     The client's name associated with this connection
 * @param tmpDir   The connection's temporary directory
 * @param cliStore The client's X.509 certificate store used for validating the server's signature
 * @param _downDir The client's download directory
 */
CliConnMgr::CliConnMgr(int csk, std::string* name, std::string* tmpDir, X509_STORE* cliStore, std::string* downDir)
                       : ConnMgr(csk,name,tmpDir), _cliStore(cliStore), _downDir(downDir), _cliSTSMMgr(nullptr), _cliSessMgr(nullptr)
 {}