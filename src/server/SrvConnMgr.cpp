/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief          SrvConnMgr object constructor
 * @param csk      The connection socket's file descriptor
 * @param ip       The connection endpoint's IP address
 * @param port     The connection endpoint's port
 * @param name     The client's name associated with this connection
 * @param tmpDir   The connection's temporary directory
 * @param srvCert  The server's X.509 certificate
 * @param _poolDir The client's pool directory
 */
SrvConnMgr::SrvConnMgr(int csk, char* name, char* tmpDir, X509* srvCert, char* _poolDir)
  : ConnMgr(csk,name,tmpDir),_srvCert(srvCert), _poolDir(_poolDir), _srvSTSMMgr(nullptr), _srvSessMgr(nullptr)
 { _connState = KEYXCHANGE; }   // On the server-side the connection manager is created when the connection is already established