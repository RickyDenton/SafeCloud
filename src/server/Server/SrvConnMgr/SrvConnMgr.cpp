/* SafeCloud Server Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvConnMgr.h"
#include "errlog.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */


/**
 * @brief          SrvConnMgr object constructor
 * @param csk      The connection socket's file descriptor
 * @param guestIdx The connected client's temporary identifier
 * @param srvCert  The server's X.509 certificate
 */
SrvConnMgr::SrvConnMgr(int csk, unsigned int guestIdx, X509* srvCert) : ConnMgr(csk,new std::string("Guest" + std::to_string(guestIdx)),nullptr),
                                                                        _srvCert(srvCert), _poolDir(nullptr), _srvSTSMMgr(nullptr), _srvSessMgr(nullptr)
 { LOG_INFO("\"" + *_name + "\" has connected") }


/**
 * @brief SrvConnMgr object destructor, which safely deletes
 *        the server-specific connection sensitive information
 */
SrvConnMgr::~SrvConnMgr()
 {
  LOG_INFO("\"" + *_name + "\" has disconnected")

  // Delete server's STSM key handshake manager and session manager
  delete _srvSTSMMgr;
  delete _srvSessMgr;

  // If set, safely delete the client's pool directory path
  if(_poolDir != nullptr)
   OPENSSL_cleanse(_poolDir, _poolDir->length()+1);

  // NOTE: The server's certificate _srvCERT is NOT deleted, as it is reused across multiple client connections
 }