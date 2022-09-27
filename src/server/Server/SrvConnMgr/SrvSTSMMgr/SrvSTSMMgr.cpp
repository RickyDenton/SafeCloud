/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "SrvSTSMMgr.h"

/* =============================== PRIVATE METHODS =============================== */
// TODO

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                  SrvSTSMMgr object constructor
 * @param myRSALongPrivKey The server's long-term RSA key pair
 * @param srvConnMgr       The parent SrvConnMgr instance managing this object
 * @param srvCert          The server's X.509 certificate
 */
SrvSTSMMgr::SrvSTSMMgr(EVP_PKEY* myRSALongPrivKey, SrvConnMgr& srvConnMgr, X509* srvCert)
                       : STSMMgr(myRSALongPrivKey), _stsmSrvState(WAITING_CLI_HELLO), _srvConnMgr(srvConnMgr), _srvCert(srvCert)
 {}

/* ============================ OTHER PUBLIC METHODS ============================ */