#ifndef SAFECLOUD_SRVCONNMGR_H
#define SAFECLOUD_SRVCONNMGR_H

/* SafeCloud Server Connection Manager  */

#include "ConnMgr/ConnMgr.h"
#include "SrvSTSMMgr/SrvSTSMMgr.h"
#include "SrvSessMgr/SrvSessMgr.h"
#include <openssl/evp.h>
#include <unordered_map>

class SrvConnMgr : ConnMgr
 {
  private:

    /* ------------------------- Attributes ------------------------- */
    X509*        _srvCert;   // The server's X.509 certificate
    std::string& _poolDir;   // The client's pool directory

    SrvSTSMMgr* _srvSTSMMgr;  // The server's STSM key handshake manager
    SrvSessMgr* _srvSessMgr;  // The server's session manager

  public:

   /* ================= Constructors and Destructor ================= */
   SrvConnMgr(int csk, std::string& name, std::string& tmpDir, X509* srvCert, std::string& _poolDir);
   // Same destructor of the ConnMgr base class

  /* ======================== Other Methods ======================== */
  // TODO
 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map mapping the file descriptors of open connection sockets with
// their associated srvConnMgr object, and thus a client connected with the server
typedef std::unordered_map<int,SrvConnMgr*> cliMap;

// cliMap type iterator
typedef std::unordered_map<int,SrvConnMgr*>::iterator cliMapIt;

#endif //SAFECLOUD_SRVCONNMGR_H
