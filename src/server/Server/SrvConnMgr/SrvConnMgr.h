#ifndef SAFECLOUD_SRVCONNMGR_H
#define SAFECLOUD_SRVCONNMGR_H

/* SafeCloud Server Connection Manager  */

#include "ConnMgr/ConnMgr.h"
#include "SrvSTSMMgr/SrvSTSMMgr.h"
#include "SrvSessMgr/SrvSessMgr.h"
#include <openssl/evp.h>
#include <unordered_map>

class SrvConnMgr : public ConnMgr
 {
  private:

    /* ------------------------- Attributes ------------------------- */
    X509*        _srvCert;   // The server's X.509 certificate
    std::string* _poolDir;   // The client's pool directory

    SrvSTSMMgr* _srvSTSMMgr;  // The server's STSM key handshake manager
    SrvSessMgr* _srvSessMgr;  // The server's session manager

  public:

   /* ================= Constructors and Destructor ================= */

   /**
    * @brief          SrvConnMgr object constructor
    * @param csk      The connection socket's file descriptor
    * @param guestIdx The connected client's temporary identifier
    * @param srvCert  The server's X.509 certificate
    */
   SrvConnMgr(int csk, unsigned int guestIdx, X509* srvCert);

   /**
    * @brief SrvConnMgr object destructor, which safely deletes
    *        the server-specific connection sensitive information
    */
   ~SrvConnMgr();

  /* ======================== Other Methods ======================== */
  // TODO
 };


/* ============================== TYPE DEFINITIONS ============================== */

// An unordered map mapping the file descriptors of open connection sockets with
// their associated srvConnMgr object, and thus a client connected with the server
typedef std::unordered_map<int,SrvConnMgr*> connMap;

// connMap type iterator
typedef std::unordered_map<int,SrvConnMgr*>::iterator connMapIt;

#endif //SAFECLOUD_SRVCONNMGR_H
