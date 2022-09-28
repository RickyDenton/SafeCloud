#ifndef SAFECLOUD_SRVSTSMMGR_H
#define SAFECLOUD_SRVSTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Server Manager */

#include "ConnMgr/STSMMgr/STSMMgr.h"

// Forward Declaration
class SrvConnMgr;

class SrvSTSMMgr : public STSMMgr
 {
   private:

    // STSM Server States
    enum STSMSrvState
     {
      // The server has not yet received the client's 'hello' message
      WAITING_CLI_HELLO,

      // The server has sent its 'auth' message and is awaiting the client's one
      WAITING_CLI_AUTH
     };

    /* ================================= ATTRIBUTES ================================= */
    enum STSMSrvState _stsmSrvState;  // Current server state in the STSM key exchange protocol
    SrvConnMgr&       _srvConnMgr;    // The parent SrvConnMgr instance managing this object
    X509*             _srvCert;       // The server's X.509 certificate

    /* =============================== PRIVATE METHODS =============================== */


    void recv_client_hello();
    void recv_client_auth();

    void checkSrvSTSMError();

   public:

    /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

    /**
     * @brief                  SrvSTSMMgr object constructor
     * @param myRSALongPrivKey The server's long-term RSA key pair
     * @param srvConnMgr       The parent SrvConnMgr instance managing this object
     * @param srvCert          The server's X.509 certificate
     */
    SrvSTSMMgr(EVP_PKEY* myRSALongPrivKey, SrvConnMgr& srvConnMgr, X509* srvCert);

    // Same destructor of the STSMMgr base class

    /* ============================= OTHER PUBLIC METHODS ============================= */

    // Returns true when switching to session mode
    bool STSMMsgHandler();

  // TODO:
  //
  // NOTE: 1) All return the success of the operation TODO: exceptions?
  //       2) All check for the STSMError message before doing their thing
  //
  // bool rcvHello();
  // bool sendSrvAuth();
  // bool recvCliAuth();
  // bool sendSrvOK();
 };

#endif //SAFECLOUD_SRVSTSMMGR_H
