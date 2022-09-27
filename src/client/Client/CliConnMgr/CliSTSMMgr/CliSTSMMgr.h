#ifndef SAFECLOUD_CLISTSMMGR_H
#define SAFECLOUD_CLISTSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager */

#include "ConnMgr/STSMMgr/STSMMgr.h"

// Forward Declaration
class CliConnMgr;

class CliSTSMMgr : public STSMMgr
 {
  private:

   // STSM Client States
   enum STSMCliState
    {
     // The client has yet to send its 'hello' message
     INIT,

     // The client has sent its 'hello' message and is awaiting the server's 'auth' message
     WAITING_SRV_AUTH,

     // The client has sent its 'auth' message and is awaiting the server 'ok' message
     WAITING_SRV_OK
    };

   /* ================================= ATTRIBUTES ================================= */
   enum STSMCliState _stsmCliState;  // Current client state in the STSM key exchange protocol
   CliConnMgr&       _cliConnMgr;    // The parent CliConnMgr instance managing this object
   X509_STORE*       _cliStore;      // The client's already-initialized X.509 certificate store used for validating the server's signature

   /* =============================== PRIVATE METHODS =============================== */

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief                  CliSTSMMgr object constructor
    * @param myRSALongPrivKey The client's long-term RSA key pair
    * @param cliConnMgr       A reference to the parent CliConnMgr object
    * @param cliStore         The client's X.509 certificates store
    */
   CliSTSMMgr(EVP_PKEY* myRSALongPrivKey, CliConnMgr& cliConnMgr, X509_STORE* cliStore);

   // Same destructor of the STSMMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   void startSTSM();

   // TODO:
   //
   // NOTE: 1) All return the success of the operation TODO: exceptions?
   //       2) All check for the STSMError message before doing their thing
   //
   // bool sendHello();
   // bool recvSrvAuth ();
   // bool sendCliAuth();
   // bool recvSrvOK();
 };


#endif //SAFECLOUD_CLISTSMMGR_H
