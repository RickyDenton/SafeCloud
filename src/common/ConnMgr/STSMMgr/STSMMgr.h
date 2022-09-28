#ifndef SAFECLOUD_STSMMGR_H
#define SAFECLOUD_STSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "STSMMsg.h"
#include "ConnMgr/ConnMgr.h"


// TODO: WRITE STSM DESCRIPTION

/*v
 *  The server authentication message comprises:
 *
 *  1) The server's ephemeral DH public key "Ys"
 *  2) The server signature of the concatenation of both ephemeral public
 *     keys encrypted with the resulting session key "{<Yc||Ys>privk_srv}k"
 *  3) The server's certificate "srvCert"
 */


/* Base STSM information used by client and server alike */
class STSMMgr
 {
  protected:

   /* ================================= ATTRIBUTES ================================= */

   // STSM shared cryptographic quantities
   EVP_PKEY*          _myRSALongPrivKey;  // The actor's long-term RSA private key
   EVP_PKEY*          _myDHEKey;          // The actor's ephemeral DH key pair
   EVP_PKEY*          _otherDHEPubKey;    // The other actor's ephemeral DH public key

   /* =============================== PRIVATE METHODS =============================== */
   /* ============================== PROTECTED METHODS ============================== */


   /**
    * @brief  Generates an ephemeral DH key pair on 2048 bit using the set of standard DH parameters
    * @return The address of the EVP_PKEY structure holding the newly generated ephemeral DH key pair
    */
   static EVP_PKEY* DHE_2048_Keygen();

   static void checkSTSMError(STSMMsgType msgType);

   static void sendSTSMErrorMsg(STSMMsg& stsmErrMsg, STSMMsgType errCode, ConnMgr& connMgr);


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief                  STSMMgr object constructor
    * @param myRSALongPrivKey The actor's long-term RSA private key
    * @note The constructor initializes the actor's ephemeral DH 2048 key pair
    */
   explicit STSMMgr(EVP_PKEY* myRSALongPrivKey);

   /**
    * @brief STSMMgr object destructor, which safely deletes its sensitive attributes
    */
   ~STSMMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

  // TODO:
  // void sendSTSMError(int csk,int buf,int bufSize);     // Inform the other that the STSM handshake has failed, close the connection
 };


#endif //SAFECLOUD_STSMMGR_H
