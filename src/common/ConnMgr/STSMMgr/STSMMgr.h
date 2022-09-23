#ifndef SAFECLOUD_STSMMGR_H
#define SAFECLOUD_STSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>


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

   /* ------------------------- Attributes ------------------------- */

   // Connection information
   const int _csk;                        // The connection socket on which to perform the STSM protocol
   char*     _name;                       // The client's username

   // Buffer for sending and receiving STSM messages
   unsigned char*     _buf;               // STSM Buffer
   unsigned int       _bufInd;            // Index to the first available byte in the STSM buffer
   const unsigned int _bufSize;           // STSM Buffer size (must be >= 4MB)

   // Cryptographic quantities
   EVP_PKEY*          _myRSALongPrivKey;  // The actor's long-term RSA private key
   EVP_PKEY*          _myDHEKey;          // The actor's ephemeral DH key pair
   EVP_PKEY*          _otherDHEPubKey;    // The other actor's ephemeral DH public key
   unsigned char*     _iv;                // The initialization vector of implicit IV_SIZE = 12 bytes (96 bit, AES_GCM)
   unsigned char*     _skey;              // The symmetric key of implicit SKEY_SIZE = 16 bytes (128 bit, AES_GCM)

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   STSMMgr(int csk, char* name, unsigned char* buf, unsigned int bufSize, EVP_PKEY* myRSALongPrivKey, unsigned char* iv, unsigned char* skey);
   ~STSMMgr();

  /* ------------------------------- Other Methods ------------------------------- */

  // TODO:
  // void sendSTSMError(int csk,int buf,int bufSize);     // Inform the other that the STSM handshake has failed, close the connection
 };


#endif //SAFECLOUD_STSMMGR_H
