#ifndef SAFECLOUD_STSMMGR_H
#define SAFECLOUD_STSMMGR_H

/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include "STSMMsg.h"
#include "SafeCloudApp/ConnMgr/ConnMgr.h"

/* Base STSM information used by client and server alike */
class STSMMgr
 {
  protected:

   /* ================================= ATTRIBUTES ================================= */

   // STSM shared cryptographic quantities
   EVP_PKEY*          _myRSALongPrivKey;  // The actor's long-term RSA private key
   EVP_PKEY*          _myDHEKey;          // The actor's ephemeral DH key pair
   EVP_PKEY*          _otherDHEPubKey;    // The other actor's ephemeral DH public key

   /* ============================== PROTECTED METHODS ============================== */

   /* ------------------------------ Object Creation  ------------------------------ */

   /**
    * @brief  Generates an ephemeral DH key pair on 2048 bit for the
    *         local actor using the set of standard DH parameters
    * @return The EVP_PKEY structure holding the local actor's ephemeral DH key pair
    * @throws ERR_OSSL_EVP_PKEY_NEW         EVP_PKEY struct creation failed
    * @throws ERR_OSSL_EVP_PKEY_ASSIGN      EVP_PKEY struct assignment failure
    * @throws ERR_OSSL_EVP_PKEY_CTX_NEW     EVP_PKEY context creation failed
    * @throws ERR_OSSL_EVP_PKEY_KEYGEN_INIT EVP_PKEY key generation initialization failed
    * @throws ERR_OSSL_EVP_PKEY_KEYGEN      EVP_PKEY Key generation failed
    */
   static EVP_PKEY* DHE_2048_Keygen();

   /* ---------------------- Ephemeral Public Keys Utilities ---------------------- */

   /**
    * @brief Prints an actor's ephemeral DH public key on stdout
    * @param EDHPubKey the actor's ephemeral DH public key to be printed
    */
   static void logEDHPubKey(EVP_PKEY* EDHPubKey);

   /**
    * @brief Writes an actor's ephemeral DH public
    *        key at the specified memory address
    * @param EDHPubKey the actor's ephemeral DH public key to be printed
    * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the actor's ephemeral DH public key into the BIO
    * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the actor's ephemeral DH public key from the BIO
    */
   static void writeEDHPubKey(EVP_PKEY* EDHPubKey,unsigned char* addr);


   /* --------------------------- Session Key Derivation --------------------------- */

   /**
    * @brief Deletes the local actor's private ephemeral DH key
    * @note  This function was defined because an easier method for deleting the private
    *        key component of an EVP_PKEY struct was not found in the OpenSSL API
    * @throws ERR_OSSL_BIO_NEW_FAILED              Memory BIO Initialization Failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the public key into the memory BIO
    * @throws ERR_OSSL_EVP_PKEY_NEW                EVP_PKEY struct creation failed
    */
   void delMyDHEPrivKey();

   /**
    * @brief  Derives the shared AES_128 session key from the local actor's
    *         private and the remote actor's public ephemeral DH keys
    * @param  skey The buffer where to write the resulting AES_128 session key
    * @note   This function assumes the "skey" destination buffer to be large enough to
    *         contain the resulting AES_128 session key (at least AES_128_KEY_SIZE = 16 bytes)
    * @throws ERR_STSM_OTHER_PUBKEY_MISSING        The remote actor's public ephemeral DH key is missing
    * @throws ERR_OSSL_EVP_PKEY_CTX_NEW            EVP_PKEY context creation failed
    * @throws ERR_OSSL_EVP_PKEY_DERIVE_INIT        Key derivation context initialization failed
    * @throws ERR_OSSL_EVP_PKEY_DERIVE_SET_PEER    Failed to set the remote actor's public key in the key derivation context
    * @throws ERR_OSSL_EVP_PKEY_DERIVE             Shared secret derivation failed
    * @throws ERR_OSSL_BIO_NEW_FAILED              Memory BIO Initialization Failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the public key into the memory BIO
    * @throws ERR_OSSL_EVP_PKEY_NEW                EVP_PKEY struct creation failed
    * @throws ERR_OSSL_EVP_MD_CTX_NEW              EVP_MD context creation failed
    * @throws ERR_OSSL_EVP_DIGEST_INIT             EVP_MD digest initialization failed
    * @throws ERR_OSSL_EVP_DIGEST_UPDATE           EVP_MD digest update failed
    * @throws ERR_OSSL_EVP_DIGEST_FINAL            EVP_MD digest final failed
    * @throws ERR_MALLOC_FAILED                    malloc() failed
    */
   void deriveAES128SKey(unsigned char* skey);

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

   /* ------------------- Ephemeral Public Keys Public Utilities ------------------- */

   /**
    * @brief Prints the local actor's ephemeral DH public key on stdout
    */
   void logMyEDHPubKey();

   /**
    * @brief Prints the remote actor's ephemeral DH public key on stdout
    */
   void logOtherEDHPubKey();

   /**
    * @brief Writes the local actor's ephemeral DH
    *        public key at the specified memory address
    * @throws ERR_STSM_MY_PUBKEY_MISSING           The local actor's ephemeral DH public key is missing
    * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the local actor's ephemeral DH public key into the BIO
    * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the local actor's ephemeral DH public key from the BIO
    */
   void writeMyEDHPubKey(unsigned char* addr);

   /**
    * @brief Writes the remote actor's ephemeral DH
    *        public key at the specified memory address
    * @throws ERR_STSM_MY_PUBKEY_MISSING           The remote actor's ephemeral DH public key is missing
    * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
    * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the remote actor's ephemeral DH public key into the BIO
    * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the remote actor's ephemeral DH public key from the BIO
    */
   void writeOtherEDHPubKey(unsigned char* addr);
 };


#endif //SAFECLOUD_STSMMGR_H