/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "STSMMgr.h"
#include "errlog.h"
#include <string.h>

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
EVP_PKEY* STSMMgr::DHE_2048_Keygen()
 {
  EVP_PKEY*     DHParams;          // Used to store default DH parameters
  EVP_PKEY_CTX* DHGenCtx;          // DH key generation context
  EVP_PKEY*     DHEKey = nullptr;  // The resulting actor's ephemeral DH key pair

  /* ----------------- DH 2048 Default Parameters Initialization ----------------- */

  // Allocate an EVP_PKEY structure for storing the default DH parameters
  DHParams = EVP_PKEY_new();
  if(DHParams == nullptr)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_NEW,OSSL_ERR_DESC);

  // Initialize the previous EVP_PKEY structure with the default DH parameters
  if(EVP_PKEY_assign(DHParams, EVP_PKEY_DHX, DH_get_2048_256()) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_ASSIGN,OSSL_ERR_DESC);

  /* ------------------- Ephemeral DH 2048 Key Pair Generation ------------------- */

  // Create a key generation context using the previously initialized DH default parameters
  DHGenCtx = EVP_PKEY_CTX_new(DHParams, nullptr);
  if(!DHGenCtx)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the key generation context
  if(EVP_PKEY_keygen_init(DHGenCtx) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_KEYGEN_INIT,OSSL_ERR_DESC);

  // Generate an ephemeral DH 2048 key pair
  if(EVP_PKEY_keygen(DHGenCtx, &DHEKey) != 1)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_KEYGEN,OSSL_ERR_DESC);

  // Free the EVP_PKEY structure containing the default
  // DH parameters and the key generation context
  // TODO: Check, it should be right
  EVP_PKEY_free(DHParams);
  EVP_PKEY_CTX_free(DHGenCtx);

  // Return the actor's ephemeral DH 2048 key pair
  return DHEKey;
 }


/* --------------------------- Public Keys Utilities --------------------------- */

/**
 * @brief Prints an actor's ephemeral DH public key on stdout
 * @param EDHPubKey the actor's ephemeral DH public key to be printed
 */
void STSMMgr::logEDHPubKey(EVP_PKEY* EDHPubKey)
 {
  // The file BIO used for logging the specified ephemeral DH public key to stdout
  BIO* EDHPubKeyBIO;

  // Initialize the file BIO
  EDHPubKeyBIO = BIO_new_fp(stdout, BIO_NOCLOSE);
  if(!EDHPubKeyBIO)
   LOG_SCODE(ERR_OSSL_BIO_NEW_FP_FAILED,OSSL_ERR_DESC);

  // Write the specified public key into the file BIO
  if(EVP_PKEY_print_public(EDHPubKeyBIO, EDHPubKey, 1, NULL) != 1)
   LOG_SCODE(ERR_OSSL_EVP_PKEY_PRINT_PUBLIC_FAILED,OSSL_ERR_DESC);

  // Print to stdout all the available information on the ephemeral public key
  std::cout << EDHPubKeyBIO << std::endl;

  // Free the file BIO
  if(BIO_free(EDHPubKeyBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);
 }


/**
 * @brief Writes an actor's ephemeral DH public
 *        key at the specified memory address
 * @param EDHPubKey the actor's ephemeral DH public key to be printed
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the actor's ephemeral DH public key into the BIO
 * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the actor's ephemeral DH public key from the BIO
 */
void STSMMgr::writeEDHPubKey(EVP_PKEY* EDHPubKey,unsigned char* addr)
 {
  // Initialize a memory BIO for storing the actor's ephemeral DH public key
  BIO* EDHPubKeyBIO = BIO_new(BIO_s_mem());
  if(EDHPubKeyBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Write the actor's ephemeral DH public key to the BIO
  if(PEM_write_bio_PUBKEY(EDHPubKeyBIO, EDHPubKey) != 1)
   THROW_SCODE(ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED,OSSL_ERR_DESC);

  // Write the actor's ephemeral DH public key from the BIO to the specified memory address
  if(BIO_read(EDHPubKeyBIO, addr, DH2048_PUBKEY_PEM_SIZE) <= 0)
   THROW_SCODE(ERR_OSSL_BIO_READ_FAILED,OSSL_ERR_DESC);

  // Free the memory BIO
  if(BIO_free(EDHPubKeyBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);
 }


/* --------------------------- Session Key Derivation --------------------------- */

/**
* @brief Deletes the local actor's private ephemeral DH key
* @note  This function was defined because an easier method for deleting the private
*        key component of an EVP_PKEY struct was not found in the OpenSSL API
* @throws ERR_OSSL_BIO_NEW_FAILED              Memory BIO Initialization Failed
* @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the public key into the memory BIO
* @throws ERR_OSSL_EVP_PKEY_NEW                EVP_PKEY struct creation failed
*/
void STSMMgr::delMyDHEPrivKey()
 {
  // Initialize a memory BIO for storing the local actor's ephemeral DH public key
  BIO* myEDHPubKeyBIO = BIO_new(BIO_s_mem());
  if(myEDHPubKeyBIO == NULL)
   THROW_SCODE(ERR_OSSL_BIO_NEW_FAILED,OSSL_ERR_DESC);

  // Write the local actor's ephemeral DH public key to the BIO
  if(PEM_write_bio_PUBKEY(myEDHPubKeyBIO, _myDHEKey) != 1)
   THROW_SCODE(ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED,OSSL_ERR_DESC);

  // Free the local actor's ephemeral DH key pair
  EVP_PKEY_free(_myDHEKey);

  // Re-initialize the local actor's EVP_PKEY structure
  _myDHEKey = EVP_PKEY_new();
  if(_myDHEKey == nullptr)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_NEW,OSSL_ERR_DESC);

  // Write the local actor's ephemeral DH public key from
  // the memory BIO into the newly created EVP_PKEY structure
  //
  // NOTE: No check is performed here, as the validity of the local actor's
  //       public key is asserted by the PEM_WRITE_BIO_PUBKEY() function
  //
  _myDHEKey = PEM_read_bio_PUBKEY(myEDHPubKeyBIO, NULL,NULL, NULL);

  // Free the memory BIO
  if(BIO_free(myEDHPubKeyBIO) != 1)
   LOG_SCODE(ERR_OSSL_BIO_FREE_FAILED,OSSL_ERR_DESC);
 }


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
void STSMMgr::deriveAES128SKey(unsigned char* skey)
 {
  // Shared secret buffer and size
  unsigned char* sSecret;
  size_t         sSecretSize;

  // Shared secret digest buffer and size (SHA-256)
  unsigned char* sSecretDigest;
  unsigned int   sSecretDigestSize;

  // Key derivation context used for deriving a shared secret from the
  // local actor's private and the remote actor's public ephemeral DH keys
  EVP_PKEY_CTX* sSecretDerCTX;

  // Message Digest context used for hashing
  // the shared secret into a symmetric key
  EVP_MD_CTX* sSecretHashCTX;

  // Ensure both actors' public keys to be available
  if(!_myDHEKey)
   THROW_SCODE(ERR_STSM_MY_PUBKEY_MISSING);
  if(!_otherDHEPubKey)
   THROW_SCODE(ERR_STSM_OTHER_PUBKEY_MISSING);

  /* ----------------- Key Derivation Context Preparation ----------------- */

  // Create the key derivation context
  sSecretDerCTX = EVP_PKEY_CTX_new(_myDHEKey, NULL);
  if(!sSecretDerCTX)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the key derivation context
  if(EVP_PKEY_derive_init(sSecretDerCTX) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_DERIVE_INIT,OSSL_ERR_DESC);

  // Set the remote actor's public key in the key derivation context
  if(EVP_PKEY_derive_set_peer(sSecretDerCTX, _otherDHEPubKey) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_DERIVE_SET_PEER,OSSL_ERR_DESC);

  /* ---------------------- Shared Secret Derivation ---------------------- */

  // Determine the required buffer size for storing the derived shared secret
  if(EVP_PKEY_derive(sSecretDerCTX, NULL, &sSecretSize) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_DERIVE,OSSL_ERR_DESC);

  // Allocate the shared secret buffer
  sSecret = (unsigned char*)(malloc(int(sSecretSize)));
  if(!sSecret)
   THROW_SCODE(ERR_MALLOC_FAILED,"requested size = " + std::to_string(sSecretSize), ERRNO_DESC);

  // Derive the shared secret into its buffer
  if(EVP_PKEY_derive(sSecretDerCTX, sSecret, &sSecretSize) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_PKEY_DERIVE,OSSL_ERR_DESC);

  // Free the key derivation context
  EVP_PKEY_CTX_free(sSecretDerCTX);

  // Delete the local actor's private ephemeral DH key, as from this point on it is no longer necessary
  //
  // NOTE: The following function was defined as an easier method for deleting the
  //       private key component of an EVP_PKEY struct was not found in the OpenSSL API
  delMyDHEPrivKey();

  /*
  // LOG: Shared secret
  printf("Shared Secret: \n");
  BIO_dump_fp(stdout, (const char *)sSecret, (int)sSecretSize);
  printf("\n");
  */

  /* ---------------------- Symmetric Key Derivation ---------------------- */

  // Allocate the shared secret digest buffer so to being
  // capable of storing a SHA-256 digest (256 bits)
  sSecretDigest = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
  if(!sSecretDigest)
   THROW_SCODE(ERR_MALLOC_FAILED,"requested size = " + std::to_string(EVP_MD_size(EVP_sha256())), ERRNO_DESC);

  // Create the message digest context for hashing the shared secret
  sSecretHashCTX = EVP_MD_CTX_new();
  if(!sSecretHashCTX)
   THROW_SCODE(ERR_OSSL_EVP_MD_CTX_NEW,OSSL_ERR_DESC);

  // Initialize the message digest context using SHA-256 as hash function
  if(EVP_DigestInit(sSecretHashCTX, EVP_sha256()) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_DIGEST_INIT,OSSL_ERR_DESC);

  // Pass the derived shared secret to the EVP_DigestUpdate()
  if(EVP_DigestUpdate(sSecretHashCTX, (unsigned char*)sSecret, sSecretSize) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_DIGEST_UPDATE,OSSL_ERR_DESC);

  // Finalize the digest and write it into its buffer
  if(EVP_DigestFinal(sSecretHashCTX, sSecretDigest, &sSecretDigestSize) <= 0)
   THROW_SCODE(ERR_OSSL_EVP_DIGEST_FINAL,OSSL_ERR_DESC);

  // Free the message digest context
  EVP_MD_CTX_free(sSecretHashCTX);

  /*
  // LOG: Shared secret digest in hexadecimal
  printf("Shared secret digest in hexadecimal: \n");
  for(int n=0; sSecretDigest[n] != '\0'; n++)
   printf("%02x", (unsigned char) sSecretDigest[n]);
  printf("\n");
  */

  /* ------------------- AES_128 Session Key Derivation ------------------- */

  // Set the shared session key as the first AES_128_KEY_SIZE = 16 bytes of the shared secret's digest
  memcpy(skey, sSecretDigest, AES_128_KEY_SIZE);

  // Free the shared secret and its digest's buffers
  free(sSecret);
  free(sSecretDigest);

  /*
  // LOG: AES_128 session key in hexadecimal
  printf("AES_128 session key in hexadecimal: ");
  for(int i=0; i < AES_128_KEY_SIZE ; i++)
   printf("%02x", (unsigned char) skey[i]);
  printf("\n");
  */
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                   STSMMgr object constructor
 * @param myRSALongPrivKey  The actor's long-term RSA private key
 * @note The constructor initializes the actor's ephemeral DH 2048 key pair
 */
STSMMgr::STSMMgr(EVP_PKEY* myRSALongPrivKey) : _myRSALongPrivKey(myRSALongPrivKey), _myDHEKey(DHE_2048_Keygen()), _otherDHEPubKey(nullptr)
 {}


/**
 * @brief STSMMgr object destructor, which safely deletes its sensitive attributes
 */
STSMMgr::~STSMMgr()
 {
  // Deallocate both actors' ephemeral keys
  EVP_PKEY_free(_myDHEKey);
  EVP_PKEY_free(_otherDHEPubKey);

  // NOTE: The actor's long-term RSA private key must NOT be
  //       deleted, as it may be reused across multiple connections
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief Prints the local actor's ephemeral DH public key on stdout
 */
void STSMMgr::logMyEDHPubKey()
 {
  // Ensure the local actor's ephemeral DH public key to (still) be present
  if(!_myDHEKey)
   LOG_ERROR("Attempting to print the deallocated local actor ephemeral DH public key")
  else
   logEDHPubKey(_myDHEKey);
 }


/**
 * @brief Prints the remote actor's ephemeral DH public key on stdout
 */
void STSMMgr::logOtherEDHPubKey()
 {
  // Ensure the remote actor's ephemeral DH public key to be present
  if(!_otherDHEPubKey)
   LOG_ERROR("Attempting to print the missing remote actor ephemeral DH public key")
  else
   logEDHPubKey(_otherDHEPubKey);
 }


/**
 * @brief Writes the local actor's ephemeral DH
 *        public key at the specified memory address
 * @throws ERR_STSM_MY_PUBKEY_MISSING           The local actor's ephemeral DH public key is missing
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the local actor's ephemeral DH public key into the BIO
 * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the local actor's ephemeral DH public key from the BIO
 */
void STSMMgr::writeMyEDHPubKey(unsigned char* addr)
 {
  // Ensure the local actor's ephemeral DH public key to be available
  if(!_myDHEKey)
   THROW_SCODE(ERR_STSM_MY_PUBKEY_MISSING);
  else
   writeEDHPubKey(_myDHEKey,addr);
 }


/**
 * @brief Writes the remote actor's ephemeral DH
 *        public key at the specified memory address
 * @throws ERR_STSM_MY_PUBKEY_MISSING           The remote actor's ephemeral DH public key is missing
 * @throws ERR_OSSL_BIO_NEW_FAILED              OpenSSL BIO initialization failed
 * @throws ERR_OSSL_PEM_WRITE_BIO_PUBKEY_FAILED Failed to write the remote actor's ephemeral DH public key into the BIO
 * @throws ERR_OSSL_BIO_READ_FAILED             Failed to read the remote actor's ephemeral DH public key from the BIO
 */
void STSMMgr::writeOtherEDHPubKey(unsigned char* addr)
 {
  // Ensure the remote actor's ephemeral DH public key to be available
  if(!_otherDHEPubKey)
   THROW_SCODE(ERR_STSM_OTHER_PUBKEY_MISSING);
  else
   writeEDHPubKey(_otherDHEPubKey,addr);
 }