/* Station-to-Station-Modified (STSM) Key Exchange Protocol Base Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "STSMMgr.h"
#include "errlog.h"
#include <string.h>

/* ============================== PROTECTED METHODS ============================== */

/**
 * @brief  Generates an ephemeral DH key pair on 2048 bit using the set of standard DH parameters
 * @return The address of the EVP_PKEY structure holding the newly generated ephemeral DH key pair
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