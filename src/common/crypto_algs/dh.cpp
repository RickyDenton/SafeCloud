/* Definitions of the OpenSSL DH utility functions used by the SafeCloud application */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include "dh.h"

/* =========================== FUNCTIONS DEFINITIONS =========================== */

// TODO: Merge somewhere
/* OpenSSL Error Handling */
int handleErrors()
 {
  printf("SSL Error!\n");
  ERR_print_errors_fp(stderr);
  exit(1);
 }


/**
 * @brief  Generates an ephemeral DH key pair using the DH standard parameters
 * @return A pointer to the generated ephemeral DH key pair
 */
EVP_PKEY* dhe_2048_keygen()
 {
  EVP_PKEY*     DHParams;          // Used to store the default DH Params
  EVP_PKEY_CTX* DHGenCtx;          // DH Key Generation Context
  EVP_PKEY*     DHEKey = nullptr;  // The resulting ephemeral DH public and private key pair

  DHParams = EVP_PKEY_new();
  if(DHParams == nullptr)
   handleErrors();

  // Use the default DH parameters for key generation
  if(EVP_PKEY_assign(DHParams, EVP_PKEY_DHX, DH_get_2048_256()) != 1)
   handleErrors();

  // Create the key generation context
  DHGenCtx = EVP_PKEY_CTX_new(DHParams, nullptr);
  if(!DHGenCtx)
   handleErrors();

  // Generate a new ephemeral DHKE key pair
  if(EVP_PKEY_keygen_init(DHGenCtx) != 1)
   handleErrors();
  if(EVP_PKEY_keygen(DHGenCtx, &DHEKey) != 1)
   handleErrors();

  // Free the DH parameters and the key generation context
  // TODO: Check, it should be right
  EVP_PKEY_free(DHParams);
  EVP_PKEY_CTX_free(DHGenCtx);

  // Return the ephemeral DHKE pair
  return DHEKey;
 }
