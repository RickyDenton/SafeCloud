/* SafeCloud AES_GCM_128 IV Definitions */

/* ================================== INCLUDES ================================== */
#include "IV.h"
#include "scode.h"
#include "errlog.h"
#include <cstring>

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief IV object default constructor, generating a random IV on 16 bytes
 * @throws ERR_OSSL_RAND_POLL_FAILED  RAND_poll() seed generation failed
 * @throws ERR_OSSL_RAND_BYTES_FAILED RAND_bytes() bytes generation failed
 */
IV::IV() : iv_AES_CBC(), iv_AES_GCM(), iv_var(), iv_var_start()
 {
  // Seed the OpenSSL PRNG
  if(!RAND_poll())
   THROW_SCODE(ERR_OSSL_RAND_POLL_FAILED,OSSL_ERR_DESC);

  // Randomly generate the IV's components
  if(RAND_bytes(reinterpret_cast<unsigned char*>(&iv_AES_CBC), sizeof(iv_AES_CBC)) != 1)
   THROW_SCODE(ERR_OSSL_RAND_BYTES_FAILED,OSSL_ERR_DESC);

  if(RAND_bytes(reinterpret_cast<unsigned char*>(&iv_AES_GCM), sizeof(iv_AES_GCM)) != 1)
   THROW_SCODE(ERR_OSSL_RAND_BYTES_FAILED,OSSL_ERR_DESC);

  if(RAND_bytes(reinterpret_cast<unsigned char*>(&iv_var), sizeof(iv_var)) != 1)
   THROW_SCODE(ERR_OSSL_RAND_BYTES_FAILED,OSSL_ERR_DESC);

  // Set starting value of the IV's variable part
  iv_var_start = iv_var;
 }


/**
 * @brief IV object destructor, safely deleting the IV value
 */
IV::~IV()
 {
  OPENSSL_cleanse(&iv_AES_CBC, sizeof(uint32_t));
  OPENSSL_cleanse(&iv_AES_GCM, sizeof(uint32_t));
  OPENSSL_cleanse(&iv_var, sizeof(uint64_t));
  OPENSSL_cleanse(&iv_var_start, sizeof(uint64_t));
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Increments the IV's variable part
 * @return A boolean indicating whether the minimum (iv_var_start - iv_var)
 *         distance after which a new symmetric key must be exchanged between
 *         parties to prevent IV reuse has been reached
 */
bool IV::incIV()
 {
  // Increment the IV least significant variable part
  //
  // NOTE: Such value eventually overflowing is an intended
  //       behaviour not causing IV reuse (see later)
  iv_var++;

  // If the minimum (iv_var_start - iv_var) distance has been reached, notify that
  // a new symmetric key must be exchanged between parties to prevent IV reuse
  if(iv_var_start - iv_var < IV_VAR_REKEYING_LIMIT)
   return true;
  else
   return false;
 }