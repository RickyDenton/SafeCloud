/* SafeCloud AES_GCM_128 IV Definitions */

/* ================================== INCLUDES ================================== */
#include "IV.h"
#include "scode.h"
#include "errlog.h"
#include <cstring>

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief IV object default constructor, generating a random IV value
 * @throws ERR_OSSL_RAND_POLL_FAILED  RAND_poll() seed generation failed
 * @throws ERR_OSSL_RAND_BYTES_FAILED RAND_bytes() bytes generation failed
 */
IV::IV() : iv_high(), iv_low(), iv_low_start()
 {
  // Seed the OpenSSL PRNG
  if(!RAND_poll())
   THROW_SCODE(ERR_OSSL_RAND_POLL_FAILED,OSSL_ERR_DESC);

  // Generate at random the IV's most significant fixed part
  if(RAND_bytes(&(iv_high)[0],4) != 1)
   THROW_SCODE(ERR_OSSL_RAND_BYTES_FAILED,OSSL_ERR_DESC);

  // Generate at random the IV's least significant variable part
  if(RAND_bytes(reinterpret_cast<unsigned char*>(&iv_low), sizeof(iv_low)) != 1)
   THROW_SCODE(ERR_OSSL_RAND_BYTES_FAILED,OSSL_ERR_DESC);

  // Set the IV least significant starting value
  iv_low_start = iv_low;
 }



// TODO: Check if it can be removed, reimplement otherwise
/**
 * @brief IV object pointer copy constructor, interpreting an address
 * @throws ERR_OSSL_RAND_POLL_FAILED  RAND_poll() seed generation failed
 * @throws ERR_OSSL_RAND_BYTES_FAILED RAND_bytes() bytes generation failed
 *//*

IV::IV(unsigned char* iv) : iv_high(), iv_low(), iv_low_start()
 {
  memcpy(iv_high, &iv[0], 4);
  memcpy((void*)iv_low, &iv[4], sizeof(uint64_t));
 }
*/


/**
 * @brief IV object destructor, safely deleting the IV value
 */
IV::~IV()
 {
  OPENSSL_cleanse(&iv_high[0], 4);
  OPENSSL_cleanse(&iv_low, sizeof(uint64_t));
  OPENSSL_cleanse(&iv_low_start, sizeof(uint64_t));
 }


/* ============================ OTHER PUBLIC METHODS ============================ */


/**
 * @brief  Increments the least significant lower part of the IV
 * @return A boolean indicating whether the minimum (iv_low_start - iv_low)
 *         distance after which a new symmetric key must be exchanged between
 *         parties to prevent IV reuse has been reached
 */
bool IV::incIV()
 {
  // Increment the IV least significant variable part
  //
  // NOTE: Such value eventually overflowing is an intended
  //       behaviour not causing IV reuse (see later)
  iv_low++;

  // If the minimum (iv_low_start - iv_low) distance has been reached, notify that
  // a new symmetric key must be exchanged between parties to prevent IV reuse
  if(iv_low_start - iv_low < IV_LOW_REKEYING_LIMIT)
   return true;
  else
   return false;
 }