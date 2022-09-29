#ifndef SAFECLOUD_IV_H
#define SAFECLOUD_IV_H

/*
 * This class represents the IV used in the SafeCloud application for the AES_GCM_128
 * cipher (12 bytes, 96 bit), where, for cross-platform and cross-compiler
 * compatibility purposes, only the least significant 64 bit (8 bytes) are updated
 * at every transmission, while the most significant 32 bit (4 bytes) are fixed
 */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <cstdint>

// The minimum (iv_low_start - iv_low) distance after which a new
// symmetric key must be exchanged between parties to prevent IV reuse
#define IV_LOW_REKEYING_LIMIT 10


class IV
 {
  public:

   /* ================================= ATTRIBUTES ================================= */
   unsigned char iv_high[4];   // The IV most significant fixed part
   uint64_t iv_low;            // The IV least significant variable part
   uint64_t iv_low_start;      // The starting value of the IV least-significant part

   /* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

   /**
    * @brief IV object default constructor, generating a random IV value
    * @throws ERR_OSSL_RAND_POLL_FAILED  RAND_poll() seed generation failed
    * @throws ERR_OSSL_RAND_BYTES_FAILED RAND_bytes() bytes generation failed
    */
   IV();

   // TODO: Check if it can be removed, reimplement otherwise
   // IV(unsigned char* iv);

   /**
    * @brief IV object destructor, safely deleting the IV value
    */
   ~IV();

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /**
    * @brief  Increments the least significant lower part of the IV
    * @return A boolean indicating whether the minimum (iv_low_start - iv_low)
    *         distance after which a new symmetric key must be exchanged between
    *         parties to prevent IV reuse has been reached
    */
   bool incIV();
 };



#endif //SAFECLOUD_IV_H
