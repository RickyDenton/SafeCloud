#ifndef SAFECLOUD_IV_H
#define SAFECLOUD_IV_H

/* This class represents the IV(s) used in the SafeCloud application, where:
 *
 *  - The Key Establishment protocol (STSM) uses an IV on 16 bytes (AES_CBC_128)
 *  - The Session Phase uses an IV on 12 bytes (AES_GCM_128)
 *
 * For providing an IV value to both connection phases and to ensure cross-platform and cross-compiler
 * compatibility in handling large numbers, IVs consist of 16 bytes initialized at random where:
 *
 * - The lower half (8 bytes, 64 bit) is variable and incremented after every encryption or decryption
 *
 * - The upper half (8 bytes, 64 bit) is instead constant, with the AES_CBC_128 cipher using it in its
 *   entirety (for an IV size of 16 bytes), while the AES_GCM_128 cipher uses its least significant 4
 *   bytes only (for an IV size of 12 bytes)
 *
 * It should also be noted that, being its variable part on 64 bits, no failsafe mechanism for preventing
 * the IV reuse were implemented, as even by encrypting or decrypting a message every 100ms would require
 * over 50 years to exchange the 2^64 messages necessary for the same IV to be reused
 */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <cstdint>


class IV
 {
  public:

   /* ================================= ATTRIBUTES ================================= */

   // IV upper half (constant)
   uint32_t iv_AES_CBC;        // The IV upper half's most significant 4 bytes (AES_CBC_128 only)
   uint32_t iv_AES_GCM;        // The IV upper half's most significant 4 bytes

   // IV lower half (variable)
   uint64_t iv_var;

   // The starting value of the IV's variable part (IV reuse protection)
   uint64_t iv_var_start;

   /* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

   /**
    * @brief IV object default constructor, generating a random IV on 16 bytes
    * @throws ERR_OSSL_RAND_POLL_FAILED  RAND_poll() seed generation failed
    * @throws ERR_OSSL_RAND_BYTES_FAILED RAND_bytes() bytes generation failed
    */
   IV();

   /**
    * @brief IV object destructor, safely deleting the IV value
    */
   ~IV();

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /**
    * @brief Increments the IV's variable part
    * @note  The IV variable part eventually overflowing is an intended behaviour
    * @note  Being its variable part on 64 bits, no failsafe mechanism for
    *        preventing the IV reuse were implemented, as even by encrypting or
    *        decrypting a message every 100ms would require over 50 years to
    *        exchange the 2^64 messages necessary for the same IV to be reused
    */
   void incIV();
 };


#endif //SAFECLOUD_IV_H
