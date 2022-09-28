#ifndef SAFECLOUD_IVMGR_H
#define SAFECLOUD_IVMGR_H

/* AES_GCM_128 IV Manager Class */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>

// TODO: Only the least-significant 64 bits of the IV are used for compatibility purpose (rewrite better)

#include <cstdint>

#define IV_SIZE   12                         // IV size (12 bytes, 96 bit)
#define IV_LOW_INIT_MAX UINT64_MAX - 100
#define IV_LOW_INIT_MIN 10
#define IV_LOW_REKEYING_LIMIT UINT64_MAX - 10


class IVMgr
 {
  public:

   /* ================================= ATTRIBUTES ================================= */
   unsigned char iv_high[4];   // Unused
   uint64_t iv_low;            // Used

   /* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */
   IVMgr();
   IVMgr(unsigned char* iv);

   /**
    * @brief IVMgr object destructor, safely deleting the IV value
    */
   ~IVMgr();

   /* ============================ OTHER PUBLIC METHODS ============================ */
   bool incIV();
 };



#endif //SAFECLOUD_IVMGR_H
