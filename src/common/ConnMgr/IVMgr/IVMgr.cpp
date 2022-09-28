/* AES_GCM_128 IV Manager Implementation*/

#include "IVMgr.h"
#include <cstring>

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief IVMgr object constructor
 */
IVMgr::IVMgr() : iv_high(), iv_low()
 {
  // Seed the OpenSSL PRNG
  RAND_poll();

  // Generate at random the IV's 4 most significant unused bytes
  RAND_bytes(&(iv_high)[0],4);

  // Generate at random the IV's 8 least significant bytes ensuring such value not to be too small or big
  do
   RAND_bytes(reinterpret_cast<unsigned char*>(&iv_low), sizeof(iv_low));
  while(iv_low > IV_LOW_INIT_MAX || iv_low < IV_LOW_INIT_MIN);
 }

IVMgr::IVMgr(unsigned char* iv) : iv_high(), iv_low()
 {
  memcpy(iv_high, &iv[0], 4);
  memcpy((void*)iv_low, &iv[4], sizeof(uint64_t));
 }

/**
 * @brief IVMgr object destructor, safely deleting the IV value
 */
IVMgr::~IVMgr()
 {
  OPENSSL_cleanse(&iv_high[0], 4);
  OPENSSL_cleanse(&iv_low, sizeof(uint64_t));
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

bool IVMgr::incIV()
 {
  if(iv_low++ > IV_LOW_REKEYING_LIMIT)
   return true;
  else
   return false;
 }