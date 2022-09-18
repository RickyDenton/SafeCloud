#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager */

#include "SessMgr.h"

class SrvSessMgr : SessMgr
 {
   private:

    /* ========================= Attributes ========================= */
    char* _poolDir;  // The client's pool directory

   public:

  /* ================= Constructors and Destructor ================= */
  SrvSessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey, char* poolDir);
  // Same destructor of the SessMgr base class

  /* ======================== Other Methods ======================== */

  // TODO
 };


#endif //SAFECLOUD_SRVSESSMGR_H
