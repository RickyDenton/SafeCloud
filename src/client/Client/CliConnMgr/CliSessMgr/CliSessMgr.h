#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager */

#include "ConnMgr/SessMgr/SessMgr.h"

class CliSessMgr : SessMgr
 {
   private:

    /* ========================= Attributes ========================= */
    char*             _downDir;       // The client's download directory

   public:

    /* ================= Constructors and Destructor ================= */
    CliSessMgr(int csk, char* tmpDir, unsigned char* buf, unsigned int bufSize, unsigned char* iv, unsigned char* skey, char* downDir);
    // Same destructor of the SessMgr base class

  /* ======================== Other Methods ======================== */

  // TODO
 };


#endif //SAFECLOUD_CLISESSMGR_H