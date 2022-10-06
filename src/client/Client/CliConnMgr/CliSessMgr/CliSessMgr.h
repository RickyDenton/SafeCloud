#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager */

#include <string>
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
  void uploadFile(std::string& filePath);

  // TODO
  void downloadFile(std::string& fileName);

  // TODO
  void listRemoteFiles();

  // TODO
  void renameRemFile(std::string& oldFileName,std::string& newFileName);
 };


#endif //SAFECLOUD_CLISESSMGR_H