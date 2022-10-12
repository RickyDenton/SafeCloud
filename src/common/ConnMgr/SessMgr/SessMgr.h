#ifndef SAFECLOUD_SESSMGR_H
#define SAFECLOUD_SESSMGR_H

/* SafeCloud Session Manager */

// TODO: Rewrite descriptions, attributes included

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <string>
#include "DirInfo/FileInfo/FileInfo.h"
#include "ConnMgr/SessMgr/ProgressBar/ProgressBar.h"
#include "ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include "ConnMgr/ConnMgr.h"

class SessMgr
 {
  protected:

   enum sessCmd : uint8_t
    {
     IDLE,      // Ready to receive commands
     UPLOAD,    // Uploading a file to the SafeCloud storage pool
     DOWNLOAD,  // Downloading a file from the SafeCloud storage pool
     DELETE,    // Deleting a file from the SafeCloud storage pool
     RENAME,    // Renaming a file within the SafeCloud storage pool
     LIST       // Listing the contents of the SafeCloud storage pool
    };

   /* ================================= ATTRIBUTES ================================= */

   /* ------------------- General Info ------------------- */
   sessCmd        _sessCmd;    // The current session command
   ConnMgr&       _connMgr;    // The associated connection manager
   AESGCMMgr      _aesGCMMgr;  // AES_128_GCM Manager

   /* ---------------- Files Management ---------------- */

   // Target File
   FILE*        _targFileDscr;
   std::string* _targFileAbsPath;     // TODO: Maybe not necessary
   FileInfo*    _targFileInfo;

   // Temporary File
   FILE*        _tmpFileDscr;
   std::string* _tmpFileAbsPath;     // TODO: Maybe not necessary
   FileInfo*    _tmpFileInfo;

   unsigned int _bytesTransf;

   /* ============================= PROTECTED METHODS ============================= */

   // TODO
   void wrapSendSessMsg();

   // TODO
   void unWrapSessMsg();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   explicit SessMgr(ConnMgr& _connMgr);

   ~SessMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   // TODO: Check and write description
   void resetSessState();

   // TODO: Send predefined SessMsg, such as "bye", "cancel", etc.
   // sendBye()?
   // sendError()?
 };


#endif //SAFECLOUD_SESSMGR_H
