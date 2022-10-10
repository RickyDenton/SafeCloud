#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"


// Forward Declaration
class CliConnMgr;

class CliSessMgr : public SessMgr
 {
  private:

   // Client session commands states
   enum cliSessCmdState : uint8_t
    {
     CLI_IDLE
     // Client UPLOAD command states


     // Client DOWNLOAD command states


     // Client DELETE command states


     // Client RENAME command states


     // Client LIST command states

    };

   /* ================================= ATTRIBUTES ================================= */
   cliSessCmdState _cliSessCmdState;  // The current client session command state
   CliConnMgr&     _cliConnMgr;    // The parent CliConnMgr instance managing this object

   /* ------------- Progress Bar Management ------------- */
   ProgressBar  _progBar;
   unsigned int _tProgUnit;
   unsigned int _tProgTemp;




   void parseOpenFile(std::string& filePath);

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */
   explicit CliSessMgr(CliConnMgr& cliConnMgr);

   // Same destructor of the SessMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   // TODO
   void resetCliSessState();

   // TODO: STUB
   void uploadFile(std::string& filePath);

  // TODO: STUB
   void downloadFile(std::string& fileName);

  // TODO: STUB
   void listRemoteFiles();

  // TODO: STUB
   void renameRemFile(std::string& oldFileName,std::string& newFileName);
 };


#endif //SAFECLOUD_CLISESSMGR_H