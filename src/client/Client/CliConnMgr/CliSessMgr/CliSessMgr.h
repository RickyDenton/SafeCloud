#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"


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

   /* ============================== PRIVATE METHODS ============================== */

   // TODO
   void sendCliSessMsg(SessMsgType sessMsgType);

   /**
    * @brief  Parses a target file to be uploaded by:\n
    *           1) Initializing its canonicalized path\n
    *           2) Opening its file descriptor in read-byte mode\n
    *           3) Determining its file name and metadata\n
    * @param  filePath The relative or absolute path of the target file to be uploaded
    * @throws ERR_SESS_FILE_NOT_FOUND   The target file was not found
    * @throws ERR_SESS_FILE_OPEN_FAILED The target file could not be opened in read mode
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading the target file's metadata
    * @throws ERR_SESS_UPLOAD_DIR       The target file is a directory
    * @throws ERR_SESS_UPLOAD_TOO_BIG   The target file is too large (> 4GB)
    */
   void parseUploadFile(std::string& filePath);


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */
   explicit CliSessMgr(CliConnMgr& cliConnMgr);

   // Same destructor of the SessMgr base class

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Resets the client session manager state
    *        to be ready for the next session command
    */
   void resetCliSessState();

   // TODO
   void uploadFile(std::string& filePath);

  // TODO: STUB
   void downloadFile(std::string& fileName);

  // TODO: STUB
   void listRemoteFiles();

  // TODO: STUB
   void renameRemFile(std::string& oldFileName,std::string& newFileName);
 };


#endif //SAFECLOUD_CLISESSMGR_H