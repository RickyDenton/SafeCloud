#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager Class Declaration */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"
#include "ConnMgr/SessMgr/SessMsg.h"


// Forward Declaration
class CliConnMgr;

class CliSessMgr : public SessMgr
 {
  private:

   // Client Session Manager Sub-states
   enum cliSessMgrSubstate : uint8_t
    {
     CLI_IDLE,
     WAITING_FILE_STATUS,
     WAITING_SRV_CONF,
     WAITING_POOL_INFO,
     WAITING_SRV_COMPL
    };

   /* ================================= ATTRIBUTES ================================= */
   cliSessMgrSubstate _cliSessMgrSubstate;  // The current client session manager sub-state
   CliConnMgr&        _cliConnMgr;          // The associated CliConnMgr parent object

   /* -------------------------- Progress Bar Management -------------------------- */

   // The progress bar object used for displaying a file upload or download progress on stdout
   ProgressBar  _progBar;

   // The number of bytes to be transferred associated with a 1% progress in the progress bar
   unsigned int _progBarUnitSize;

   // The number of bytes in the last data transfer whose progress
   // was not accounted for in the progress bar (< _progBarUnitSize)
   unsigned int _progBarLeftovers;

   /* ============================== PRIVATE METHODS ============================== */

   // TODO
   void sendCliSessSignalMsg(SessMsgType sessMsgType);

   // TODO
   void recvCheckCliSessMsg();

   // TODO
   void sendCliSessPayloadMsg(SessMsgType sessMsgType);

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

   void sendByeMsg();

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