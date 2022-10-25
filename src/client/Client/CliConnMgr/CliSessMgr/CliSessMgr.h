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
     CMD_START,
     WAITING_FILE_STATUS,
     WAITING_SRV_CONF,
     WAITING_POOL_INFO,
     WAITING_SRV_COMPL
    };

   /* ================================= ATTRIBUTES ================================= */
   cliSessMgrSubstate _cliSessMgrSubstate;  // The current client session manager sub-state
   CliConnMgr&        _cliConnMgr;          // The associated CliConnMgr parent object

   /* ============================== PRIVATE METHODS ============================== */

   /**
    * @brief Sends a session message signaling type to the server and performs the actions
    *        appropriate to session signaling types resetting or terminating the session
    * @param sessMsgSignalingType The session message signaling type to be sent to the server
    * @param errReason            An optional error reason to be embedded with the exception that
    *                             must be thrown after sending such session message signaling type
    * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message invalid for its current state
    * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
    * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED          The server disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void sendCliSessSignalMsg(SessMsgType sessMsgSignalingType);

   void sendCliSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason);

   /**
    * @brief  Client Session message reception handler, which:\n
    *            1) Blocks the execution until a complete session message wrapper has
    *               been received in the associated connection manager's primary buffer\n
    *            2) Unwraps the received session message wrapper from
    *               the primary into the secondary connection buffer\n
    *            3) Asserts the resulting session message to be allowed in
    *               the current client session manager state and substate\n
    *            4) Handles session-resetting or terminating signaling messages\n
    *            5) Handles session error signaling messages\n
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void recvCheckCliSessMsg();

   /**
    * @brief  Prints a table comparing the metadata of the local and remote file and asks the user
    *         whether to continue the current file upload or download operation, confirming or
    *         cancelling the operation on the SafeCloud server depending on the user's response
    * @return A boolean indicating whether the file upload or download operation should continue
    * @throws ERR_SESS_INTERNAL_ERROR      Invalid session state  or the '_locFileInfo' or the
    *                                      '_remFileInfo' attribute have not been initialized
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   bool askFileOpConf();

   /* ------------------------------ 'UPLOAD' Operation Methods ------------------------------ */

   /**
    * @brief  Parses a file to be uploaded to the SafeCloud storage pool by:\n
    *           1) Writing its canonicalized path into the '_mainFileAbsPath' attribute\n
    *           2) Opening its '_mainFileDscr' file descriptor in read-byte mode\n
    *           3) Loading the file name and metadata into the '_locFileInfo' attribute\n
    * @param  filePath The relative or absolute path of the file to be uploaded
    * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
    * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
    * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
    * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
    */
   void parseUploadFile(std::string& filePath);

   /**
    * @brief  Parses the 'FILE_UPLOAD_REQ' session response message returned by the SafeCloud server, where:
    *            1) If the SafeCloud server has reported that a file with the same name of the one to be
    *               uploaded does not exist in the user's storage pool, the file upload operation should continue
    *            2) If the SafeCloud server has reported that a file with the same name of the one to be uploaded
    *               already exists in the user's storage pool:
    *                  2.1) If the file to be uploaded was more recently modified than the
    *                       one in the storage pool the file upload operation should continue
    *                  2.2) If the file to be uploaded has the same size and last modified time of
    *                       the one in the storage pool, or the latter was more recently modified,
    *                       ask for user confirmation on whether the upload operation should continue
    *            3) If the SafeCloud server has reported that the empty file has been
    *               uploaded successfully, inform the user of the success of the operation
    * @return A boolean indicating whether the file raw contents should be uploaded to the SafeCloud server
    * @throws ERR_SESS_MALFORMED_MESSAGE  Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_UNEXPECTED_MESSAGE The server reported to have completed uploading a non-empty file or an
    *                                     invalid 'FILE_UPLOAD_REQ' session message response type was received
    */
   bool parseUploadResponse();

   /**
    * @brief  Uploads the main file's raw contents and the
    *         resulting integrity tag to the SafeCloud server
    * @throws ERR_FILE_WRITE_FAILED         Error in reading from the main file
    * @throws ERR_FILE_READ_UNEXPECTED_SIZE The main file raw contents that were read differ from its size
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The plaintext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_SEND_OVERFLOW             Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void uploadFileData();

   /* ----------------------------- 'DOWNLOAD' Operation Methods ----------------------------- */

   bool parseDownloadResponse(std::string& fileName);


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Client session manager object constructor, initializing the session parameters
    *        of the authenticated client associated with the cliConnMgr parent object
    * @param cliConnMgr A reference to the client connection manager parent object
    */
   explicit CliSessMgr(CliConnMgr& cliConnMgr);

   /* Same destructor of the SessMgr base class */

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Resets all session parameters in preparation for the next
    *        session command to be executed by the client session manager
    */
   void resetCliSessState();

   /* ---------------------------- Session Commands API ---------------------------- */

   /**
    * @brief  Uploads a file to the user's storage pool within the SafeCloud server
    * @param  filePath The relative or absolute path of the file to be uploaded
    * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
    * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
    * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
    * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void uploadFile(std::string& filePath);

   // TODO
   void downloadFile(std::string& fileName);

   // TODO: STUB
   void listRemoteFiles();

   // TODO: STUB
   void renameRemFile(std::string& oldFileName,std::string& newFileName);

   /**
    * @brief  Sends the 'BYE session signaling message to the
    *         SafeCloud server, gracefully terminating the connection
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendByeMsg();
 };


#endif //SAFECLOUD_CLISESSMGR_H