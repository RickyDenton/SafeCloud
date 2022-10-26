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

   /* ================================= ATTRIBUTES ================================= */

   /* Same of the base 'SessMgr' class */

   /* ============================== PRIVATE METHODS ============================== */

   /**
    * @brief Sends a session message signaling type to the server and performs the actions
    *        appropriate to session signaling types resetting or terminating the session
    * @param sessMsgSignalingType The session message signaling type to be sent to the server
    * @param errReason            An optional error reason to be embedded with the exception that
    *                             must be thrown after sending such session message signaling type
    * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message
    *                                       invalid for its current operation or step
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
    *               the current client session manager operation and step\n
    *            4) Handles session-resetting or terminating signaling messages\n
    *            5) Handles session error signaling messages\n
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void recvCheckCliSessMsg();

   /**
    * @brief  Prints a table comparing the metadata of the main and remote file and asks the user
    *         whether to continue the current file upload or download operation, confirming or
    *         cancelling the operation on the SafeCloud server depending on the user's response
    * @return A boolean indicating whether the file upload or download operation should continue
    * @throws ERR_SESS_INTERNAL_ERROR      Invalid session operation or step or uninitialized
    *                                      '_mainFileInfo' or '_remFileInfo' attributes
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
    * @brief  Loads and sanitizes the information of the file to\n
    *         be uploaded to the SafeCloud storage pool by:\n
    *           1) Writing its canonicalized path into the '_mainFileAbsPath' attribute\n
    *           2) Opening its '_mainFileDscr' file descriptor in read-byte mode\n
    *           3) Loading the file name and metadata into the '_mainFileInfo' attribute\n
    * @param  filePath The relative or absolute path of the file to be uploaded
    * @throws ERR_SESS_FILE_NOT_FOUND   The file to be uploaded was not found
    * @throws ERR_SESS_FILE_OPEN_FAILED The file to be uploaded could not be opened in read mode
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading the metadata of the file to be uploaded
    * @throws ERR_SESS_UPLOAD_DIR       The file to be uploaded is in fact a directory
    * @throws ERR_SESS_UPLOAD_TOO_BIG   The file to be uploaded is too large (>= 4GB)
    */
   void checkLoadUploadFile(std::string& filePath);

   /**
    * @brief  Parses the 'FILE_UPLOAD_REQ' session response message returned by the SafeCloud server, where:\n
    *            1) If the SafeCloud server has reported to have successfully uploaded
    *               the empty file, inform the user of the success of the operation.\n
    *            2) If the SafeCloud server has reported that a file with the same name of the one to be
    *               uploaded does not exist in the user's storage pool, the file upload operation should continue\n
    *            3) If the SafeCloud server has reported that a file with the same name of the one to be uploaded
    *               already exists in the user's storage pool:\n
    *                  3.1) If the file to be uploaded was more recently modified than the
    *                       one in the storage pool the file upload operation should continue\n
    *                  3.2) If the file to be uploaded has the same size and last modified time of
    *                       the one in the storage pool, or the latter was more recently modified,
    *                       ask for user confirmation on whether the upload operation should continue\n
    * @return A boolean indicating whether the upload operation should continue
    * @throws ERR_SESS_MALFORMED_MESSAGE  Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_UNEXPECTED_MESSAGE The server reported to have completed uploading a non-empty file or an
    *                                     invalid 'FILE_UPLOAD_REQ' session message response type was received
    */
   bool parseUploadResponse();

   /**
    * @brief  Uploads the main file's raw contents and sends the
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

   /**
    * @brief  Parses the 'FILE_DOWNLOAD_REQ' session response message returned by the SafeCloud server, where:\n
    *            1) If the SafeCloud server has reported that the file to be downloaded does not exist in
    *               the user's storage pool, inform the client that the download operation cannot proceed.\n
    *            2) If the SafeCloud server has returned the information on the existing file to be downloaded:\n
    *                  2.1) If the file to be downloaded is empty, directly touch such a file in the user's
    *                       download directory and inform them that the download operation has completed\n
    *                  2.2) If the file to be downloaded is NOT empty, check whether a file
    *                       with the same name exists in the user's download directory, and:\n
    *                          2.2.1) If it does not, confirm the download operation to the SafeCloud server
    *                          2.2.2) If it does, if the file in the user's storage pool:\n
    *                                    2.2.2.1) Was more recently modified than the one in the download
    *                                             directory, confirm the download operation to the SafeCloud server\n
    *                                    2.2.2.2) Has the same size and last modified time of the one
    *                                             in the download directory, ask for user confirmation
    *                                             on whether the download operation should continue\n
    *                                    2.2.2.3) Has a last modified time older than the one in the
    *                                             download directory, ask for user confirmation on
    *                                             whether the download operation should continue
    * @return A boolean indicating whether the download operation should continue
    * @throws ERR_SESS_MALFORMED_MESSAGE  Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_UNEXPECTED_MESSAGE The server reported to have completed uploading a non-empty file or an
    *                                     invalid 'FILE_DOWNLOAD_REQ' session message response type was received
    */
   bool parseDownloadResponse(std::string& fileName);

   /**
    * @brief Downloads a file's raw contents from the user's SafeCloud storage pool by:
    *            1) Preparing the client session manager to receive the file's raw contents..\n
    *            2) Receiving and decrypting the file's raw contents.\n
    *            3) Verifying the file trailing integrity tag.\n
    *            4) Moving the resulting temporary file into the associated
    *               associated main file in the user's download directory.\n
    *            5) Setting the main file last modified time to
    *               the one specified in the '_remFileInfo' object.\n
    *            6) Notifying the success of the download operation to the SafeCloud server.
    * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid session manager operation or step
    *                                        for receiving a file's raw contents
    * @throws ERR_SESS_FILE_OPEN_FAILED      Failed to open the temporary file
    *                                        descriptor in write-byte mode
    * @throws ERR_FILE_WRITE_FAILED          Error in writing to the temporary file
    * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the downloaded file's metadata
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT      EVP_CIPHER encrypt initialization failed
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE    EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL     EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED        Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED          The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED                send() fatal error
    * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the downloaded temporary
    *                                        file or NULL session attributes
    */
   void downloadFileData();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Client session manager object constructor, initializing the session attributes
    *         of the authenticated user associated with the CliConnMgr parent object
    * @param cliConnMgr A reference to the CliConnMgr parent object
    */
   explicit CliSessMgr(CliConnMgr& cliConnMgr);

   /* Same destructor of the 'SessMgr' base class */

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /* ---------------------------- Session Operations API ---------------------------- */

   /**
    * @brief  Uploads a file to the user's SafeCloud storage pool
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

   /**
    * @brief  Downloads a file from the user's SafeCloud storage pool into their download directory
    * @param  fileName The name of the file to be downloaded from the user's SafeCloud storage pool
    * @throws ERR_SESS_FILE_INVALID_NAME The provided file name is not a valid Linux file name
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void downloadFile(std::string& fileName);

   // TODO: STUB
   void listRemoteFiles();

   // TODO: STUB
   void renameRemFile(std::string& oldFileName,std::string& newFileName);

   /**
    * @brief  Sends the 'BYE session signaling message to the
    *         SafeCloud server, gracefully terminating the session
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