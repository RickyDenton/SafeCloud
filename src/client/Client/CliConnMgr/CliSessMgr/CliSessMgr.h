#ifndef SAFECLOUD_CLISESSMGR_H
#define SAFECLOUD_CLISESSMGR_H

/* SafeCloud Client Session Manager Class Declaration */

/* ================================== INCLUDES ================================== */
#include "SafeCloudApp/ConnMgr/SessMgr/SessMgr.h"
#include "SafeCloudApp/ConnMgr/SessMgr/SessMsg.h"


// Forward Declaration
class CliConnMgr;

class CliSessMgr : public SessMgr
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* Same of the 'SessMgr' base class */

   /* ============================== PRIVATE METHODS ============================== */

   /* ------------------------ Client Session Manager Utility Methods ------------------------ */

   /**
    * @brief Sends a session message signaling type to the server and throws the
    *        associated exception in case of session error signaling message types
    * @param sessMsgSignalingType The session message signaling type to be sent to the server
    * @param errReason            An optional error reason to be embedded with the exception
    *                             associated with the session error signaling message type
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
    *                  3.1) If the file to be uploaded is empty and, at this point, the file with the
    *                       same name in the SafeCloud storage pool is not, inform the user and ask
    *                       for their confirmation on whether the upload operation should continue\n
    *                  3.2) If the file to be uploaded was more recently modified than the
    *                       one in the storage pool the file upload operation should continue\n
    *                  3.3) If the file to be uploaded has the same size and last modified time of
    *                       the one in the storage pool, or the latter was more recently modified,
    *                       ask for user confirmation on whether the upload operation should continue\n
    * @return A boolean indicating whether the upload operation should continue
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE  The server reported to have completed uploading a non-empty file or an
    *                                      invalid 'FILE_UPLOAD_REQ' session message response type was received
    */
   bool parseUploadResponse();

   /**
    * @brief  Uploads the main file's raw contents and sends the
    *         resulting integrity tag to the SafeCloud server
    * @throws ERR_FILE_WRITE_FAILED              Error in reading from the main file
    * @throws ERR_SESSABORT_UNEXPECTED_FILE_SIZE The main file raw contents that were read differ from its size
    * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The plaintext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
    * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED                    send() fatal error
    */
   void uploadFileData();

   /* ----------------------------- 'DOWNLOAD' Operation Methods ----------------------------- */

   /**
    * @brief  Parses the 'FILE_DOWNLOAD_REQ' session response message returned by the SafeCloud server, where:\n
    *            1) If the SafeCloud server has reported that the file to be downloaded does not exist in
    *               the user's storage pool, inform the client that the download operation cannot proceed.\n
    *            2) If the SafeCloud server has returned the information on the existing file to be downloaded:\n
    *                  2.1) If the file to be downloaded is empty and a file with the same name in the user's
    *                       download directory does not exist or is empty the download operation should proceed\n
    *                  2.2) [PATCH] If the file to be downloaded is empty and a non-empty file with
    *                       the same name does exist in the user's download directory, ask for
    *                       their confirmation on whether the download operation should proceed\n
    *                  2.3) If the file to be downloaded is NOT empty and a file with such name does not exist
    *                       in the user's download directory, confirm the download operation to the server\n
    *                  2.4) If the file to be downloaded is NOT empty and a file with such name does exist in
    *                       the user's download directory, if the file in the storage pool:\n
    *                                    2.4.1) Was more recently modified than the one in the download
    *                                           directory, confirm the upload operation to the SafeCloud server\n
    *                                    2.4.2) Has the same size and last modified time of the one
    *                                           in the download directory, ask for user confirmation
    *                                           on whether the upload operation should continue\n
    *                                    2.4.3) Has a last modified time older than the one in the
    *                                           download directory, ask for user confirmation on
    *                                           whether the upload operation should continue
    * @return A boolean indicating whether the downloaded operation should continue
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_MAIN_FILE_IS_DIR    The main file was found to be a directory (!)
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_DOWNLOAD_REQ' session
    *                                      message response type was received
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
    * @param  fileName The name of the file to be downloaded from the SafeCloud storage pool
    * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid session manager operation or step
    *                                        for receiving a file's raw contents
    * @throws ERR_SESS_FILE_OPEN_FAILED      Failed to open the temporary file
    *                                        descriptor in write-byte mode
    * @throws ERR_FILE_WRITE_FAILED          Error in writing to the temporary file
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
    * @throws ERR_SESS_FILE_CLOSE_FAILED     Error in closing the temporary file
    * @throws ERR_SESS_FILE_RENAME_FAILED    Error in moving the temporary file to the main directory
    * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the main file's last modification time
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

   /* ------------------------------ 'DELETE' Operation Methods ------------------------------ */

   /**
    * @brief  Parses the 'FILE_DELETE_REQ' session response message returned by the SafeCloud server, where:\n
    *            1) If the SafeCloud server has reported that the file to be deleted does not exist in
    *               the user's storage pool, inform the client that the deletion operation cannot proceed.\n
    *            2) If the SafeCloud server has returned the information on the existing file
    *               to be deleted, print it on stdout and ask for user confirmation on whether
    *               proceeding deleting the file, sending the appropriate deletion operation
    *               confirmation or cancellation notification to the SafeCloud server.
    * @param  fileName The name of the file to be downloaded from the SafeCloud storage pool
    * @return A boolean indicating whether to expect the deletion completion notification from the SafeCloud server
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_DELETE_REQ' session message response type was received
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   bool parseDeleteResponse(std::string& fileName);

   /* ------------------------------ 'RENAME' Operation Methods ------------------------------ */

   /**
    * @brief  Parses the 'FILE_RENAME_REQ' session response message returned by the SafeCloud server, where:\n
    *            1) If the SafeCloud server has reported that the file to be renamed does not exist in
    *               the user's storage pool, inform the client that the renaming operation cannot proceed.\n
    *            2) If the SafeCloud server has returned the information on a file with the same name of the
    *               one the user wants to rename the file to, prints them on stdout and inform the client that
    *               such a file should be renamed or deleted before attempting to rename the original file.\n
    *            3) If the SafeCloud server has reported that the file was renamed successfully, inform the
    *               client of the success of operation.
    * @param  oldFilename The name of the file to be renamed
    * @param  newFilename The name the file should be renamed to
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_UNEXPECTED_MESSAGE  An invalid 'FILE_RENAME_REQ' session message response type was received
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED         The server disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void parseRenameResponse(std::string& oldFileName, std::string& newFileName);

   /* ------------------------------- 'LIST' Operation Methods ------------------------------- */

   /**
    * @brief  Prepares the client session manager to receive the
    *         serialized contents of the user's storage pool
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_DECRYPT_INIT    EVP_CIPHER decrypt initialization failed
    * @throws ERR_SESSABORT_INTERNAL_ERROR Invalid session operation or expected
    *                                      serialized pool contents' size
    */
   void prepRecvPoolRaw();

   /**
    * @brief  Receives the serialized contents of the user's storage
    *         pool and validates their associated integrity tag
    * @throws ERR_SESS_FILE_INVALID_NAME     Received a file of name
    * @throws ERR_SESS_FILE_META_NEGATIVE    Received a file with negative metadata values
    * @throws ERR_FILE_TOO_LARGE             Received a too large file (> 9999GB)
    * @throws ERR_SESS_DIR_INFO_OVERFLOW     The storage pool information size exceeds 4GB
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Plaintext integrity verification failed
    * @throws ERR_CSK_RECV_FAILED            Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED          The connection peer has abruptly disconnected
    */
   void recvPoolRawContents();

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

   /* ---------------- Client Session Manager Public Utility Methods ---------------- */

   /**
    * @brief  Checks and parses a possible asynchronous session message received from the SafeCloud server
    * @throws ERR_PEER_DISCONNECTED                      The SafeCloud server has abruptly disconnected
    * @throws ERR_SESSABORT_SRV_GRACEFUL_DISCONNECT      The SafeCloud server has gracefully disconnected
    * @throws ERR_UNKNOWN_SESSMSG_TYPE                   Received a session message of unknown type
    * @throws ERR_UNEXPECTED_SESS_MESSAGE                An unexpected session message for the client session
    *                                                    manager current operation and state was received
    * @throws ERR_SESS_CLI_SRV_INTERNAL_ERROR            The SafeCloud server reported to have
    *                                                    experienced a recoverable internal error
    * @throws ERR_SESS_CLI_SRV_UNEXPECTED_MESSAGE        The SafeCloud server reported to have
    *                                                    received an unexpected session message
    * @throws ERR_SESS_CLI_SRV_MALFORMED_MESSAGE         The SafeCloud server reported to have
    *                                                    received a malformed session message
    * @throws ERR_SESSABORT_CLI_SRV_UNKNOWN_SESSMSG_TYPE The SafeCloud server reported to have
    *                                                    received a session message of unknown type
    * @throws ERR_CSK_RECV_FAILED                        Error in receiving data from the connection socket
    */
   void checkAsyncSrvMsg();

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

   /**
    * @brief  Deletes a file from the user's SafeCloud storage pool
    * @param  fileName The name of the file to be deleted from the user's SafeCloud storage pool
    * @throws ERR_SESS_FILE_INVALID_NAME The provided file name is not a valid Linux file name
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void deleteFile(std::string& fileName);

   /**
    * @brief  Renames a file in the user's SafeCloud storage pool
    * @param  oldFilename The name of the file to be renamed
    * @param  newFilename The name the file should be renamed to
    * @throws ERR_SESS_FILE_INVALID_NAME The old or new file name is not a valid Linux file name
    * @throws ERR_SESS_RENAME_SAME_NAME  The old and new file names coincide
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void renameFile(std::string& oldFilename, std::string& newFilename);

   /**
    * @brief Prints on stdout the list of files in the user's storage pool
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void listPoolFiles();
 };


#endif //SAFECLOUD_CLISESSMGR_H