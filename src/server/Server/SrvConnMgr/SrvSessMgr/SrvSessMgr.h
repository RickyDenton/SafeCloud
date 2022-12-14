#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager Declaration */

/* ================================== INCLUDES ================================== */
#include "SafeCloudApp/ConnMgr/SessMgr/SessMgr.h"


// Forward Declaration
class SrvConnMgr;

class SrvSessMgr : public SessMgr
 {
  private:

   /* ================================= ATTRIBUTES ================================= */

   /* Same of the 'SessMgr' base class */

   /* ============================== PRIVATE METHODS ============================== */

   /* ------------------- Server Session Manager Utility Methods ------------------- */

   /**
    * @brief Sends a session message signaling type to the client and throws the
    *        associated exception in case of session error signaling message types
    * @param sessMsgSignalingType The session message signaling type to be sent to the client
    * @param errReason            An optional error reason to be embedded with the exception
    *                             associated with the session error signaling message type
    * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message
    *                                       invalid for its current operation or step
    * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received
    *                                       a malformed session message
    * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a
    *                                       session message of unknown type
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void sendSrvSessSignalMsg(SessMsgType sessMsgType);

   void sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason);

   /**
    * @brief  Dispatches a received session message to the callback method associated with
    *         its type and the server session manager current operation and implicit step
    * @note   The validity of the received session message type in the
    *         srvSessMsgHandler() server session message handler method
    * @throws ERR_SESS_UNEXPECTED_MESSAGE The received session message type is invalid
    *                                     for the current session manager operation
    *                                     and step (should NEVER happen)
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void dispatchRecvSessMsg();

   /* --------------------- 'UPLOAD' Operation Callback Methods --------------------- */

   /**
    * @brief 'UPLOAD' operation 'START' callback, which:\n\n
    *           1) Loading the name and metadata of the remote file to be uploaded\n\n
    *              2.1) If the file to be uploaded is empty, directly touch such a file in the
    *                   user's storage pool and notify them that the upload operation has completed\n\n
    *              2.2) If the file to be uploaded is NOT empty, depending on whether a file with
    *                   the same name already exists in the user's storage pool:\n\n
    *                   2.1.1) If it does, the local file information are sent to the client,
    *                          with their confirmation  being required on whether the upload
    *                          should proceed and so such file be overwritten\n\n
    *                   2.2.2) If it does not, notify the client that the server
    *                          is ready to receive the file's raw contents
    * @throws ERR_SESS_MALFORMED_MESSAGE    Invalid file values in the 'SessMsgFileInfo' message
    * @throws ERR_SESS_MAIN_FILE_IS_DIR     The file to be uploaded was found as a
    *                                       directory in the client's storage pool (!)
    * @throws ERR_SESS_INTERNAL_ERROR       Invalid session manager operation
    *                                       or step or file read/write error
    * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the uploaded empty main file
    * @throws ERR_SESS_FILE_OPEN_FAILED     Error in opening the uploaded empty main file
    * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the uploaded empty main file
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the empty main file's metadata
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void uploadStartCallback();

   /**
    * @brief  'UPLOAD' operation 'CONFIRM' session message callback, which:\n\n
    *             1) [PATCH] If the file to be uploaded is empty, touch it in the user's
    *                storage pool, possibly overwriting the existing one, notify the client
    *                the success of the upload operation and reset the session state\n\n
    *             2) If the file to be uploaded is NOT empty, prepare the server session
    *                manager to receive its raw contents.
    * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the existing empty file
    * @throws ERR_SESS_FILE_OPEN_FAILED     Error in touching the empty file to be uploaded
    * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the empty file to be uploaded
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the metadata
    *                                       of the file to be uploaded
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED         The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    * @throws ERR_SESS_FILE_OPEN_FAILED     Failed to open the temporary file
    *                                       descriptor in write-byte mode
    */
   void uploadConfCallback();

   /**
    * @brief  'UPLOAD' operation raw file contents callback, which:\n\n
    *            1) If the file being uploaded has not been completely received yet, decrypts its received raw
    *               bytes and writes them into the session's temporary file in the user's temporary directory\n\n
    *            2) If the file being uploaded has been completely received, verifies its trailing integrity
    *               tag, moves the temporary into the associated main file in the user's storage pool, sets
    *               its last modified time to the one specified in the '_remFileInfo' object, notifies the
    *               success of the upload operation to the client and resets the server session manager state
    * @param  recvBytes The number of bytes received in the associated connection manager's primary buffer
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
    * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
    *                                        file or NULL session attributes
    */
   void uploadRecvRawCallback(size_t recvBytes);

   /* -------------------- 'DOWNLOAD' Operation Callback Methods -------------------- */

   /**
    * @brief  'DOWNLOAD' operation 'START' callback, checking whether a file with the same
    *         name of the one the client wants to download exists in their storage pool and:\n\n
    *            1) If such a file does not exist, notify the client that the
    *               download operation cannot proceed and reset the session state.\n\n
    *            2) If such a file exists, send its information to the client and set the
    *               session manager to expect the download operation completion or confirmation
    *               notification depending on whether the file to be downloaded is empty or not.
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file name in the 'SessMsgFileName' message
    * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be downloaded was found to be a directory (!)
    * @throws ERR_SESS_INTERNAL_ERROR      Failed to open the file descriptor
    *                                      of the file to be downloaded
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void downloadStartCallback();

   /**
    * @brief 'DOWNLOAD' operation 'CONFIRM' session message callback, sending the raw contents of
    *        the file to be downloaded and its resulting integrity tag to the client, and setting
    *        the server session manager to expect the client download completion notification
    * @throws ERR_FILE_WRITE_FAILED              Error in reading from the main file
    * @throws ERR_SESSABORT_UNEXPECTED_FILE_SIZE The sent file raw contents differ from its expected size
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
   void downloadConfSendFileCallback();

   /**
    * @brief  'DOWNLOAD' operation 'COMPLETE' session message callback, logging the
    *         successful download operation and resetting the server session manager state
    */
   void downloadComplCallback();

   /* --------------------- 'DELETE' Operation Callback Methods --------------------- */

   /**
    * @brief  'DELETE' operation 'START' callback, checking whether a file with the same
    *         name of the one the client wants to delete exists in their storage pool, and:\n\n
    *            1) If such a file does not exist, notify the client that the
    *               delete operation cannot proceed and reset the session state.\n\n
    *            2) If such a file exists, send its information to the client and set
    *               the session manager to expect the delete operation confirmation.
    * @throws ERR_SESS_MALFORMED_MESSAGE   Invalid file name in the 'SessMsgFileName' message
    * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be deleted was found to be a directory (!)
    * @throws ERR_SESS_INTERNAL_ERROR      Failed to open the file descriptor
    *                                      of the file to be deleted
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void deleteStartCallback();

   /**
    * @brief  'DELETE' operation 'CONFIRM' session message callback, deleting the main file,
    *         notifying the client of its deletion and resetting the server session manager state
    * @throws ERR_SESS_INTERNAL_ERROR      Failed to delete the main file
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void deleteConfCallback();

   /* --------------------- 'RENAME' Operation Callback Methods --------------------- */

   /**
    * @brief  Starts a file rename operation, where:\n\n
    *            1) If the file to be renamed does not exist in the user's storage
    *               pool, notify them that the rename operation cannot proceed.\n\n
    *            2) If a file with the same name of the one the user wants to rename
    *               the file to exists in their storage pool, send them its
    *               information, implying that the rename operation cannot proceed.\n\n
    *            3) If the file to be renamed exists and a file with its new name does not,
    *               rename the file and notify the client the success of the rename operation.\n\n
    *         The session manager state is reset regardless of the outcome.
    * @throws ERR_SESS_MALFORMED_MESSAGE   The old or new file name is not a valid Linux
    *                                      file name or the two file names coincide
    * @throws ERR_SESS_MAIN_FILE_IS_DIR    The file to be renamed or the one with its
    *                                      new name was found to be a directory (!)
    * @throws ERR_SESS_INTERNAL_ERROR      Failed to rename the file from its old to its new name
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void renameStartCallback();

   /* ---------------------- 'LIST' Operation Callback Methods ---------------------- */

   /**
    * @brief  'LIST' operation 'START' callback, building a snapshot of the user's
    *         storage pool contents, sending its serialized size to the client and:\n
    *            1) If the user's storage pool is empty, reset the server session state.\n
    *            2) If the user's storage pool is NOT empty, send the client its
    *               serialized contents and set the server session manager to
    *               expect their completion notification.
    * @throws ERR_DIR_OPEN_FAILED                The user's storage pool was not found (!)
    * @throws ERR_SESS_FILE_READ_FAILED          Error in reading from the user's storage pool
    * @throws ERR_SESS_DIR_INFO_OVERFLOW         The storage pool information size exceeds 4GB
    * @throws ERR_SESS_INTERNAL_ERROR            The serialized size of the
    *                                            user's storage pool exceeds 4GB
    * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
    * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED                    send() fatal error
    * @throws ERR_SESSABORT_UNEXPECTED_POOL_SIZE The sent pool serialized contents
    *                                            differ from their expected size
    */
   void listStartCallback();

   /**
    * @brief  Serializes and sends a user's pool contents and its associated integrity tag to the client
    * @throws ERR_SESSABORT_UNEXPECTED_POOL_SIZE The sent pool serialized contents
    *                                            differ from their expected size
    * @throws ERR_AESGCMMGR_INVALID_STATE        Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE       The plaintext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT          EVP_CIPHER encrypt initialization failed
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE        EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL         EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED            Error in retrieving the resulting integrity tag
    * @throws ERR_SEND_OVERFLOW                  Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED              The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED                    send() fatal error
    */
   void sendPoolRawContents();

   /**
    * @brief 'LIST' operation 'COMPLETED' session message callback, logging the success
    *        of the 'LIST' operation and resetting the server session manager state
    */
   void listComplCallback();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Server session manager object constructor, initializing the session parameters
    *        of the authenticated client associated with the srvConnMgr parent object
    * @param srvConnMgr A reference to the server connection manager parent object
    */
   explicit SrvSessMgr(SrvConnMgr& cliConnMgr);

   /* Same destructor of the SessMgr base class */

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Server Session message handler, which:\n\n
    *            1) Unwraps a received session message wrapper from
    *               the primary into the secondary connection buffer\n\nn
    *            2) Asserts the resulting session message to be allowed in
    *               the current server session manager operation and step\n\n
    *            3) Handles session-resetting or terminating signaling messages\n\n
    *            4) Handles session error signaling messages\n\n
    *            5) Valid session messages requiring further action are
    *               dispatched to the session callback method associated
    *               with the current server session manager operation and step
    * @throws Most of the session and OpenSSL exceptions (see
    *         "execErrCode.h" and "sessErrCodes.h" for more details)
    */
   void srvSessMsgHandler();

   /**
    * @brief  Server session raw handler, passing the number of bytes read from the
    *         connection socket into the primary connection buffer to the raw sub-handler
    *         associated with the current server session manager operation and step
    * @param  recvBytes The number of bytes read from the connection
    *                   socket into the primary connection buffer
    * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid server session manager operation
    *                                        and step for receiving raw data
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The ciphertext block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_FILE_WRITE_FAILED          Failed to write into the temporary file
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected file integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED File integrity verification failed
    * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
    *                                        file or NULL session attributes
    * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the uploaded file's metadata
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT      EVP_CIPHER encrypt initialization failed
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE    EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL     EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED        Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED          The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED                send() fatal error
    */
   void srvSessRawHandler(size_t recvBytes);
 };


#endif //SAFECLOUD_SRVSESSMGR_H