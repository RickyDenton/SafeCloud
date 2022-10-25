#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager Class Declaration */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"


// Forward Declaration
class SrvConnMgr;

class SrvSessMgr : public SessMgr
 {
  private:

   // Server Session Manager Sub-states
   enum srvSessCmdState : uint8_t
    {
     SRV_IDLE,
     WAITING_CLI_CONF,
     WAITING_CLI_RAW_DATA,
     WAITING_CLI_COMPL
    };

   /* ================================= ATTRIBUTES ================================= */
   srvSessCmdState _srvSessMgrSubstate;  // The current server session manager sub-state
   SrvConnMgr&     _srvConnMgr;          // The associated SrvConnMgr parent object

   /* ============================== PRIVATE METHODS ============================== */

   /**
    * @brief Sends a session message signaling type to the client and performs the actions
    *        appropriate to session signaling types resetting or terminating the session
    * @param sessMsgSignalingType The session message signaling type to be sent to the client
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
    * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void sendSrvSessSignalMsg(SessMsgType sessMsgType);
   void sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason);


   // TODO
   void dispatchRecvSessMsg();

   /* ------------------------------- 'UPLOAD' Callback Methods ------------------------------- */

   /**
   * @brief Starts a file upload operation by:\n
   *           1) Loading into the '_remFileInfo' attribute the name and metadata of the file to be uploaded\n
   *           2) Checking whether a file with the same name of the one to be uploaded already exists in the client's storage pool\n
   *              2.1) If it does, the name and metadata of such file are sent to the client, with
   *                   their confirmation being required on whether such file should be overwritten\n
   *              2.2) If it does not:\n
   *                   2.2.1) If the file to be uploaded is empty, directly touch such file, set its last modified time to
   *                          the one provided by the client and inform them that the file has been successfully uploaded \n
   *                   2.2.2) If the file to be uploaded is NOT empty, inform the client
   *                          that the server is ready to receive the file's raw contents
   * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file values in the 'SessMsgFileInfo' message
   * @throws ERR_SESS_MAIN_FILE_IS_DIR  The file to be uploaded was found as a directory in the client's storage pool (!)
   * @throws ERR_SESS_INTERNAL_ERROR       Invalid session manager state or file read/write error
   * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the uploaded empty main file
   * @throws ERR_SESS_FILE_OPEN_FAILED     Error in opening the uploaded empty main file
   * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the uploaded empty main file
   * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the empty main file's metadata
   * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
   * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
   * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
   * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
   * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
   * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
   * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
   * @throws ERR_SEND_FAILED              send() fatal error
   */
   void srvUploadStart();

   /**
    * @brief Prepares the server session manager to receive
    *        the raw contents of a file to be uploaded
    * @throws ERR_INTERNAL_ERROR            Could not open the temporary file descriptor in write-byte mode
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void srvUploadSetRecvRaw();

   /**
    * @brief  Server file upload raw data handler, which:\n
    *            1) If the file being uploaded has not been completely received yet, decrypts its received raw
    *               contents and writes them into the session's temporary file in the user's temporary directory\n
    *            2) If the file being uploaded has been completely received, verifies its trailing integrity tag,
    *               moves the temporary into the associated main file in the user's storage pool, notifies the
    *               client the success of the upload operation and resets the server session manager state\n
    * @param  recvBytes The number of bytes received in the associated connection manager's primary buffer
    * @throws ERR_FILE_WRITE_FAILED          Error in writing to the temporary file
    * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the uploaded file's metadata
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
    * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
    *                                        file or NULL session attributes
    */
   void recvUploadFileData(size_t recvBytes);

   /* ------------------------------ 'DOWNLOAD' Callback Methods ------------------------------ */

   /**
    * @brief  Starts a file download operation by checking whether a file with the same name
    *         of the one the client wants to download exists in their storage pool, and:\n
    *            1) If such a file does not exist, notify the client and reset the session state
    *            2) If such a file exists, send its information to the client and set\n
    *               the session manager to expect the download operation confirmation
    * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file name in the 'SessMsgFileName' message
    * @throws ERR_SESS_MAIN_FILE_IS_DIR  The file to be downloaded was found to be a directory (!)
    * @throws ERR_SESS_INTERNAL_ERROR      Failed to open the file descriptor of the file to be downloaded
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void srvDownloadStart();

   // TODO
   void sendDownloadFileData();

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
    * @brief Resets all session parameters in preparation for the next
    *        session command to be executed by the server session manager
    */
   void resetSrvSessState();

   /**
    * @brief  Server Session message handler, which:\name
    *            1) Unwraps a received session message wrapper from
    *               the primary into the secondary connection buffer\n
    *            2) Asserts the resulting session message to be allowed in
    *               the current server session manager state and substate\n
    *            3) Handles session-resetting or terminating signaling messages\n
    *            4) Handles session error signaling messages\n
    *            5) Valid session messages requiring further action are
    *               dispatched to the session callback method associated
    *               with the session manager current state and substate
    * @throws TODO (most session exceptions)
    */
   void srvSessMsgHandler();

   /**
    * @brief  Server session raw handler, passing the raw data received from the socket to
    *         the appropriate handler depending on the session manager's state and substate
    * @param  recvBytes The number of bytes received in the associated connection manager's primary buffer
    * @throws ERR_SESSABORT_INTERNAL_ERROR   Invalid AES_128_GCM manager state
    * @throws ERR_FILE_WRITE_FAILED          Error in writing to the temporary file
    * @throws ERR_SESS_FILE_META_SET_FAILED  Error in setting the uploaded file's metadata
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
    * @throws ERR_SESS_INTERNAL_ERROR        Failed to close or move the uploaded temporary
    *                                        file or NULL session attributes
    */
   void srvSessRawHandler(size_t recvBytes);
 };


#endif //SAFECLOUD_SRVSESSMGR_H
