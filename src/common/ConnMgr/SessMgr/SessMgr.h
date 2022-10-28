#ifndef SAFECLOUD_SESSMGR_H
#define SAFECLOUD_SESSMGR_H

/* SafeCloud Session Manager */

/*
 * Session Manager Glossary:
 * ========================
 * - Main Directory: A user's storage pool on the SafeCloud server or
 *                   their downloads folder in the client application
 * - Main File:      A file in the user's storage pool on the SafeCloud server
 *                   or in their download folder in the client application
 * - Temporary File: A file in the user's temporary folder on the
 *                   SafeCloud server or in the client application
 *
 * NOTE: In the context of an 'UPLOAD' operation the main file is the file
 *       the user wants to upload, whether it is in its main directory or not
 */


/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <string>
#include <unordered_map>
#include "DirInfo/FileInfo/FileInfo.h"
#include "ConnMgr/SessMgr/ProgressBar/ProgressBar.h"
#include "ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include "ConnMgr/ConnMgr.h"
#include "SessMsg.h"
#include "DirInfo/DirInfo.h"

class SessMgr
 {
  protected:

   // Session manager operations
   enum sessMgrOp : uint8_t
    {
     IDLE,      // Idle session manager
     UPLOAD,    // File upload to the user's SafeCloud storage pool
     DOWNLOAD,  // File download from the user's SafeCloud storage pool
     DELETE,    // File deletion from the user's SafeCloud storage pool
     RENAME,    // File renaming in the user's SafeCloud storage pool
     LIST       // Listing the user's SafeCloud storage pool contents
    };

  // Session manager operations steps
  enum sessMgrOpStep : uint8_t
   {
    OP_START,      // Default starting step                                                   (both)
    WAITING_RESP,  // Awaiting the server's response to an operation-starting session message (client only)
    WAITING_CONF,  // Awaiting the client confirmation notification                           (server only)
    WAITING_RAW,   // Awaiting raw data                                                       (both)
    WAITING_COMPL  // Awaiting the operation completion notification                          (both)
   };

   /* ================================= ATTRIBUTES ================================= */

   /* ------------------------ Constant Session Attributes ------------------------ */

   /*
    * These attributes are constant across the entire Session Manager execution
    */

   // The associated connection manager parent object
   ConnMgr&       _connMgr;

   // The absolute path of the session's main directory
   std::string* _mainDirAbsPath;

   // The absolute path of the session's temporary directory
   std::string* _tmpDirAbsPath;

   /* -------------------------- Session State Attributes -------------------------- */

   /*
    * These attributes are reset, possibly to a degree,
    * across different session manager operations
    */

   // The session manager current operation and operation step
   sessMgrOp     _sessMgrOp;
   sessMgrOpStep _sessMgrOpStep;

   // The associated AES_128_GCM manager child object
   AESGCMMgr     _aesGCMMgr;

   // The contents of the session's main directory
   DirInfo* _mainDirInfo;

   // The absolute path, information and file descriptor
   // of a same file in the session's main directory
   std::string* _mainFileAbsPath;
   FileInfo*    _mainFileInfo;
   FILE*        _mainFileDscr;

   // The absolute path and file descriptor
   // of a same file in the session's temporary directory
   std::string* _tmpFileAbsPath;
   FILE* _tmpFileDscr;

   // Information on a remote file
   FileInfo*  _remFileInfo;

   // The number of remaining raw bytes to be
   // sent or received in a raw data transmission
   unsigned int _rawBytesRem;

   // The length and type of the last received session message
   uint16_t    _recvSessMsgLen;
   SessMsgType _recvSessMsgType;


   /* ============================= PROTECTED METHODS ============================= */

   /* ------------------------------ Utility Methods ------------------------------ */

   /**
    * @brief  Returns whether a session message type
    *         is a signaling session message type
    * @return 'true' if the provided session message type is
    *         a signaling session message type or 'false' otherwise
    */
   static bool isSessSignalingMsgType(SessMsgType sessMsgType);

   /**
    * @brief   Returns whether a session message type
    *          is a signaling error session message type
    * @return 'true' if the provided session message type is a signaling
    *          error session message type or 'false' otherwise
    */
   static bool isSessErrSignalingMsgType(SessMsgType sessMsgType);

   /**
    * @brief  Converts the current session manager operation to a lowercase string
    * @return The current session manager operation as a lowercase string
    */
   std::string sessMgrOpToStrLowCase();

   /**
    * @brief  Converts the current session manager operation to a uppercase string
    * @return The current session manager operation as a uppercase string
    */
   std::string sessMgrOpToStrUpCase();

   /**
    * @brief  Converts the current session manager operation step to a uppercase string
    * @return The current session manager operation step as a uppercase string
    */
   std::string sessMgrOpStepToStrUpCase();

   /**
    * @brief  Returns a string outlining the current
    *         operation that has been aborted, if any
    * @return A string outlining the current
    *         operation that has been aborted
    */
   std::string abortedOpToStr();

   /* --------------------------- Session Files Methods --------------------------- */

   // TODO
   void validateSessFileName(std::string& fileName);

   /**
    * @brief Attempts to load into the '_mainFileInfo' attribute the information
    *        of the main file referred by the '_mainFileAbsPath' attribute
    * @throws ERR_SESS_INTERNAL_ERROR   The '_mainFileAbsPath' attribute has not been initialized
    * @throws ERR_SESS_MAIN_FILE_IS_DIR The main file was found to be a directory (!)
    */
   void checkLoadMainFileInfo();

   /**
    * @brief  Sets the main file last modification time to the one specified in the '_remFileInfo' attribute
    * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
    */
   void mainToRemLastModTime();

   /**
    * @brief  If present deletes the main empty file for then touching it and setting its
    *         last modified time to the one specified in the '_remFileInfo' attribute
    * @note   If present the main file is preliminarily deleted
    *         for the purposes of updating its creation time
    * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
    * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the main file
    * @throws ERR_SESS_FILE_OPEN_FAILED     Error in touching the main file
    * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the main file
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
    */
   void touchEmptyFile();

   /**
    * @brief  Prepares the session manager to receive the raw
    *         contents of a file being uploaded or downloaded
    * @throws ERR_SESSABORT_INTERNAL_ERROR  Invalid session manager operation or step
    *                                       for receiving a file's raw contents
    * @throws ERR_SESS_FILE_OPEN_FAILED     Failed to open the temporary file
    *                                       descriptor in write-byte mode
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_OSSL_EVP_DECRYPT_INIT     EVP_CIPHER decrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void prepRecvFileData();

   /* -------------------- Session Messages Wrapping/Unwrapping -------------------- */

   /**
    * @brief  Wraps a session message stored in the associated connection's
    *         secondary buffer into a session message wrapper in the connection's
    *         primary buffer, sending the resulting wrapper to the connection peer
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void wrapSendSessMsg();

   /**
    * @brief  Unwraps a session message wrapper stored in the associated connection's primary
    *         buffer into its resulting session message in the connection's secondary buffer
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_DECRYPT_INIT      EVP_CIPHER decrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The AAD size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Session message integrity verification failed
    */
   void unwrapSessMsg();

   /* -------------------------- Session Messages Sending -------------------------- */

   /**
    * @brief  Wraps and sends a session signaling message, i.e. a session
    *         session message with no payload, to the connection peer
    * @param  sessMsgSignalingType         The session signaling message type to be sent
    * @throws ERR_SESS_INTERNAL_ERROR      Attempting to send a non-signaling session message
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendSessSignalMsg(SessMsgType sessMsgSignalingType);

   /**
    * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileInfo' session message
    *         of the specified type containing the name and metadata of the main file referred by the '_mainFileInfo'
    *         attribute, for then wrapping and sending the resulting session message wrapper to the connection peer
    * @param  sessMsgType The 'SessMsgFileInfo' session message type (FILE_UPLOAD_REQ || FILE_EXISTS)
    * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType' or uninitialized '_mainFileInfo' attribute
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendSessMsgFileInfo(SessMsgType sessMsgType);

   /**
    * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileName'
    *         session message of the specified type and fileName value, for then wrapping
    *         and sending the resulting session message wrapper to the connection peer
    * @param  sessMsgType The 'SessMsgFileName' session message type (FILE_DOWNLOAD_REQ || FILE_DELETE_REQ)
    * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType'
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendSessMsgFileName(SessMsgType sessMsgType, std::string& fileName);

   /**
    * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileRename' session
    *         message of implicit type 'FILE_RENAME_REQ' containing the specified old and new file names,
    *         for then wrapping and sending the resulting session message wrapper to the connection peer
    * @param  oldFilename The name of the file to be renamed
    * @param  newFilename The name the file should be renamed to
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendSessMsgFileRename(std::string& oldFilename, std::string& newFilename);

   /**
    * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgPoolSize' session
    *         message of implicit type 'POOL_SIZE' containing the serialized size of the user's storage pool,
    *         for then wrapping and sending the resulting session message wrapper to the connection peer
    * @param  serPoolSize The serialized size of the user's storage pool
    * @throws ERR_AESGCMMGR_INVALID_STATE  Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT    EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE  EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL   EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED      Error in retrieving the resulting integrity tag
    * @throws ERR_PEER_DISCONNECTED        The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED              send() fatal error
    */
   void sendSessMsgPoolSize(unsigned int serPoolSize);

   /* ------------------------- Session Messages Reception ------------------------- */

   /**
    * @brief Validates and loads into a FileInfo object pointed by the '_remFileInfo' attribute
    *        the name and metadata of a remote file embedded within a 'SessMsgFileInfo'
    *        session message stored in the associated connection manager's secondary buffer
    * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file values in the 'SessMsgFileInfo' message
    */
   void loadRemSessMsgFileInfo();

   /**
    * @brief  Validates the 'fileName' string embedded within a 'SessMsgFileName' session message stored
    *         in the associated connection manager's secondary buffer and initializes the '_mainFileAbsPath'
    *         attribute to the concatenation of the session's main directory with such file name
    * @return The file name embedded in the 'SessMsgFileName' session message
    * @throws ERR_SESS_MALFORMED_MESSAGE The 'fileName' string does not represent a valid Linux file name
    */
   std::string loadMainSessMsgFileName();

   /**
    * @brief Extracts and validates the old and new file names embedded within a 'SessMsgFileRename'
    *        session message stored in the associated connection manager's secondary buffer
    * @param oldFilenameDest The pointer to be initialized to the old file name
    * @param newFilenameDest The pointer to be initialized to the new file name
    * @throws ERR_SESS_MALFORMED_MESSAGE The old or new file name is not a valid Linux
    *                                    file name or the two file names coincide
    */
   void loadSessMsgFileRename(std::string** oldFilenameDest, std::string** newFilenameDest);

   /**
    * @brief Reads the serialized size of a user's storage pool from a
    *        'SessMsgPoolSize' session  message into the '_rawBytesRem' attribute
    */
   void loadSessMsgPoolSize();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Client session manager object constructor, initializing the session attributes
    *         of the authenticated user associated with the CliConnMgr parent object
    * @param cliConnMgr A reference to the CliConnMgr parent object
    */
   SessMgr(ConnMgr& connMgr, std::string* mainDir);

   /**
    * @brief Session manager object destructor,  performing cleanup operations on the session's
    *        state attributes and resetting the associated connection manager's reception mode
    *        to 'RECV_MSG' and marking the contents of its primary connection buffer as consumed
    * @note  It is assumed the connection's cryptographic quantities (session key, IV)
    *        to be securely erased by the associated connection manager parent object
    */
   ~SessMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief  Returns whether the session manager is idle
    * @return A boolean indicating whether the connection manager is idle
    */
   bool isIdle();

   /**
    * @brief Reset the session manager state in preparation to the next session operation by
    *        resetting and performing cleanup operation on all its session state attributes
    *        and by resetting the associated connection manager's reception mode to 'RECV_MSG'
    *        and by marking the contents of its primary connection buffer as consumed
    */
   void resetSessState();
 };


#endif //SAFECLOUD_SESSMGR_H
