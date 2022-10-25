#ifndef SAFECLOUD_SESSMGR_H
#define SAFECLOUD_SESSMGR_H

/* SafeCloud Session Manager */

// TODO: Rewrite descriptions, attributes included

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <string>
#include <unordered_map>
#include "DirInfo/FileInfo/FileInfo.h"
#include "ConnMgr/SessMgr/ProgressBar/ProgressBar.h"
#include "ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include "ConnMgr/ConnMgr.h"
#include "SessMsg.h"

class SessMgr
 {
  protected:

   // Session manager states
   enum sessMgrState : uint8_t
    {
     IDLE,      // Ready to execute commands
     UPLOAD,    // File upload to the SafeCloud storage pool in progress
     DOWNLOAD,  // File download from the SafeCloud storage pool in progress
     DELETE,    // File deletion from the SafeCloud storage pool in progress
     RENAME,    // File renaming within the SafeCloud storage pool in progress
     LIST       // Contents' listing of the SafeCloud storage pool in progress
    };

   /* ================================= ATTRIBUTES ================================= */

   /* ------------------------- General Session Attributes ------------------------- */
   sessMgrState   _sessMgrState;  // The current session manager state
   ConnMgr&       _connMgr;       // The associated connection manager parent object
   AESGCMMgr      _aesGCMMgr;     // The associated AES_128_GCM manager child object

   // TODO: Section

  // The session's main directory, consisting in the user's storage
  // pool on the server or their downloads folder on the client
   std::string* _mainDir;

   // The session's temporary directory
   std::string* _tmpDir;

   /* ------------------------ Files Management Attributes ------------------------ */

  // The file descriptor used for reading and the absolute path of a
  // file in the connection's main folder (the "username/download"
  // folder on the client and the "username/pool" folder on the server)
  FILE* _mainFileDscr;
  std::string* _mainFileAbsPath;

  // The file descriptor used for writing and the absolute path of a file in the
  // connection's temporary folder ("username/temp" for both the client and server)
  FILE* _tmpFileDscr;
  std::string* _tmpFileAbsPath;

   // The file name and metadata of the target local and remote file
   FileInfo*  _locFileInfo;
   FileInfo*  _remFileInfo;

   // TODO: Check description
   // The number of bytes pending to be sent or received in a raw data transmission
   unsigned int _rawBytesRem;

   /* -------------- Currently Received Session Message Header -------------- */
   uint16_t    _recvSessMsgLen;  // The currently received session message's length
   SessMsgType _recvSessMsgType; // The currently received session message's type


   /* ============================= PROTECTED METHODS ============================= */


   // TODO: Section?
   /**
    * @brief Validates and loads into a FileInfo object pointed by the '_remFileInfo' attribute
    *        the name and metadata of a remote file embedded within a 'SessMsgFileInfo'
    *        session message stored in the associated connection manager's secondary buffer
    * @throws ERR_SESS_MALFORMED_MESSAGE Invalid file values in the 'SessMsgFileInfo' message
    */
   void loadRemFileInfo();

   /**
    * @brief  Validates the 'fileName' string embedded within a 'SessMsgFileName' session message stored
    *         in the associated connection manager's secondary buffer and initializes the '_mainFileAbsPath'
    *         attribute to the concatenation of the session's main directory with such file name
    * @return The file name embedded in the 'SessMsgFileName' session message
    * @throws ERR_SESS_MALFORMED_MESSAGE The 'fileName' string does not represent a valid Linux file name
    */
   std::string loadMainFileName();

   /**
    * @brief Attempts to load into the '_locFileInfo' attribute the information
    *        of the main file referred by the '_mainFileAbsPath' attribute
    * @throws ERR_SESS_INTERNAL_ERROR   The '_mainFileAbsPath' attribute has not been initialized
    * @throws ERR_SESS_MAIN_FILE_IS_DIR The main file was found to be a directory (!)
    */
   void checkLoadMainFile();

   /**
    * @brief  Prepares in the associated connection manager's secondary buffer a 'SessMsgFileInfo' session message
    *         of the specified type containing the name and metadata of the local file referred by the '_locFileInfo'
    *         attribute, for then wrapping and sending the resulting session message wrapper to the connection peer
    * @param  sessMsgType The 'SessMsgFileInfo' session message type (FILE_UPLOAD_REQ || FILE_EXISTS || NEW_FILENAME_EXISTS)
    * @throws ERR_SESS_INTERNAL_ERROR      Invalid 'sessMsgType' or the '_locFileInfo' attribute has not been initialized
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
    *        session message of the specified type and fileName value, for then wrapping
    *        and sending the resulting session message wrapper to the connection peer
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
    * @brief  Mirrors the remote file last modification time as for the '_remFileInfo' attribute into the main file
    * @param  fileAbsPath The absolute path of the local file whose last modification time is to be changed
    * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
    */
   void mirrorRemLastModTime();

   /**
    * @brief  Deletes if present the empty file in the main directory referred by the
    *         '_mainFileAbsPath' and '_locFileInfo' attributes, for then touching it and
    *         setting its last modified time to the one referred by the '_remFileInfo' object
    * @note   If present the file is preliminarily deleted from the main
    *         directory for the purposes of updating its creation time
    * @throws ERR_SESS_INTERNAL_ERROR       NULL '_mainFileAbsPath' or '_remFileInfo' attributes
    * @throws ERR_SESS_FILE_DELETE_FAILED   Error in deleting the main file
    * @throws ERR_SESS_FILE_OPEN_FAILED     Error in touching the main file
    * @throws ERR_SESS_FILE_CLOSE_FAILED    Error in closing the main file
    * @throws ERR_SESS_FILE_META_SET_FAILED Error in setting the main file's metadata
    */
   void touchEmptyFile();


   /* ------------------------------ Utility Methods ------------------------------ */

   /**
    * @brief  Returns whether a session message type
    *         is a signaling session message type
    * @return 'true' if the provided session message type is
    *         a signaling session message type or 'false' otherwise
    */
   static bool isSessSignalingMsgType(SessMsgType sessMsgType);

   /**
    * @brief  Returns whether a session message type
    *         is a signaling error session message type
    * @return 'true' if the provided session message type is a signaling
    *          error session message type or 'false' otherwise
    */
   static bool isSessErrSignalingMsgType(SessMsgType sessMsgType);

   /**
    * @brief Converts a session manager state to string
    * @return The session manager state as a string
    */
   static std::string sessMgrStateToStr(sessMgrState sesMgrState);

   /**
    * @brief Converts the current session manager state to string
    * @return The current session manager state as a string
    */
   std::string currSessMgrStateToStr();

   /**
    * @brief  Returns a string outlining the current
    *         operation that has been aborted, if any
    * @return A string outlining the current
    *         operation that has been aborted
    */
   std::string abortedCmdToStr();

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
    *         buffer into its associated session message in the connection's secondary buffer
    * @throws ERR_AESGCMMGR_INVALID_STATE    Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_DECRYPT_INIT      EVP_CIPHER decrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE   The AAD size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_DECRYPT_UPDATE    EVP_CIPHER decrypt update failed
    * @throws ERR_OSSL_SET_TAG_FAILED        Error in setting the expected integrity tag
    * @throws ERR_OSSL_DECRYPT_VERIFY_FAILED Session message integrity verification failed
    */
   void unwrapSessMsg();

   /* --------------------- Session Signaling Messages Sending --------------------- */

   /**
    * @brief Wraps and sends a session signaling message, i.e. a session
    *        session message with no payload, to the connection peer
    * @param sessMsgSignalingType          The session signaling message type to be sent
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

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Session manager object constructor, initializing
    *        session parameters and its child AESGCMMgr object
    * @param connMgr A reference to the connection manager parent object
    * @param connMgr The session's main directory, consisting in the user's storage
    *                pool on the server or their downloads folder on the client
    */
   SessMgr(ConnMgr& connMgr, std::string* mainDir);

   /**
    * @brief Session manager object destructor, performing cleanup operation
    * @note  It is assumed the secure erasure of the connection's cryptographic quantities
    *        (session key, IV) to be performed by the associated connection manager object
    */
   ~SessMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Resets all session parameters in preparation to the next session command to be executed,
    *        also resetting the associated connection manager's reception mode to 'RECV_MSG'
    */
   void resetSessState();
 };


#endif //SAFECLOUD_SESSMGR_H
