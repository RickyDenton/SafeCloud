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
   unsigned int _bytesRem;

   /* -------------- Currently Received Session Message Header -------------- */
   uint16_t    _recvSessMsgLen;  // The currently received session message's length
   SessMsgType _recvSessMsgType; // The currently received session message's type


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
    * @brief Converts the current session manager state to string
    * @return The current session manager state as a string
    */
   std::string sessMgrStateToStr();

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
    */
   explicit SessMgr(ConnMgr& _connMgr);

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
